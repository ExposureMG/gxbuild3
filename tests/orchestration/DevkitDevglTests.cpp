// run_build's devkit and devgl images (src/BuildRunner.cpp, src/nand/FlashImage.cpp,
// src/utils/XeRsa.cpp). Devkit: the SB/SC/SD/SE chain is sealed from the zero secret under a
// header stating the SE build, a 64 MB image reads back and rebuilds its chain byte for byte, the
// stages take the donor nonces of their positions, the image keeps its own 64 MB shape beside a
// 16 MB donor, and raw patches are written last and bounded by the image. Devgl: the SD carries the
// CD patch section and is signed again with the SB private key (the throwaway key of
// support/XeRsaTestKey.hpp, through test::devgl_input), the fuses and KHV patches fill the second
// slot, a big-block image steps its slots by 0x20000, and a missing or malformed SB key is refused.
// The stages are opened here by hand with GxCrypt's HMAC-SHA and RC4, independently of src/. One
// ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "excrypt.h"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BootloaderCe;
        using nand::Driver;
        using nand::NANDBootloaderMagic;
        using test::Bytes;

        std::array<uint8_t, 16> hmac_key(std::span<const uint8_t> parent,
                                         std::span<const uint8_t> nonce) {
            uint8_t digest[20];
            ExCryptHmacSha(parent.data(), static_cast<uint32_t>(parent.size()), nonce.data(),
                           static_cast<uint32_t>(nonce.size()), nullptr, 0, nullptr, 0, digest, 20);
            std::array<uint8_t, 16> key{};
            std::copy_n(digest, key.size(), key.begin());
            return key;
        }

        // A stage opened by hand: its nonce at 0x10 keys RC4 over everything from 0x20.
        Bytes open_stage(Bytes stage, std::span<const uint8_t> key) {
            ExCryptRc4(key.data(), static_cast<uint32_t>(key.size()), stage.data() + 0x20,
                       static_cast<uint32_t>(stage.size() - 0x20));
            return stage;
        }

        // The nonce slot of a stored stage.
        std::span<const uint8_t> nonce_of(const Bytes& stage) {
            return std::span<const uint8_t>(stage).subspan(0x10, 0x10);
        }

        // The 0x37 bytes of the copyright notice at 0x10 of a 0x80-byte header.
        std::string_view copyright_of(const Bytes& header) {
            return std::string_view(reinterpret_cast<const char*>(header.data() + 0x10), 0x37);
        }

        // Whether an opened stage is the supplied one from `from` on, at the supplied size.
        ::testing::AssertionResult body_matches(const Bytes& opened, const Bytes& supplied,
                                                size_t from) {
            if (opened.size() != supplied.size()) {
                return ::testing::AssertionFailure()
                       << std::format("the opened stage is {:#x} bytes, the supplied {:#x}",
                                      opened.size(), supplied.size());
            }
            if (!std::equal(opened.begin() + static_cast<std::ptrdiff_t>(from), opened.end(),
                            supplied.begin() + static_cast<std::ptrdiff_t>(from))) {
                return ::testing::AssertionFailure() << "the bodies differ";
            }
            return ::testing::AssertionSuccess();
        }

        // An opened stage runs to its 16-byte boundary; the rounding reads back zero.
        ::testing::AssertionResult reads_back_as(const Bytes& opened, const Bytes& supplied) {
            if (opened.size() != align_16(static_cast<uint32_t>(supplied.size()))) {
                return ::testing::AssertionFailure() << std::format(
                           "the stage reads back as {:#x} bytes, not {:#x}", opened.size(),
                           align_16(static_cast<uint32_t>(supplied.size())));
            }
            if (!std::equal(supplied.begin() + 0x40, supplied.end(), opened.begin() + 0x40)) {
                return ::testing::AssertionFailure() << "the bodies differ from 0x40";
            }
            if (!zero_between(opened, supplied.size(), opened.size())) {
                return ::testing::AssertionFailure() << "the 16-byte rounding is not zero";
            }
            return ::testing::AssertionSuccess();
        }

        TEST(Devkit, ChainIsSealedFromTheZeroSecret) {
            const auto input = test::devkit_input(ImageType::NewSmallBlock);
            ASSERT_TRUE(input.bootloaders.sc.has_value());
            ASSERT_TRUE(input.bootloaders.ce.has_value());
            const auto built = run_build(input);
            ASSERT_OK(built) << "a small-block devkit image is 64 MB with spare";
            ASSERT_EQ(built->size(), 0x4200000u)
                << "a small-block devkit image is 64 MB with spare";

            const auto header = read_logical(*built, 0, 0x80);
            const uint32_t chain_end = 0x8000 +
                                       align_16(uint32_t(input.bootloaders.cb_or_a.size())) +
                                       align_16(uint32_t(input.bootloaders.sc->size())) +
                                       align_16(uint32_t(input.bootloaders.cd.size())) +
                                       align_16(uint32_t(input.bootloaders.ce->size()));
            const uint32_t slot = (chain_end + 0x3FFF) & ~uint32_t{0x3FFF};
            ASSERT_TRUE(header.has_value()) << "the devkit header states the SE build";
            ASSERT_EQ(header->size(), 0x80u) << "the devkit header states the SE build";
            EXPECT_EQ(test::be16(*header, 0x02), 17489u) << "the devkit header states the SE build";
            EXPECT_EQ(test::be16(*header, 0x04), 0x8000u)
                << "the devkit header states 0x8000 at 0x04";
            EXPECT_TRUE(copyright_of(*header).contains("2004-2010"))
                << "the devkit header states 2010 on a Jasper";
            EXPECT_EQ(test::be32(*header, 0x0C), slot)
                << "the first slot follows the chain at the next erase block";
            EXPECT_EQ(test::be32(*header, 0x64), slot)
                << "the first slot follows the chain at the next erase block";
            EXPECT_EQ(test::be16(*header, 0x68), 2u) << "the devkit header states two slots of "
                                                        "0x10000";
            EXPECT_EQ(test::be32(*header, 0x70), 0x10000u)
                << "the devkit header states two slots of 0x10000";
            EXPECT_EQ(test::be32(*header, 0x48), 0u)
                << "a devkit image states no hack or boot flags";
            EXPECT_EQ(test::be32(*header, 0x4C), 0u)
                << "a devkit image states no hack or boot flags";

            size_t at = 0x8000;
            const auto stored = [&](const Bytes& supplied) {
                auto bytes = read_logical(*built, at, supplied.size());
                at += align_16(static_cast<uint32_t>(supplied.size()));
                return bytes.value_or(Bytes{});
            };
            const auto sb = stored(input.bootloaders.cb_or_a);
            const auto sc = stored(*input.bootloaders.sc);
            const auto sd = stored(input.bootloaders.cd);
            const auto se = stored(*input.bootloaders.ce);
            ASSERT_EQ(sb.size(), input.bootloaders.cb_or_a.size()) << "the stored SB reads";
            ASSERT_EQ(sc.size(), input.bootloaders.sc->size()) << "the stored SC reads";
            ASSERT_EQ(sd.size(), input.bootloaders.cd.size()) << "the stored SD reads";
            ASSERT_EQ(se.size(), input.bootloaders.ce->size()) << "the stored SE reads";
            ASSERT_GE(sb.size(), 0x40u) << "the stored SB holds its per-box digest";
            const std::array<uint8_t, 16> zero{};
            const auto k_sb = hmac_key(std::span(nand::key_1bl), nonce_of(sb));
            const auto k_sc = hmac_key(zero, nonce_of(sc));
            const auto k_sd = hmac_key(k_sc, nonce_of(sd));
            const auto k_se = hmac_key(k_sd, nonce_of(se));
            const auto sb_plain = open_stage(sb, k_sb);
            EXPECT_TRUE(body_matches(sb_plain, input.bootloaders.cb_or_a, 0x40))
                << "SB opens under HMAC(1BL key, nonce)";
            EXPECT_BYTES_EQ(input.metadata.pairing_data, std::span(sb_plain).subspan(0x20, 3))
                << "SB carries the console's pairing";
            EXPECT_FALSE(zero_between(sb_plain, 0x30, 0x40))
                << "SB binds the SMC in its per-box digest";
            EXPECT_TRUE(body_matches(open_stage(sc, k_sc), *input.bootloaders.sc, 0x20))
                << "SC opens under HMAC(16 zero bytes, nonce)";
            EXPECT_TRUE(body_matches(open_stage(sd, k_sd), input.bootloaders.cd, 0x20))
                << "SD opens under HMAC(SC key, nonce)";
            EXPECT_TRUE(body_matches(open_stage(se, k_se), *input.bootloaders.ce, 0x20))
                << "SE opens under HMAC(SD key, nonce)";
        }

        TEST(Devkit, ImageReadsBackAndRebuildsItsChain) {
            const auto input = test::devkit_input(ImageType::NewSmallBlock);
            ASSERT_TRUE(input.bootloaders.sc.has_value());
            ASSERT_TRUE(input.bootloaders.ce.has_value());
            const auto built = run_build(input);
            ASSERT_OK(built) << "a devkit image parses and opens";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "a devkit image parses and opens";
            EXPECT_EQ(extracted->build_type, BuildType::Devkit)
                << "a devkit image reads back as a small-block devkit image";
            EXPECT_EQ(extracted->image_type, ImageType::NewSmallBlock)
                << "a devkit image reads back as a small-block devkit image";
            ASSERT_TRUE(extracted->bootloaders.sc.has_value())
                << "the whole SB/SC/SD/SE chain reads back";
            ASSERT_TRUE(extracted->bootloaders.ce.has_value())
                << "the whole SB/SC/SD/SE chain reads back";

            constexpr const char* kPlaintext = "every stage reads back as the plaintext it was "
                                               "built from";
            EXPECT_TRUE(reads_back_as(extracted->bootloaders.cb_or_a, input.bootloaders.cb_or_a))
                << kPlaintext << " (SB)";
            EXPECT_TRUE(reads_back_as(*extracted->bootloaders.sc, *input.bootloaders.sc))
                << kPlaintext << " (SC)";
            EXPECT_TRUE(reads_back_as(extracted->bootloaders.cd, input.bootloaders.cd))
                << kPlaintext << " (SD)";
            EXPECT_TRUE(reads_back_as(*extracted->bootloaders.ce, *input.bootloaders.ce))
                << kPlaintext << " (SE)";
            EXPECT_EQ(extracted->metadata.pairing_data, input.metadata.pairing_data)
                << "the SB's pairing reads back";

            // Rebuilt over itself, every stage keeps the nonce at its position, so the sealed
            // chain comes out byte for byte.
            const auto rebuilt = run_build(*extracted);
            ASSERT_OK(rebuilt) << "an extracted devkit image builds again in its own shape";
            EXPECT_EQ(rebuilt->size(), built->size())
                << "an extracted devkit image builds again in its own shape";
            constexpr const char* kChain =
                "the header, SMC, keyvault and sealed chain rebuild byte "
                "for byte";
            const auto header = read_logical(*built, 0, 0x80);
            ASSERT_TRUE(header.has_value()) << kChain;
            const uint32_t slot = test::be32(*header, 0x64);
            ASSERT_NE(slot, 0u) << kChain;
            const auto chain = read_logical(*built, 0, slot);
            const auto rebuilt_chain = read_logical(*rebuilt, 0, slot);
            ASSERT_TRUE(chain.has_value()) << kChain;
            ASSERT_TRUE(rebuilt_chain.has_value()) << kChain;
            EXPECT_BYTES_EQ(*chain, *rebuilt_chain) << kChain;
        }

        TEST(Devkit, NoncesComeFromDonorPositions) {
            auto input = test::devkit_input(ImageType::BigBlock);
            ASSERT_TRUE(input.bootloaders.sc.has_value());
            ASSERT_TRUE(input.bootloaders.ce.has_value());
            DonorNonces donor{};
            for (size_t index = 0; index < donor.stages.size(); ++index) {
                BootloaderNonce nonce{};
                nonce.fill(static_cast<uint8_t>(0xA0 + index));
                donor.stages[index] = nonce;
            }
            input.metadata.donor_nonces = donor;
            const auto built = run_build(input);
            ASSERT_OK(built) << "a big-block devkit image builds";
            ASSERT_EQ(built->size(), 0x4200000u) << "a big-block devkit image builds";

            size_t at = 0x8000;
            const std::array<const Bytes*, 4> stages{&input.bootloaders.cb_or_a,
                                                     &*input.bootloaders.sc, &input.bootloaders.cd,
                                                     &*input.bootloaders.ce};
            constexpr std::array<const char*, 4> kNames{"SB", "SC", "SD", "SE"};
            for (size_t index = 0; index < stages.size(); ++index) {
                SCOPED_TRACE(kNames[index]);
                const auto nonce = read_logical(*built, at + 0x10, 0x10);
                EXPECT_BYTES_EQ(Bytes(0x10, static_cast<uint8_t>(0xA0 + index)),
                                nonce.value_or(Bytes{}))
                    << "SB, SC, SD and SE take the donor's CB_A, CB_B, CD and CE nonces";
                at += align_16(static_cast<uint32_t>(stages[index]->size()));
            }
            constexpr const char* kSlot = "a big-block devkit slot follows the chain at the next "
                                          "0x20000 block";
            const auto header = read_logical(*built, 0, 0x80);
            ASSERT_TRUE(header.has_value()) << kSlot;
            EXPECT_EQ(test::be32(*header, 0x64), 0x20000u) << kSlot;
            EXPECT_EQ(test::be32(*header, 0x70), 0x20000u) << kSlot;
        }

        // A 16 MB donor gives a devkit image its nonces and console data; the image itself is
        // the 64 MB shape the console's spare layout takes.
        TEST(Devkit, ImageTakesItsOwnShapeBesideA16MbDonor) {
            auto donor_input = test::fresh_input(ImageType::NewSmallBlock);
            // A donor's nonces are read off a chain that reaches CE.
            BootloaderCe ce{};
            ce.header.header.magic = NANDBootloaderMagic::CE;
            ce.header.header.version = 1;
            ce.data.assign(0x20, 0x45);
            ce.header.header.size = static_cast<uint32_t>(sizeof(nand::ce_header) + ce.data.size());
            ce.decrypted = true;
            donor_input.bootloaders.ce = ce.serialize();
            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "16 MB donor builds";
            ASSERT_EQ(donor->size(), 0x1080000u) << "16 MB donor builds";

            auto input = test::devkit_input(ImageType::NewSmallBlock);
            input.metadata.nand_image = *donor;
            const auto built = run_build(input);
            constexpr const char* kShape = "the devkit image is 64 MB beside a 16 MB donor";
            ASSERT_OK(built) << kShape;
            EXPECT_EQ(built->size(), 0x4200000u) << kShape;
            const auto image = parse_image(*built);
            ASSERT_TRUE(image.has_value()) << kShape;
            EXPECT_EQ(image->flash_driver.driver_mode(), Driver::DriverMode::NewSmall)
                << "it keeps the donor's spare layout";
            EXPECT_EQ(image->build_type, BuildType::Devkit) << "it reads back as devkit";

            constexpr const char* kNonce = "its SB takes the donor's first CB nonce";
            const auto donor_cb = read_logical(*donor, 0x8010, 0x10);
            const auto sb_nonce = read_logical(*built, 0x8010, 0x10);
            ASSERT_TRUE(donor_cb.has_value()) << kNonce;
            ASSERT_TRUE(sb_nonce.has_value()) << kNonce;
            EXPECT_BYTES_EQ(*donor_cb, *sb_nonce) << kNonce;
        }

        TEST(Devkit, RawPatchesAreWrittenLastAndBounded) {
            auto input = test::devkit_input(ImageType::NewSmallBlock);
            input.raw_patches.push_back(InputRawPatch{"reason.bin", 0x4E, Bytes{0x12}});
            input.raw_patches.push_back(InputRawPatch{"khv.bin", 0xE4000, Bytes(0x20, 0x77)});
            const auto built = run_build(input);
            ASSERT_OK(built) << "a raw patch overwrites the header byte it names";
            const auto reason = read_logical(*built, 0x4E, 1);
            const auto khv = read_logical(*built, 0xE4000, 0x20);
            ASSERT_TRUE(reason.has_value()) << "a raw patch overwrites the header byte it names";
            EXPECT_BYTES_EQ(Bytes{0x12}, *reason)
                << "a raw patch overwrites the header byte it names";
            ASSERT_TRUE(khv.has_value()) << "a raw patch lands at its clean offset";
            EXPECT_BYTES_EQ(Bytes(0x20, 0x77), *khv) << "a raw patch lands at its clean offset";

            auto outside = test::devkit_input(ImageType::NewSmallBlock);
            outside.raw_patches.push_back(InputRawPatch{"far.bin", 0x3FFFFFF, Bytes{1, 2}});
            EXPECT_ERROR(run_build(outside), BuildErrorCode::SerializationFailure)
                << "a raw patch running past the image is refused";
        }

        TEST(Devgl, ImagePatchesAndSignsItsSd) {
            const auto input = test::devgl_input(ImageType::NewSmallBlock);
            ASSERT_TRUE(input.bootloaders.sc.has_value());
            ASSERT_TRUE(input.sb_private_key.has_value());
            const auto built = run_build(input);
            ASSERT_OK(built) << "a Jasper devgl image keeps the console's 16 MB shape";
            ASSERT_EQ(built->size(), 0x1080000u)
                << "a Jasper devgl image keeps the console's 16 MB shape";

            const auto header = read_logical(*built, 0, 0x80);
            ASSERT_TRUE(header.has_value()) << "the devgl header states 0x0760 and no 0x8000";
            ASSERT_EQ(header->size(), 0x80u) << "the devgl header states 0x0760 and no 0x8000";
            EXPECT_EQ(test::be16(*header, 0x02), 0x0760u)
                << "the devgl header states 0x0760 and no 0x8000";
            EXPECT_EQ(test::be16(*header, 0x04), 0u)
                << "the devgl header states 0x0760 and no 0x8000";
            EXPECT_EQ(test::be32(*header, 0x48), 1u)
                << "a devgl image states the hack flag and the eject XeLL button";
            EXPECT_EQ(test::be32(*header, 0x4C), 0x12u)
                << "a devgl image states the hack flag and the eject XeLL button";
            EXPECT_EQ(test::be32(*header, 0x0C), 0xD0000u) << "the first slot is stated at 0xD0000";
            EXPECT_EQ(test::be32(*header, 0x64), 0xD0000u) << "the first slot is stated at 0xD0000";
            EXPECT_EQ(test::be16(*header, 0x68), 2u) << "two slots of 0x10000";
            EXPECT_EQ(test::be32(*header, 0x70), 0x10000u) << "two slots of 0x10000";
            EXPECT_TRUE(copyright_of(*header).contains("2004-2009"))
                << "a Jasper devgl image states the Jasper year";

            const uint32_t sd_patch_address = test::devgl_sd_patch_address(input);
            const uint32_t sd_size = align_16(sd_patch_address + 4);
            size_t at = 0x8000;
            const auto stored = [&](size_t size) {
                auto bytes = read_logical(*built, at, size);
                at += align_16(static_cast<uint32_t>(size));
                return bytes.value_or(Bytes{});
            };
            const auto sb = stored(input.bootloaders.cb_or_a.size());
            const auto sc = stored(input.bootloaders.sc->size());
            const auto sd = stored(sd_size);
            ASSERT_EQ(sb.size(), input.bootloaders.cb_or_a.size()) << "the stored SB reads";
            ASSERT_GE(sb.size(), 0x40u) << "the stored SB holds its per-box digest";
            ASSERT_EQ(sc.size(), input.bootloaders.sc->size()) << "the stored SC reads";
            ASSERT_EQ(sd.size(), sd_size) << "the stored SD reads";
            const std::array<uint8_t, 16> zero{};
            const auto k_sc = hmac_key(zero, nonce_of(sc));
            const auto sb_plain = open_stage(sb, hmac_key(std::span(nand::key_1bl), nonce_of(sb)));
            const auto sd_plain = open_stage(sd, hmac_key(k_sc, nonce_of(sd)));
            const auto key = utils::XeRsaPrivateKey::parse(*input.sb_private_key);
            const auto khv = test::devgl_khv();
            const auto slot = read_logical(*built, 0xE0000, 0x60 + khv.size() + 4);
            // 0x60 fuse bytes, the KHV patch and its terminator. Presized and copied rather than
            // inserted: g++ -O3 flags the insert into the 0x60-byte vector as -Warray-bounds.
            Bytes expected_slot(0x60 + khv.size(), 0xF5);
            std::copy(khv.begin(), khv.end(), expected_slot.begin() + 0x60);
            test::append_be32(expected_slot, 0xFFFFFFFF);
            const auto image = parse_image(*built);

            constexpr const char* kSb = "the SB is zero-paired and carries no patch";
            EXPECT_TRUE(zero_between(sb_plain, 0x20, 0x40)) << kSb;
            EXPECT_BYTES_EQ(std::span(input.bootloaders.cb_or_a).subspan(0x40),
                            std::span(sb_plain).subspan(0x40))
                << kSb;
            constexpr const char* kSd = "the SD carries the CD patch section and states its "
                                        "patched size";
            EXPECT_EQ(test::be32(sd_plain, 0x0C), sd_size) << kSd;
            EXPECT_EQ(test::be32(sd_plain, sd_patch_address), 0x10203040u) << kSd;
            constexpr const char* kSigned = "the patched SD is signed with the SB private key";
            ASSERT_OK(key) << kSigned;
            EXPECT_OK(utils::verify_sd_signature(sd_plain, key->public_key())) << kSigned;
            EXPECT_BYTES_EQ(expected_slot, slot.value_or(Bytes{}))
                << "the fuses and KHV patches fill the second slot at 0xE0000";
            ASSERT_TRUE(image.has_value()) << "the image reads back as devgl";
            EXPECT_EQ(image->build_type, BuildType::Devgl) << "the image reads back as devgl";
        }

        TEST(Devgl, BigBlockSlotsFollowTheBigBlockStep) {
            const auto built = run_build(test::devgl_input(ImageType::BigBlock));
            constexpr const char* kSlot =
                "a big-block devgl image states its first slot at 0xE0000";
            ASSERT_OK(built) << kSlot;
            const auto header = read_logical(*built, 0, 0x80);
            const auto fuses = read_logical(*built, 0x100000, 0x60);
            ASSERT_TRUE(header.has_value()) << kSlot;
            EXPECT_EQ(test::be32(*header, 0x64), 0xE0000u) << kSlot;
            EXPECT_EQ(test::be32(*header, 0x70), 0x20000u) << kSlot;
            EXPECT_BYTES_EQ(Bytes(0x60, 0xF5), fuses.value_or(Bytes{}))
                << "its fuses go to 0x100000";
        }

        TEST(Devgl, NeedsAWellFormedSbPrivateKey) {
            auto missing = test::devgl_input(ImageType::NewSmallBlock);
            missing.sb_private_key.reset();
            auto malformed = test::devgl_input(ImageType::NewSmallBlock);
            malformed.sb_private_key = Bytes(utils::kXeRsa2048PrivateKeySize, 0);
            EXPECT_ERROR_HAS(run_build(missing), BuildErrorCode::InvalidInput, "SB private key")
                << "a devgl build without the SB private key is refused";
            EXPECT_ERROR(run_build(malformed), BuildErrorCode::InvalidInput)
                << "a devgl build with a malformed key is refused";
        }

    } // namespace
} // namespace gxbuild3::orchestration
