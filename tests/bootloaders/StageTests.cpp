// Direct tests for src/nand/bootloaders/Stage.hpp, covering what the bootloader corpus
// (tests/golden/wire_corpus_bootloaders.txt) does not reach through the stage classes: the
// parse failures and their messages, payload padding, crypt_stage_record against a plain
// crypt_single_bl over the serialized stage (crypt starts 0x20 and 0x30), its failure path
// leaving the stage untouched, and randomize_zero_nonce on zero and set nonces.
// It also names three stage quirks the corpus pins only as lines (old WireCorpusTests.cpp
// header, lines 20-25): SC's is_decrypted() reads only the flag, CB's 1BL crypt toggles
// instead of forcing a direction, and a seal over an all-zero nonce draws a fresh one, which is
// why the corpus renderer pins kPinnedNonce before every crypt.

#include "Error.hpp"
#include "bootloaders/StageBytes.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <iterator>
#include <span>
#include <string_view>
#include <utility>

namespace gxbuild3::bootloaders {
    namespace {

        namespace stage = nand::stage;
        using test::Bytes;

        TEST(Stage, ParseStageKeepsHeaderAndPayloadAndRefusesShortOrUndersizedStages) {
            const Bytes short_image(sizeof(nand::sc_header) - 1, 0);
            EXPECT_ERROR_MSG(stage::parse_stage<nand::sc_header>(short_image, "SC/3BL"),
                             ErrorCode::Truncated, "SC/3BL data too short")
                << "parse_stage refuses bytes shorter than the header with the stage message";

            const Bytes undersized =
                stage_bytes(nand::CG, sizeof(nand::cg_header) + 0x20, 0x10, Fill::Counting);
            const auto undersized_parse = stage::parse_stage<nand::cg_header>(undersized, "CG/7BL");
            EXPECT_ERROR(undersized_parse, ErrorCode::Malformed)
                << "parse_stage refuses a declared size smaller than the header";
            EXPECT_TRUE(
                !undersized_parse.has_value() &&
                undersized_parse.error().describe().starts_with("CG/7BL declared size 0x10"))
                << "parse_stage refuses a declared size smaller than the header";

            const Bytes image =
                stage_bytes(nand::SC, sizeof(nand::sc_header) + 0x40,
                            static_cast<uint32_t>(sizeof(nand::sc_header) + 0x40), Fill::Counting);
            const auto parsed = stage::parse_stage<nand::sc_header>(image, "SC/3BL");
            ASSERT_OK(parsed) << "parse_stage accepts a well-formed SC";
            EXPECT_EQ(parsed->header.header.magic, nand::SC) << "parse_stage decodes the magic";
            EXPECT_EQ(parsed->header.header.size, sizeof(nand::sc_header) + 0x40)
                << "parse_stage decodes the declared size";
            EXPECT_BYTES_EQ(Bytes(image.begin() + sizeof(nand::sc_header), image.end()),
                            parsed->data)
                << "parse_stage keeps the bytes after the header as the payload";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(parsed->header, parsed->data))
                << "serialize_stage reproduces the parsed image";
        }

        // wire_corpus_bootloaders.txt records `state is_decrypted=0 decrypted=0` for every SC
        // fixture: unlike CB (an all-zero tail) and CD (nonce_6bl and ce_hash), SC derives
        // nothing from its bytes, so even an all-zero payload parses as sealed, and setting the
        // flag alone makes it read as plaintext.
        TEST(Stage, ScIsDecryptedReadsOnlyTheFlagAsToday) {
            const auto size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x40);
            const Bytes plain = stage_bytes(nand::SC, size, size, Fill::Zero);
            ASSERT_OK_AND_ASSIGN(auto sc, nand::BootloaderSc::parse(plain));
            EXPECT_FALSE(sc.decrypted) << "parse leaves the flag clear on an all-zero SC";
            EXPECT_FALSE(sc.is_decrypted()) << "an all-zero SC payload does not read as plaintext";

            sc.decrypted = true;
            EXPECT_TRUE(sc.is_decrypted()) << "the flag alone makes the SC read as plaintext";
            EXPECT_BYTES_EQ(plain, sc.serialize()) << "setting the flag changes no byte";
        }

        TEST(Stage, PayloadSizeIsTheAlignedSizeMinusTheHeaderAndPaddingOnlyGrowsWithZeros) {
            nand::sc_header header{};
            header.header.size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x31);
            const auto size = stage::stage_payload_size(header, "SC/3BL");
            EXPECT_OK(size) << "stage_payload_size is the aligned size minus the header";
            EXPECT_EQ(size.value_or(0), 0x40u)
                << "stage_payload_size is the aligned size minus the header";

            header.header.size = 0x10;
            EXPECT_ERROR(stage::stage_payload_size(header, "SC/3BL"), ErrorCode::Malformed)
                << "stage_payload_size refuses a declared size smaller than the header";

            Bytes data(0x10, 0xAB);
            stage::pad_payload(data, 0x40);
            Bytes padded(0x40, 0x00);
            std::fill_n(padded.begin(), 0x10, uint8_t{0xAB});
            EXPECT_BYTES_EQ(padded, data) << "pad_payload grows the payload with zeros";
            stage::pad_payload(data, 0x20);
            EXPECT_EQ(data.size(), 0x40u) << "pad_payload never shrinks the payload";
        }

        // crypt_stage_record must give exactly what crypt_single_bl gives over the serialized
        // stage. Its ASSERTs end the calling case.
        template <class H>
        void check_crypt_matches_packer(const Bytes& image, size_t crypt_start,
                                        nand::HmacType hmac_type, const uint8_t* cpu_key,
                                        std::string_view label) {
            const std::array<uint8_t, 16> key = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                                                 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
            const auto parsed = stage::parse_stage<H>(image, label);
            ASSERT_OK(parsed) << label << " parses";

            Bytes expected = image;
            std::array<uint8_t, 16> expected_key = key;
            ASSERT_OK(nand::crypt_single_bl(expected, hmac_type, expected_key.data(), cpu_key,
                                            nullptr, crypt_start))
                << label << " crypt_single_bl succeeds";

            H header = parsed->header;
            Bytes data = parsed->data;
            const auto derived = stage::crypt_stage_record(header, data, hmac_type, key.data(),
                                                           cpu_key, crypt_start, label);
            ASSERT_OK(derived) << label << " crypt_stage_record succeeds";
            EXPECT_BYTES_EQ(expected, stage::serialize_stage(header, data))
                << label << " crypt_stage_record matches crypt_single_bl byte for byte";
            EXPECT_BYTES_EQ(expected_key, *derived)
                << label << " crypt_stage_record returns the derived key";

            EXPECT_OK(stage::crypt_stage_record(header, data, hmac_type, key.data(), cpu_key,
                                                crypt_start, label))
                << label << " a second crypt_stage_record restores the image";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(header, data))
                << label << " a second crypt_stage_record restores the image";
        }

        TEST(StageCryptRecord, ScMatchesCryptSingleBlFromCryptStart0x20) {
            const auto sc_size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x60);
            check_crypt_matches_packer<nand::sc_header>(
                stage_bytes(nand::SC, sc_size, sc_size, Fill::Counting), 0x20,
                nand::HmacType::Default, nullptr, "SC/3BL");
        }

        TEST(StageCryptRecord, CdMatchesCryptSingleBlUnderTheCpuKeyedHmac1920) {
            const std::array<uint8_t, 16> cpu_key = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
                                                     0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
                                                     0xCC, 0xCD, 0xCE, 0xCF};
            const auto cd_size = static_cast<uint32_t>(sizeof(nand::cd_header) + 0x40);
            check_crypt_matches_packer<nand::cd_header>(
                stage_bytes(nand::CD, cd_size, cd_size, Fill::Counting), 0x20,
                nand::HmacType::Hmac1920, cpu_key.data(), "CD/4BL");
        }

        TEST(StageCryptRecord, CfMatchesCryptSingleBlFromCryptStart0x30) {
            const auto cf_size = static_cast<uint32_t>(sizeof(nand::cf_header) + 0x200);
            check_crypt_matches_packer<nand::cf_header>(
                stage_bytes(nand::CF, cf_size, cf_size, Fill::Counting), 0x30,
                nand::HmacType::Default, nullptr, "CF/6BL");
        }

        TEST(StageCryptRecord, AFailedCryptLeavesHeaderAndPayloadUntouched) {
            const auto size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x20);
            const Bytes image = stage_bytes(nand::SC, size, size, Fill::Counting);
            const auto parsed = stage::parse_stage<nand::sc_header>(image, "SC/3BL");
            ASSERT_OK(parsed) << "failure fixture parses";
            const uint8_t key[16] = {};
            nand::sc_header header = parsed->header;
            Bytes data = parsed->data;

            // Hmac1920 without a CPU key is refused by crypt_single_bl before it writes anything.
            EXPECT_ERROR_MSG(stage::crypt_stage_record(header, data, nand::HmacType::Hmac1920, key,
                                                       nullptr, 0x20, "SC/3BL"),
                             ErrorCode::InvalidArgument,
                             "SC/3BL: bootloader HMAC type needs a CPU key")
                << "crypt_stage_record adds the stage context to a crypt failure";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(header, data))
                << "a failed crypt_stage_record leaves header and payload untouched";

            // A crypt start past the end of the stage is Truncated.
            EXPECT_ERROR(stage::crypt_stage_record(header, data, nand::HmacType::Default, key,
                                                   nullptr, image.size() + 1, "SC/3BL"),
                         ErrorCode::Truncated)
                << "crypt_stage_record refuses a crypt start past the stage";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(header, data))
                << "a truncated crypt_stage_record leaves header and payload untouched";
        }

        TEST(StageNonce, ANonceWithAnySetByteIsKept) {
            std::array<uint8_t, 16> set_nonce{};
            set_nonce[15] = 0x01;
            const auto kept = set_nonce;
            stage::randomize_zero_nonce(set_nonce);
            EXPECT_BYTES_EQ(kept, set_nonce)
                << "randomize_zero_nonce keeps a nonce with any set byte";
        }

        TEST(StageNonce, AnAllZeroNonceGetsAFreshDraw) {
            std::array<uint8_t, 16> zero_nonce{};
            stage::randomize_zero_nonce(zero_nonce);
            EXPECT_TRUE(std::any_of(zero_nonce.begin(), zero_nonce.end(), [](uint8_t b) {
                return b != 0;
            })) << "randomize_zero_nonce draws a fresh nonce for an all-zero one";
        }

        // The corpus pin (kPinnedNonce 0x11..0x20 in tests/snapshots/WireCorpusRender.cpp):
        // sealing a plaintext SC whose nonce is all zero draws a fresh nonce, so two seals of
        // the same stage differ; with a set nonce the seal is a pure function of its input.
        TEST(StageNonce, PinnedNonceSealIsDeterministicZeroNonceSealIsNot) {
            constexpr std::array<uint8_t, 16> kPinnedNonce = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                                              0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                                                              0x1D, 0x1E, 0x1F, 0x20};
            const auto size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x40);
            ASSERT_OK_AND_ASSIGN(auto plain, nand::BootloaderSc::parse(stage_bytes(
                                                 nand::SC, size, size, Fill::Counting)));
            plain.decrypted = true;

            const auto seal = [&plain](std::span<const uint8_t, 16> nonce) -> Result<Bytes> {
                nand::BootloaderSc sc = plain;
                std::ranges::copy(nonce, std::begin(sc.header.key));
                if (auto sealed = sc.encrypt(nand::BootloaderSc::kZeroSecret); !sealed) {
                    return std::unexpected(std::move(sealed.error()));
                }
                return sc.serialize();
            };

            const std::array<uint8_t, 16> zero{};
            ASSERT_OK_AND_ASSIGN(const Bytes zero_first, seal(zero));
            ASSERT_OK_AND_ASSIGN(const Bytes zero_second, seal(zero));
            EXPECT_FALSE(zero_first == zero_second)
                << "two seals over an all-zero nonce draw two nonces and differ";
            EXPECT_FALSE(std::ranges::equal(std::span(zero_first).subspan(0x10, 0x10), zero))
                << "the sealed stage carries the drawn nonce, not zero";

            ASSERT_OK_AND_ASSIGN(const Bytes pinned_first, seal(kPinnedNonce));
            ASSERT_OK_AND_ASSIGN(const Bytes pinned_second, seal(kPinnedNonce));
            EXPECT_BYTES_EQ(pinned_first, pinned_second)
                << "two seals over the pinned nonce are byte-identical";
            EXPECT_BYTES_EQ(kPinnedNonce, std::span(pinned_first).subspan(0x10, 0x10))
                << "the pinned nonce is kept at +0x10";
        }

        // wire_corpus_bootloaders.txt's cb.crypt_1bl lines open an encrypted fixture through
        // encrypt(): BootloaderCb's 1BL decrypt() and encrypt() are one RC4 toggle that flips
        // `decrypted`, never a forced direction (SC and CD no-op when already in the requested
        // state). An all-zero payload parses as plaintext (verify_decrypted).
        TEST(BootloaderCb, OneBlCryptTogglesInsteadOfForcingAsToday) {
            constexpr std::array<uint8_t, 16> kOneBlKey = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                                                           0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67,
                                                           0x89, 0xAB, 0xCD, 0xEF};
            const Bytes plain = stage_bytes(nand::CB, 0x400, 0x400, Fill::Zero);
            ASSERT_OK_AND_ASSIGN(auto cb, nand::BootloaderCb::parse(plain));
            ASSERT_TRUE(cb.decrypted) << "an all-zero CB payload parses as plaintext";

            ASSERT_OK(cb.decrypt(kOneBlKey.data()));
            EXPECT_FALSE(cb.decrypted)
                << "decrypt() of a plaintext CB seals it and clears the flag";
            const Bytes sealed = cb.serialize();
            EXPECT_FALSE(sealed == plain) << "decrypt() of a plaintext CB rewrites the payload";
            EXPECT_BYTES_EQ(std::span(plain).first(0x20), std::span(sealed).first(0x20))
                << "the header and the nonce stay in the clear";

            ASSERT_OK(cb.encrypt(kOneBlKey.data()));
            EXPECT_TRUE(cb.decrypted) << "encrypt() of a sealed CB opens it and sets the flag";
            EXPECT_BYTES_EQ(plain, cb.serialize()) << "encrypt() of a sealed CB restores the input";

            ASSERT_OK_AND_ASSIGN(auto other, nand::BootloaderCb::parse(plain));
            ASSERT_OK(other.encrypt(kOneBlKey.data()));
            EXPECT_FALSE(other.decrypted) << "encrypt() of a plaintext CB seals it";
            EXPECT_BYTES_EQ(sealed, other.serialize())
                << "encrypt() and decrypt() of a plaintext CB give the same sealed bytes";
        }

    } // namespace
} // namespace gxbuild3::bootloaders
