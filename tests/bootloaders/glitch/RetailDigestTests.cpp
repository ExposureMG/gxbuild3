// The retail CB digest at +0x30 (J-Runner FixPerBoxDigest): HMAC under the CPU key over the
// CB's RC4 key, its per-box bytes +0x20..+0x2F and two running sums of the sealed SMC. Checked
// against fixed Python vectors and, through run_build, against the oracle in GlitchOracle.hpp
// for a single CB and split CB_B regimes as the pairing, CB LDV, CPU key or SMC change.

#include "BuildRunner.hpp"
#include "bootloaders/glitch/GlitchFixture.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <tuple>

namespace gxbuild3::bootloaders::glitch {
    namespace {

        // Fixed vectors generated separately with Python hashlib/hmac and struct.pack
        // from the J-Runner FixPerBoxDigest algorithm. SMC input is ciphertext 00..3f,
        // CPU key 00..0f, and the 16 authenticated metadata bytes are 10..1f.
        // variant 0 is a single CB under the 1BL key; 1 and 2 are a CB_B under CB_A flags 0x800
        // and 0x1800.
        struct DigestVector {
            const char* name;
            int variant;
            Key expected;
        };
        GX_PRINT_ROW_AS_NAME(DigestVector)
        constexpr DigestVector kDigestVectors[] = {
            {"SingleCb",
             0,
             {0xab, 0xe7, 0x10, 0x53, 0x08, 0x26, 0xc0, 0x7d, 0x59, 0xd4, 0x80, 0x91, 0x36, 0x2a,
              0x0c, 0xa0}},
            {"SplitFlags0x0800",
             1,
             {0x91, 0x1a, 0x8b, 0xa4, 0x93, 0x53, 0x59, 0x36, 0x9f, 0xee, 0xd9, 0xf7, 0x93, 0x1d,
              0x11, 0x6a}},
            {"SplitFlags0x1800",
             2,
             {0xbb, 0x31, 0x7e, 0xfb, 0x41, 0xe0, 0x42, 0xdd, 0xe5, 0x7c, 0xca, 0xcd, 0xce, 0xfa,
              0xc2, 0x3d}},
        };

        class RetailDigestVector : public ::testing::TestWithParam<DigestVector> {};

        TEST_P(RetailDigestVector, MatchesTheIndependentPythonVector) {
            const auto& row = GetParam();
            const int variant = row.variant;
            Key cpu{};
            Bytes smc(64);
            for (size_t i = 0; i < cpu.size(); ++i) {
                cpu[i] = i;
            }
            for (size_t i = 0; i < smc.size(); ++i) {
                smc[i] = i;
            }
            ASSERT_OK_AND_ASSIGN(
                auto cba, nand::BootloaderCb::parse(cb(9188, variant == 2 ? 0x1800 : 0x800, 0x11)));
            ASSERT_OK_AND_ASSIGN(
                auto target, nand::BootloaderCb::parse(cb(6750, 0, variant == 0 ? 0x11 : 0x33)));
            for (size_t i = 0; i < 16; ++i) {
                target.data[0x10 + i] = 0x10 + i;
            }
            const auto parent = variant == 0 ? kOneBlKey : hmac(kOneBlKey, Bytes(16, 0x11));
            ASSERT_OK(target.encrypt_retail(parent.data(), cpu, smc,
                                            variant == 0 ? nullptr : &cba.header));
            ASSERT_TRUE(target.derived_key.has_value()) << "the retail seal derives the CB key";
            auto wire = target.serialize();
            ExCryptRc4(target.derived_key->data(), 16, wire.data() + 0x20, wire.size() - 0x20);
            EXPECT_BYTES_EQ(row.expected, Bytes(wire.begin() + 0x30, wire.begin() + 0x40))
                << "retail digest matches independent Python vector";
        }

        INSTANTIATE_TEST_SUITE_P(Vector, RetailDigestVector, ::testing::ValuesIn(kDigestVectors),
                                 test::RowName{});

        // The old nested loop's two dimensions: a regime (single CB, or CB_B under the CB_A
        // flags) and a change to the console data (change 0 is a big-block image whose
        // unchanged rebuild must keep the authenticated CB bytes).
        struct DigestRegime {
            const char* name;
            bool split;
            uint16_t flags;
        };
        GX_PRINT_ROW_AS_NAME(DigestRegime)
        struct DigestChange {
            const char* name;
            int change;
        };
        GX_PRINT_ROW_AS_NAME(DigestChange)
        constexpr DigestRegime kSingle{"Single", false, 0};
        constexpr DigestRegime kSplit0800{"Split0800", true, 0x800};
        constexpr DigestRegime kSplit1800{"Split1800", true, 0x1800};
        constexpr DigestChange kDigestChanges[] = {
            {"UnchangedBigBlock", 0}, {"PairingChanged", 1}, {"CbLdvChanged", 2},
            {"CpuKeyChanged", 3},     {"SmcChanged", 4},
        };

        class RetailDigest
            : public ::testing::TestWithParam<std::tuple<DigestRegime, DigestChange>> {};

        // A row prints and lists as its change; the instantiation names the regime.
        struct ChangeName {
            std::string
            operator()(const ::testing::TestParamInfo<RetailDigest::ParamType>& info) const {
                return std::get<1>(info.param).name;
            }
        };

        TEST_P(RetailDigest, CbDigestBindsTheConsoleDataAndTheSealedSmc) {
            const auto& [regime, change_row] = GetParam();
            const bool split = regime.split;
            const uint16_t flags = regime.flags;
            const int change = change_row.change;
            auto input = fixture(BuildType::Retail, flags);
            input.image_type = change == 0 ? ImageType::BigBlock : ImageType::SmallBlock;
            if (!split) {
                input.bootloaders.cb_or_a = cb(6750, 0, 0x11);
                input.bootloaders.cb_b.reset();
            }
            input.metadata.pairing_data = {1, 2, 3};
            input.metadata.cb_ldv = 4;
            if (change == 1) {
                input.metadata.pairing_data[1] ^= 0x80;
            }
            if (change == 2) {
                input.metadata.cb_ldv = 5;
            }
            if (change == 3) {
                // Move one set bit within the CPU key's data region, then repair ECC.
                input.metadata.cpu_key[0] ^= 1;
                input.metadata.cpu_key[8] ^= 1;
                XeCryptUidEccEncode(input.metadata.cpu_key.data());
                ASSERT_OK_AND_ASSIGN(const Bytes sealed_keyvault,
                                     nand::keyvault_encrypt(input.metadata.cpu_key,
                                                            Bytes(nand::Keyvault::kSize, 0)));
                ASSERT_OK_AND_ASSIGN(
                    input.metadata.keyvault,
                    nand::keyvault_decrypt(input.metadata.cpu_key, sealed_keyvault));
            }
            if (change == 4) {
                ASSERT_TRUE(input.metadata.smc.has_value()) << "the fixture carries an SMC";
                (*input.metadata.smc)[7] = 0xAB;
            }
            ASSERT_TRUE(!split || input.bootloaders.cb_b.has_value()) << "a split CB has a CB_B";
            auto& target = split ? *input.bootloaders.cb_b : input.bootloaders.cb_or_a;
            target[0x24] = 0xA7; // Reserved bytes also participate in authentication.
            std::fill(target.begin() + 0x30, target.begin() + 0x40, 0xCC);
            const auto built = run_build(input);
            ASSERT_OK(built) << "retail BB digest fixture builds";
            auto image = nand::FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "retail BB parses";
            ASSERT_OK(image->parse()) << "retail BB parses";
            ASSERT_TRUE(image->smc.has_value()) << "retail BB parses";
            ASSERT_TRUE(!split || image->cb_section.cb_B.has_value()) << "retail BB parses";
            // parse() retains the on-NAND bytes; do not apply the SMC plaintext heuristic
            // to ciphertext when checking the authentication input.
            const auto& smc = image->smc->data;
            auto key = encrypt(input.bootloaders.cb_or_a, kOneBlKey).second;
            if (split) {
                Bytes suffix = input.metadata.cpu_key;
                if (flags & 0x1000) {
                    Bytes header(input.bootloaders.cb_or_a.begin(),
                                 input.bootloaders.cb_or_a.begin() + 16);
                    header[6] = header[7] = 0;
                    suffix.insert(suffix.end(), header.begin(), header.end());
                }
                key = encrypt(target, key, suffix).second;
            }
            Bytes decoded =
                split ? image->cb_section.cb_B->serialize() : image->cb_section.cb_or_A.serialize();
            ExCryptRc4(key.data(), 16, decoded.data() + 0x20, decoded.size() - 0x20);
            const auto expected = authenticate(decoded, key, input.metadata.cpu_key, smc);
            EXPECT_BYTES_EQ(expected, decoded)
                << "retail digest: split=" << split << " flags=" << flags << " change=" << change;
            auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "retail BB extracts";
            if (change != 0) {
                return;
            }
            input.bootloaders = extracted->bootloaders;
            const auto rebuilt = run_build(input);
            ASSERT_OK(rebuilt) << "retail BB rebuilds";
            auto again = nand::FlashImage::read(*rebuilt);
            ASSERT_TRUE(again.has_value()) << "rebuilt retail BB parses";
            ASSERT_OK(again->parse()) << "rebuilt retail BB parses";
            ASSERT_TRUE(!split || again->cb_section.cb_B.has_value()) << "rebuilt retail BB parses";
            EXPECT_BYTES_EQ(
                split ? image->cb_section.cb_B->serialize() : image->cb_section.cb_or_A.serialize(),
                split ? again->cb_section.cb_B->serialize() : again->cb_section.cb_or_A.serialize())
                << "unchanged retail inputs preserve authenticated CB bytes";
        }

        INSTANTIATE_TEST_SUITE_P(Single, RetailDigest,
                                 ::testing::Combine(::testing::Values(kSingle),
                                                    ::testing::ValuesIn(kDigestChanges)),
                                 ChangeName{});
        INSTANTIATE_TEST_SUITE_P(Split0800, RetailDigest,
                                 ::testing::Combine(::testing::Values(kSplit0800),
                                                    ::testing::ValuesIn(kDigestChanges)),
                                 ChangeName{});
        INSTANTIATE_TEST_SUITE_P(Split1800, RetailDigest,
                                 ::testing::Combine(::testing::Values(kSplit1800),
                                                    ::testing::ValuesIn(kDigestChanges)),
                                 ChangeName{});

    } // namespace
} // namespace gxbuild3::bootloaders::glitch
