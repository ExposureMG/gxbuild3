// Glitch3 (RGH3 through RGH2to3) chains: CB_A, CB_X and CB_B are all required; encrypted CB_A
// and CB_B replacements keep the real CB_B's handoff key for CD; the RGH2to3 fix of a plaintext
// v1 CB_X rewrites exactly four words, and the build seals the fixed CB_X under CB_A's key, its
// own nonce and a zero CPU key.

#include "BuildRunner.hpp"
#include "bootloaders/glitch/GlitchFixture.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace gxbuild3::bootloaders::glitch {
    namespace {

        struct IncompleteChainRow {
            const char* name;
            bool missing_x;
        };
        GX_PRINT_ROW_AS_NAME(IncompleteChainRow)
        constexpr IncompleteChainRow kIncompleteChainRows[] = {
            {"MissingCbX", true},
            {"MissingCbB", false},
        };

        class Glitch3IncompleteChain : public ::testing::TestWithParam<IncompleteChainRow> {};

        TEST_P(Glitch3IncompleteChain, IsRefusedEvenWithNoBlPatch) {
            auto input = fixture(BuildType::Glitch3);
            input.options.noblpatch = true;
            if (GetParam().missing_x) {
                input.bootloaders.cb_x.reset();
            } else {
                input.bootloaders.cb_b.reset();
            }
            const auto result = run_build(input);
            EXPECT_ERROR(result, BuildErrorCode::InvalidBootloader)
                << "glitch3 rejects an incomplete CB_A/CB_X/CB_B chain even with noblpatch";
        }

        INSTANTIATE_TEST_SUITE_P(Case, Glitch3IncompleteChain,
                                 ::testing::ValuesIn(kIncompleteChainRows), test::RowName{});

        TEST(Glitch3Replacement, EncryptedReplacementPreservesHandoffKey) {
            auto expected = fixture(BuildType::Glitch3);
            auto input = expected;
            ASSERT_TRUE(input.bootloaders.cb_b.has_value()) << "the glitch3 fixture has a CB_B";
            const auto [cba, cba_key] = encrypt(input.bootloaders.cb_or_a, kOneBlKey);
            const auto [cbb, cbb_key] =
                encrypt(*input.bootloaders.cb_b, cba_key, input.metadata.cpu_key);
            input.bootloaders.cb_or_a = cba;
            input.bootloaders.cb_b = cbb;
            std::copy(cbb_key.begin(), cbb_key.end(), expected.bootloaders.cb_b->begin() + 0x10);
            const auto built = run_build(input);
            ASSERT_OK(built) << "encrypted glitch3 replacements build";
            ASSERT_NO_FATAL_FAILURE(
                expect_chain(expected, *built, "encrypted replacement handoff"));
        }

        // The four words of a plaintext v1 RGH3 CB_X (0x646A0002 at +0x354) and RGH2to3's fix.
        void put_v1_words(Bytes& cb_x) {
            test::put_be32(cb_x, 0x354, 0x646A0002);
            test::put_be32(cb_x, 0x368, 0x7D8C502A);
            test::put_be32(cb_x, 0x370, 0x646A0006);
            test::put_be32(cb_x, 0x37C, 0xF84A1010);
        }

        void put_fixed_words(Bytes& cb_x) {
            test::put_be32(cb_x, 0x354, 0x64690002);
            test::put_be32(cb_x, 0x368, 0x7D8C482A);
            test::put_be32(cb_x, 0x370, 0x64690006);
            test::put_be32(cb_x, 0x37C, 0xF8491010);
        }

        // RGH2to3 (2to3.py) rewrites four words of a plaintext v1 RGH3 CB_X, the one with
        // 0x646A0002 at +0x354, and leaves every other CB_X as it is.
        TEST(CbXFix, RewritesExactlyFourWordsOfAPlaintextV1CbXOnly) {
            auto v1 = cb(15432, 0x800, 0);
            put_v1_words(v1);
            auto expected = v1;
            put_fixed_words(expected);

            ASSERT_OK_AND_ASSIGN(auto loader, nand::BootloaderCb::parse(v1));
            loader.decrypted = true;
            EXPECT_TRUE(loader.patch_rgh3_v1_cb_x()) << "a v1 CB_X is patched";
            EXPECT_BYTES_EQ(expected, loader.serialize())
                << "the v1 fix rewrites exactly four words";
            EXPECT_FALSE(loader.patch_rgh3_v1_cb_x()) << "a patched CB_X is not patched again";
            EXPECT_BYTES_EQ(expected, loader.serialize()) << "a patched CB_X is not patched again";

            auto v2 = cb(15432, 0x800, 0);
            test::put_be32(v2, 0x368, 0x7D8C502A);
            ASSERT_OK_AND_ASSIGN(auto v2_loader, nand::BootloaderCb::parse(v2));
            v2_loader.decrypted = true;
            EXPECT_FALSE(v2_loader.patch_rgh3_v1_cb_x())
                << "a v2 CB_X (zero at +0x354) is left unchanged";
            EXPECT_BYTES_EQ(v2, v2_loader.serialize())
                << "a v2 CB_X (zero at +0x354) is left unchanged";

            ASSERT_OK_AND_ASSIGN(auto sealed, nand::BootloaderCb::parse(v1));
            sealed.decrypted = false;
            EXPECT_FALSE(sealed.patch_rgh3_v1_cb_x()) << "a sealed CB_X is never patched";
            EXPECT_BYTES_EQ(v1, sealed.serialize()) << "a sealed CB_X is never patched";

            ASSERT_OK_AND_ASSIGN(auto short_loader,
                                 nand::BootloaderCb::parse(Bytes(v1.begin(), v1.begin() + 0x37C)));
            short_loader.decrypted = true;
            EXPECT_FALSE(short_loader.patch_rgh3_v1_cb_x())
                << "a CB_X too short for the fix is left unchanged";
        }

        struct SealsCbXRow {
            const char* name;
            bool v1;
            const char* label;
        };
        GX_PRINT_ROW_AS_NAME(SealsCbXRow)
        constexpr SealsCbXRow kSealsCbXRows[] = {
            {"V1", true, "glitch3 v1 CB_X"},
            {"V2", false, "glitch3 v2 CB_X"},
        };

        class Glitch3SealsCbX : public ::testing::TestWithParam<SealsCbXRow> {};

        // A glitch3 build seals the fixed v1 CB_X, or a v2 CB_X unchanged, under
        // HMAC(K_cba, its own nonce || 16 zero bytes), keeping the nonce as supplied.
        TEST_P(Glitch3SealsCbX, SealsTheFixedCbXUnderCbAsKeyItsNonceAndAZeroCpuKey) {
            const auto& row = GetParam();
            auto input = fixture(BuildType::Glitch3);
            ASSERT_TRUE(input.bootloaders.cb_x.has_value()) << "the glitch3 fixture has a CB_X";
            auto& cb_x = *input.bootloaders.cb_x;
            if (row.v1) {
                // The v1 templates RGH2to3 handles carry an all-zero nonce.
                std::fill_n(cb_x.begin() + 0x10, 16, 0);
                put_v1_words(cb_x);
            } else {
                test::put_be32(cb_x, 0x354, 0);
            }
            auto expected = cb_x;
            if (row.v1) {
                put_fixed_words(expected);
            }
            const std::string label = row.label;

            const auto built = run_build(input);
            ASSERT_OK(built) << label << " builds";
            auto image = nand::FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << label << " parses";
            ASSERT_OK(image->parse()) << label << " parses";
            ASSERT_TRUE(image->cb_section.cb_x.has_value()) << label << " parses";
            const auto cba_key = encrypt(input.bootloaders.cb_or_a, kOneBlKey).second;
            const auto sealed = image->cb_section.cb_x->serialize();
            EXPECT_BYTES_EQ(encrypt(expected, cba_key, Bytes(16, 0)).first, sealed)
                << label << " is sealed under CB_A's key, its nonce and a zero CPU key";
            EXPECT_BYTES_EQ(Bytes(cb_x.begin() + 0x10, cb_x.begin() + 0x20),
                            Bytes(sealed.begin() + 0x10, sealed.begin() + 0x20))
                << label << " keeps its nonce as supplied";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << label << " extracts as the sealed plaintext";
            EXPECT_OPTIONAL_BYTES_EQ(std::optional<Bytes>(expected), extracted->bootloaders.cb_x)
                << label << " extracts as the sealed plaintext";
        }

        INSTANTIATE_TEST_SUITE_P(Row, Glitch3SealsCbX, ::testing::ValuesIn(kSealsCbXRows),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::bootloaders::glitch
