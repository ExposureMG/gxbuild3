// Which key seals each stage of a built chain, per build type: CB_A under the 1BL key, CB_B
// under CB_A's key with the CPU key (and CB_A's head for flag 0x1000, a zero digest for a
// manufacturing CB_A), CB_X under CB_A's key and a zero CPU key with CB_B plaintext for glitch3,
// CD and CE encrypted. Every chain extracts back to its inputs and rebuilds the same way.

#include "BuildRunner.hpp"
#include "bootloaders/glitch/GlitchFixture.hpp"
#include "nand/bootloaders/Common.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace gxbuild3::bootloaders::glitch {
    namespace {

        // One test_build_policy call: the old name string is `label` and leads every message.
        struct ChainPolicyRow {
            const char* name;
            BuildType type;
            const char* label;
            uint16_t flags;
            ImageType image_type;
        };
        GX_PRINT_ROW_AS_NAME(ChainPolicyRow)

        // The ten calls of the old main(), grouped by family; within a family in today's order.
        constexpr ChainPolicyRow kRetailRows[] = {
            {"Retail", BuildType::Retail, "retail", 0x800, ImageType::SmallBlock},
            {"RetailManufacturing", BuildType::Retail, "retail manufacturing", 0x0801,
             ImageType::SmallBlock},
        };
        constexpr ChainPolicyRow kGlitchRows[] = {
            {"Glitch1", BuildType::Glitch, "glitch1", 0x800, ImageType::SmallBlock},
            {"Glitch2", BuildType::Glitch2, "glitch2", 0x800, ImageType::SmallBlock},
            {"BigBlockGlitch2", BuildType::Glitch2, "big-block glitch2", 0x800,
             ImageType::BigBlock},
        };
        constexpr ChainPolicyRow kGlitch2mRows[] = {
            {"Glitch2m", BuildType::Glitch2m, "glitch2m", 0x800, ImageType::SmallBlock},
            {"Glitch2mManufacturing", BuildType::Glitch2m, "glitch2m manufacturing", 0x0801,
             ImageType::SmallBlock},
            {"Glitch2mManufacturingV2", BuildType::Glitch2m, "glitch2m manufacturing v2", 0x1801,
             ImageType::SmallBlock},
        };
        constexpr ChainPolicyRow kGlitch3Rows[] = {
            {"Glitch3", BuildType::Glitch3, "glitch3", 0x800, ImageType::SmallBlock},
            {"Glitch3V2", BuildType::Glitch3, "glitch3 v2", 0x1800, ImageType::SmallBlock},
        };

        class ChainPolicy : public ::testing::TestWithParam<ChainPolicyRow> {};

        TEST_P(ChainPolicy, BuildsExtractsAndRebuildsTheSealedChain) {
            const auto& row = GetParam();
            const std::string name = row.label;
            auto input = fixture(row.type, row.flags);
            input.image_type = row.image_type;
            const bool manufacturing = (row.flags & 0x01) != 0;
            // A stale digest in the input CB_B, which a manufacturing seal must clear.
            if (manufacturing) {
                ASSERT_TRUE(input.bootloaders.cb_b.has_value()) << name << " has a CB_B";
                std::fill_n(input.bootloaders.cb_b->begin() + 0x30, 16, 0xCC);
            }
            const auto built = run_build(input);
            ASSERT_OK(built) << name << " builds";
            EXPECT_NO_FATAL_FAILURE(expect_chain(input, *built, name));
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << name << " extracts";
            EXPECT_OPTIONAL_BYTES_EQ(input.bootloaders.cb_x, extracted->bootloaders.cb_x)
                << name << " extracts plaintext CB_X";
            if (input.bootloaders.cb_b && row.type != BuildType::Glitch3) {
                auto expected = *input.bootloaders.cb_b;
                ASSERT_TRUE(extracted->bootloaders.cb_b.has_value())
                    << name << " extracts original CB_B, CD and CE";
                std::copy_n(extracted->bootloaders.cb_b->begin() + 0x30, 16,
                            expected.begin() + 0x30);
                input.bootloaders.cb_b = expected;
            }
            EXPECT_OPTIONAL_BYTES_EQ(input.bootloaders.cb_b, extracted->bootloaders.cb_b)
                << name << " extracts original CB_B, CD and CE";
            EXPECT_BYTES_EQ(input.bootloaders.cd, extracted->bootloaders.cd)
                << name << " extracts original CB_B, CD and CE";
            EXPECT_OPTIONAL_BYTES_EQ(input.bootloaders.ce, extracted->bootloaders.ce)
                << name << " extracts original CB_B, CD and CE";
            input.bootloaders = extracted->bootloaders;
            const auto rebuilt = run_build(input);
            ASSERT_OK(rebuilt) << name << " rebuilds";
            ASSERT_NO_FATAL_FAILURE(expect_chain(input, *rebuilt, name + " rebuild"));
        }

        INSTANTIATE_TEST_SUITE_P(Retail, ChainPolicy, ::testing::ValuesIn(kRetailRows),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch, ChainPolicy, ::testing::ValuesIn(kGlitchRows),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch2m, ChainPolicy, ::testing::ValuesIn(kGlitch2mRows),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch3, ChainPolicy, ::testing::ValuesIn(kGlitch3Rows),
                                 test::RowName{});

        // A patched glitch2/glitch3 image seals the patched CB_B and CD for their parents.
        struct PatchedStageRow {
            const char* name;
            BuildType type;
        };
        GX_PRINT_ROW_AS_NAME(PatchedStageRow)
        constexpr PatchedStageRow kPatchedStageRows[] = {
            {"Glitch2", BuildType::Glitch2},
            {"Glitch3", BuildType::Glitch3},
        };

        class PatchedStageSealing : public ::testing::TestWithParam<PatchedStageRow> {};

        TEST_P(PatchedStageSealing, PatchedStagesAreEncryptedForTheirParent) {
            auto input = fixture(GetParam().type);
            Bytes patch;
            test::append_be32(patch, 0x400);
            test::append_be32(patch, 1);
            test::append_be32(patch, 0xDEADBEEF);
            test::append_be32(patch, 0xFFFFFFFF);
            test::append_be32(patch, sizeof(nand::cd_header));
            test::append_be32(patch, 1);
            test::append_be32(patch, 0x11223344);
            test::append_be32(patch, 0xFFFFFFFF);
            patch.push_back(0xA5);
            ASSERT_TRUE(input.patches && input.patches->automatic)
                << "the glitch fixture carries an automatic patchset";
            input.patches->automatic->data = patch;
            const auto built = run_build(input);
            ASSERT_OK(built) << "patched glitch image builds";
            const Bytes cb_patch{0xDE, 0xAD, 0xBE, 0xEF};
            const Bytes cd_patch{0x11, 0x22, 0x33, 0x44};
            ASSERT_TRUE(input.bootloaders.cb_b.has_value()) << "the glitch fixture has a CB_B";
            std::copy(cb_patch.begin(), cb_patch.end(), input.bootloaders.cb_b->begin() + 0x400);
            std::copy(cd_patch.begin(), cd_patch.end(),
                      input.bootloaders.cd.begin() + sizeof(nand::cd_header));
            ASSERT_NO_FATAL_FAILURE(expect_chain(input, *built, "patched bootloader stages"));
        }

        INSTANTIATE_TEST_SUITE_P(Type, PatchedStageSealing, ::testing::ValuesIn(kPatchedStageRows),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::bootloaders::glitch
