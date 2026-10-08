// src/cli/BuildInputResolver.hpp: the automatic patchset and the add-ons. The automatic patch
// file is <root>/bin/patches_<stem>[_<suffix>].bin with the stem the code states (jtag the
// section, glitch fat, glitch2 g2<section>, glitch2m g2m<section>, glitch3 g3<section> searched
// in every root before the g2 fallback); retail and devkit select none and refuse add-ons.
// Add-ons resolve as <root>/bin/<name>.bin in command-line order, first root first, and append
// to the KHV section. A missing patch file or add-on names its file, and direct BuildArgs refuse
// an add-on, section or suffix that is not a bare filename component.
//
// AutomaticPatchsetName: one row per hacked build type, bundled as Row/AutomaticPatchsetName
// (devgl's name is checked by ResolverPayload.DevglResolveFindsTheSbKeyAndBuildsRetailFuses,
// as it resolves only with an SB key). NoAutomaticPatchset: retail and devkit, bundled as
// Row/NoAutomaticPatchset.

#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "nand/objects/Patchset.hpp"
#include "support/Expect.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/ResolverTree.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace gxbuild3::cli {
    namespace {

        using test::Bytes;

        class ResolverPatchset : public ResolverTest {};

        TEST_F(ResolverPatchset, Glitch3SearchesAllG3RootsBeforeG2Fallback) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch3));
            args.source_dirs = {path("first"), path("second")};
            args.patch_extension = "test";
            write("first/bin/patches_g2falcon_test.bin", test::valid_glitch_patchset(0x22));
            write("second/bin/patches_g3falcon_test.bin", test::valid_glitch_patchset(0x33));
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
            const auto g3 = resolve(args);
            ASSERT_OK(g3) << "glitch3 fixture resolves";
            ASSERT_TRUE(g3->input.patches.has_value() && g3->input.patches->automatic.has_value())
                << "a later-root g3 patch beats an earlier-root g2 fallback";
            const auto& g3_file = *g3->input.patches->automatic;
            ASSERT_EQ(g3_file.name, "patches_g3falcon_test.bin")
                << "a later-root g3 patch beats an earlier-root g2 fallback";
            ASSERT_FALSE(g3_file.data.empty())
                << "a later-root g3 patch beats an earlier-root g2 fallback";
            ASSERT_EQ(g3_file.data.back(), 0x33)
                << "a later-root g3 patch beats an earlier-root g2 fallback";

            std::error_code error;
            ASSERT_TRUE(
                std::filesystem::remove(path("second/bin/patches_g3falcon_test.bin"), error))
                << "the later root's g3 patch is removed: " << error.message();
            const auto fallback = resolve(args);
            ASSERT_OK(fallback) << "glitch3 falls back only after every g3 root is exhausted";
            ASSERT_TRUE(fallback->input.patches.has_value() &&
                        fallback->input.patches->automatic.has_value())
                << "glitch3 falls back only after every g3 root is exhausted";
            const auto& g2_file = *fallback->input.patches->automatic;
            EXPECT_EQ(g2_file.name, "patches_g2falcon_test.bin")
                << "glitch3 falls back only after every g3 root is exhausted";
            ASSERT_FALSE(g2_file.data.empty())
                << "glitch3 falls back only after every g3 root is exhausted";
            EXPECT_EQ(g2_file.data.back(), 0x22)
                << "glitch3 falls back only after every g3 root is exhausted";
        }

        TEST_F(ResolverPatchset, Glitch3PrefersG3ThenG2AndFailsCleanlyWithoutEither) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args(BuildType::Glitch3));
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

            const auto neither = resolve(args);
            ASSERT_ERROR(neither, ResolutionErrorCode::PatchsetNotFound)
                << "glitch3 without a g3 or g2 patchset fails naming both files";
            ASSERT_EQ(neither.error().item, "patches_g2falcon.bin")
                << "glitch3 without a g3 or g2 patchset fails naming both files";
            ASSERT_TRUE(neither.error().message.contains("patches_g3falcon.bin"))
                << "glitch3 without a g3 or g2 patchset fails naming both files";
            ASSERT_TRUE(neither.error().message.contains("patches_g2falcon.bin"))
                << "glitch3 without a g3 or g2 patchset fails naming both files";

            write("first/bin/patches_g2falcon.bin", test::valid_glitch_patchset(0x22));
            const auto g2_only = resolve(args);
            ASSERT_OK(g2_only) << "glitch3 with only a g2 patchset resolves";
            ASSERT_TRUE(g2_only->input.patches.has_value() &&
                        g2_only->input.patches->automatic.has_value())
                << "glitch3 uses the g2 patchset when no g3 patchset exists";
            const auto& g2_file = *g2_only->input.patches->automatic;
            ASSERT_EQ(g2_file.name, "patches_g2falcon.bin")
                << "glitch3 uses the g2 patchset when no g3 patchset exists";
            ASSERT_FALSE(g2_file.data.empty())
                << "glitch3 uses the g2 patchset when no g3 patchset exists";
            ASSERT_EQ(g2_file.data.back(), 0x22)
                << "glitch3 uses the g2 patchset when no g3 patchset exists";

            write("first/bin/patches_g3falcon.bin", test::valid_glitch_patchset(0x33));
            const auto both = resolve(args);
            ASSERT_OK(both) << "glitch3 with both patchsets resolves";
            ASSERT_TRUE(both->input.patches.has_value() &&
                        both->input.patches->automatic.has_value())
                << "glitch3 prefers the g3 patchset over a g2 one in the same root";
            const auto& g3_file = *both->input.patches->automatic;
            EXPECT_EQ(g3_file.name, "patches_g3falcon.bin")
                << "glitch3 prefers the g3 patchset over a g2 one in the same root";
            ASSERT_FALSE(g3_file.data.empty())
                << "glitch3 prefers the g3 patchset over a g2 one in the same root";
            EXPECT_EQ(g3_file.data.back(), 0x33)
                << "glitch3 prefers the g3 patchset over a g2 one in the same root";
        }

        TEST_F(ResolverPatchset, MissingPatchsetAndAddonErrorsArePrecise) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2));
            const auto missing_patch = resolve(args);
            ASSERT_ERROR(missing_patch, ResolutionErrorCode::PatchsetNotFound)
                << "a missing required automatic patch names the exact file";
            ASSERT_EQ(missing_patch.error().item, "patches_g2falcon.bin")
                << "a missing required automatic patch names the exact file";

            write("first/bin/patches_g2falcon.bin", test::valid_glitch_patchset());
            args.addons = {"missing"};
            const auto missing_addon = resolve(args);
            ASSERT_ERROR(missing_addon, ResolutionErrorCode::AddonNotFound)
                << "a missing add-on names the exact bin filename";
            EXPECT_EQ(missing_addon.error().item, "missing.bin")
                << "a missing add-on names the exact bin filename";
        }

        TEST_F(ResolverPatchset, AddonsResolveFromRootBinInCliOrder) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2));
            args.source_dirs = {path("first"), path("second")};
            args.addons = {"second-addon", "first-addon"};
            write("first/bin/patches_g2falcon.bin", test::valid_glitch_patchset());
            write("first/bin/second-addon.bin", Bytes{0x21});
            write("second/bin/second-addon.bin", Bytes{0x99});
            write("second/bin/first-addon.bin", Bytes{0x12});
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
            const auto result = resolve(args);
            ASSERT_OK(result) << "add-on fixture resolves";
            ASSERT_TRUE(result->input.patches.has_value()) << "both add-ons resolve";
            const auto& addons = result->input.patches->addons;
            ASSERT_EQ(addons.size(), 2U) << "both add-ons resolve";
            EXPECT_EQ(addons[0].name, "second-addon.bin")
                << "add-ons preserve CLI order and first-root priority";
            EXPECT_BYTES_EQ(Bytes{0x21}, addons[0].data)
                << "add-ons preserve CLI order and first-root priority";
            EXPECT_EQ(addons[1].name, "first-addon.bin")
                << "add-ons preserve CLI order and first-root priority";
            EXPECT_BYTES_EQ(Bytes{0x12}, addons[1].data)
                << "add-ons preserve CLI order and first-root priority";

            const auto merged =
                nand::parse_and_merge_patch_set(*result->input.patches, result->input.build_type);
            ASSERT_OK(merged) << "resolved patches parse and merge";
            const auto khv = std::find_if(
                merged->sections.begin(), merged->sections.end(), [](const auto& section) {
                    return section.target == nand::PatchSectionTarget::Khv;
                });
            ASSERT_NE(khv, merged->sections.end()) << "resolved add-ons append to KHV in CLI order";
            ASSERT_GE(khv->raw_data.size(), 3U) << "resolved add-ons append to KHV in CLI order";
            EXPECT_BYTES_EQ((Bytes{0xA0, 0x21, 0x12}), std::span{khv->raw_data}.last(3))
                << "resolved add-ons append to KHV in CLI order";
        }

        // One TEST over both build types, as the plan keeps it: each runs in a tree of its own
        // and a failure names its build type.
        TEST_F(ResolverPatchset, RetailAndDevkitRejectAddonsWithoutAutomaticPatchset) {
            for (const auto& [label, type] :
                 {std::pair{"retail", BuildType::Retail}, std::pair{"devkit", BuildType::Devkit}}) {
                SCOPED_TRACE(label);
                ASSERT_OK_AND_ASSIGN(const auto own, test::ResolverTree::make(path(label)));
                ASSERT_OK_AND_ASSIGN(auto args, own.complete_loose_args(type));
                args.addons = {"extra"};
                ASSERT_OK(own.write_binary("first/bin/extra.bin", Bytes{0x41}));
                const auto result = own.resolve(args);
                ASSERT_ERROR_MSG(result, ResolutionErrorCode::InvalidInput,
                                 "Add-ons require an automatic patchset and are not supported for "
                                 "retail or devkit builds")
                    << "retail and devkit reject add-ons that cannot be applied";
                EXPECT_TRUE(result.error().path.empty())
                    << "retail and devkit reject add-ons that cannot be applied";
                EXPECT_EQ(result.error().item, "extra")
                    << "retail and devkit reject add-ons that cannot be applied";
            }
        }

        // One TEST over the refused add-ons, sections and suffixes, as the plan keeps it: each
        // runs in a tree of its own and a failure names the refused value. The accepted
        // internal-underscore suffix runs in the test's own tree.
        TEST_F(ResolverPatchset, DirectBuildArgsRejectUnconfinedPatchComponents) {
            int tree_index = 0;
            const auto own_tree = [&] {
                return test::ResolverTree::make(path("refused-" + std::to_string(tree_index++)));
            };

            for (const std::string invalid :
                 {"../outside", "/outside", "nested/addon", "addon.bin", "C:\\outside"}) {
                SCOPED_TRACE("add-on '" + invalid + "'");
                ASSERT_OK_AND_ASSIGN(const auto own, own_tree());
                ASSERT_OK_AND_ASSIGN(auto args, own.complete_loose_args(BuildType::Glitch2));
                args.addons = {invalid};
                const auto result = own.resolve(args);
                ASSERT_ERROR(result, ResolutionErrorCode::InvalidInput)
                    << "direct BuildArgs add-ons are bare ASCII logical names";
                EXPECT_TRUE(result.error().path.empty())
                    << "direct BuildArgs add-ons are bare ASCII logical names";
                EXPECT_EQ(result.error().item, invalid)
                    << "direct BuildArgs add-ons are bare ASCII logical names";
            }

            for (const std::string invalid :
                 {"../falcon", "/falcon", "nested\\falcon", "C:\\falcon"}) {
                SCOPED_TRACE("section '" + invalid + "'");
                ASSERT_OK_AND_ASSIGN(const auto own, own_tree());
                ASSERT_OK_AND_ASSIGN(auto args, own.complete_loose_args(BuildType::Glitch2));
                args.section = invalid;
                const auto result = own.resolve(args);
                ASSERT_ERROR(result, ResolutionErrorCode::InvalidInput)
                    << "direct BuildArgs section cannot escape a filename component";
                EXPECT_TRUE(result.error().path.empty())
                    << "direct BuildArgs section cannot escape a filename component";
                EXPECT_EQ(result.error().item, invalid)
                    << "direct BuildArgs section cannot escape a filename component";
            }

            for (const std::string invalid :
                 {"_test", "test.alt", "../test", "/test", "nested\\test", "C:\\test"}) {
                SCOPED_TRACE("patch suffix '" + invalid + "'");
                ASSERT_OK_AND_ASSIGN(const auto own, own_tree());
                ASSERT_OK_AND_ASSIGN(auto args, own.complete_loose_args(BuildType::Glitch2));
                args.patch_extension = invalid;
                const auto result = own.resolve(args);
                ASSERT_ERROR(result, ResolutionErrorCode::InvalidInput)
                    << "direct BuildArgs patch suffix is a safe non-underscored component";
                EXPECT_TRUE(result.error().path.empty())
                    << "direct BuildArgs patch suffix is a safe non-underscored component";
                EXPECT_EQ(result.error().item, invalid)
                    << "direct BuildArgs patch suffix is a safe non-underscored component";
            }

            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2));
            args.patch_extension = "test_alt";
            write("first/bin/patches_g2falcon_test_alt.bin", test::valid_glitch_patchset());
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
            const auto valid_internal_underscore = resolve(args);
            ASSERT_OK(valid_internal_underscore) << "an internal-underscore patch suffix resolves";
            ASSERT_TRUE(valid_internal_underscore->input.patches.has_value() &&
                        valid_internal_underscore->input.patches->automatic.has_value())
                << "safe internal underscores are retained in automatic patch names";
            EXPECT_EQ(valid_internal_underscore->input.patches->automatic->name,
                      "patches_g2falcon_test_alt.bin")
                << "safe internal underscores are retained in automatic patch names";
        }

        // ---- AutomaticPatchsetName --------------------------------------------------------

        // name is the row's gtest name; type the build type, xell the XeLL it needs and file
        // the automatic patch file it must select with the suffix "test" (today's names,
        // following BuildInputResolver.cpp, not the old docs).
        struct AutomaticPatchsetNameCase {
            const char* name;
            BuildType type;
            std::string_view xell;
            std::string_view file;
        };
        GX_PRINT_ROW_AS_NAME(AutomaticPatchsetNameCase)

        constexpr std::array kAutomaticPatchsetNameCases{
            AutomaticPatchsetNameCase{"JtagUsesTheSectionStem", BuildType::Jtag, "xell-2f.bin",
                                      "patches_falcon_test.bin"},
            AutomaticPatchsetNameCase{"GlitchUsesTheFatStem", BuildType::Glitch, "xell-gggggg.bin",
                                      "patches_fat_test.bin"},
            AutomaticPatchsetNameCase{"Glitch2", BuildType::Glitch2, "xell-gggggg.bin",
                                      "patches_g2falcon_test.bin"},
            AutomaticPatchsetNameCase{"Glitch2m", BuildType::Glitch2m, "xell-gggggg.bin",
                                      "patches_g2mfalcon_test.bin"},
            AutomaticPatchsetNameCase{"Glitch3", BuildType::Glitch3, "xell-gggggg.bin",
                                      "patches_g3falcon_test.bin"},
        };

        class AutomaticPatchsetName
            : public ResolverTest,
              public ::testing::WithParamInterface<AutomaticPatchsetNameCase> {};

        TEST_P(AutomaticPatchsetName, SelectsTheBuildTypeStemWithTheSuffix) {
            const auto& row = GetParam();
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(row.type));
            args.patch_extension = "test";
            write("first/bin/" + std::string{row.file}, test::valid_glitch_patchset());
            write("first/" + std::string{row.xell}, Bytes(0x40000, 0x5A));
            const auto result = resolve(args);
            ASSERT_OK(result) << "automatic patch fixture resolves";
            ASSERT_TRUE(result->input.patches.has_value() &&
                        result->input.patches->automatic.has_value())
                << "automatic patch name uses the exact build-type table and suffix";
            EXPECT_EQ(result->input.patches->automatic->name, row.file)
                << "automatic patch name uses the exact build-type table and suffix";
        }

        INSTANTIATE_TEST_SUITE_P(Row, AutomaticPatchsetName,
                                 ::testing::ValuesIn(kAutomaticPatchsetNameCases), test::RowName{});

        // ---- NoAutomaticPatchset ----------------------------------------------------------

        struct NoAutomaticPatchsetCase {
            const char* name;
            BuildType type;
        };
        GX_PRINT_ROW_AS_NAME(NoAutomaticPatchsetCase)

        constexpr std::array kNoAutomaticPatchsetCases{
            NoAutomaticPatchsetCase{"Retail", BuildType::Retail},
            NoAutomaticPatchsetCase{"Devkit", BuildType::Devkit},
        };

        class NoAutomaticPatchset : public ResolverTest,
                                    public ::testing::WithParamInterface<NoAutomaticPatchsetCase> {
        };

        TEST_P(NoAutomaticPatchset, ARootPatchsetIsNotAutoSelected) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args(GetParam().type));
            write("first/bin/patches_falcon.bin", test::valid_glitch_patchset());
            const auto result = resolve(args);
            ASSERT_OK(result) << "retail and devkit do not auto-select patchsets";
            EXPECT_TRUE(!result->input.patches || !result->input.patches->automatic.has_value())
                << "retail and devkit do not auto-select patchsets";
        }

        INSTANTIATE_TEST_SUITE_P(Row, NoAutomaticPatchset,
                                 ::testing::ValuesIn(kNoAutomaticPatchsetCases), test::RowName{});

    } // namespace
} // namespace gxbuild3::cli
