// tests/golden/run_build_digests.txt: the size and SHA-1 of run_build's output for SmallBlock,
// NewSmallBlock, BigBlock and Emmc crossed with retail, glitch2, devkit and devgl, each built
// twice under the pinned build time (RunBuildDigestRender.cpp), compared per section. The old
// BuildRunnerTests.cpp test_run_build_output_digests built the 16 rows, failed on a row that did
// not build or built differently twice, compared the text with the golden and printed
// "run_build digests: built twice and identical N/16, compared N/16 with ...". Each of its rows
// is one line of the golden, "<layout>.<build> size=... sha1=...", and is a section here:
//
//   RunBuildDigest.MatchesSlice   one row: render_row builds the pair twice, reports a build
//                                 error or a difference as one failure each, and compares its
//                                 line with the golden line its "<layout>.<build> " key owns.
//                                 Instantiated per build type over the four layouts
//                                 (Retail/RunBuildDigest.MatchesSlice/Small ...), each
//                                 instantiation one bundled ctest entry of eight builds;
//   RunBuildDigestGolden.IsPartitioned
//                                 the 16 keys, in file order (layout-major), own every line of
//                                 the golden exactly once, so the rows together are the old
//                                 whole-file compare.
//
// The old summary line has no single case left to carry it: a row that does not build or differs
// fails on its own. The whole-file renderer registered for --update concatenates the same rows.

#include "RunBuildGoldenRender.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"

#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {
    namespace {

        using run_build_digests::kGolden;
        using run_build_digests::render_file;

        GX_GOLDEN(kGolden, render_file);

        struct DigestRow {
            const char* name;
            ImageType layout;
            BuildType build;
            std::string_view key;
        };
        GX_PRINT_ROW_AS_NAME(DigestRow)

        constexpr DigestRow kRetailRows[] = {
            {"Small", ImageType::SmallBlock, BuildType::Retail, "small.retail "},
            {"NewSmall", ImageType::NewSmallBlock, BuildType::Retail, "newsmall.retail "},
            {"Big", ImageType::BigBlock, BuildType::Retail, "big.retail "},
            {"Emmc", ImageType::Emmc, BuildType::Retail, "emmc.retail "},
        };
        constexpr DigestRow kGlitch2Rows[] = {
            {"Small", ImageType::SmallBlock, BuildType::Glitch2, "small.glitch2 "},
            {"NewSmall", ImageType::NewSmallBlock, BuildType::Glitch2, "newsmall.glitch2 "},
            {"Big", ImageType::BigBlock, BuildType::Glitch2, "big.glitch2 "},
            {"Emmc", ImageType::Emmc, BuildType::Glitch2, "emmc.glitch2 "},
        };
        constexpr DigestRow kDevkitRows[] = {
            {"Small", ImageType::SmallBlock, BuildType::Devkit, "small.devkit "},
            {"NewSmall", ImageType::NewSmallBlock, BuildType::Devkit, "newsmall.devkit "},
            {"Big", ImageType::BigBlock, BuildType::Devkit, "big.devkit "},
            {"Emmc", ImageType::Emmc, BuildType::Devkit, "emmc.devkit "},
        };
        constexpr DigestRow kDevglRows[] = {
            {"Small", ImageType::SmallBlock, BuildType::Devgl, "small.devgl "},
            {"NewSmall", ImageType::NewSmallBlock, BuildType::Devgl, "newsmall.devgl "},
            {"Big", ImageType::BigBlock, BuildType::Devgl, "big.devgl "},
            {"Emmc", ImageType::Emmc, BuildType::Devgl, "emmc.devgl "},
        };

        // The row tables in the file's build order; row i of each is layout i.
        constexpr std::array<std::span<const DigestRow>, 4> kRowTables{kRetailRows, kGlitch2Rows,
                                                                       kDevkitRows, kDevglRows};

        test::Section row_section(const DigestRow& row) {
            return {row.key, std::span{&row.key, 1}};
        }

        class RunBuildDigest : public ::testing::TestWithParam<DigestRow> {};

        TEST_P(RunBuildDigest, MatchesSlice) {
            const DigestRow& row = GetParam();
            std::vector<std::string> problems;
            const auto text = run_build_digests::render_row(row.layout, row.build, problems);
            for (const auto& problem : problems) {
                ADD_FAILURE() << problem;
            }
            EXPECT_TRUE(test::matches_golden_slice(kGolden, row_section(row), text));
        }

        INSTANTIATE_TEST_SUITE_P(Retail, RunBuildDigest, ::testing::ValuesIn(kRetailRows),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch2, RunBuildDigest, ::testing::ValuesIn(kGlitch2Rows),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Devkit, RunBuildDigest, ::testing::ValuesIn(kDevkitRows),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Devgl, RunBuildDigest, ::testing::ValuesIn(kDevglRows),
                                 test::RowName{});

        TEST(RunBuildDigestGolden, IsPartitioned) {
            // File order: layout-major, each layout's rows in the build order of kRowTables.
            std::vector<test::Section> sections;
            for (std::size_t layout = 0; layout < std::size(kRetailRows); ++layout) {
                for (const auto table : kRowTables) {
                    sections.push_back(row_section(table[layout]));
                }
            }
            EXPECT_EQ(sections.size(), 16u);
            EXPECT_TRUE(test::golden_is_partitioned(kGolden, sections));
        }

    } // namespace
} // namespace gxbuild3::snapshots
