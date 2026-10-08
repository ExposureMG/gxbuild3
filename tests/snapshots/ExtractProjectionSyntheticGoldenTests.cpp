// tests/golden/extract_projections_synthetic.txt: every public extract_* projection of three
// run_build digest outputs, small.glitch2, newsmall.devkit and newsmall.devkit under the all-zero
// CPU key (ExtractProjectionSyntheticRender.cpp), compared per section. The old
// BuildRunnerTests.cpp test_extract_projection_snapshots built each image twice and projected it
// twice, failed on a build that differed, a projection that differed or an overload or shim that
// disagreed with the core's span overload, compared the text with the golden and printed
// "extract projections: inputs stable N/3, overloads and shims agreed A/C, compared N/3 with
// ...". Each of its cases owns the golden lines that start with "<label>.extract_" and is a
// section here:
//
//   ExtractProjectionSynthetic.MatchesSlice
//                                 one case: render_case builds its image twice, projects it
//                                 twice, reports each problem as one failure, checks that the
//                                 12 other overloads and shims agreed with the core's span
//                                 overload and compares its lines with the golden lines its
//                                 key owns. Case/ExtractProjectionSynthetic.MatchesSlice/
//                                 SmallGlitch2 ..., each row its own ctest entry (PER_ROW: a
//                                 row takes several seconds);
//   ExtractProjectionSyntheticGolden.IsPartitioned
//                                 the three keys, in file order, own every line of the golden
//                                 exactly once, so the rows together are the old whole-file
//                                 compare.
//
// The ".extract_" suffix of each key is needed: a plain "newsmall.devkit." would also own the
// zero-key case's lines. The old summary line has no single case left to carry it: a case that
// does not build, differs or disagrees fails on its own. The whole-file renderer registered for
// --update concatenates the same cases.

#include "RunBuildGoldenRender.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"

#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {
    namespace {

        using extract_projections_synthetic::kGolden;
        using extract_projections_synthetic::render_file;

        GX_GOLDEN(kGolden, render_file);

        // Every projected image is compared through the vector overload and the span and
        // vector library shims of each of the four extract_* cores.
        constexpr std::size_t kAgreementsPerImage = 12;

        struct ProjectionRow {
            const char* name;
            std::string_view label;
            std::string_view key;
        };
        GX_PRINT_ROW_AS_NAME(ProjectionRow)

        // The file's order.
        constexpr ProjectionRow kRows[] = {
            {"SmallGlitch2", "small.glitch2", "small.glitch2.extract_"},
            {"NewsmallDevkit", "newsmall.devkit", "newsmall.devkit.extract_"},
            {"NewsmallDevkitZeroKey", "newsmall.devkit.zero-key",
             "newsmall.devkit.zero-key.extract_"},
        };

        test::Section row_section(const ProjectionRow& row) {
            return {row.key, std::span{&row.key, 1}};
        }

        class ExtractProjectionSynthetic : public ::testing::TestWithParam<ProjectionRow> {};

        TEST_P(ExtractProjectionSynthetic, MatchesSlice) {
            const ProjectionRow& row = GetParam();
            const auto rendered = extract_projections_synthetic::render_case(row.label);
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            EXPECT_EQ(rendered.agreements, kAgreementsPerImage)
                << row.label << ": every overload and shim renders the same as the core's span "
                << "overload (" << rendered.agreements << "/" << rendered.comparisons << ")";
            EXPECT_TRUE(test::matches_golden_slice(kGolden, row_section(row), rendered.text));
        }

        INSTANTIATE_TEST_SUITE_P(Case, ExtractProjectionSynthetic, ::testing::ValuesIn(kRows),
                                 test::RowName{});

        TEST(ExtractProjectionSyntheticGolden, IsPartitioned) {
            std::vector<test::Section> sections;
            for (const auto& row : kRows) {
                sections.push_back(row_section(row));
            }
            EXPECT_EQ(sections.size(), 3u);
            EXPECT_TRUE(test::golden_is_partitioned(kGolden, sections));
        }

    } // namespace
} // namespace gxbuild3::snapshots
