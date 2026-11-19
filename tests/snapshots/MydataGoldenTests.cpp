// tests/golden/orchestration_mydata_builds.txt and tests/golden/extract_projections_mydata.txt:
// the run_build digests and extract_* projections over the tracked mydata/image.bin
// (MydataRender.cpp), each compared per section. The old tests/OrchestrationGoldenTests.cpp
// main() read image.bin and opened it with extract_all (returning at once when either failed),
// checked that all six donor nonces were filled, built the three variants, compared the digests
// with the golden and printed "orchestration digests: built twice and identical N/3, compared
// N/3 with ...", then test_extract_projection_snapshots projected image.bin and the glitch2
// rebuild, compared them with their golden and printed "extract projections: inputs stable N/3,
// overloads and shims agreed A/C, compared N/3 with ...". Here:
//
//   MydataBuild.MatchesSlice      one variant (Retail, Jtag, Glitch2): the donor, its build
//                                 (twice, identical) through the per-process variant cache, one
//                                 failure per problem, and its line against the golden line its
//                                 "mydata.<variant> " key owns. Build/MydataBuild, one bundled
//                                 entry (six builds, about 2 s);
//   MydataProjection.MatchesSlice one case (Image, ImageZeroKey, Glitch2): the donor, the case
//                                 projected twice (Glitch2 projects the glitch2 rebuild, built
//                                 through the cache), one failure per problem, the 12 overload
//                                 and shim agreements, and its lines against the golden lines
//                                 its "<label>.extract_" key owns. Case/MydataProjection, each
//                                 row its own ctest entry (PER_ROW: a row takes seconds);
//   MydataGolden                  ExtractAllFillsAllSixDonorNonces (the donor reads and opens, a
//                                 missing tracked image.bin fails and never skips, then the
//                                 nonce check), BuildsArePartitioned and
//                                 ProjectionsArePartitioned (the keys, in file order, own every
//                                 line of their golden exactly once, so the rows together are
//                                 the old whole-file compares); one bundled entry.
//
// Each case stands alone: the donor and the builds are cached per process, never carried from
// one test to another. The old summary lines have no single case left to carry them: a row that
// does not build, differs or disagrees fails on its own. The whole-file renderers registered for
// --update concatenate the same rows.

#include "MydataGoldenRender.hpp"
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

        // GX_GOLDEN names its registration after the renderer, so each gets a plain name.
        constexpr auto& render_builds = orchestration_mydata_builds::render_file;
        constexpr auto& render_projections = extract_projections_mydata::render_file;

        GX_GOLDEN(orchestration_mydata_builds::kGolden, render_builds);
        GX_GOLDEN(extract_projections_mydata::kGolden, render_projections);

        // Every projected image is compared through the vector overload and the span and
        // vector library shims of each of the four extract_* cores.
        constexpr std::size_t kAgreementsPerImage = 12;

        struct BuildRow {
            const char* name;
            std::size_t variant;
            std::string_view key;
        };
        GX_PRINT_ROW_AS_NAME(BuildRow)

        // The file's order.
        constexpr BuildRow kBuildRows[] = {
            {"Retail", mydata::kRetail, "mydata.retail "},
            {"Jtag", mydata::kJtag, "mydata.jtag "},
            {"Glitch2", mydata::kGlitch2, "mydata.glitch2 "},
        };

        struct ProjectionRow {
            const char* name;
            std::string_view label;
            std::string_view key;
        };
        GX_PRINT_ROW_AS_NAME(ProjectionRow)

        // The file's order.
        constexpr ProjectionRow kProjectionRows[] = {
            {"Image", "mydata.image", "mydata.image.extract_"},
            {"ImageZeroKey", "mydata.image.zero-key", "mydata.image.zero-key.extract_"},
            {"Glitch2", "mydata.glitch2", "mydata.glitch2.extract_"},
        };

        template <class Row> test::Section row_section(const Row& row) {
            return {row.key, std::span{&row.key, 1}};
        }

        template <class Row, std::size_t N>
        std::vector<test::Section> row_sections(const Row (&rows)[N]) {
            std::vector<test::Section> sections;
            for (const auto& row : rows) {
                sections.push_back(row_section(row));
            }
            return sections;
        }

        class MydataBuild : public ::testing::TestWithParam<BuildRow> {};

        TEST_P(MydataBuild, MatchesSlice) {
            const BuildRow& row = GetParam();
            ASSERT_OK(mydata::donor()) << "mydata/image.bin reads and extract_all opens it";
            const auto& build = mydata::variant_build(row.variant);
            for (const auto& problem : build.problems) {
                ADD_FAILURE() << problem;
            }
            EXPECT_TRUE(test::matches_golden_slice(orchestration_mydata_builds::kGolden,
                                                   row_section(row), build.line));
        }

        INSTANTIATE_TEST_SUITE_P(Build, MydataBuild, ::testing::ValuesIn(kBuildRows),
                                 test::RowName{});

        class MydataProjection : public ::testing::TestWithParam<ProjectionRow> {};

        TEST_P(MydataProjection, MatchesSlice) {
            const ProjectionRow& row = GetParam();
            ASSERT_OK(mydata::donor()) << "mydata/image.bin reads and extract_all opens it";
            const auto rendered = extract_projections_mydata::render_case(row.label);
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            EXPECT_EQ(rendered.agreements, kAgreementsPerImage)
                << row.label << ": every overload and shim renders the same as the core's span "
                << "overload (" << rendered.agreements << "/" << rendered.comparisons << ")";
            EXPECT_TRUE(test::matches_golden_slice(extract_projections_mydata::kGolden,
                                                   row_section(row), rendered.text));
        }

        INSTANTIATE_TEST_SUITE_P(Case, MydataProjection, ::testing::ValuesIn(kProjectionRows),
                                 test::RowName{});

        TEST(MydataGolden, ExtractAllFillsAllSixDonorNonces) {
            const auto& donor = mydata::donor();
            ASSERT_OK(donor) << "mydata/image.bin reads and extract_all opens it";
            EXPECT_TRUE(mydata::all_nonces_filled(donor->extracted))
                << "extract_all fills all six donor nonces, so run_build draws none";
        }

        TEST(MydataGolden, BuildsArePartitioned) {
            const auto sections = row_sections(kBuildRows);
            EXPECT_EQ(sections.size(), mydata::kVariants);
            EXPECT_TRUE(
                test::golden_is_partitioned(orchestration_mydata_builds::kGolden, sections));
        }

        TEST(MydataGolden, ProjectionsArePartitioned) {
            const auto sections = row_sections(kProjectionRows);
            EXPECT_EQ(sections.size(), 3u);
            EXPECT_TRUE(test::golden_is_partitioned(extract_projections_mydata::kGolden, sections));
        }

    } // namespace
} // namespace gxbuild3::snapshots
