// tests/golden/orchestration_mydata_builds.txt and tests/golden/extract_projections_mydata.txt:
// the run_build digests and extract_* projections over the tracked mydata/image.bin
// (MydataRender.cpp), each compared whole. The old tests/OrchestrationGoldenTests.cpp main()
// read image.bin and opened it with extract_all (returning at once when either failed), checked
// that all six donor nonces were filled, built the three variants, compared the digests with the
// golden and printed "orchestration digests: built twice and identical N/3, compared N/3 with
// ...", then test_extract_projection_snapshots projected image.bin and the glitch2 rebuild,
// compared them with their golden and printed "extract projections: inputs stable N/3, overloads
// and shims agreed A/C, compared N/3 with ...". Those are three cases of MydataGolden, each its
// own ctest entry and each standing alone (the donor and the builds are cached per process, never
// carried from one test to another):
//   ExtractAllFillsAllSixDonorNonces  the donor reads and opens (a missing tracked image.bin
//                                     fails, it never skips), then the nonce check;
//   BuildsMatchGolden                 the donor, one failure per problem, the golden match;
//   ProjectionsMatchGolden            the donor, the glitch2 rebuild through the cache, one
//                                     failure per problem, the golden match.
// Each summary line is recorded as a property and repeated in its failure message.

#include "MydataGoldenRender.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"

#include <format>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::snapshots {
    namespace {

        // GX_GOLDEN names its registration after the renderer, so each gets a plain name.
        constexpr auto& render_builds = orchestration_mydata_builds::render_file;
        constexpr auto& render_projections = extract_projections_mydata::render_file;

        GX_GOLDEN(orchestration_mydata_builds::kGolden, render_builds);
        GX_GOLDEN(extract_projections_mydata::kGolden, render_projections);

        TEST(MydataGolden, ExtractAllFillsAllSixDonorNonces) {
            const auto& donor = mydata::donor();
            ASSERT_OK(donor) << "mydata/image.bin reads and extract_all opens it";
            EXPECT_TRUE(mydata::all_nonces_filled(donor->extracted))
                << "extract_all fills all six donor nonces, so run_build draws none";
        }

        TEST(MydataGolden, BuildsMatchGolden) {
            ASSERT_OK(mydata::donor()) << "mydata/image.bin reads and extract_all opens it";
            const auto rendered = orchestration_mydata_builds::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto matched =
                test::matches_golden(orchestration_mydata_builds::kGolden, rendered.text);
            const std::string summary = std::format(
                "orchestration digests: built twice and identical {}/{}, compared {}/{} with "
                "tests/golden/orchestration_mydata_builds.txt",
                rendered.identical, rendered.total, matched ? rendered.identical : 0,
                rendered.total);
            RecordProperty("summary", summary);
            EXPECT_TRUE(matched) << "mydata rebuild digests match the golden (" << summary << ")";
        }

        TEST(MydataGolden, ProjectionsMatchGolden) {
            ASSERT_OK(mydata::donor()) << "mydata/image.bin reads and extract_all opens it";
            const auto rendered = extract_projections_mydata::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto matched =
                test::matches_golden(extract_projections_mydata::kGolden, rendered.text);
            const std::string summary = std::format(
                "extract projections: inputs stable {}/{}, overloads and shims agreed {}/{}, "
                "compared {}/{} with tests/golden/extract_projections_mydata.txt",
                rendered.stable, rendered.cases, rendered.agreements, rendered.comparisons,
                matched ? rendered.stable : 0, rendered.cases);
            RecordProperty("summary", summary);
            EXPECT_TRUE(matched) << "mydata extract projections match the golden (" << summary
                                 << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
