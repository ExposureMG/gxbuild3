// tests/golden/extract_projections_synthetic.txt: every public extract_* projection of three
// run_build digest outputs, small.glitch2, newsmall.devkit and newsmall.devkit under the all-zero
// CPU key (ExtractProjectionSyntheticRender.cpp), compared whole. The old BuildRunnerTests.cpp
// test_extract_projection_snapshots built each image twice and projected it twice, failed on a
// build that differed, a projection that differed or an overload or shim that disagreed with the
// core's span overload, compared the text with the golden and printed "extract projections:
// inputs stable N/3, overloads and shims agreed A/C, compared N/3 with ...". That is the one case
// ExtractProjectionSyntheticGolden.MatchesGolden: one failure per problem, then the golden match,
// with the old summary line recorded as a property and repeated in the failure message. The
// render takes about 23 s in Release; the golden is split into sections in its own later commit.

#include "RunBuildGoldenRender.hpp"
#include "support/golden/Golden.hpp"

#include <format>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::snapshots {
    namespace {

        using extract_projections_synthetic::kGolden;
        using extract_projections_synthetic::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(ExtractProjectionSyntheticGolden, MatchesGolden) {
            const auto rendered = extract_projections_synthetic::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto matched = test::matches_golden(kGolden, rendered.text);
            const std::string summary = std::format(
                "extract projections: inputs stable {}/{}, overloads and shims agreed {}/{}, "
                "compared {}/{} with tests/golden/extract_projections_synthetic.txt",
                rendered.stable, rendered.cases, rendered.agreements, rendered.comparisons,
                matched ? rendered.stable : 0, rendered.cases);
            RecordProperty("summary", summary);
            EXPECT_TRUE(matched) << "synthetic extract projections match the golden (" << summary
                                 << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
