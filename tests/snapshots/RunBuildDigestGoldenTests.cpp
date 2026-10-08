// tests/golden/run_build_digests.txt: the size and SHA-1 of run_build's output for SmallBlock,
// NewSmallBlock, BigBlock and Emmc crossed with retail, glitch2, devkit and devgl, each built
// twice under the pinned build time (RunBuildDigestRender.cpp), compared whole. The old
// BuildRunnerTests.cpp test_run_build_output_digests built the 16 rows, failed on a row that did
// not build or built differently twice, compared the text with the golden and printed
// "run_build digests: built twice and identical N/16, compared N/16 with ...". That is the one
// case RunBuildDigestGolden.MatchesGolden: one failure per problem, then the golden match, with
// the old summary line recorded as a property and repeated in the failure message. The 32 builds
// take about 12 s in Release; the golden is split into sections in its own later commit.

#include "RunBuildGoldenRender.hpp"
#include "support/golden/Golden.hpp"

#include <format>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::snapshots {
    namespace {

        using run_build_digests::kGolden;
        using run_build_digests::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(RunBuildDigestGolden, MatchesGolden) {
            const auto rendered = run_build_digests::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto matched = test::matches_golden(kGolden, rendered.text);
            const std::string summary = std::format(
                "run_build digests: built twice and identical {}/{}, compared {}/{} with "
                "tests/golden/run_build_digests.txt",
                rendered.identical, rendered.total, matched ? rendered.identical : 0,
                rendered.total);
            RecordProperty("summary", summary);
            EXPECT_TRUE(matched) << "run_build output digests match the golden (" << summary << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
