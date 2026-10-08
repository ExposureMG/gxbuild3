// tests/golden/run_build_failures.txt: the BuildErrorCode and describe() message of each of the
// 30 run_build exits an Input can reach, then the 19 exits only a fault could reach as
// not-covered lines (RunBuildFailureRender.cpp), compared whole. The old BuildRunnerTests.cpp
// test_run_build_failure_exits_keep_code_and_message ran each input twice, failed on an input
// that built or was refused differently twice, compared the text with the golden and printed
// "run_build failure exits: refused N/30, compared N/30 with ..., 19 exits not covered". That
// is the one case RunBuildFailureGolden.MatchesGolden: one failure per problem, then the golden
// match, with the old summary line recorded as a property and repeated in the failure message.
// The 60 refused builds take under a second in Release.

#include "RunBuildGoldenRender.hpp"
#include "support/golden/Golden.hpp"

#include <format>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::snapshots {
    namespace {

        using run_build_failures::kGolden;
        using run_build_failures::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(RunBuildFailureGolden, MatchesGolden) {
            const auto rendered = run_build_failures::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto matched = test::matches_golden(kGolden, rendered.text);
            const std::string summary =
                std::format("run_build failure exits: refused {}/{}, compared {}/{} with "
                            "tests/golden/run_build_failures.txt, {} exits not covered",
                            rendered.refused, rendered.cases, matched ? rendered.refused : 0,
                            rendered.cases, rendered.uncovered);
            RecordProperty("summary", summary);
            EXPECT_TRUE(matched) << "run_build failure exits match the golden (" << summary << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
