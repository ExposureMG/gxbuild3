// tests/golden/flashimage_failures.txt: ErrorCode and describe() of each reachable FlashImage
// exit in today's check order (FlashImageFailureRender.cpp), compared whole. The old
// FlashImageGoldenTests.cpp main() rendered it once and compared it; a fixture that did not
// load, build, seal or write was a failed check. That is the one case
// FlashImageFailureGolden.MatchesGolden: one failure per problem, then the golden match.

#include "FlashImageGoldenRender.hpp"
#include "support/golden/Golden.hpp"

#include <algorithm>
#include <cstddef>
#include <gtest/gtest.h>

namespace gxbuild3::snapshots {
    namespace {

        using flashimage_failures::kGolden;
        using flashimage_failures::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(FlashImageFailureGolden, MatchesGolden) {
            const auto rendered = flashimage_failures::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto lines = static_cast<std::size_t>(std::ranges::count(rendered.text, '\n'));
            EXPECT_TRUE(test::matches_golden(kGolden, rendered.text))
                << kGolden << ".txt does not match HEAD output (snapshot lines " << lines << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
