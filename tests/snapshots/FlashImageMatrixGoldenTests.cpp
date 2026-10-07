// tests/golden/flashimage_matrix.txt: the synthetic fresh-layout matrix, Small/Big/Emmc x the
// eight build types plain and sealed, plus the header encoded for a zeroed nand_header
// (FlashImageMatrixRender.cpp), compared whole. The old FlashImageGoldenTests.cpp main()
// rendered it once and compared it; a cell that did not build or kept a zero nonce was a failed
// check. That is the one case FlashImageMatrixGolden.MatchesGolden: one failure per problem,
// then the golden match. The render writes 48 full-size images (about 25 s in Release); it is
// split into sections in its own later commit.

#include "FlashImageGoldenRender.hpp"
#include "support/golden/Golden.hpp"

#include <algorithm>
#include <cstddef>
#include <gtest/gtest.h>

namespace gxbuild3::snapshots {
    namespace {

        using flashimage_matrix::kGolden;
        using flashimage_matrix::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(FlashImageMatrixGolden, MatchesGolden) {
            const auto rendered = flashimage_matrix::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto lines = static_cast<std::size_t>(std::ranges::count(rendered.text, '\n'));
            EXPECT_TRUE(test::matches_golden(kGolden, rendered.text))
                << kGolden << ".txt does not match HEAD output (snapshot lines " << lines
                << ", cells " << rendered.cells << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
