// tests/golden/flashfs_roots.txt: the FlashFS root codec, save()+driver.serialize() and load pins
// over synthetic layouts, compared whole. The old FlashFileSystemTests.cpp main() rendered the
// five root cases and the nine load pins once, failed on any check() inside them and compared the
// text with the golden; that is the one case FlashFsRootGolden.MatchesGolden: one failure per
// problem the render reports (the old check() messages), then the golden match. The render takes
// about 2.5 s and is one ctest entry.

#include "FlashFsRootRender.hpp"
#include "support/golden/Golden.hpp"

#include <gtest/gtest.h>

namespace gxbuild3::snapshots {
    namespace {

        using flashfs_roots::kGolden;
        using flashfs_roots::render_file;
        using flashfs_roots::Rendered;

        GX_GOLDEN(kGolden, render_file);

        TEST(FlashFsRootGolden, MatchesGolden) {
            const Rendered rendered = flashfs_roots::render();
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            EXPECT_TRUE(test::matches_golden(kGolden, rendered.text))
                << kGolden
                << ".txt does not match HEAD output (flashfs root goldens: " << rendered.layouts
                << " layouts)";
        }

    } // namespace
} // namespace gxbuild3::snapshots
