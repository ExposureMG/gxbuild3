#pragma once

// Renderer of tests/golden/flashfs_roots.txt: the FlashFS root codec (serialize_root_block),
// save() plus driver.serialize() and a reload, for five synthetic layouts (small, newsmall, big,
// big_larger, emmc), then the load pins of today's load() skip, drop and error behaviour. It needs
// no fixture file. FlashFsRootRender.cpp describes the lines; FlashFsRootGoldenTests.cpp compares
// them. The root builders are tests/support/builders/FlashFsRoots.hpp.

#include "Error.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots::flashfs_roots {

    inline constexpr std::string_view kGolden = "flashfs_roots";

    struct Rendered {
        std::string text;
        // The root-codec layouts rendered (the old binary printed "flashfs root goldens: 5
        // layouts").
        std::size_t layouts = 0;
        // What the render found wrong on its own: the old check() messages, in order, empty when
        // all is well. The text is the same either way.
        std::vector<std::string> problems;
    };

    // The golden text, the layout count and the problems.
    [[nodiscard]] Rendered render();

    // The whole golden file, registered with GX_GOLDEN for --update; an error when the render
    // reports a problem, so --update refuses to write it.
    [[nodiscard]] Result<std::string> render_file();

} // namespace gxbuild3::snapshots::flashfs_roots
