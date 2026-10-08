#pragma once

// Renderers of the three run_build text goldens, moved from tests/BuildRunnerTests.cpp:
//
//   run_build_digests              (RunBuildDigestRender.cpp) SmallBlock, NewSmallBlock, BigBlock
//                                  and Emmc crossed with retail, glitch2, devkit and devgl, each
//                                  built twice under the pinned build time; the size and SHA-1
//                                  of each output, one line per row (render_row);
//   extract_projections_synthetic  (ExtractProjectionSyntheticRender.cpp) every public extract_*
//                                  projection (support/render/ExtractProjection.hpp) of
//                                  small.glitch2, newsmall.devkit and newsmall.devkit under the
//                                  all-zero CPU key;
//   run_build_failures             (RunBuildFailureRender.cpp) the BuildErrorCode and describe()
//                                  message of each run_build exit an Input can reach, then the
//                                  19 exits only a fault could reach, as not-covered lines.
//
// The renderers and their emitted strings are the old ones, verbatim (' error=',
// ' nondeterministic', ' build-error=', 'not-covered ' included). Their require() calls no
// longer print "FAIL: ..." on stderr: the messages are returned as problems, which the golden
// tests report one failure each, and render_file (registered with GX_GOLDEN) refuses while a
// problem is reported, so --update cannot write such a render. The digest and projection builds
// run under test::PinnedBuildTime{"1791105724", "UTC0"}, as the old build_pinned did (SOURCE_DATE_
// EPOCH and TZ=UTC0 around each run_build); the failure exits pin nothing, as before. Every input
// is synthetic (tests/support/builders/Inputs.hpp), so the three render on a clean clone.

#include "Args.hpp"
#include "Error.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {

    namespace run_build_digests {

        inline constexpr std::string_view kGolden = "run_build_digests";

        struct Rendered {
            std::string text;
            // The old summary: built twice and identical `identical`/`total`.
            std::size_t total = 0;
            std::size_t identical = 0;
            // The failed require() messages, in order; the text is the same either way.
            std::vector<std::string> problems;
        };

        // One row: the "<layout>.<build> " line of image_type built as build_type, twice under
        // the pinned build time; a build error or a difference is appended to problems (the line
        // then says error= or nondeterministic). A pair outside the file's 4x4 table renders
        // nothing and is a problem.
        [[nodiscard]] std::string render_row(ImageType image_type, BuildType build_type,
                                             std::vector<std::string>& problems);
        // render_row over SmallBlock, NewSmallBlock, BigBlock, Emmc x Retail, Glitch2, Devkit,
        // Devgl, layout-major (the file's order).
        [[nodiscard]] Rendered render();
        // render(), registered with GX_GOLDEN; an error while the render reports a problem.
        [[nodiscard]] Result<std::string> render_file();

    } // namespace run_build_digests

    namespace extract_projections_synthetic {

        inline constexpr std::string_view kGolden = "extract_projections_synthetic";

        struct Rendered {
            std::string text;
            // The old summary: inputs stable `stable`/`cases`, overloads and shims agreed
            // `agreements`/`comparisons`.
            std::size_t cases = 0;
            std::size_t stable = 0;
            std::size_t comparisons = 0;
            std::size_t agreements = 0;
            std::vector<std::string> problems;
        };

        [[nodiscard]] Rendered render();
        [[nodiscard]] Result<std::string> render_file();

    } // namespace extract_projections_synthetic

    namespace run_build_failures {

        inline constexpr std::string_view kGolden = "run_build_failures";

        struct Rendered {
            std::string text;
            // The old summary: refused `refused`/`cases`, `uncovered` exits not covered.
            std::size_t cases = 0;
            std::size_t refused = 0;
            std::size_t uncovered = 0;
            std::vector<std::string> problems;
        };

        [[nodiscard]] Rendered render();
        [[nodiscard]] Result<std::string> render_file();

    } // namespace run_build_failures

} // namespace gxbuild3::snapshots
