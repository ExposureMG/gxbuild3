#pragma once

// Renderers of the two text goldens over the tracked donor dump tests/gxBuild-support-files/
// mydata/image.bin (16 MiB Jasper retail), moved from tests/OrchestrationGoldenTests.cpp:
//
//   orchestration_mydata_builds  (MydataRender.cpp) run_build of the Input extract_all() opens
//                                from image.bin under its CPU key (public in build_all.sh), as
//                                  retail   the extracted Input as it stands;
//                                  jtag     plus the tracked 17559/bin/patches_jasper.bin,
//                                           mydata/xell-2f.bin and smcnocheck (the stock donor
//                                           SMC carries no JTAG mark, as tests/gxBuild-support-
//                                           files/options.ini says);
//                                  glitch2  plus the tracked 17559/bin/patches_g2jasper.bin and
//                                           mydata/xell-gggggg.bin;
//                                each built twice (both outputs identical), as its size and SHA-1;
//   extract_projections_mydata   (MydataRender.cpp) every public extract_* projection
//                                (support/render/ExtractProjection.hpp) of image.bin under its
//                                CPU key and under the all-zero key, and of the glitch2 rebuild,
//                                each projected twice with identical text.
//
// The bootloader chain is the donor's own in every build: the per-console chains the release
// INIs name live in untracked directories. Every nonce comes from the donor (extract_all fills
// all six from image.bin), and each build runs under test::PinnedBuildTime{"1791105724", "UTC0"},
// as the old build_pinned did, so nothing is drawn. Both goldens render on a clean clone.
//
// image.bin and its extract_all() are read once per process (donor()), and each variant is built
// once per process when first asked for (variant_build()), so a test that needs only the glitch2
// rebuild builds only that one and no test depends on another having run. A missing or
// unreadable image.bin is an error, never a skip.
//
// The renderers and their emitted strings are the old ones, verbatim (' missing-input',
// ' error=', ' nondeterministic' included). Their check() calls no longer print "FAIL: ..." on
// stderr: the messages are returned as problems, which the golden tests report one failure each,
// and render_file (registered with GX_GOLDEN) refuses while a problem is reported, so --update
// cannot write such a render. Console identity strings appear only as SHA-1.
//
// GXBUILD3_ORCHESTRATION_GOLDEN_SUPPORT (kSupportOverride) overrides the support directory, for
// mutation checks against scratch copies only.

#include "Args.hpp"
#include "Error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {

    namespace mydata {

        inline constexpr const char* kSupportOverride = "GXBUILD3_ORCHESTRATION_GOLDEN_SUPPORT";

        struct Donor {
            std::vector<uint8_t> image;
            // extract_all(image, CPU key of image.bin).
            Input extracted;
        };

        // <support>/mydata/image.bin and its extract_all(), read once per process. An error when
        // image.bin does not read ("mydata/image.bin reads: ...") or extract_all refuses it
        // ("extract_all(mydata/image.bin): ...").
        [[nodiscard]] const Result<Donor>& donor();

        // extract_all filled every donor nonce (the CF, the CG and each stage), so run_build
        // draws none.
        [[nodiscard]] bool all_nonces_filled(const Input& input);

        // The variants, in golden order: retail, jtag, glitch2.
        inline constexpr std::size_t kVariants = 3;
        inline constexpr std::size_t kGlitch2 = 2;

        struct VariantBuild {
            // This variant's golden line.
            std::string line;
            // Built twice with byte-identical outputs.
            bool identical = false;
            // The output, when it built identically twice.
            std::optional<std::vector<uint8_t>> output;
            // The failed check() messages, in order.
            std::vector<std::string> problems;
        };

        // Variant `index` (below kVariants) of donor(), built once per process when first asked
        // for. With no donor it holds one problem and no line.
        [[nodiscard]] const VariantBuild& variant_build(std::size_t index);

    } // namespace mydata

    namespace orchestration_mydata_builds {

        inline constexpr std::string_view kGolden = "orchestration_mydata_builds";

        struct Rendered {
            std::string text;
            // The old summary: built twice and identical `identical`/`total`.
            std::size_t total = 0;
            std::size_t identical = 0;
            std::vector<std::string> problems;
        };

        [[nodiscard]] Rendered render();
        // render(), registered with GX_GOLDEN; an error while the render reports a problem.
        [[nodiscard]] Result<std::string> render_file();

    } // namespace orchestration_mydata_builds

    namespace extract_projections_mydata {

        inline constexpr std::string_view kGolden = "extract_projections_mydata";

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

    } // namespace extract_projections_mydata

} // namespace gxbuild3::snapshots
