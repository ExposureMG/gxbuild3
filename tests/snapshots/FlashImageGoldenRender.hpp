#pragma once

// Renderers of the three FlashImage text goldens, moved from tests/FlashImageGoldenTests.cpp:
//
//   flashimage_golden    (FlashImageDonorRender.cpp) the tracked donor mydata/image.bin (16 MiB
//                        Jasper retail): parse, layout queries, write() after parse, the
//                        snapshot after decrypt_all, the round trip through encrypt_all and
//                        extract_all_info()'s summary cross-checked with xeBuild's image.info;
//   flashimage_matrix    (FlashImageMatrixRender.cpp) synthetic fresh layouts, Small/Big/Emmc x
//                        the eight build types, hashed after write() and after the seal, plus the
//                        header encoded for a zeroed nand_header;
//   flashimage_failures  (FlashImageFailureRender.cpp) ErrorCode and describe() of each
//                        reachable FlashImage exit, in today's check order.
//
// Each render opens with test::PinnedBuildTime (SOURCE_DATE_EPOCH=1791105724, TZ=UTC), as the
// old binary's main did before anything else, so the tests and --update render under the same
// time in any process. The renderers' own checks no longer print "FAIL: ..." on stderr: their
// messages are returned as problems, which the golden tests report one failure each, and
// render_file (registered with GX_GOLDEN) refuses while a problem is reported, so --update cannot
// write such a render. Console identity only ever appears as a SHA-1; the CPU key is the one
// already public in build_all.sh.
//
// GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE overrides the donor image and
// GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT the support directory the matrix and the failure table read
// their stages from, for mutation checks against scratch copies only.

#include "Args.hpp"
#include "Error.hpp"
#include "nand/FlashDriver.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {

    namespace flashimage_golden {

        inline constexpr std::string_view kGolden = "flashimage_golden";
        inline constexpr const char* kImageOverride = "GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE";

        struct Inputs {
            std::filesystem::path image_path;
            std::vector<uint8_t> image;
            std::string image_info;
        };

        // The donor (support_dir()/mydata/image.bin, or kImageOverride when set and not empty;
        // a note goes to stderr then) and the tracked mydata/image.info. An unreadable or empty
        // donor and an unreadable image.info are errors.
        [[nodiscard]] Result<Inputs> load_inputs();

        struct Rendered {
            std::string text;
            // The renderer's checks run and the failed ones, in order: the old check() messages
            // (and describe() of a failed Result). The text is the same either way.
            std::size_t checks = 0;
            std::vector<std::string> problems;
        };

        [[nodiscard]] Rendered render(const Inputs& inputs);

        // load_inputs() and render(), registered with GX_GOLDEN; an error when either fails or
        // the render reports a problem.
        [[nodiscard]] Result<std::string> render_file();

    } // namespace flashimage_golden

    namespace flashimage_matrix {

        inline constexpr std::string_view kGolden = "flashimage_matrix";

        struct Rendered {
            std::string text;
            std::size_t cells = 0;
            std::vector<std::string> problems;
        };

        // The shapes and build types the matrix walks, in file order (shape-major).
        inline constexpr std::array<nand::Driver::DriverMode, 3> kModes{
            nand::Driver::Small, nand::Driver::Big, nand::Driver::Emmc};
        inline constexpr std::array<BuildType, 8> kTypes{
            BuildType::Retail,   BuildType::Jtag,    BuildType::Glitch, BuildType::Glitch2,
            BuildType::Glitch2m, BuildType::Glitch3, BuildType::Devgl,  BuildType::Devkit};

        // The pieces of the file, each under PinnedBuildTime: the "# F0c" comment and the
        // header_encode.<Mode>. lines of every shape; one cell's matrix.<Mode>.<Type>. lines over
        // the stages in support (its failed checks appended to problems); the closing
        // "matrix.cells=<cells>" line.
        [[nodiscard]] std::string render_header_encode();
        [[nodiscard]] std::string render_cell(const std::filesystem::path& support,
                                              nand::Driver::DriverMode mode, BuildType type,
                                              std::vector<std::string>& problems);
        [[nodiscard]] std::string render_trailer(std::size_t cells);

        // The matrix over the stages in support: render_header_encode, render_cell over kModes x
        // kTypes, render_trailer.
        [[nodiscard]] Rendered render(const std::filesystem::path& support);
        // render(test::support_dir(GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT)); a note goes to stderr
        // when the override is set.
        [[nodiscard]] Rendered render();
        [[nodiscard]] Result<std::string> render_file();

    } // namespace flashimage_matrix

    namespace flashimage_failures {

        inline constexpr std::string_view kGolden = "flashimage_failures";

        struct Rendered {
            std::string text;
            std::vector<std::string> problems;
        };

        [[nodiscard]] Rendered render(const std::filesystem::path& support);
        [[nodiscard]] Rendered render();
        [[nodiscard]] Result<std::string> render_file();

    } // namespace flashimage_failures

    // test::support_dir(GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT), with a note on stderr when the
    // override is in effect (the old main printed it once).
    [[nodiscard]] std::filesystem::path flashimage_cells_support();

} // namespace gxbuild3::snapshots
