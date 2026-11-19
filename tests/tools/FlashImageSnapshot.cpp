// gxbuild3_flashimage_snapshot: the byte oracle's snapshot tool (tests/scripts/
// FlashImageTests.cmake, against tests/golden/build_all.parse.txt).
//
//   gxbuild3_flashimage_snapshot --snapshot <image> [--expect <file>]
//
// Prints the parse., layout., write., decrypt., roundtrip. and info. lines of one image
// build_all.sh wrote (render_snapshot in support/render/FlashImageRender.hpp) on stdout. With
// --expect it also compares the snapshot with <file> (one section of build_all.parse.txt) and
// reports the first differing lines on stderr. Exit 0 on success, 1 on a mismatch or an
// unreadable file, 2 on a usage error. The build time is pinned to SOURCE_DATE_EPOCH=1791105724
// and TZ=UTC as for build_all.sh. This was FlashImageGoldenTests --snapshot; its output is
// byte-identical.

#include "support/golden/GoldenSnapshot.hpp"
#include "support/render/FlashImageRender.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace gxbuild3::test::render {
    namespace {

        constexpr const char* kSourceDateEpoch = "1791105724";

        // --snapshot <image> [--expect <file>]: prints the snapshot of <image> on stdout. With
        // --expect it also compares the snapshot with <file> (one section of
        // build_all.parse.txt) and reports the first differing lines on stderr. Exit 0 on
        // success, 1 on a mismatch or an unreadable file, 2 on a usage error.
        int run_snapshot_mode(int argc, char** argv) {
            std::optional<std::filesystem::path> image;
            std::optional<std::filesystem::path> expect;
            for (int i = 1; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if ((arg == "--snapshot" || arg == "--expect") && i + 1 < argc) {
                    (arg == "--snapshot" ? image : expect) = argv[++i];
                } else {
                    std::cerr << "usage: " << argv[0] << " --snapshot <image> [--expect <file>]\n";
                    return 2;
                }
            }
            if (!image) {
                std::cerr << "usage: " << argv[0] << " --snapshot <image> [--expect <file>]\n";
                return 2;
            }
            const auto bytes = read_file(*image);
            if (!bytes || bytes->empty()) {
                std::cerr << "FAIL: cannot read " << image->string() << '\n';
                return 1;
            }
            const std::string rendered = render_snapshot(*bytes);
            std::cout << rendered << std::flush;
            if (!expect) {
                return 0;
            }
            const auto expected = read_file(*expect);
            if (!expected) {
                std::cerr << "FAIL: cannot read the expected snapshot " << expect->string() << '\n';
                return 1;
            }
            const std::string want(expected->begin(), expected->end());
            if (const auto difference = test::golden_difference(want, rendered)) {
                std::cerr << "snapshot of " << image->filename().string() << " differs from "
                          << expect->string() << '\n'
                          << *difference;
                return 1;
            }
            return 0;
        }

        void pin_build_time() {
#ifdef _WIN32
            _putenv_s("SOURCE_DATE_EPOCH", kSourceDateEpoch);
            _putenv_s("TZ", "UTC");
#else
            setenv("SOURCE_DATE_EPOCH", kSourceDateEpoch, 1);
            setenv("TZ", "UTC", 1);
#endif
        }

    } // namespace
} // namespace gxbuild3::test::render

int main(int argc, char** argv) {
    gxbuild3::test::render::pin_build_time();
    return gxbuild3::test::render::run_snapshot_mode(argc, argv);
}
