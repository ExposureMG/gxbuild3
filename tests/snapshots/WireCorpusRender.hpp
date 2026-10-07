#pragma once

// Renderer of tests/golden/wire_corpus_bootloaders.txt, the wire-corpus snapshot over the
// tracked bootloader stage fixtures in tests/gxBuild-support-files/common (every *.bin there;
// 145 on a clean clone). It needs no untracked fixture. WireCorpusRender.cpp describes the
// lines; WireCorpusGoldenTests.cpp compares them.
//
// GXBUILD3_WIRE_CORPUS_SUPPORT (kSupportOverride) overrides the support directory, for
// mutation checks against scratch copies only.

#include "Error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots::wire_corpus {

    inline constexpr std::string_view kGolden = "wire_corpus_bootloaders";
    inline constexpr const char* kSupportOverride = "GXBUILD3_WIRE_CORPUS_SUPPORT";
    inline constexpr std::size_t kExpectedFixtures = 145;

    struct Fixture {
        std::string name;
        std::vector<std::uint8_t> bytes;
    };

    struct Rendered {
        std::string text;
        std::size_t fixtures = 0;
        std::size_t parsed = 0;
    };

    // Every regular *.bin file in <support_dir>/common, sorted by file name. An unlistable
    // directory or an unreadable fixture is an error.
    [[nodiscard]] Result<std::vector<Fixture>>
    load_fixtures(const std::filesystem::path& support_dir);

    // load_fixtures over test::support_dir(kSupportOverride), loaded once per process on first
    // use (a lazy function-local cache, so main() does no work).
    [[nodiscard]] const Result<std::vector<Fixture>>& tracked_fixtures();

    // The golden text with the fixture and parse tallies.
    [[nodiscard]] Rendered render(const std::vector<Fixture>& fixtures);

    // The whole golden file over tracked_fixtures(), registered with GX_GOLDEN for --update.
    [[nodiscard]] Result<std::string> render_file();

} // namespace gxbuild3::snapshots::wire_corpus
