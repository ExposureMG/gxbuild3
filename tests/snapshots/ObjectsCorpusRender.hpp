#pragma once

// Renderer of tests/golden/objects_corpus.txt, the NAND-object codec snapshot over the tracked
// fixtures in tests/gxBuild-support-files (17559/bin/*.bin, the mydata XeLLs and secured files,
// mydata/image.bin and 17559/su20076000_00000000). It needs no untracked fixture.
// ObjectsCorpusRender.cpp describes the lines; ObjectsCorpusGoldenTests.cpp compares them.
//
// GXBUILD3_OBJECTS_CORPUS_SUPPORT (kSupportOverride) overrides the support directory, for
// mutation checks against scratch copies only.

#include "Error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots::objects_corpus {

    inline constexpr std::string_view kGolden = "objects_corpus";
    inline constexpr const char* kSupportOverride = "GXBUILD3_OBJECTS_CORPUS_SUPPORT";
    inline constexpr std::size_t kExpectedPatchFiles = 25;
    inline constexpr std::size_t kExpectedAddons = 14;
    // Build types every patches_*.bin is parsed for (jtag .. devgl).
    inline constexpr std::size_t kPatchTypeCount = 6;

    struct Fixture {
        std::string name;
        std::vector<std::uint8_t> bytes;
    };

    struct Corpus {
        std::vector<Fixture> patches;
        std::vector<Fixture> addons;
        std::vector<Fixture> xells;
        std::vector<Fixture> secured; // crl, dae, extended, secdata, fcrt (by name)
        std::vector<std::uint8_t> image;
        std::vector<std::uint8_t> update_package;
    };

    struct Counters {
        std::size_t patch_parses = 0;
        std::size_t patch_parses_ok = 0;
        std::size_t xells_ok = 0;
        std::size_t secured_files = 0;
        std::size_t smc_cases = 0;
        bool xboxupd_split = false;
        bool image_smc = false;
    };

    struct Rendered {
        std::string text;
        Counters counters;
        // What the render found wrong on its own (the XConfig region round trip); the old
        // check() messages, empty when all is well. The text is the same either way.
        std::vector<std::string> problems;
    };

    // The tracked fixtures under support_dir: patches_*.bin and the other *.bin add-ons of
    // 17559/bin sorted by name, the three mydata XeLLs, the five mydata secured files,
    // mydata/image.bin and 17559/su20076000_00000000. Any unlistable directory or unreadable
    // fixture is an error.
    [[nodiscard]] Result<Corpus> load_corpus(const std::filesystem::path& support_dir);

    // load_corpus over test::support_dir(kSupportOverride), loaded once per process on first
    // use (a lazy function-local cache, so main() does no work).
    [[nodiscard]] const Result<Corpus>& tracked_corpus();

    // The golden text, the counters and the problems.
    [[nodiscard]] Rendered render(const Corpus& corpus);

    // render(tracked_corpus()), rendered once per process on first use and shared by the cases.
    [[nodiscard]] const Result<Rendered>& tracked_render();

    // A fresh render of the whole golden file over tracked_corpus(), registered with GX_GOLDEN
    // for --update (which renders twice and compares, so it never reuses tracked_render()).
    [[nodiscard]] Result<std::string> render_file();

} // namespace gxbuild3::snapshots::objects_corpus
