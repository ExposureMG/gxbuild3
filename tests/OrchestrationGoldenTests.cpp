// In-process run_build digests over the tracked donor dump tests/gxBuild-support-files/mydata/
// image.bin (16 MiB Jasper retail). Runs on a clean clone: it needs no untracked fixture.
//
// extract_all() opens image.bin under its CPU key (public in build_all.sh) and run_build() builds
// that Input again as
//   retail   the extracted Input as it stands;
//   jtag     plus the tracked 17559/bin/patches_jasper.bin, mydata/xell-2f.bin and smcnocheck
//            (the stock donor SMC carries no JTAG mark, as tests/gxBuild-support-files/options.ini
//            says);
//   glitch2  plus the tracked 17559/bin/patches_g2jasper.bin and mydata/xell-gggggg.bin.
// The bootloader chain is the donor's own in every build: the per-console chains the release
// INIs name live in untracked directories. Every nonce comes from the donor (extract_all fills
// all six from image.bin), and the build time is pinned (SOURCE_DATE_EPOCH in UTC), so nothing
// is drawn. Each build runs twice; both outputs must be identical, and the size and SHA-1 of the
// output are compared with tests/golden/orchestration_mydata_builds.txt.
//
// --update rewrites the golden (CTest never passes it). GXBUILD3_ORCHESTRATION_GOLDEN_SUPPORT
// overrides the support directory, for mutation checks against scratch copies only.

#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "ScopedTimeZone.hpp"
#include "excrypt.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;

namespace {

    using Bytes = std::vector<uint8_t>;

    // The CPU key of the tracked mydata/image.bin, public in build_all.sh (-p ...).
    constexpr std::array<uint8_t, 16> kCpuKey = {0x93, 0xFB, 0x9D, 0x01, 0x19, 0x30, 0xAF, 0xC4,
                                                 0x53, 0xAA, 0x75, 0xB1, 0x83, 0xEF, 0xAC, 0x09};
    constexpr const char* kSourceDateEpoch = "1791105724";

    int g_checks = 0;
    int g_failures = 0;

    bool check(bool ok, std::string_view message) {
        ++g_checks;
        if (!ok) {
            ++g_failures;
            std::cerr << "FAIL: " << message << '\n';
        }
        return ok;
    }

    std::filesystem::path support_directory() {
        if (const char* overridden = std::getenv("GXBUILD3_ORCHESTRATION_GOLDEN_SUPPORT")) {
            return overridden;
        }
#ifdef GXBUILD3_SUPPORT_DIR
        return GXBUILD3_SUPPORT_DIR;
#else
        return {};
#endif
    }

    std::optional<Bytes> read_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }
        return Bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    std::string sha1_hex(std::span<const uint8_t> bytes) {
        std::array<uint8_t, 20> digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const uint8_t byte : digest) {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0F]);
        }
        return out;
    }

    void set_source_date_epoch(const char* value) {
#ifdef _WIN32
        _putenv_s("SOURCE_DATE_EPOCH", value ? value : "");
#else
        if (value) {
            setenv("SOURCE_DATE_EPOCH", value, 1);
        } else {
            unsetenv("SOURCE_DATE_EPOCH");
        }
#endif
    }

    BuildResult build_pinned(const Input& input) {
        const ScopedTimeZone utc{"UTC0"};
        set_source_date_epoch(kSourceDateEpoch);
        auto result = run_build(input);
        set_source_date_epoch(nullptr);
        return result;
    }

    bool all_nonces_filled(const Input& input) {
        const auto& nonces = input.metadata.donor_nonces;
        if (!nonces || !nonces->cf || !nonces->cg) {
            return false;
        }
        for (const auto& stage : nonces->stages) {
            if (!stage) {
                return false;
            }
        }
        return true;
    }

    struct Variant {
        std::string_view name;
        BuildType build_type;
        const char* patchset;
        const char* xell;
        bool smcnocheck;
    };

} // namespace

int main(int argc, char** argv) {
    const auto options = test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }
    const auto support = support_directory();
    const auto image = read_file(support / "mydata" / "image.bin");
    if (!check(image.has_value(), "mydata/image.bin reads")) {
        return 1;
    }
    const auto extracted = extract_all(*image, kCpuKey);
    if (!extracted) {
        check(false, "extract_all(mydata/image.bin): " + extracted.error().describe());
        return 1;
    }
    check(all_nonces_filled(*extracted),
          "extract_all fills all six donor nonces, so run_build draws none");

    constexpr std::array variants{
        Variant{"retail", BuildType::Retail, nullptr, nullptr, false},
        Variant{"jtag", BuildType::Jtag, "patches_jasper.bin", "xell-2f.bin", true},
        Variant{"glitch2", BuildType::Glitch2, "patches_g2jasper.bin", "xell-gggggg.bin", false},
    };

    std::string rendered;
    size_t identical = 0;
    for (const auto& variant : variants) {
        const std::string label = "mydata." + std::string{variant.name};
        Input input = *extracted;
        input.build_type = variant.build_type;
        if (variant.patchset) {
            const auto patchset = read_file(support / "17559" / "bin" / variant.patchset);
            const auto xell = read_file(support / "mydata" / variant.xell);
            if (!check(patchset && xell, label + ": tracked patch file and XeLL read")) {
                rendered += label + " missing-input\n";
                continue;
            }
            InputPatches patches{};
            patches.automatic = InputPatchFile{variant.patchset, *patchset};
            input.patches = std::move(patches);
            if (!input.payloads) {
                input.payloads = InputPayloads{};
            }
            input.payloads->xell = *xell;
        }
        if (variant.smcnocheck) {
            input.options.smcnocheck = true;
        }
        const auto first = build_pinned(input);
        const auto second = build_pinned(input);
        if (!first || !second) {
            const auto& error = first ? second.error() : first.error();
            rendered += label + " error=" + error.message + '\n';
            check(false, label + " builds: " + error.message);
            continue;
        }
        if (!check(*first == *second, label + " builds byte-identically twice")) {
            rendered += label + " nondeterministic\n";
            continue;
        }
        ++identical;
        char size[32];
        std::snprintf(size, sizeof(size), "0x%zx", first->size());
        rendered += label + " size=" + size + " sha1=" + sha1_hex(*first) + '\n';
    }

    const bool matched =
        check(test::check_golden(*options, "orchestration_mydata_builds", rendered),
              "mydata rebuild digests match the golden");
    std::cout << "orchestration digests: built twice and identical " << identical << '/'
              << variants.size() << ", compared " << (matched ? identical : 0) << '/'
              << variants.size() << " with tests/golden/orchestration_mydata_builds.txt\n";
    std::cout << g_checks << " checks, " << g_failures << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
