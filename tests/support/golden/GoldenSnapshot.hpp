#pragma once

// Text golden snapshots for tests.
//
// check_golden(options, "name", text) compares text with tests/golden/<name>.txt byte for byte
// (CRLF in the golden file is read as LF so a Windows checkout still matches). On a mismatch it
// prints the golden path and the first differing lines and returns false. With options.update
// set it rewrites the golden instead; golden_main (Golden.hpp) compares with update off and
// writes goldens only on its explicit --update <name> path, so CTest can only compare.

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace gxbuild3::test {

    struct GoldenOptions {
        std::filesystem::path directory;
        bool update = false;
    };

    // The tracked golden directory, injected by CMake as GXBUILD3_GOLDEN_DIR.
    [[nodiscard]] inline std::filesystem::path default_golden_directory() {
#ifdef GXBUILD3_GOLDEN_DIR
        return std::filesystem::path{GXBUILD3_GOLDEN_DIR};
#else
        return {};
#endif
    }

    namespace detail {
        [[nodiscard]] inline std::vector<std::string_view> split_lines(std::string_view text) {
            std::vector<std::string_view> lines;
            while (!text.empty()) {
                const auto end = text.find('\n');
                if (end == std::string_view::npos) {
                    lines.push_back(text);
                    break;
                }
                lines.push_back(text.substr(0, end));
                text.remove_prefix(end + 1);
            }
            return lines;
        }

        [[nodiscard]] inline bool valid_golden_name(std::string_view name) {
            return !name.empty() && name.front() != '.' && std::ranges::all_of(name, [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                       c == '_' || c == '-' || c == '.';
            });
        }

        [[nodiscard]] inline std::optional<std::string>
        read_golden(const std::filesystem::path& path) {
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                return std::nullopt;
            }
            const std::string raw{std::istreambuf_iterator<char>(in),
                                  std::istreambuf_iterator<char>()};
            std::string text;
            text.reserve(raw.size());
            for (std::size_t i = 0; i < raw.size(); ++i) {
                if (raw[i] == '\r' && i + 1 < raw.size() && raw[i + 1] == '\n') {
                    continue;
                }
                text.push_back(raw[i]);
            }
            return text;
        }

        [[nodiscard]] inline bool write_golden(const std::filesystem::path& path,
                                               std::string_view text) {
            std::error_code error;
            std::filesystem::create_directories(path.parent_path(), error);
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            return static_cast<bool>(out);
        }
    } // namespace detail

    // Describes how actual differs from expected, starting at the first differing line and
    // listing at most max_lines differing line pairs. nullopt when the texts are identical.
    [[nodiscard]] inline std::optional<std::string> golden_difference(std::string_view expected,
                                                                      std::string_view actual,
                                                                      std::size_t max_lines = 5) {
        if (expected == actual) {
            return std::nullopt;
        }
        const auto want = detail::split_lines(expected);
        const auto have = detail::split_lines(actual);
        const std::size_t rows = std::max(want.size(), have.size());
        std::ostringstream out;
        std::size_t shown = 0;
        std::size_t differing = 0;
        for (std::size_t i = 0; i < rows; ++i) {
            const bool in_want = i < want.size();
            const bool in_have = i < have.size();
            if (in_want && in_have && want[i] == have[i]) {
                continue;
            }
            ++differing;
            if (shown == max_lines) {
                continue;
            }
            if (shown == 0) {
                out << "  first difference at line " << (i + 1) << '\n';
            }
            out << "  @@ line " << (i + 1) << '\n';
            out << "  - " << (in_want ? want[i] : std::string_view{"<no line in golden>"}) << '\n';
            out << "  + " << (in_have ? have[i] : std::string_view{"<no line in actual>"}) << '\n';
            ++shown;
        }
        if (differing > shown) {
            out << "  ... " << (differing - shown) << " more differing line(s)\n";
        }
        if (differing == 0) {
            out << "  lines are identical; the texts differ only in the trailing newline\n";
        }
        out << "  golden has " << want.size() << " line(s), actual has " << have.size()
            << " line(s)\n";
        return out.str();
    }

    // Compares actual with <directory>/<name>.txt. Returns true when they match, or when
    // options.update is set and the golden was (re)written. Reports go to out.
    [[nodiscard]] inline bool check_golden(const GoldenOptions& options, std::string_view name,
                                           std::string_view actual, std::ostream& out = std::cerr) {
        if (!detail::valid_golden_name(name)) {
            out << "GOLDEN FAIL: invalid golden name '" << name
                << "' (use [A-Za-z0-9_.-], not starting with '.')\n";
            return false;
        }
        const auto path = options.directory / (std::string{name} + ".txt");
        const auto expected = detail::read_golden(path);
        if (expected && *expected == actual) {
            return true;
        }
        if (options.update) {
            if (!detail::write_golden(path, actual)) {
                out << "GOLDEN FAIL: " << name << ": cannot write " << path.string() << '\n';
                return false;
            }
            out << "GOLDEN UPDATED: " << name << " -> " << path.string() << '\n';
            return true;
        }
        if (!expected) {
            out << "GOLDEN FAIL: " << name << ": missing golden " << path.string()
                << "\n  run this test binary with --update to create it\n";
            return false;
        }
        out << "GOLDEN FAIL: " << name << " differs from " << path.string() << '\n'
            << *golden_difference(*expected, actual)
            << "  run this test binary with --update to accept the new output\n";
        return false;
    }

} // namespace gxbuild3::test
