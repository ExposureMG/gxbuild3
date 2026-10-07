// Self-test for the shared test helpers tests/GoldenSnapshot.hpp and tests/TestResult.hpp.
//
// Default run (what CTest does): checks the diff renderer, compares a rendered text with the
// tracked golden tests/golden/golden_snapshot_selftest.txt, and runs a mutation check on a
// scratch copy of that golden (one perturbed line must fail and name the line).
//
// --update rewrites the tracked golden. --must-abort-demo [void] makes must() fail on purpose;
// tests/scripts/MustAbortTest.cmake drives it and expects an abort with Error::describe()
// on stderr.

#include "Error.hpp"
#include "GoldenSnapshot.hpp"
#include "TestResult.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

    using gxbuild3::Error;
    using gxbuild3::ErrorCode;
    using gxbuild3::Result;
    namespace test = gxbuild3::test;

    constexpr std::string_view kGoldenName = "golden_snapshot_selftest";

    int g_checks = 0;
    int g_failures = 0;

    void check(bool condition, std::string_view message) {
        ++g_checks;
        if (!condition) {
            ++g_failures;
            std::cerr << "FAIL: " << message << '\n';
        }
    }

    bool contains(std::string_view text, std::string_view needle) {
        return text.find(needle) != std::string_view::npos;
    }

    Result<int> planted(bool ok) {
        if (!ok) {
            return gxbuild3::with_context(
                Result<int>{gxbuild3::fail(ErrorCode::Malformed, "planted failure")}, "inner");
        }
        return 42;
    }

    Result<std::unique_ptr<int>> planted_move_only() {
        return std::make_unique<int>(7);
    }

    Result<void> planted_void(bool ok) {
        if (!ok) {
            return gxbuild3::fail(ErrorCode::Truncated, "planted void failure");
        }
        return {};
    }

    // The text pinned by the tracked golden. It goes through must() so the helper's success
    // path is part of the snapshot.
    std::string render_selftest_text() {
        std::ostringstream out;
        out << "# GoldenSnapshot self-test golden.\n";
        out << "# Regenerate: gxbuild3_golden_snapshot_tests --update\n";
        out << "must.value: " << test::must(planted(true)) << '\n';
        out << "must.move_only: " << *test::must(planted_move_only()) << '\n';
        test::must(planted_void(true));
        out << "must.void: ok\n";
        out << "error.describe: "
            << gxbuild3::with_context(planted(false), "outer").error().describe() << '\n';
        out << '\n';
        for (int code = 0; code <= static_cast<int>(ErrorCode::Internal); ++code) {
            out << "error_code[" << code
                << "]: " << gxbuild3::to_string(static_cast<ErrorCode>(code)) << '\n';
        }
        return out.str();
    }

    void test_difference_renderer() {
        check(!test::golden_difference("a\nb\n", "a\nb\n"), "identical texts have no difference");

        const auto diff = test::golden_difference("a\nb\nc\nd\n", "a\nb\nC\nd\n");
        check(diff.has_value(), "a changed line is a difference");
        if (diff) {
            check(contains(*diff, "first difference at line 3"), "names the first differing line");
            check(contains(*diff, "  - c\n") && contains(*diff, "  + C\n"),
                  "prints the golden and the actual line");
            check(!contains(*diff, "- a") && !contains(*diff, "- d"),
                  "does not print matching lines");
        }

        std::string many_want;
        std::string many_have;
        for (int i = 0; i < 9; ++i) {
            many_want += "w" + std::to_string(i) + '\n';
            many_have += "h" + std::to_string(i) + '\n';
        }
        const auto truncated = test::golden_difference(many_want, many_have, 3);
        check(truncated && contains(*truncated, "- w2") && !contains(*truncated, "- w3") &&
                  contains(*truncated, "... 6 more differing line(s)"),
              "caps the report at max_lines and counts the rest");

        const auto longer = test::golden_difference("a\n", "a\nextra\n");
        check(longer && contains(*longer, "line 2") && contains(*longer, "- <no line in golden>") &&
                  contains(*longer, "+ extra"),
              "an extra actual line is reported");

        const auto shorter = test::golden_difference("a\ngone\n", "a\n");
        check(shorter && contains(*shorter, "- gone") &&
                  contains(*shorter, "+ <no line in actual>"),
              "a missing actual line is reported");

        const auto newline = test::golden_difference("a\n", "a");
        check(newline && contains(*newline, "differ only in the trailing newline"),
              "a trailing-newline-only difference is explained");
    }

    void test_options() {
        const std::filesystem::path dir{"golden-dir"};
        char prog[] = "selftest";
        char update[] = "--update";
        char typo[] = "--updat";

        char* plain_argv[] = {prog, nullptr};
        const auto plain = test::golden_options(1, plain_argv, dir);
        check(plain && !plain->update && plain->directory == dir, "no argument means compare-only");

        char* update_argv[] = {prog, update, nullptr};
        const auto updating = test::golden_options(2, update_argv, dir);
        check(updating && updating->update, "--update turns on rewriting");

        char* typo_argv[] = {prog, typo, nullptr};
        std::ostringstream usage;
        check(!test::golden_options(2, typo_argv, dir, usage) &&
                  contains(usage.str(), "unknown argument: --updat"),
              "an unknown argument is rejected with a usage message");

        check(!test::default_golden_directory().empty(), "CMake injects GXBUILD3_GOLDEN_DIR");
    }

    std::string read_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    void write_file(const std::filesystem::path& path, std::string_view text) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }

    // Mutation check on a scratch copy: never touches the tracked golden.
    void test_mutation_on_scratch_copy(const std::string& rendered) {
        const std::filesystem::path scratch{GXBUILD3_TEST_SCRATCH_DIR};
        std::error_code error;
        std::filesystem::remove_all(scratch, error);
        std::filesystem::create_directories(scratch, error);
        check(!error, "scratch directory is created");
        const test::GoldenOptions compare{scratch, false};
        const auto golden = scratch / (std::string{kGoldenName} + ".txt");

        std::ostringstream missing_report;
        check(!test::check_golden(compare, kGoldenName, rendered, missing_report),
              "a missing golden fails");
        check(contains(missing_report.str(), "missing golden"), "a missing golden is named");
        check(!std::filesystem::exists(golden), "a compare-only run never creates a golden");

        std::filesystem::copy_file(
            test::default_golden_directory() / (std::string{kGoldenName} + ".txt"), golden,
            std::filesystem::copy_options::overwrite_existing, error);
        check(!error, "the tracked golden is copied to scratch");
        std::ostringstream clean_report;
        check(test::check_golden(compare, kGoldenName, rendered, clean_report),
              "the scratch copy matches before mutation");

        // Perturb one line: "must.value: 42" -> "must.value: 43".
        std::string perturbed = read_file(golden);
        const auto at = perturbed.find("must.value: 42");
        check(at != std::string::npos, "the scratch golden has the line to perturb");
        if (at != std::string::npos) {
            perturbed[at + std::string_view{"must.value: 4"}.size()] = '3';
        }
        write_file(golden, perturbed);

        std::ostringstream report;
        check(!test::check_golden(compare, kGoldenName, rendered, report),
              "a perturbed golden line fails the comparison");
        const auto text = report.str();
        check(contains(text, "GOLDEN FAIL: golden_snapshot_selftest differs"),
              "the failure names the golden");
        check(contains(text, "first difference at line 3"),
              "the failure names the first differing line");
        check(contains(text, "  - must.value: 43\n") && contains(text, "  + must.value: 42\n"),
              "the failure prints the golden and the actual line");
        check(read_file(golden) == perturbed, "a failed compare-only run never rewrites");
        std::cout << "mutation report (expected failure):\n" << text;

        std::ostringstream update_report;
        check(test::check_golden({scratch, true}, kGoldenName, rendered, update_report),
              "--update accepts the new output");
        check(read_file(golden) == rendered, "--update writes the actual text");
        check(test::check_golden(compare, kGoldenName, rendered, update_report),
              "the rewritten golden matches");

        std::string crlf;
        for (const char c : rendered) {
            if (c == '\n') {
                crlf += '\r';
            }
            crlf += c;
        }
        write_file(golden, crlf);
        check(test::check_golden(compare, kGoldenName, rendered, update_report),
              "a CRLF checkout of the golden still matches");

        std::ostringstream name_report;
        check(!test::check_golden(compare, "../escape", rendered, name_report) &&
                  contains(name_report.str(), "invalid golden name"),
              "a golden name cannot leave the golden directory");

        std::filesystem::remove_all(scratch, error);
    }

    [[noreturn]] void must_abort_demo(bool void_overload) {
        if (void_overload) {
            test::must(planted_void(false));
        } else {
            [[maybe_unused]] const int value =
                test::must(gxbuild3::with_context(planted(false), "outer"));
        }
        std::cerr << "must() returned on a failed Result\n";
        std::exit(0);
    }

} // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::string_view{argv[1]} == "--must-abort-demo") {
        must_abort_demo(argc >= 3 && std::string_view{argv[2]} == "void");
    }
    const auto options = test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }

    const std::string rendered = render_selftest_text();
    check(rendered == render_selftest_text(), "the rendered text is deterministic");

    test_difference_renderer();
    test_options();
    check(test::check_golden(*options, kGoldenName, rendered),
          "rendered text matches tests/golden/golden_snapshot_selftest.txt");
    test_mutation_on_scratch_copy(rendered);

    std::cout << "golden snapshot self-test: " << (g_checks - g_failures) << '/' << g_checks
              << " checks passed\n";
    return g_failures == 0 ? 0 : 1;
}
