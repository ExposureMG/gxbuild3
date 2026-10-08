#pragma once

// Text goldens of the golden binary, gxbuild3_golden_tests (tests/snapshots/).
//
// Each golden tests/golden/<name>.txt is owned by one whole-file renderer registered with
// GX_GOLDEN(name, render). Tests only compare:
//
//   EXPECT_TRUE(test::matches_golden("name", text));                  the whole file
//   EXPECT_TRUE(test::matches_golden_slice("name", section, text));   the lines one Section owns
//   EXPECT_TRUE(test::golden_is_partitioned("name", sections));       every line owned once
//
// The comparison is the unchanged GoldenSnapshot.hpp core: CRLF in the golden reads as LF, the
// name must stay inside the golden directory and a difference is reported by golden_difference.
// The golden directory is GXBUILD3_GOLDEN_DIR from the environment when set and not empty (a
// scratch copy for mutation checks), else the tracked tests/golden injected by CMake.
//
// golden_main is the binary's main. After InitGoogleTest has taken the --gtest_* flags it runs
// the tests (no argument), prints the registered names (--list-goldens) or re-renders the named
// goldens (--update <name>...): each renderer runs twice and a golden is written only when both
// renders agree and every named golden rendered. --update runs no test and is refused (exit 2)
// without a name, with an unknown name, and together with a test filter, repetition, sharding
// or --gtest_list_tests, given as a flag or through the environment. No environment variable
// can turn updating on.

#include "Error.hpp"

#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::test {

    // Renders one golden's whole file.
    using GoldenRender = std::function<Result<std::string>()>;

    struct GoldenEntry {
        std::string name;
        GoldenRender render;
    };

    // Adds a golden to this binary's registry (during static initialization, through
    // GX_GOLDEN). Always returns true so it can initialize a namespace-scope constant.
    bool register_golden(std::string_view name, GoldenRender render);

    // The registered goldens, sorted by name.
    [[nodiscard]] std::vector<GoldenEntry> registered_goldens();

    // The entry called name, or nullptr.
    [[nodiscard]] const GoldenEntry* find_golden(std::span<const GoldenEntry> registry,
                                                 std::string_view name);

#define GX_GOLDEN(name, render)                                                                    \
    [[maybe_unused]] const bool gx_golden_##render = ::gxbuild3::test::register_golden(name, render)

    // Reads one environment variable: the value, or nullopt when it is unset.
    using EnvLookup = std::function<std::optional<std::string>(const char*)>;

    // The process environment (Env.hpp's env_value).
    [[nodiscard]] EnvLookup process_environment();

    // GXBUILD3_GOLDEN_DIR from env when it is set and not empty, else the tracked directory
    // CMake injects (GoldenSnapshot.hpp's default_golden_directory()).
    [[nodiscard]] std::filesystem::path golden_directory(const EnvLookup& env);
    [[nodiscard]] std::filesystem::path golden_directory();

    // text equals <directory>/<name>.txt; the failure message is check_golden's report.
    [[nodiscard]] ::testing::AssertionResult matches_golden(std::string_view name,
                                                            std::string_view text);
    [[nodiscard]] ::testing::AssertionResult matches_golden(const std::filesystem::path& directory,
                                                            std::string_view name,
                                                            std::string_view text);

    // A section of a golden: the lines that start with one of its (non-empty) prefixes, in file
    // order. A section may own lines through several prefixes.
    struct Section {
        std::string_view id;
        std::span<const std::string_view> prefixes;
    };

    // text equals the section's lines of <directory>/<name>.txt, each followed by '\n'. A
    // difference names the golden file line of the first differing slice line. A section that
    // owns no line fails.
    [[nodiscard]] ::testing::AssertionResult
    matches_golden_slice(std::string_view name, const Section& section, std::string_view text);
    [[nodiscard]] ::testing::AssertionResult
    matches_golden_slice(const std::filesystem::path& directory, std::string_view name,
                         const Section& section, std::string_view text);

    // Every line of <directory>/<name>.txt is owned by exactly one section, the owners follow
    // the order of sections through the file, and every section owns a line.
    [[nodiscard]] ::testing::AssertionResult
    golden_is_partitioned(std::string_view name, std::span<const Section> sections);
    [[nodiscard]] ::testing::AssertionResult
    golden_is_partitioned(const std::filesystem::path& directory, std::string_view name,
                          std::span<const Section> sections);

    struct GoldenCommand {
        enum class Kind {
            Run,
            List,
            Update
        };
        Kind kind = Kind::Run;
        std::vector<std::string> names; // Update only
    };

    // GoogleTest's flags after InitGoogleTest (GTEST_FILTER and GTEST_REPEAT feed them too).
    struct GtestState {
        std::string filter = "*";
        int repeat = 1;
        bool list_tests = false;
    };

    // Classifies the arguments InitGoogleTest left (argv[1..]). Refusals are InvalidArgument
    // errors whose message golden_main prints under the usage text.
    [[nodiscard]] Result<GoldenCommand> parse_golden_args(std::span<const std::string> args,
                                                          const GtestState& gtest,
                                                          const EnvLookup& env,
                                                          std::span<const GoldenEntry> registry);

    // Renders each named golden twice and, when every render succeeded and each pair agrees,
    // writes the goldens whose text changed into directory (an unchanged golden, CRLF checkout
    // included, is left untouched). Writes nothing when any name fails. Runs no test. Reports
    // each golden on out; false on any failure.
    [[nodiscard]] bool update_goldens(std::span<const std::string> names,
                                      std::span<const GoldenEntry> registry,
                                      const std::filesystem::path& directory, std::ostream& out);

    // The golden binary's main: see the top of this file. Exit codes: the tests' result, 0 after
    // --list-goldens or a successful --update, 1 when an update failed, 2 on a refusal.
    int golden_main(int argc, char** argv);

} // namespace gxbuild3::test
