// golden_main's command line (parse_golden_args: run, --list-goldens, --update <name>... and
// every refusal), the golden directory it uses and the registry it serves. The environment is
// a fake lookup, so no test changes the process environment.

#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"
#include "support/golden/GoldenSnapshot.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots {
    namespace {

        using Kind = test::GoldenCommand::Kind;

        Result<std::string> render_alpha() {
            return std::string{"alpha\n"};
        }

        Result<std::string> render_beta() {
            return std::string{"beta\n"};
        }

        const std::vector<test::GoldenEntry>& fake_registry() {
            static const std::vector<test::GoldenEntry> registry{{"alpha", render_alpha},
                                                                 {"beta", render_beta}};
            return registry;
        }

        test::EnvLookup environment(std::map<std::string, std::string> variables = {}) {
            return [variables = std::move(variables)](const char* name) {
                const auto it = variables.find(name);
                return it == variables.end() ? std::nullopt
                                             : std::optional<std::string>{it->second};
            };
        }

        Result<test::GoldenCommand> parse(std::vector<std::string> args,
                                          const test::GtestState& gtest = {},
                                          const test::EnvLookup& env = environment()) {
            return test::parse_golden_args(args, gtest, env, fake_registry());
        }

        // ---- parse_golden_args ----------------------------------------------------------

        TEST(GoldenArgs, NoArgumentsRunsTests) {
            ASSERT_OK_AND_ASSIGN(const auto command, parse({}));
            EXPECT_EQ(command.kind, Kind::Run);
            EXPECT_TRUE(command.names.empty());
        }

        TEST(GoldenArgs, RunIgnoresTheGtestFilterAndRepeat) {
            ASSERT_OK_AND_ASSIGN(const auto command,
                                 parse({}, {"GoldenArgs.*", 3, false},
                                       environment({{"GTEST_FILTER", "GoldenArgs.*"}})));
            EXPECT_EQ(command.kind, Kind::Run);
        }

        TEST(GoldenArgs, ListGoldensListsTheRegistry) {
            ASSERT_OK_AND_ASSIGN(const auto command, parse({"--list-goldens"}));
            EXPECT_EQ(command.kind, Kind::List);
            EXPECT_TRUE(command.names.empty());
        }

        TEST(GoldenArgs, ListGoldensTakesNoOtherArgument) {
            EXPECT_ERROR_MSG(parse({"--list-goldens", "alpha"}), ErrorCode::InvalidArgument,
                             "--list-goldens takes no other argument: alpha");
        }

        TEST(GoldenArgs, UnknownArgumentIsAUsageError) {
            EXPECT_ERROR_HAS(parse({"--updat"}), ErrorCode::InvalidArgument,
                             "unknown argument: --updat");
        }

        TEST(GoldenArgs, UpdateTakesRegisteredNames) {
            ASSERT_OK_AND_ASSIGN(const auto command, parse({"--update", "beta", "alpha"}));
            EXPECT_EQ(command.kind, Kind::Update);
            EXPECT_EQ(command.names, (std::vector<std::string>{"beta", "alpha"}));
        }

        TEST(GoldenArgs, UpdateNeedsAName) {
            EXPECT_ERROR_MSG(parse({"--update"}), ErrorCode::InvalidArgument,
                             "--update needs at least one golden name");
        }

        TEST(GoldenArgs, UpdateRefusesAnUnknownName) {
            EXPECT_ERROR_MSG(
                parse({"--update", "alpha", "nosuch"}), ErrorCode::InvalidArgument,
                "--update: unknown golden 'nosuch' (--list-goldens prints the registered names)");
        }

        TEST(GoldenArgs, UpdateRefusesAFlagAmongTheNames) {
            EXPECT_ERROR_MSG(parse({"--update", "alpha", "--list-goldens"}),
                             ErrorCode::InvalidArgument, "unknown argument: --list-goldens");
        }

        TEST(GoldenArgs, UpdateIsRefusedWithAGtestFilter) {
            EXPECT_ERROR_MSG(parse({"--update", "alpha"}, {"X", 1, false}),
                             ErrorCode::InvalidArgument,
                             "--update runs no test and is refused with --gtest_filter=X");
        }

        TEST(GoldenArgs, UpdateIsRefusedWithGtestFilterInTheEnvironment) {
            // GoogleTest also reads GTEST_FILTER into its filter flag; the variable is named.
            EXPECT_ERROR_MSG(
                parse({"--update", "alpha"}, {"X", 1, false}, environment({{"GTEST_FILTER", "X"}})),
                ErrorCode::InvalidArgument,
                "--update runs no test and is refused while GTEST_FILTER=X is set");
        }

        TEST(GoldenArgs, UpdateIsRefusedWithRepeat) {
            EXPECT_ERROR_MSG(parse({"--update", "alpha"}, {"*", 2, false}),
                             ErrorCode::InvalidArgument,
                             "--update runs no test and is refused with --gtest_repeat=2");
            EXPECT_ERROR_MSG(
                parse({"--update", "alpha"}, {"*", 2, false}, environment({{"GTEST_REPEAT", "2"}})),
                ErrorCode::InvalidArgument,
                "--update runs no test and is refused while GTEST_REPEAT=2 is set");
        }

        TEST(GoldenArgs, UpdateIsRefusedWhenSharded) {
            EXPECT_ERROR_MSG(
                parse({"--update", "alpha"}, {}, environment({{"GTEST_TOTAL_SHARDS", "2"}})),
                ErrorCode::InvalidArgument,
                "--update runs no test and is refused while GTEST_TOTAL_SHARDS=2 is set");
            EXPECT_ERROR_MSG(
                parse({"--update", "alpha"}, {}, environment({{"GTEST_SHARD_INDEX", "0"}})),
                ErrorCode::InvalidArgument,
                "--update runs no test and is refused while GTEST_SHARD_INDEX=0 is set");
        }

        TEST(GoldenArgs, UpdateIsRefusedWithListTests) {
            EXPECT_ERROR_MSG(parse({"--update", "alpha"}, {"*", 1, true}),
                             ErrorCode::InvalidArgument,
                             "--update runs no test and is refused with --gtest_list_tests");
        }

        TEST(GoldenArgs, NoEnvironmentVariableTurnsUpdatingOn) {
            const test::EnvLookup everything_set = [](const char*) {
                return std::optional<std::string>{"1"};
            };
            ASSERT_OK_AND_ASSIGN(const auto run, parse({}, {}, everything_set));
            EXPECT_EQ(run.kind, Kind::Run);
            ASSERT_OK_AND_ASSIGN(const auto list, parse({"--list-goldens"}, {}, everything_set));
            EXPECT_EQ(list.kind, Kind::List);
        }

        // ---- the golden directory -------------------------------------------------------

        TEST(GoldenArgs, DefaultDirectoryIsInjected) {
            EXPECT_FALSE(test::default_golden_directory().empty());
            EXPECT_EQ(test::golden_directory(environment()), test::default_golden_directory());
        }

        TEST(GoldenArgs, GoldenDirectoryComesFromGxbuild3GoldenDirWhenSet) {
            EXPECT_EQ(test::golden_directory(environment({{"GXBUILD3_GOLDEN_DIR", "scratch"}})),
                      std::filesystem::path{"scratch"});
            EXPECT_EQ(test::golden_directory(environment({{"GXBUILD3_GOLDEN_DIR", ""}})),
                      test::default_golden_directory());
        }

        // ---- the registry ---------------------------------------------------------------

        // Every golden this binary registered has a unique valid name and a tracked file.
        TEST(GoldenRegistry, NamesAreUniqueValidAndTracked) {
            const auto registry = test::registered_goldens();
            ASSERT_FALSE(registry.empty());
            EXPECT_NE(test::find_golden(registry, "golden_snapshot_selftest"), nullptr);
            for (std::size_t i = 0; i < registry.size(); ++i) {
                const auto& name = registry[i].name;
                EXPECT_TRUE(test::detail::valid_golden_name(name)) << name;
                EXPECT_TRUE(static_cast<bool>(registry[i].render)) << name;
                EXPECT_TRUE(std::filesystem::is_regular_file(test::default_golden_directory() /
                                                             (name + ".txt")))
                    << name;
                if (i > 0) {
                    EXPECT_NE(registry[i - 1].name, name) << "registered twice";
                }
            }
        }

    } // namespace
} // namespace gxbuild3::snapshots
