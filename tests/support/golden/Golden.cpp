#include "support/golden/Golden.hpp"

#include "support/Env.hpp"
#include "support/golden/GoldenSnapshot.hpp"

#include <algorithm>
#include <cstddef>
#include <format>
#include <iostream>
#include <ostream>
#include <sstream>
#include <utility>

namespace gxbuild3::test {

    namespace {
        std::vector<GoldenEntry>& registry_storage() {
            static std::vector<GoldenEntry> entries;
            return entries;
        }

        constexpr std::string_view kProgram = "gxbuild3_golden_tests";

        std::string usage() {
            return std::format("usage: {0} [--gtest_* flags]      run the golden tests\n"
                               "       {0} --list-goldens         print the registered goldens\n"
                               "       {0} --update <name>...     render each named golden twice "
                               "and rewrite it when both renders agree\n",
                               kProgram);
        }

        // The golden's text and path, or a failure naming why it cannot be read.
        struct LoadedGolden {
            std::filesystem::path path;
            std::string text;
        };

        Result<LoadedGolden> load_golden(const std::filesystem::path& directory,
                                         std::string_view name) {
            if (!detail::valid_golden_name(name)) {
                return fail(ErrorCode::InvalidArgument,
                            "invalid golden name '{}' (use [A-Za-z0-9_.-], not starting with '.')",
                            name);
            }
            auto path = directory / (std::string{name} + ".txt");
            auto text = detail::read_golden(path);
            if (!text) {
                return fail(ErrorCode::NotFound, "{}: missing golden {}", name, path.string());
            }
            return LoadedGolden{std::move(path), std::move(*text)};
        }

        bool owns(const Section& section, std::string_view line) {
            return std::ranges::any_of(section.prefixes, [line](std::string_view prefix) {
                return !prefix.empty() && line.starts_with(prefix);
            });
        }

        Result<> check_prefixes(std::span<const Section> sections) {
            for (const auto& section : sections) {
                if (section.prefixes.empty() ||
                    std::ranges::any_of(section.prefixes,
                                        [](std::string_view prefix) { return prefix.empty(); })) {
                    return fail(ErrorCode::InvalidArgument,
                                "section {} needs at least one prefix and no empty prefix",
                                section.id);
                }
            }
            return {};
        }

        std::string refused(std::string_view why) {
            return std::format("--update runs no test and is refused {}", why);
        }
    } // namespace

    bool register_golden(std::string_view name, GoldenRender render) {
        registry_storage().push_back(GoldenEntry{std::string{name}, std::move(render)});
        return true;
    }

    std::vector<GoldenEntry> registered_goldens() {
        auto entries = registry_storage();
        std::ranges::stable_sort(entries, {}, &GoldenEntry::name);
        return entries;
    }

    const GoldenEntry* find_golden(std::span<const GoldenEntry> registry, std::string_view name) {
        const auto it = std::ranges::find(registry, name, &GoldenEntry::name);
        return it == registry.end() ? nullptr : &*it;
    }

    EnvLookup process_environment() {
        return [](const char* variable) { return env_value(variable); };
    }

    std::filesystem::path golden_directory(const EnvLookup& env) {
        if (const auto overridden = env("GXBUILD3_GOLDEN_DIR");
            overridden && !overridden->empty()) {
            return std::filesystem::path{*overridden};
        }
        return default_golden_directory();
    }

    std::filesystem::path golden_directory() {
        return golden_directory(process_environment());
    }

    ::testing::AssertionResult matches_golden(std::string_view name, std::string_view text) {
        return matches_golden(golden_directory(), name, text);
    }

    ::testing::AssertionResult matches_golden(const std::filesystem::path& directory,
                                              std::string_view name, std::string_view text) {
        std::ostringstream report;
        if (check_golden(GoldenOptions{directory, false}, name, text, report)) {
            return ::testing::AssertionSuccess();
        }
        return ::testing::AssertionFailure() << report.str() << "  (on purpose only: " << kProgram
                                             << " --update " << name << ")\n";
    }

    ::testing::AssertionResult matches_golden_slice(std::string_view name, const Section& section,
                                                    std::string_view text) {
        return matches_golden_slice(golden_directory(), name, section, text);
    }

    ::testing::AssertionResult matches_golden_slice(const std::filesystem::path& directory,
                                                    std::string_view name, const Section& section,
                                                    std::string_view text) {
        if (auto prefixes = check_prefixes(std::span{&section, 1}); !prefixes) {
            return ::testing::AssertionFailure() << "GOLDEN FAIL: " << prefixes.error().describe();
        }
        const auto golden = load_golden(directory, name);
        if (!golden) {
            return ::testing::AssertionFailure() << "GOLDEN FAIL: " << golden.error().describe();
        }
        std::string slice;
        std::vector<std::size_t> file_lines;
        const auto lines = detail::split_lines(golden->text);
        for (std::size_t i = 0; i < lines.size(); ++i) {
            if (owns(section, lines[i])) {
                slice.append(lines[i]);
                slice.push_back('\n');
                file_lines.push_back(i + 1);
            }
        }
        if (file_lines.empty()) {
            return ::testing::AssertionFailure()
                   << "GOLDEN FAIL: " << name << " section " << section.id << " owns no line of "
                   << golden->path.string();
        }
        const auto difference = golden_difference(slice, text);
        if (!difference) {
            return ::testing::AssertionSuccess();
        }
        const auto want = detail::split_lines(slice);
        const auto have = detail::split_lines(text);
        std::size_t first = 0;
        while (first < want.size() && first < have.size() && want[first] == have[first]) {
            ++first;
        }
        auto failure = ::testing::AssertionFailure();
        failure << "GOLDEN FAIL: " << name << " section " << section.id << " differs from "
                << golden->path.string() << '\n'
                << *difference;
        if (first < file_lines.size()) {
            failure << "  slice line " << (first + 1) << " is golden line " << file_lines[first]
                    << '\n';
        } else {
            failure << "  slice line " << (first + 1) << " follows golden line "
                    << file_lines.back() << '\n';
        }
        return failure;
    }

    ::testing::AssertionResult golden_is_partitioned(std::string_view name,
                                                     std::span<const Section> sections) {
        return golden_is_partitioned(golden_directory(), name, sections);
    }

    ::testing::AssertionResult golden_is_partitioned(const std::filesystem::path& directory,
                                                     std::string_view name,
                                                     std::span<const Section> sections) {
        if (auto prefixes = check_prefixes(sections); !prefixes) {
            return ::testing::AssertionFailure() << "GOLDEN FAIL: " << prefixes.error().describe();
        }
        const auto golden = load_golden(directory, name);
        if (!golden) {
            return ::testing::AssertionFailure() << "GOLDEN FAIL: " << golden.error().describe();
        }
        constexpr std::size_t kShown = 5;
        std::vector<std::string> problems;
        std::vector<bool> owned(sections.size(), false);
        std::size_t last_owner = 0;
        const auto lines = detail::split_lines(golden->text);
        for (std::size_t i = 0; i < lines.size(); ++i) {
            std::vector<std::size_t> owners;
            for (std::size_t s = 0; s < sections.size(); ++s) {
                if (owns(sections[s], lines[i])) {
                    owners.push_back(s);
                }
            }
            if (owners.empty()) {
                problems.push_back(
                    std::format("line {} is owned by no section: {}", i + 1, lines[i]));
                continue;
            }
            if (owners.size() > 1) {
                problems.push_back(std::format("line {} is owned by sections {} and {}: {}", i + 1,
                                               sections[owners[0]].id, sections[owners[1]].id,
                                               lines[i]));
                continue;
            }
            const std::size_t owner = owners.front();
            if (owner < last_owner) {
                problems.push_back(std::format("line {} belongs to section {} but follows section "
                                               "{} (sections must follow table order)",
                                               i + 1, sections[owner].id, sections[last_owner].id));
            }
            last_owner = std::max(last_owner, owner);
            owned[owner] = true;
        }
        for (std::size_t s = 0; s < sections.size(); ++s) {
            if (!owned[s]) {
                problems.push_back(std::format("section {} owns no line", sections[s].id));
            }
        }
        if (problems.empty()) {
            return ::testing::AssertionSuccess();
        }
        auto failure = ::testing::AssertionFailure();
        failure << "GOLDEN FAIL: " << name << " (" << golden->path.string()
                << ") is not partitioned by its sections\n";
        for (std::size_t i = 0; i < problems.size() && i < kShown; ++i) {
            failure << "  " << problems[i] << '\n';
        }
        if (problems.size() > kShown) {
            failure << "  ... " << (problems.size() - kShown) << " more problem(s)\n";
        }
        return failure;
    }

    Result<GoldenCommand> parse_golden_args(std::span<const std::string> args,
                                            const GtestState& gtest, const EnvLookup& env,
                                            std::span<const GoldenEntry> registry) {
        if (args.empty()) {
            return GoldenCommand{};
        }
        if (args.front() == "--list-goldens") {
            if (args.size() > 1) {
                return fail(ErrorCode::InvalidArgument,
                            "--list-goldens takes no other argument: {}", args[1]);
            }
            return GoldenCommand{GoldenCommand::Kind::List, {}};
        }
        if (args.front() != "--update") {
            return fail(ErrorCode::InvalidArgument, "unknown argument: {}", args.front());
        }

        GoldenCommand command{GoldenCommand::Kind::Update, {}};
        for (const auto& name : args.subspan(1)) {
            if (name.starts_with("-")) {
                return fail(ErrorCode::InvalidArgument, "unknown argument: {}", name);
            }
            if (find_golden(registry, name) == nullptr) {
                return fail(ErrorCode::InvalidArgument,
                            "--update: unknown golden '{}' (--list-goldens prints the registered "
                            "names)",
                            name);
            }
            command.names.push_back(name);
        }
        if (command.names.empty()) {
            return fail(ErrorCode::InvalidArgument, "--update needs at least one golden name");
        }
        for (const char* variable :
             {"GTEST_FILTER", "GTEST_REPEAT", "GTEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX"}) {
            if (const auto value = env(variable)) {
                return fail(ErrorCode::InvalidArgument, "{}",
                            refused(std::format("while {}={} is set", variable, *value)));
            }
        }
        if (gtest.filter != "*") {
            return fail(ErrorCode::InvalidArgument, "{}",
                        refused(std::format("with --gtest_filter={}", gtest.filter)));
        }
        if (gtest.repeat != 1) {
            return fail(ErrorCode::InvalidArgument, "{}",
                        refused(std::format("with --gtest_repeat={}", gtest.repeat)));
        }
        if (gtest.list_tests) {
            return fail(ErrorCode::InvalidArgument, "{}", refused("with --gtest_list_tests"));
        }
        return command;
    }

    bool update_goldens(std::span<const std::string> names, std::span<const GoldenEntry> registry,
                        const std::filesystem::path& directory, std::ostream& out) {
        struct Rendered {
            std::string name;
            std::string text;
        };
        std::vector<Rendered> rendered;
        bool ok = true;
        for (const auto& name : names) {
            const auto* entry = find_golden(registry, name);
            if (entry == nullptr) {
                out << "GOLDEN UPDATE FAILED: unknown golden '" << name << "'\n";
                ok = false;
                continue;
            }
            if (!detail::valid_golden_name(name)) {
                out << "GOLDEN UPDATE FAILED: invalid golden name '" << name << "'\n";
                ok = false;
                continue;
            }
            auto first = entry->render();
            auto second = entry->render();
            if (!first || !second) {
                out << "GOLDEN UPDATE FAILED: " << name
                    << ": render failed: " << (!first ? first.error() : second.error()).describe()
                    << '\n';
                ok = false;
                continue;
            }
            if (const auto difference = golden_difference(*first, *second)) {
                out << "GOLDEN UPDATE FAILED: " << name
                    << ": two renders differ (first render as golden, second as actual)\n"
                    << *difference;
                ok = false;
                continue;
            }
            rendered.push_back(Rendered{name, std::move(*first)});
        }
        if (!ok) {
            out << "nothing written\n";
            return false;
        }
        for (const auto& golden : rendered) {
            const auto path = directory / (golden.name + ".txt");
            const auto existing = detail::read_golden(path);
            if (existing && *existing == golden.text) {
                out << "golden " << golden.name << " unchanged: " << path.string() << '\n';
                continue;
            }
            if (!detail::write_golden(path, golden.text)) {
                out << "GOLDEN UPDATE FAILED: " << golden.name << ": cannot write " << path.string()
                    << '\n';
                ok = false;
                continue;
            }
            out << "GOLDEN UPDATED: " << golden.name << " -> " << path.string() << '\n';
        }
        return ok;
    }

    int golden_main(int argc, char** argv) {
        ::testing::InitGoogleTest(&argc, argv);
        const std::vector<std::string> args(argv + std::min(argc, 1), argv + argc);
        const GtestState gtest{GTEST_FLAG_GET(filter), GTEST_FLAG_GET(repeat),
                               GTEST_FLAG_GET(list_tests)};
        const auto registry = registered_goldens();
        const auto command = parse_golden_args(args, gtest, process_environment(), registry);
        if (!command) {
            std::cerr << usage() << command.error().describe() << '\n';
            return 2;
        }
        switch (command->kind) {
            case GoldenCommand::Kind::Run:
                return RUN_ALL_TESTS();
            case GoldenCommand::Kind::List:
                for (const auto& entry : registry) {
                    std::cout << entry.name << '\n';
                }
                return 0;
            case GoldenCommand::Kind::Update:
                return update_goldens(command->names, registry, golden_directory(), std::cout) ? 0
                                                                                               : 1;
        }
        return 2;
    }

} // namespace gxbuild3::test
