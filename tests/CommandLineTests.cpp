#include "cli/CommandLine.hpp"

#include <filesystem>
#include <iostream>
#include <string_view>
#include <variant>
#include <vector>

namespace {

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    const gxbuild3::cli::BuildArgs* build_args(const gxbuild3::cli::ParsedCommand& parsed) {
        return std::get_if<gxbuild3::cli::BuildArgs>(&parsed);
    }

    bool test_implicit_build_and_lists() {
        const std::vector<std::string_view> argv{"gxbuild",
                                                 "-b",
                                                 "_glitch2.ini",
                                                 "-s",
                                                 "falcon",
                                                 "-t",
                                                 "gg:psb",
                                                 "-d",
                                                 R"(C:\first;D:\second)",
                                                 "-d",
                                                 "third",
                                                 "-c",
                                                 "nofcrt,nandmu=false",
                                                 "-c",
                                                 "nofcrt=false",
                                                 "-a",
                                                 "nohdmiwait;nolan",
                                                 "-a",
                                                 "demon"};
        const auto parsed = gxbuild3::cli::ParseCommandLine(argv);
        const auto* args = parsed ? build_args(*parsed) : nullptr;
        return require(args != nullptr, "valid implicit build parses") &&
               require(args->build_type == BuildType::Glitch, "gg normalizes to glitch") &&
               require(args->image_type == ImageType::NewSmallBlock,
                       "psb maps to new small block") &&
               require(args->source_dirs == std::vector<std::filesystem::path>{R"(C:\first)",
                                                                               R"(D:\second)",
                                                                               "third"},
                       "repeated directories preserve list and flag order") &&
               require(args->config ==
                           std::vector<std::string>{"nofcrt", "nandmu=false", "nofcrt=false"},
                       "repeated config lists preserve later override order") &&
               require(args->addons == std::vector<std::string>{"nohdmiwait", "nolan", "demon"},
                       "repeated add-on lists preserve order") &&
               require(args->output_path.filename() == "updflash.bin",
                       "default output is updflash.bin");
    }

    bool test_explicit_build_and_all_block_types() {
        const std::vector<std::pair<std::string_view, ImageType>> blocks{
            {"xsb", ImageType::SmallBlock},
            {"psb", ImageType::NewSmallBlock},
            {"bb", ImageType::BigBlock},
            {"emmc", ImageType::Emmc}};
        for (const auto& [block, expected] : blocks) {
            const std::vector<std::string_view> argv{"gxbuild",
                                                     "build",
                                                     "-b",
                                                     "build.ini",
                                                     "-s",
                                                     "falcon",
                                                     "-t",
                                                     block == "xsb"   ? "retail:xsb"
                                                     : block == "psb" ? "retail:psb"
                                                     : block == "bb"  ? "retail:bb"
                                                                      : "retail:emmc",
                                                     "-d",
                                                     "firmware"};
            const auto parsed = gxbuild3::cli::ParseCommandLine(argv);
            const auto* args = parsed ? build_args(*parsed) : nullptr;
            if (!require(args != nullptr && args->image_type == expected,
                         "explicit build parses each block type")) {
                return false;
            }
        }
        return true;
    }

    bool test_long_option_aliases_and_windows_paths() {
        const std::vector<std::string_view> argv{"gxbuild",
                                                 "--buildini",
                                                 "build.ini",
                                                 "--section",
                                                 "falcon",
                                                 "--buildtype",
                                                 "glitch1:xsb",
                                                 "--dir",
                                                 R"(C:\firmware)",
                                                 "--input",
                                                 R"(D:\nanddump.bin)",
                                                 "--output",
                                                 R"(E:\out\upd.bin)",
                                                 "--cpukey",
                                                 "0123456789abcdef0123456789abcdef",
                                                 "--ext",
                                                 "test",
                                                 "--config",
                                                 "nofcrt",
                                                 "--addon",
                                                 "nolan",
                                                 "--verbose"};
        const auto parsed = gxbuild3::cli::ParseCommandLine(argv);
        const auto* args = parsed ? build_args(*parsed) : nullptr;
        return require(args != nullptr, "Windows path build parses") &&
               require(args->build_type == BuildType::Glitch, "glitch1 normalizes to glitch") &&
               require(args->source_dirs.size() == 1, "Windows drive colon remains in path") &&
               require(args->input_path && *args->input_path == R"(D:\nanddump.bin)",
                       "input path is retained") &&
               require(args->output_path == R"(E:\out\upd.bin)", "output path is retained") &&
               require(args->cpu_key && *args->cpu_key == "0123456789abcdef0123456789abcdef",
                       "CPU key is retained") &&
               require(args->patch_extension && *args->patch_extension == "test",
                       "patch extension is retained") &&
               require(args->config == std::vector<std::string>{"nofcrt"},
                       "long config option is retained") &&
               require(args->addons == std::vector<std::string>{"nolan"},
                       "long add-on option is retained") &&
               require(args->verbose, "long verbose option is retained");
    }

    bool test_patch_extension_allows_internal_underscore_only() {
        const std::vector<std::string_view> valid{"gxbuild", "-b", "build.ini", "-s", "falcon",
                                                  "-t",      "retail",    "-d", "firmware", "-e",
                                                  "test_alt"};
        const std::vector<std::string_view> leading_underscore{
            "gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware",
            "-e",     "_test"};
        const std::vector<std::string_view> unsafe_character{
            "gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware",
            "-e",     "test.alt"};
        const auto valid_result = gxbuild3::cli::ParseCommandLine(valid);
        const auto invalid_result = gxbuild3::cli::ParseCommandLine(leading_underscore);
        const auto unsafe_result = gxbuild3::cli::ParseCommandLine(unsafe_character);
        const auto* args = valid_result ? build_args(*valid_result) : nullptr;
        return require(args && args->patch_extension && *args->patch_extension == "test_alt",
                       "patch extension accepts a safe internal underscore") &&
               require(!invalid_result &&
                           invalid_result.error().code == gxbuild3::cli::ParseErrorCode::InvalidExtension,
                       "patch extension rejects a leading underscore") &&
               require(!unsafe_result &&
                           unsafe_result.error().code == gxbuild3::cli::ParseErrorCode::InvalidExtension,
                       "patch extension rejects unsafe characters");
    }

    bool test_help_and_version_bypass_build_validation() {
        const std::vector<std::string_view> help{"gxbuild", "--help"};
        const std::vector<std::string_view> version{"gxbuild", "--version"};
        const auto help_result = gxbuild3::cli::ParseCommandLine(help);
        const auto version_result = gxbuild3::cli::ParseCommandLine(version);
        return require(help_result &&
                           std::holds_alternative<gxbuild3::cli::HelpCommand>(*help_result),
                       "help bypasses build requirements") &&
               require(version_result &&
                           std::holds_alternative<gxbuild3::cli::VersionCommand>(*version_result),
                       "version bypasses build requirements");
    }

    bool test_errors_are_structured() {
        struct Case {
            std::vector<std::string_view> argv;
            gxbuild3::cli::ParseErrorCode expected;
        };
        const std::vector<Case> cases{
            {{"gxbuild", "-b"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "-b", "one.ini", "-b", "two.ini"},
             gxbuild3::cli::ParseErrorCode::DuplicateArgument},
            {{"gxbuild", "-v", "-v"}, gxbuild3::cli::ParseErrorCode::DuplicateArgument},
            {{"gxbuild", "--unknown"}, gxbuild3::cli::ParseErrorCode::UnknownArgument},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "unknown", "-d", "firmware"},
             gxbuild3::cli::ParseErrorCode::InvalidBuildType},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail:unknown", "-d",
              "firmware"},
             gxbuild3::cli::ParseErrorCode::InvalidBlockType},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-a",
              "folder/addon"},
             gxbuild3::cli::ParseErrorCode::InvalidAddon},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-a",
              "addon.bin"},
             gxbuild3::cli::ParseErrorCode::InvalidAddon},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-a",
              "C:"},
             gxbuild3::cli::ParseErrorCode::InvalidAddon},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-a",
              "name:stream"},
             gxbuild3::cli::ParseErrorCode::InvalidAddon},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-e",
              "_bad"},
             gxbuild3::cli::ParseErrorCode::InvalidExtension},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-e",
              "bad/path"},
             gxbuild3::cli::ParseErrorCode::InvalidExtension},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "one,,two"},
             gxbuild3::cli::ParseErrorCode::InvalidList},
            {{"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d", "firmware", "-c",
              "unknown=true"},
             gxbuild3::cli::ParseErrorCode::InvalidList},
            {{"gxbuild", "build", "extra"}, gxbuild3::cli::ParseErrorCode::UnknownArgument},
            {{"gxbuild", "-b", "build.ini"},
             gxbuild3::cli::ParseErrorCode::MissingRequiredArgument},
            {{"gxbuild", "--buildini"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--section"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--buildtype"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--dir"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--input"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--output"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--cpukey"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--ext"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--config"}, gxbuild3::cli::ParseErrorCode::MissingValue},
            {{"gxbuild", "--addon"}, gxbuild3::cli::ParseErrorCode::MissingValue},
        };
        for (const auto& test : cases) {
            const auto parsed = gxbuild3::cli::ParseCommandLine(test.argv);
            if (!require(!parsed && parsed.error().code == test.expected,
                         "invalid command returns the expected parse error")) {
                return false;
            }
        }
        return true;
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_implicit_build_and_lists() && passed;
    passed = test_explicit_build_and_all_block_types() && passed;
    passed = test_long_option_aliases_and_windows_paths() && passed;
    passed = test_patch_extension_allows_internal_underscore_only() && passed;
    passed = test_help_and_version_bypass_build_validation() && passed;
    passed = test_errors_are_structured() && passed;
    return passed ? 0 : 1;
}
