// src/cli/CommandLine.hpp: parse_command_line turns argv into a BuildArgs (implicit or explicit
// "build"), a HelpCommand or a VersionCommand. Build types and block types normalize, list
// options keep their command-line order and Windows drive paths survive because only the build
// type splits on ':'. The refused command lines are CommandLineErrorTests.cpp.

#include "cli/CommandLine.hpp"
#include "support/Expect.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace gxbuild3::cli {
    namespace {

        const BuildArgs* build_args(const ParsedCommand& parsed) {
            return std::get_if<BuildArgs>(&parsed);
        }

        TEST(CommandLine, ImplicitBuildNormalizesGgAndKeepsListOrder) {
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
            const auto parsed = parse_command_line(argv);
            const auto* args = parsed ? build_args(*parsed) : nullptr;
            ASSERT_NE(args, nullptr) << "valid implicit build parses";
            EXPECT_EQ(args->build_type, BuildType::Glitch) << "gg normalizes to glitch";
            EXPECT_EQ(args->image_type, ImageType::NewSmallBlock) << "psb maps to new small block";
            EXPECT_EQ(args->source_dirs,
                      (std::vector<std::filesystem::path>{R"(C:\first)", R"(D:\second)", "third"}))
                << "repeated directories preserve list and flag order";
            EXPECT_EQ(args->config,
                      (std::vector<std::string>{"nofcrt", "nandmu=false", "nofcrt=false"}))
                << "repeated config lists preserve later override order";
            EXPECT_EQ(args->addons, (std::vector<std::string>{"nohdmiwait", "nolan", "demon"}))
                << "repeated add-on lists preserve order";
            EXPECT_EQ(args->output_path.filename(), "updflash.bin")
                << "default output is updflash.bin";
        }

        TEST(CommandLine, LongOptionAliasesAndWindowsDrivePathsSurvive) {
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
            const auto parsed = parse_command_line(argv);
            const auto* args = parsed ? build_args(*parsed) : nullptr;
            ASSERT_NE(args, nullptr) << "Windows path build parses";
            EXPECT_EQ(args->build_type, BuildType::Glitch) << "glitch1 normalizes to glitch";
            EXPECT_EQ(args->source_dirs.size(), 1u) << "Windows drive colon remains in path";
            EXPECT_EQ(args->input_path, std::filesystem::path{R"(D:\nanddump.bin)"})
                << "input path is retained";
            EXPECT_EQ(args->output_path, std::filesystem::path{R"(E:\out\upd.bin)"})
                << "output path is retained";
            EXPECT_EQ(args->cpu_key, "0123456789abcdef0123456789abcdef") << "CPU key is retained";
            EXPECT_EQ(args->patch_extension, "test") << "patch extension is retained";
            EXPECT_EQ(args->config, std::vector<std::string>{"nofcrt"})
                << "long config option is retained";
            EXPECT_EQ(args->addons, std::vector<std::string>{"nolan"})
                << "long add-on option is retained";
            EXPECT_TRUE(args->verbose) << "long verbose option is retained";
        }

        TEST(CommandLine, PatchExtensionAllowsInternalUnderscoreOnly) {
            const std::vector<std::string_view> valid{"gxbuild",  "-b", "build.ini", "-s",
                                                      "falcon",   "-t", "retail",    "-d",
                                                      "firmware", "-e", "test_alt"};
            const std::vector<std::string_view> leading_underscore{
                "gxbuild", "-b", "build.ini", "-s", "falcon", "-t",
                "retail",  "-d", "firmware",  "-e", "_test"};
            const std::vector<std::string_view> unsafe_character{
                "gxbuild", "-b", "build.ini", "-s", "falcon",  "-t",
                "retail",  "-d", "firmware",  "-e", "test.alt"};
            const auto valid_result = parse_command_line(valid);
            const auto* args = valid_result ? build_args(*valid_result) : nullptr;
            ASSERT_NE(args, nullptr) << "patch extension accepts a safe internal underscore";
            EXPECT_EQ(args->patch_extension, "test_alt")
                << "patch extension accepts a safe internal underscore";
            EXPECT_ERROR(parse_command_line(leading_underscore), ParseErrorCode::InvalidExtension)
                << "patch extension rejects a leading underscore";
            EXPECT_ERROR(parse_command_line(unsafe_character), ParseErrorCode::InvalidExtension)
                << "patch extension rejects unsafe characters";
        }

        TEST(CommandLine, HelpAndVersionBypassBuildValidation) {
            const std::vector<std::string_view> help{"gxbuild", "--help"};
            const std::vector<std::string_view> version{"gxbuild", "--version"};
            const auto help_result = parse_command_line(help);
            const auto version_result = parse_command_line(version);
            ASSERT_OK(help_result) << "help bypasses build requirements";
            EXPECT_TRUE(std::holds_alternative<HelpCommand>(*help_result))
                << "help bypasses build requirements";
            ASSERT_OK(version_result) << "version bypasses build requirements";
            EXPECT_TRUE(std::holds_alternative<VersionCommand>(*version_result))
                << "version bypasses build requirements";
        }

        TEST(CommandLine, SectionResolvesConsoleCaseInsensitivelyAndUnknownStaysUnresolved) {
            const std::vector<std::string_view> known{
                "gxbuild", "-b", "_jtag.ini", "-s", "Jasper", "-t", "jtag:psb", "-d", "firmware"};
            const auto known_result = parse_command_line(known);
            const auto* known_args = known_result ? build_args(*known_result) : nullptr;
            const std::vector<std::string_view> unknown{"gxbuild",  "-b",          "_jtag.ini",
                                                        "-s",       "notaconsole", "-t",
                                                        "jtag:psb", "-d",          "firmware"};
            const auto unknown_result = parse_command_line(unknown);
            const auto* unknown_args = unknown_result ? build_args(*unknown_result) : nullptr;
            ASSERT_NE(known_args, nullptr) << "-s jasper parses";
            EXPECT_EQ(known_args->section, "Jasper") << "section text is preserved verbatim";
            EXPECT_EQ(known_args->console, ConsoleType::Jasper)
                << "known section resolves to ConsoleType::Jasper case-insensitively";
            ASSERT_NE(unknown_args, nullptr) << "unknown section still parses";
            EXPECT_FALSE(unknown_args->console.has_value())
                << "unknown section leaves the console unresolved";
        }

        // ---- explicit "build" with each block type --------------------------------------------

        struct BlockTypeRow {
            const char* name;
            const char* build_type;
            ImageType expected;
        };
        GX_PRINT_ROW_AS_NAME(BlockTypeRow)

        class CommandLineBlockType : public ::testing::TestWithParam<BlockTypeRow> {};

        TEST_P(CommandLineBlockType, ExplicitBuildParsesEachBlockType) {
            const auto& row = GetParam();
            const std::vector<std::string_view> argv{"gxbuild", "build",   "-b", "build.ini",
                                                     "-s",      "falcon",  "-t", row.build_type,
                                                     "-d",      "firmware"};
            const auto parsed = parse_command_line(argv);
            const auto* args = parsed ? build_args(*parsed) : nullptr;
            ASSERT_NE(args, nullptr) << "explicit build parses each block type";
            EXPECT_EQ(args->image_type, row.expected) << "explicit build parses each block type";
        }

        INSTANTIATE_TEST_SUITE_P(
            Block, CommandLineBlockType,
            ::testing::Values(BlockTypeRow{"Xsb", "retail:xsb", ImageType::SmallBlock},
                              BlockTypeRow{"Psb", "retail:psb", ImageType::NewSmallBlock},
                              BlockTypeRow{"Bb", "retail:bb", ImageType::BigBlock},
                              BlockTypeRow{"Emmc", "retail:emmc", ImageType::Emmc}),
            test::RowName{});

    } // namespace
} // namespace gxbuild3::cli
