// src/cli/CommandLine.hpp: every refused command line fails with a structured ParseError whose
// code names the reason (a missing value, a duplicate, an unknown option or build/block type, an
// unsafe add-on, extension or list item, a stray positional or a missing required option).

#include "cli/CommandLine.hpp"
#include "support/Expect.hpp"

#include <gtest/gtest.h>
#include <string_view>
#include <vector>

namespace gxbuild3::cli {
    namespace {

        struct ParseErrorRow {
            const char* name;
            std::vector<std::string_view> argv;
            ParseErrorCode expected;
        };
        GX_PRINT_ROW_AS_NAME(ParseErrorRow)

        class CommandLineError : public ::testing::TestWithParam<ParseErrorRow> {};

        TEST_P(CommandLineError, ReturnsTheExpectedParseErrorCode) {
            const auto& row = GetParam();
            EXPECT_ERROR(parse_command_line(row.argv), row.expected)
                << "invalid command returns the expected parse error";
        }

        // The rows in the order of the old table.
        INSTANTIATE_TEST_SUITE_P(
            Argv, CommandLineError,
            ::testing::Values(
                ParseErrorRow{
                    "BuildIniWithoutValue", {"gxbuild", "-b"}, ParseErrorCode::MissingValue},
                ParseErrorRow{"DuplicateBuildIni",
                              {"gxbuild", "-b", "one.ini", "-b", "two.ini"},
                              ParseErrorCode::DuplicateArgument},
                ParseErrorRow{
                    "DuplicateVerbose", {"gxbuild", "-v", "-v"}, ParseErrorCode::DuplicateArgument},
                ParseErrorRow{
                    "UnknownLongOption", {"gxbuild", "--unknown"}, ParseErrorCode::UnknownArgument},
                ParseErrorRow{"UnknownBuildType",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "unknown", "-d",
                               "firmware"},
                              ParseErrorCode::InvalidBuildType},
                ParseErrorRow{"UnknownBlockType",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail:unknown",
                               "-d", "firmware"},
                              ParseErrorCode::InvalidBlockType},
                ParseErrorRow{"AddonWithFolder",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-a", "folder/addon"},
                              ParseErrorCode::InvalidAddon},
                ParseErrorRow{"AddonWithBinExtension",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-a", "addon.bin"},
                              ParseErrorCode::InvalidAddon},
                ParseErrorRow{"AddonDriveOnly",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-a", "C:"},
                              ParseErrorCode::InvalidAddon},
                ParseErrorRow{"AddonWithStream",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-a", "name:stream"},
                              ParseErrorCode::InvalidAddon},
                ParseErrorRow{"ExtensionWithLeadingUnderscore",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-e", "_bad"},
                              ParseErrorCode::InvalidExtension},
                ParseErrorRow{"ExtensionWithSlash",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-e", "bad/path"},
                              ParseErrorCode::InvalidExtension},
                ParseErrorRow{"DirListWithEmptyItem",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "one,,two"},
                              ParseErrorCode::InvalidList},
                ParseErrorRow{"ConfigWithUnknownKey",
                              {"gxbuild", "-b", "build.ini", "-s", "falcon", "-t", "retail", "-d",
                               "firmware", "-c", "unknown=true"},
                              ParseErrorCode::InvalidList},
                ParseErrorRow{"BuildWithExtraArgument",
                              {"gxbuild", "build", "extra"},
                              ParseErrorCode::UnknownArgument},
                ParseErrorRow{"BuildIniAloneMissesRequired",
                              {"gxbuild", "-b", "build.ini"},
                              ParseErrorCode::MissingRequiredArgument},
                ParseErrorRow{"LongBuildIniWithoutValue",
                              {"gxbuild", "--buildini"},
                              ParseErrorCode::MissingValue},
                ParseErrorRow{"LongSectionWithoutValue",
                              {"gxbuild", "--section"},
                              ParseErrorCode::MissingValue},
                ParseErrorRow{"LongBuildTypeWithoutValue",
                              {"gxbuild", "--buildtype"},
                              ParseErrorCode::MissingValue},
                ParseErrorRow{
                    "LongDirWithoutValue", {"gxbuild", "--dir"}, ParseErrorCode::MissingValue},
                ParseErrorRow{
                    "LongInputWithoutValue", {"gxbuild", "--input"}, ParseErrorCode::MissingValue},
                ParseErrorRow{"LongOutputWithoutValue",
                              {"gxbuild", "--output"},
                              ParseErrorCode::MissingValue},
                ParseErrorRow{"LongCpuKeyWithoutValue",
                              {"gxbuild", "--cpukey"},
                              ParseErrorCode::MissingValue},
                ParseErrorRow{
                    "LongExtWithoutValue", {"gxbuild", "--ext"}, ParseErrorCode::MissingValue},
                ParseErrorRow{"LongConfigWithoutValue",
                              {"gxbuild", "--config"},
                              ParseErrorCode::MissingValue},
                ParseErrorRow{
                    "LongAddonWithoutValue", {"gxbuild", "--addon"}, ParseErrorCode::MissingValue}),
            test::RowName{});

    } // namespace
} // namespace gxbuild3::cli
