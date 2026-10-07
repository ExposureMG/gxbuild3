// src/cli/BuildInputResolver.hpp: the options. Only <working directory>/options.ini is read
// (never a source root's), then each -c item in command-line order, later values winning; the
// CLI overrides stay apart for later layering. An unknown or malformed option, an empty -c item
// and an unreadable options.ini fail with their own code and provenance.
//
// OptionsText: the options.ini decode edge by edge, each row the file's text and either the
// options it yields or the InvalidOption message and item it is refused with. Every row runs
// twice: ThroughFile writes it as working/options.ini and resolves (file_options),
// ThroughParseOptionsText hands it to parse_options_text with a virtual path.

#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "support/Expect.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace gxbuild3::cli {
    namespace {

        class ResolverOptions : public ResolverTest {};

        TEST_F(ResolverOptions, OnlyTheWorkingDirectoryOptionsIniIsLoaded) {
            write("working/options.ini",
                  "nofcrt = false\ntype = falcon\nrev = alt\n1blkey = ignored\n"
                  "cpukey = ignored\naddon = ignored\n");
            write("first/options.ini", "nofcrt = true\ndemon = true\n");
            const auto result = resolve_foundations(minimum_args());
            ASSERT_OK(result) << "known options and every legacy key resolve";
            EXPECT_EQ(result->options.nofcrt, std::optional<bool>{false})
                << "working-directory options.ini supplies the lowest tier";
            EXPECT_FALSE(result->options.demon.has_value())
                << "source-root options.ini is not loaded even for an unoverridden sentinel";
        }

        TEST_F(ResolverOptions, CliOptionsPreserveBareBooleansAndRepeatedOrder) {
            write("working/options.ini", "nofcrt = false\ncfldv = 1\n");
            auto args = minimum_args();
            args.config = {"nofcrt", "cfldv=2", "nofcrt=false"};
            const auto result = resolve_foundations(args);
            ASSERT_OK(result) << "known ordered CLI options resolve";
            EXPECT_EQ(result->options.nofcrt, std::optional<bool>{false})
                << "later CLI values override earlier CLI and options.ini values";
            EXPECT_EQ(result->options.cfldv, std::optional<std::string>{"2"})
                << "CLI string option overrides options.ini";
            EXPECT_EQ(result->cli_overrides.nofcrt, std::optional<bool>{false})
                << "explicit CLI overrides remain distinguishable for later layering";
            EXPECT_EQ(result->cli_overrides.cfldv, std::optional<std::string>{"2"})
                << "explicit CLI overrides remain distinguishable for later layering";
        }

        TEST_F(ResolverOptions, InvalidOptionsArePrecise) {
            write("working/options.ini", "unrecognized = value\n");
            auto args = minimum_args();
            const auto unknown_file_option = resolve_foundations(args);
            ASSERT_ERROR(unknown_file_option, ResolutionErrorCode::InvalidOption)
                << "unknown options.ini keys are rejected with provenance";
            ASSERT_EQ(unknown_file_option.error().path, path("working/options.ini"))
                << "unknown options.ini keys are rejected with provenance";
            ASSERT_EQ(unknown_file_option.error().item, "unrecognized")
                << "unknown options.ini keys are rejected with provenance";

            write("working/options.ini", "nofcrt = maybe\n");
            const auto malformed_file_option = resolve_foundations(args);
            ASSERT_ERROR(malformed_file_option, ResolutionErrorCode::InvalidOption)
                << "malformed known options.ini values are rejected";
            ASSERT_EQ(malformed_file_option.error().item, "nofcrt")
                << "malformed known options.ini values are rejected";

            write("working/options.ini", "nofcrt = false\n");
            args.config = {"not-an-option=true"};
            const auto invalid_cli_option = resolve_foundations(args);
            ASSERT_ERROR(invalid_cli_option, ResolutionErrorCode::InvalidOption)
                << "invalid CLI configuration is rejected with its original item";
            EXPECT_TRUE(invalid_cli_option.error().path.empty())
                << "invalid CLI configuration is rejected with its original item";
            EXPECT_EQ(invalid_cli_option.error().item, "not-an-option=true")
                << "invalid CLI configuration is rejected with its original item";
        }

        TEST_F(ResolverOptions, EmptyCliOptionIsRejected) {
            auto args = minimum_args();
            args.config = {""};
            const auto result = resolve_foundations(args);
            ASSERT_ERROR(result, ResolutionErrorCode::InvalidOption)
                << "an empty direct BuildArgs configuration item is invalid";
            EXPECT_TRUE(result.error().item.empty())
                << "an empty direct BuildArgs configuration item is invalid";
        }

        TEST_F(ResolverOptions, OptionsReadFailureIsDistinct) {
            std::error_code error;
            ASSERT_TRUE(std::filesystem::create_directory(path("working/options.ini"), error))
                << "a directory stands in working/options.ini: " << error.message();
            const auto result = resolve_foundations(minimum_args());
            ASSERT_ERROR(result, ResolutionErrorCode::OptionsReadFailed)
                << "an unreadable options.ini has a distinct error";
            EXPECT_EQ(result.error().path, path("working/options.ini"))
                << "options read error identifies working-directory options.ini";
        }

        // ---- OptionsText --------------------------------------------------------------------

        enum class Via : uint8_t {
            File,
            ParseOptionsText,
        };

        // name is the row's gtest name, sentence the old table's name (kept in failure
        // messages). options is set when the text decodes; otherwise message and item are those
        // of the InvalidOption error.
        struct OptionsTextCase {
            const char* name;
            Via via;
            std::string_view sentence;
            std::string_view text;
            std::optional<OptionsArgs> options;
            std::string_view message;
            std::string_view item;
        };
        GX_PRINT_ROW_AS_NAME(OptionsTextCase)

        auto options_fields(const OptionsArgs& o) {
            return std::tie(o.cbldv, o.pairing_data, o.cfldv, o.xellbutton, o.xellbutton2, o.cygnos,
                            o.demon, o.olddvd, o.nodvd, o.dualboot, o.nomobile, o.nofcrt, o.noremap,
                            o.noecdremap, o.nandmu, o.nosecurity, o.nosusecurity, o.smcnocheck,
                            o.noblpatch, o.nopatch, o.cputemp, o.gputemp, o.edramtemp,
                            o.overcputemp, o.overgputemp, o.overedramtemp, o.cpufan, o.gpufan,
                            o.dvdkey, o.avregion, o.gameregion, o.dvdregion, o.macid);
        }

        // The names of the options_fields members, in the same order.
        constexpr std::array<std::string_view, 33> kOptionsFieldNames{
            "cbldv",       "pairing_data",  "cfldv",   "xellbutton", "xellbutton2",  "cygnos",
            "demon",       "olddvd",        "nodvd",   "dualboot",   "nomobile",     "nofcrt",
            "noremap",     "noecdremap",    "nandmu",  "nosecurity", "nosusecurity", "smcnocheck",
            "noblpatch",   "nopatch",       "cputemp", "gputemp",    "edramtemp",    "overcputemp",
            "overgputemp", "overedramtemp", "cpufan",  "gpufan",     "dvdkey",       "avregion",
            "gameregion",  "dvdregion",     "macid"};
        static_assert(std::tuple_size_v<decltype(options_fields(std::declval<OptionsArgs>()))> ==
                      kOptionsFieldNames.size());

        template <std::size_t I, class Fields>
        void expect_same_field(const Fields& actual, const Fields& expected,
                               const std::string& label) {
            EXPECT_EQ(std::get<I>(actual), std::get<I>(expected))
                << label << " (field " << kOptionsFieldNames[I] << ")";
        }

        // Field by field, so a failure names the option that differs.
        template <std::size_t... I>
        void expect_same_options(const OptionsArgs& actual, const OptionsArgs& expected,
                                 const std::string& label, std::index_sequence<I...>) {
            const auto actual_fields = options_fields(actual);
            const auto expected_fields = options_fields(expected);
            (expect_same_field<I>(actual_fields, expected_fields, label), ...);
        }

        template <class Set> OptionsArgs options_with(Set set) {
            OptionsArgs options{};
            set(options);
            return options;
        }

        std::vector<OptionsTextCase> options_text_cases(Via via) {
            const auto error_case = [via](const char* name, std::string_view sentence,
                                          std::string_view text, std::string_view message,
                                          std::string_view item) {
                return OptionsTextCase{name, via, sentence, text, std::nullopt, message, item};
            };
            const auto ok_case = [via](const char* name, std::string_view sentence,
                                       std::string_view text, OptionsArgs options) {
                return OptionsTextCase{name, via, sentence, text, std::move(options), {}, {}};
            };
            return {
                ok_case("EmptyText", "empty text", "", {}),
                ok_case("BlankAndCommentLinesOnly", "blank and comment lines only",
                        "\n   \n; semi\n# hash\n   ; indented semi\n\t# indented hash\n#cbldv=1\n",
                        {}),
                ok_case("KeyAndValueAreTrimmed", "key and value are trimmed",
                        "  nofcrt   =   false  \n\tcbldv\t=\t5\t\n",
                        options_with([](OptionsArgs& o) {
                            o.nofcrt = false;
                            o.cbldv = "5";
                        })),
                ok_case("KeysAreCaseInsensitiveValuesKeepTheirCase",
                        "keys are case-insensitive, values keep their case",
                        "NoFcrt = TRUE\nCFLDV = Ab\n", options_with([](OptionsArgs& o) {
                            o.nofcrt = true;
                            o.cfldv = "Ab";
                        })),
                ok_case("LeadingDashesAreStrippedFromTheKey",
                        "leading dashes are stripped from the key", "--cbldv = 4\n",
                        options_with([](OptionsArgs& o) { o.cbldv = "4"; })),
                ok_case("DashThenSpaceStillNamesTheOptionThroughOptionsManager",
                        "a dash then a space still names the option through OptionsManager",
                        "- cfldv = 6\n", options_with([](OptionsArgs& o) { o.cfldv = "6"; })),
                error_case("DashThenSpaceKeepsTheInnerSpaceInAnUnknownKey",
                           "a dash then a space keeps the inner space in an unknown key",
                           "- bogus = 1\n", "Invalid option ' bogus' in options.ini (line 1)",
                           " bogus"),
                error_case("SpaceInsideTheKeyIsKept", "a space inside the key is kept",
                           "no fcrt = 1\n", "Invalid option 'no fcrt' in options.ini (line 1)",
                           "no fcrt"),
                ok_case("FirstEqualsSplitsKeyFromValue", "the first '=' splits key from value",
                        "pairing_data = a=b\n",
                        options_with([](OptionsArgs& o) { o.pairing_data = "a=b"; })),
                ok_case("InlineSemicolonCommentIsCutAndTheValueReTrimmed",
                        "an inline ';' comment is cut and the value re-trimmed",
                        "cfldv = 7 ; seven\n", options_with([](OptionsArgs& o) { o.cfldv = "7"; })),
                ok_case("InlineHashIsNotAComment", "an inline '#' is not a comment",
                        "cfldv = 7 # seven\n",
                        options_with([](OptionsArgs& o) { o.cfldv = "7 # seven"; })),
                ok_case("SemicolonRightAfterEqualsLeavesAnEmptyStringValue",
                        "a ';' right after '=' leaves an empty string value", "cbldv = ; nothing\n",
                        options_with([](OptionsArgs& o) { o.cbldv = ""; })),
                ok_case("StringOptionWithAnEmptyValueIsStoredEmpty",
                        "a string option with an empty value is stored empty", "cbldv=\n",
                        options_with([](OptionsArgs& o) { o.cbldv = ""; })),
                ok_case("EmptyBooleanValueIsTrue", "an empty boolean value is true",
                        "nofcrt =\ndemon = ; c\n", options_with([](OptionsArgs& o) {
                            o.nofcrt = true;
                            o.demon = true;
                        })),
                ok_case("EmptyButtonValueClearsIt", "an empty button value clears it",
                        "xellbutton = power\nxellbutton =\n", {}),
                ok_case("LaterLineWins", "a later line wins", "cfldv = 1\ncfldv = 2\n",
                        options_with([](OptionsArgs& o) { o.cfldv = "2"; })),
                ok_case("NopatchStagesAccumulate", "nopatch stages accumulate",
                        "nopatch = khv\nnopatch = cb\n",
                        options_with([](OptionsArgs& o) { o.nopatch = "cb+khv"; })),
                ok_case("AliasesReachTheirOption", "aliases reach their option",
                        "pd = 0a0b0c\nnochecksmc = yes\n", options_with([](OptionsArgs& o) {
                            o.pairing_data = "0a0b0c";
                            o.smcnocheck = true;
                        })),
                ok_case("LegacyKeysAreSkippedWhateverTheirValue",
                        "legacy keys are skipped whatever their value",
                        "type = falcon\nrev = \n1blkey=zz\ncpukey = 00\naddon = x;y\n", {}),
                ok_case("LegacyKeysMatchAfterNormalization",
                        "legacy keys match after normalization", "--TYPE = x\n", {}),
                error_case("LegacyKeyWithoutEqualsIsStillRefused",
                           "a legacy key without '=' is still refused", "type\n",
                           "Expected key=value in options.ini (line 1)", "type"),
                error_case("BareBooleanWithoutEqualsIsRefused",
                           "a bare boolean without '=' is refused", "cbldv = 1\nnofcrt\n",
                           "Expected key=value in options.ini (line 2)", "nofcrt"),
                error_case("BareStringOptionWithoutEqualsIsRefused",
                           "a bare string option without '=' is refused", "  cbldv  \n",
                           "Expected key=value in options.ini (line 1)", "cbldv"),
                error_case("SectionHeaderIsRefusedWithItsLine",
                           "a section header is refused with its line",
                           "nofcrt = true\n\n  [falconbl]  \n",
                           "Sections are not valid in options.ini (line 3)", "[falconbl]"),
                ok_case("BracketAfterTheKeyIsPartOfTheValue",
                        "a '[' after the key is part of the value", "cfldv = [1]\n",
                        options_with([](OptionsArgs& o) { o.cfldv = "[1]"; })),
                error_case("EmptyKeyIsRefused", "an empty key is refused", " = 5\n",
                           "Invalid option '' in options.ini (line 1)", ""),
                error_case("LineNumbersCountBlankAndCommentLines",
                           "line numbers count blank and comment lines", "\n; c\n\nbogus = 1\n",
                           "Invalid option 'bogus' in options.ini (line 4)", "bogus"),
                error_case("InvalidBooleanValueIsRefused", "an invalid boolean value is refused",
                           "nofcrt = maybe\n", "Invalid option 'nofcrt' in options.ini (line 1)",
                           "nofcrt"),
                error_case("InvalidNopatchStageIsRefused", "an invalid nopatch stage is refused",
                           "nopatch = sc\n", "Invalid option 'nopatch' in options.ini (line 1)",
                           "nopatch"),
                error_case("FirstBadLineStopsTheDecode", "the first bad line stops the decode",
                           "bogus = 1\n[x]\n", "Invalid option 'bogus' in options.ini (line 1)",
                           "bogus"),
                ok_case("CrlfLineEndingsAreAccepted", "CRLF line endings are accepted",
                        "cbldv = 1\r\n\r\n; c\r\ncfldv = 2 ; x\r\n",
                        options_with([](OptionsArgs& o) {
                            o.cbldv = "1";
                            o.cfldv = "2";
                        })),
                error_case("CrlfLinesAreCountedOnce", "CRLF lines are counted once",
                           "cbldv = 1\r\n\r\nbogus\r\n",
                           "Expected key=value in options.ini (line 3)", "bogus"),
                ok_case("LoneCrIsNotALineBreak", "a lone CR is not a line break",
                        "cbldv = 1\rcfldv = 2\n",
                        options_with([](OptionsArgs& o) { o.cbldv = "1\rcfldv = 2"; })),
                ok_case("LastLineNeedsNoNewline", "the last line needs no newline", "cfldv = 9",
                        options_with([](OptionsArgs& o) { o.cfldv = "9"; })),
                error_case("Utf8BomStaysPartOfTheFirstKey",
                           "a UTF-8 BOM stays part of the first key",
                           "\xEF\xBB\xBF"
                           "cbldv = 1\n",
                           "Invalid option '\xEF\xBB\xBF"
                           "cbldv' in options.ini (line 1)",
                           "\xEF\xBB\xBF"
                           "cbldv"),
            };
        }

        class OptionsText : public ResolverTest,
                            public ::testing::WithParamInterface<OptionsTextCase> {};

        TEST_P(OptionsText, YieldsTheOptionsOrTheInvalidOptionError) {
            const auto& row = GetParam();
            std::filesystem::path source;
            std::expected<OptionsArgs, ResolutionError> decoded;
            std::string label;
            if (row.via == Via::File) {
                source = write("working/options.ini", row.text);
                const auto result = resolve_foundations(minimum_args());
                if (result) {
                    decoded = result->file_options;
                } else {
                    decoded = std::unexpected(result.error());
                }
                label = "options.ini: " + std::string(row.sentence);
            } else {
                source = "virtual/options.ini";
                decoded = parse_options_text(row.text, source);
                label = "parse_options_text: " + std::string(row.sentence);
            }

            if (row.options) {
                ASSERT_OK(decoded) << label;
                expect_same_options(*decoded, *row.options, label,
                                    std::make_index_sequence<kOptionsFieldNames.size()>{});
                return;
            }
            ASSERT_ERROR(decoded, ResolutionErrorCode::InvalidOption) << label;
            EXPECT_EQ(decoded.error().message, row.message) << label;
            EXPECT_EQ(decoded.error().item, row.item) << label;
            EXPECT_EQ(decoded.error().path, source) << label;
        }

        // The rows in the order of the old table, through the file and through the decoder.
        INSTANTIATE_TEST_SUITE_P(ThroughFile, OptionsText,
                                 ::testing::ValuesIn(options_text_cases(Via::File)),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(ThroughParseOptionsText, OptionsText,
                                 ::testing::ValuesIn(options_text_cases(Via::ParseOptionsText)),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::cli
