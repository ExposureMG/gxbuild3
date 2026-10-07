#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "TestResult.hpp"
#include "cli/BuildInputResolver.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/Freeboot.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/Patchset.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/XeRsaTestKey.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/builders/Stages.hpp"
#include "support/render/ExtractProjection.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::cli::BuildArgs;
    using gxbuild3::cli::BuildInputResolver;
    using gxbuild3::cli::ResolutionErrorCode;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    bool require_resolved(
        const std::expected<gxbuild3::cli::BuildRequest, gxbuild3::cli::ResolutionError>& result,
        std::string_view message) {
        if (!result) {
            std::cerr << "RESOLUTION ERROR: code=" << static_cast<int>(result.error().code)
                      << " path='" << result.error().path.string() << "' item='"
                      << result.error().item << "' message='" << result.error().message << "'\n";
        }
        return require(result.has_value(), message);
    }

    std::string uppercase(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });
        return value;
    }

    // The shared builders (tests/support/builders/), byte for byte what this file defined.
    using gxbuild3::test::canonical_keyvault_filled;
    using gxbuild3::test::cb_with_word;
    using gxbuild3::test::encrypted_keyvault;
    using gxbuild3::test::glitch2_donor_input;
    using gxbuild3::test::hex;
    using gxbuild3::test::kFuseCbWord;
    using gxbuild3::test::make_smc;
    using gxbuild3::test::malformed_supported_size_nand;
    using gxbuild3::test::valid_bootloaders;
    using gxbuild3::test::valid_glitch_patchset;

    // The resolver's two test keys as bytes: valid_cpu_key() (bits 0..52 ECC-encoded) and, as
    // the alternate, different_valid_cpu_key() (bits 53..105), pinned by core.Keys.
    Bytes valid_cpu_key(bool alternate = false) {
        const auto key =
            alternate ? gxbuild3::test::different_valid_cpu_key() : gxbuild3::test::valid_cpu_key();
        return Bytes(key.begin(), key.end());
    }

    // The Result-returning builders, unwrapped as before: a failure aborts the binary with its
    // description. These go as their callers are ported.
    Bytes donor_image(ImageType type, std::span<const uint8_t> key) {
        return test::must(gxbuild3::test::donor_image(type, key));
    }

    Input donor_input_with_metadata(ImageType type, std::span<const uint8_t> key) {
        return test::must(gxbuild3::test::donor_input_with_metadata(type, key));
    }

    Bytes donor_image_with_metadata(ImageType type, std::span<const uint8_t> key) {
        return test::must(gxbuild3::test::donor_image_with_metadata(type, key));
    }

    // A donor image built twice under the pinned build time with every donor nonce pinned;
    // nullopt unless both builds succeed and are byte-identical.
    std::optional<Bytes> pinned_donor_image(Input input, std::string_view label) {
        auto donor = gxbuild3::test::pinned_donor_image(std::move(input), label);
        if (!donor) {
            std::cerr << "DONOR BUILD ERROR: " << donor.error().describe() << '\n';
            return std::nullopt;
        }
        return std::move(*donor);
    }

    // ResolverTree (tests/support/builders/ResolverTree.hpp) rooted at a fresh directory under
    // the temporary directory, removed again at scope end. A write that fails aborts the binary.
    struct ResolverFixture : gxbuild3::test::ResolverTree {
        ResolverFixture() : ResolverTree(test::must(ResolverTree::make(fresh_root()))) {}

        ~ResolverFixture() {
            std::error_code error;
            std::filesystem::remove_all(root(), error);
        }

        ResolverFixture(const ResolverFixture&) = delete;
        ResolverFixture& operator=(const ResolverFixture&) = delete;

        void write_text(std::string_view relative, std::string_view content) const {
            test::must(ResolverTree::write_text(relative, content));
        }

        void write_binary(std::string_view relative, std::span<const uint8_t> content) const {
            test::must(ResolverTree::write_binary(relative, content));
        }

        BuildArgs complete_loose_args(BuildType build_type = BuildType::Retail,
                                      ImageType image_type = ImageType::SmallBlock) const {
            return test::must(ResolverTree::complete_loose_args(build_type, image_type));
        }

      private:
        static std::filesystem::path fresh_root() {
            const auto unique =
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            return std::filesystem::temp_directory_path() / ("gxbuild3-resolver-" + unique);
        }
    };

    bool test_source_roots_are_all_validated() {
        ResolverFixture fixture;
        fixture.write_text("not-a-directory", "file");
        auto args = fixture.minimum_args();
        args.source_dirs = {fixture.path("first"), fixture.path("not-a-directory")};
        const auto result = fixture.resolve_foundations(args);
        return require(!result &&
                           result.error().code == ResolutionErrorCode::InvalidSourceDirectory,
                       "every declared source root must be a directory") &&
               require(result.error().path == fixture.path("not-a-directory"),
                       "invalid source directory error identifies the rejected root");
    }

    bool test_source_roots_cannot_be_empty() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.source_dirs.clear();
        const auto result = fixture.resolve_foundations(args);
        return require(!result &&
                           result.error().code == ResolutionErrorCode::InvalidSourceDirectory,
                       "direct resolver callers must provide at least one source root");
    }

    bool test_empty_source_root_path_is_rejected() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.source_dirs = {std::filesystem::path{}};
        const auto only_empty = fixture.resolve_foundations(args);
        if (!require(!only_empty &&
                         only_empty.error().code == ResolutionErrorCode::InvalidSourceDirectory &&
                         only_empty.error().path.empty(),
                     "an empty source-root path is rejected before anchoring")) {
            return false;
        }

        args.source_dirs = {fixture.path("first"), std::filesystem::path{}};
        const auto mixed = fixture.resolve_foundations(args);
        return require(!mixed &&
                           mixed.error().code == ResolutionErrorCode::InvalidSourceDirectory &&
                           mixed.error().path.empty(),
                       "an empty source-root path is rejected in a mixed list");
    }

    bool test_only_working_directory_options_are_loaded() {
        ResolverFixture fixture;
        fixture.write_text("working/options.ini",
                           "nofcrt = false\ntype = falcon\nrev = alt\n1blkey = ignored\n"
                           "cpukey = ignored\naddon = ignored\n");
        fixture.write_text("first/options.ini", "nofcrt = true\ndemon = true\n");
        auto args = fixture.minimum_args();
        const auto result = fixture.resolve_foundations(args);
        return require(result.has_value(), "known options and every legacy key resolve") &&
               require(result->options.nofcrt == false,
                       "working-directory options.ini supplies the lowest tier") &&
               require(!result->options.demon,
                       "source-root options.ini is not loaded even for an unoverridden sentinel");
    }

    bool test_cli_options_preserve_bare_boolean_and_repeated_order() {
        ResolverFixture fixture;
        fixture.write_text("working/options.ini", "nofcrt = false\ncfldv = 1\n");
        auto args = fixture.minimum_args();
        args.config = {"nofcrt", "cfldv=2", "nofcrt=false"};
        const auto result = fixture.resolve_foundations(args);
        return require(result.has_value(), "known ordered CLI options resolve") &&
               require(result->options.nofcrt == false,
                       "later CLI values override earlier CLI and options.ini values") &&
               require(result->options.cfldv == "2", "CLI string option overrides options.ini") &&
               require(result->cli_overrides.nofcrt == false && result->cli_overrides.cfldv == "2",
                       "explicit CLI overrides remain distinguishable for later layering");
    }

    bool test_invalid_options_are_precise() {
        ResolverFixture fixture;
        fixture.write_text("working/options.ini", "unrecognized = value\n");
        auto args = fixture.minimum_args();
        const auto unknown_file_option = fixture.resolve_foundations(args);
        if (!require(!unknown_file_option &&
                         unknown_file_option.error().code == ResolutionErrorCode::InvalidOption &&
                         unknown_file_option.error().path == fixture.path("working/options.ini") &&
                         unknown_file_option.error().item == "unrecognized",
                     "unknown options.ini keys are rejected with provenance")) {
            return false;
        }

        fixture.write_text("working/options.ini", "nofcrt = maybe\n");
        const auto malformed_file_option = fixture.resolve_foundations(args);
        if (!require(!malformed_file_option &&
                         malformed_file_option.error().code == ResolutionErrorCode::InvalidOption &&
                         malformed_file_option.error().item == "nofcrt",
                     "malformed known options.ini values are rejected")) {
            return false;
        }

        fixture.write_text("working/options.ini", "nofcrt = false\n");
        args.config = {"not-an-option=true"};
        const auto invalid_cli_option = fixture.resolve_foundations(args);
        return require(!invalid_cli_option &&
                           invalid_cli_option.error().code == ResolutionErrorCode::InvalidOption &&
                           invalid_cli_option.error().path.empty() &&
                           invalid_cli_option.error().item == "not-an-option=true",
                       "invalid CLI configuration is rejected with its original item");
    }

    bool test_empty_cli_option_is_rejected() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.config = {""};
        const auto result = fixture.resolve_foundations(args);
        return require(!result && result.error().code == ResolutionErrorCode::InvalidOption &&
                           result.error().item.empty(),
                       "an empty direct BuildArgs configuration item is invalid");
    }

    bool test_options_read_failure_is_distinct() {
        ResolverFixture fixture;
        std::filesystem::create_directory(fixture.path("working/options.ini"));
        const auto result = fixture.resolve_foundations(fixture.minimum_args());
        return require(!result && result.error().code == ResolutionErrorCode::OptionsReadFailed,
                       "an unreadable options.ini has a distinct error") &&
               require(result.error().path == fixture.path("working/options.ini"),
                       "options read error identifies working-directory options.ini");
    }

    // The options.ini decode, edge by edge: each case is the file's text and either the options
    // it yields or the InvalidOption message and item it is refused with.
    struct OptionsTextCase {
        std::string_view name;
        std::string_view text;
        std::optional<OptionsArgs> options;
        std::string_view message;
        std::string_view item;
    };

    auto options_fields(const OptionsArgs& o) {
        return std::tie(o.cbldv, o.pairing_data, o.cfldv, o.xellbutton, o.xellbutton2, o.cygnos,
                        o.demon, o.olddvd, o.nodvd, o.dualboot, o.nomobile, o.nofcrt, o.noremap,
                        o.noecdremap, o.nandmu, o.nosecurity, o.nosusecurity, o.smcnocheck,
                        o.noblpatch, o.nopatch, o.cputemp, o.gputemp, o.edramtemp, o.overcputemp,
                        o.overgputemp, o.overedramtemp, o.cpufan, o.gpufan, o.dvdkey, o.avregion,
                        o.gameregion, o.dvdregion, o.macid);
    }

    template <class Set> OptionsArgs options_with(Set set) {
        OptionsArgs options{};
        set(options);
        return options;
    }

    std::vector<OptionsTextCase> options_text_cases() {
        const auto error_case = [](std::string_view name, std::string_view text,
                                   std::string_view message, std::string_view item) {
            return OptionsTextCase{name, text, std::nullopt, message, item};
        };
        const auto ok_case = [](std::string_view name, std::string_view text, OptionsArgs options) {
            return OptionsTextCase{name, text, std::move(options), {}, {}};
        };
        return {
            ok_case("empty text", "", {}),
            ok_case("blank and comment lines only",
                    "\n   \n; semi\n# hash\n   ; indented semi\n\t# indented hash\n#cbldv=1\n", {}),
            ok_case("key and value are trimmed", "  nofcrt   =   false  \n\tcbldv\t=\t5\t\n",
                    options_with([](OptionsArgs& o) {
                        o.nofcrt = false;
                        o.cbldv = "5";
                    })),
            ok_case("keys are case-insensitive, values keep their case",
                    "NoFcrt = TRUE\nCFLDV = Ab\n", options_with([](OptionsArgs& o) {
                        o.nofcrt = true;
                        o.cfldv = "Ab";
                    })),
            ok_case("leading dashes are stripped from the key", "--cbldv = 4\n",
                    options_with([](OptionsArgs& o) { o.cbldv = "4"; })),
            ok_case("a dash then a space still names the option through OptionsManager",
                    "- cfldv = 6\n", options_with([](OptionsArgs& o) { o.cfldv = "6"; })),
            error_case("a dash then a space keeps the inner space in an unknown key",
                       "- bogus = 1\n", "Invalid option ' bogus' in options.ini (line 1)",
                       " bogus"),
            error_case("a space inside the key is kept", "no fcrt = 1\n",
                       "Invalid option 'no fcrt' in options.ini (line 1)", "no fcrt"),
            ok_case("the first '=' splits key from value", "pairing_data = a=b\n",
                    options_with([](OptionsArgs& o) { o.pairing_data = "a=b"; })),
            ok_case("an inline ';' comment is cut and the value re-trimmed", "cfldv = 7 ; seven\n",
                    options_with([](OptionsArgs& o) { o.cfldv = "7"; })),
            ok_case("an inline '#' is not a comment", "cfldv = 7 # seven\n",
                    options_with([](OptionsArgs& o) { o.cfldv = "7 # seven"; })),
            ok_case("a ';' right after '=' leaves an empty string value", "cbldv = ; nothing\n",
                    options_with([](OptionsArgs& o) { o.cbldv = ""; })),
            ok_case("a string option with an empty value is stored empty", "cbldv=\n",
                    options_with([](OptionsArgs& o) { o.cbldv = ""; })),
            ok_case("an empty boolean value is true", "nofcrt =\ndemon = ; c\n",
                    options_with([](OptionsArgs& o) {
                        o.nofcrt = true;
                        o.demon = true;
                    })),
            ok_case("an empty button value clears it", "xellbutton = power\nxellbutton =\n", {}),
            ok_case("a later line wins", "cfldv = 1\ncfldv = 2\n",
                    options_with([](OptionsArgs& o) { o.cfldv = "2"; })),
            ok_case("nopatch stages accumulate", "nopatch = khv\nnopatch = cb\n",
                    options_with([](OptionsArgs& o) { o.nopatch = "cb+khv"; })),
            ok_case("aliases reach their option", "pd = 0a0b0c\nnochecksmc = yes\n",
                    options_with([](OptionsArgs& o) {
                        o.pairing_data = "0a0b0c";
                        o.smcnocheck = true;
                    })),
            ok_case("legacy keys are skipped whatever their value",
                    "type = falcon\nrev = \n1blkey=zz\ncpukey = 00\naddon = x;y\n", {}),
            ok_case("legacy keys match after normalization", "--TYPE = x\n", {}),
            error_case("a legacy key without '=' is still refused", "type\n",
                       "Expected key=value in options.ini (line 1)", "type"),
            error_case("a bare boolean without '=' is refused", "cbldv = 1\nnofcrt\n",
                       "Expected key=value in options.ini (line 2)", "nofcrt"),
            error_case("a bare string option without '=' is refused", "  cbldv  \n",
                       "Expected key=value in options.ini (line 1)", "cbldv"),
            error_case("a section header is refused with its line",
                       "nofcrt = true\n\n  [falconbl]  \n",
                       "Sections are not valid in options.ini (line 3)", "[falconbl]"),
            ok_case("a '[' after the key is part of the value", "cfldv = [1]\n",
                    options_with([](OptionsArgs& o) { o.cfldv = "[1]"; })),
            error_case("an empty key is refused", " = 5\n",
                       "Invalid option '' in options.ini (line 1)", ""),
            error_case("line numbers count blank and comment lines", "\n; c\n\nbogus = 1\n",
                       "Invalid option 'bogus' in options.ini (line 4)", "bogus"),
            error_case("an invalid boolean value is refused", "nofcrt = maybe\n",
                       "Invalid option 'nofcrt' in options.ini (line 1)", "nofcrt"),
            error_case("an invalid nopatch stage is refused", "nopatch = sc\n",
                       "Invalid option 'nopatch' in options.ini (line 1)", "nopatch"),
            error_case("the first bad line stops the decode", "bogus = 1\n[x]\n",
                       "Invalid option 'bogus' in options.ini (line 1)", "bogus"),
            ok_case("CRLF line endings are accepted", "cbldv = 1\r\n\r\n; c\r\ncfldv = 2 ; x\r\n",
                    options_with([](OptionsArgs& o) {
                        o.cbldv = "1";
                        o.cfldv = "2";
                    })),
            error_case("CRLF lines are counted once", "cbldv = 1\r\n\r\nbogus\r\n",
                       "Expected key=value in options.ini (line 3)", "bogus"),
            ok_case("a lone CR is not a line break", "cbldv = 1\rcfldv = 2\n",
                    options_with([](OptionsArgs& o) { o.cbldv = "1\rcfldv = 2"; })),
            ok_case("the last line needs no newline", "cfldv = 9",
                    options_with([](OptionsArgs& o) { o.cfldv = "9"; })),
            error_case("a UTF-8 BOM stays part of the first key",
                       "\xEF\xBB\xBF"
                       "cbldv = 1\n",
                       "Invalid option '\xEF\xBB\xBF"
                       "cbldv' in options.ini (line 1)",
                       "\xEF\xBB\xBF"
                       "cbldv"),
        };
    }

    bool
    check_options_case(const OptionsTextCase& expected,
                       const std::expected<OptionsArgs, gxbuild3::cli::ResolutionError>& result,
                       const std::filesystem::path& source, std::string_view via) {
        const std::string label = std::string(via) + ": " + std::string(expected.name);
        if (expected.options) {
            if (!result) {
                std::cerr << "  error: '" << result.error().message << "' item '"
                          << result.error().item << "'\n";
                return require(false, label);
            }
            return require(options_fields(*result) == options_fields(*expected.options), label);
        }
        if (result) {
            return require(false, label + " (decoded without an error)");
        }
        const auto& error = result.error();
        const bool matches = error.code == ResolutionErrorCode::InvalidOption &&
                             error.message == expected.message && error.item == expected.item &&
                             error.path == source;
        if (!matches) {
            std::cerr << "  code=" << static_cast<int>(error.code) << " message='" << error.message
                      << "' item='" << error.item << "' path='" << error.path.string() << "'\n";
        }
        return require(matches, label);
    }

    bool test_options_ini_edge_cases_through_the_file() {
        ResolverFixture fixture;
        const auto args = fixture.minimum_args();
        bool passed = true;
        for (const auto& options_case : options_text_cases()) {
            fixture.write_text("working/options.ini", options_case.text);
            const auto result = fixture.resolve_foundations(args);
            std::expected<OptionsArgs, gxbuild3::cli::ResolutionError> decoded;
            if (result) {
                decoded = result->file_options;
            } else {
                decoded = std::unexpected(result.error());
            }
            passed = check_options_case(options_case, decoded, fixture.path("working/options.ini"),
                                        "options.ini") &&
                     passed;
        }
        return passed;
    }

    bool test_parse_options_text_edge_cases() {
        const std::filesystem::path source = "virtual/options.ini";
        bool passed = true;
        for (const auto& options_case : options_text_cases()) {
            passed = check_options_case(
                         options_case, gxbuild3::cli::parse_options_text(options_case.text, source),
                         source, "parse_options_text") &&
                     passed;
        }
        return passed;
    }

    bool test_cpu_key_precedence_and_discovery_order() {
        ResolverFixture fixture;
        const auto first_key = valid_cpu_key();
        const auto second_key = valid_cpu_key(true);
        fixture.write_text("first/cpukey.txt", " \r\n" + hex(first_key) + "\t\n");
        fixture.write_text("second/cpukey.txt", hex(second_key));
        auto args = fixture.minimum_args();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.cpu_key.reset();
        const auto discovered = fixture.resolve_foundations(args);
        if (!require(discovered && discovered->cpu_key == first_key,
                     "the first source root supplies the discovered CPU key")) {
            return false;
        }

        args.cpu_key = "  " + hex(second_key) + "\r\n";
        const auto explicit_key = fixture.resolve_foundations(args);
        return require(explicit_key && explicit_key->cpu_key == second_key,
                       "an explicit trimmed CPU key overrides every source root");
    }

    bool test_relative_source_root_is_anchored_to_working_directory() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_text("first/cpukey.txt", hex(key));
        auto args = fixture.minimum_args();
        args.cpu_key.reset();
        args.source_dirs = {"../first"};
        const auto result = fixture.resolve_foundations(args);
        return require(result && result->cpu_key == key,
                       "relative source roots resolve from the explicit working directory");
    }

    bool test_uppercase_and_corrected_cpu_keys_are_accepted() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        auto args = fixture.minimum_args();
        args.cpu_key = uppercase(hex(key));
        const auto uppercase_result = fixture.resolve_foundations(args);
        if (!require(uppercase_result && uppercase_result->cpu_key == key,
                     "uppercase hexadecimal CPU keys are accepted")) {
            return false;
        }

        auto correctable = key;
        correctable.front() ^= 0x01;
        args.cpu_key = hex(correctable);
        const auto corrected_result = fixture.resolve_foundations(args);
        return require(corrected_result && corrected_result->cpu_key == key,
                       "correctable CPU-key ECC errors return the corrected 16-byte key");
    }

    bool test_cpu_key_errors_are_precise() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.cpu_key.reset();
        const auto missing = fixture.resolve_foundations(args);
        if (!require(!missing && missing.error().code == ResolutionErrorCode::CpuKeyNotFound,
                     "missing CPU key is reported distinctly")) {
            return false;
        }

        fixture.write_text("first/cpukey.txt", "0123xyz\n");
        const auto invalid_file = fixture.resolve_foundations(args);
        if (!require(!invalid_file &&
                         invalid_file.error().code == ResolutionErrorCode::InvalidCpuKey &&
                         invalid_file.error().path == fixture.path("first/cpukey.txt"),
                     "invalid discovered CPU key identifies its file")) {
            return false;
        }

        args.cpu_key = "not-a-cpu-key";
        const auto invalid_explicit = fixture.resolve_foundations(args);
        return require(!invalid_explicit &&
                           invalid_explicit.error().code == ResolutionErrorCode::InvalidCpuKey &&
                           invalid_explicit.error().path.empty(),
                       "invalid explicit CPU key is not attributed to a file");
    }

    bool test_cpu_key_lookup_failure_does_not_fall_through() {
        ResolverFixture fixture;
        std::filesystem::create_directory(fixture.path("first/cpukey.txt"));
        fixture.write_text("second/cpukey.txt", hex(valid_cpu_key()));
        auto args = fixture.minimum_args();
        args.cpu_key.reset();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};

        try {
            const auto result = fixture.resolve_foundations(args);
            return require(!result &&
                               result.error().code == ResolutionErrorCode::CpuKeyReadFailed &&
                               result.error().path == fixture.path("first/cpukey.txt") &&
                               result.error().item == "cpukey.txt",
                           "first-priority CPU-key inspection failure is structured and terminal");
        } catch (...) {
            return require(false, "CPU-key filesystem failures must not escape the resolver");
        }
    }

    bool test_nand_discovery_and_explicit_override() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin", donor_image(ImageType::SmallBlock, key));
        fixture.write_binary("second/nanddump.bin", Bytes{0x00, 0x01});
        auto args = fixture.minimum_args();
        args.cpu_key = hex(key);
        args.image_type.reset();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        const auto discovered = fixture.resolve_foundations(args);
        if (!require(discovered && discovered->donor &&
                         discovered->image_type == ImageType::SmallBlock,
                     "the first exact nanddump.bin is discovered and determines layout")) {
            return false;
        }

        fixture.write_binary("explicit.bin", donor_image(ImageType::BigBlock, key));
        args.input_path = "../explicit.bin";
        const auto explicit_nand = fixture.resolve_foundations(args);
        if (!require(explicit_nand && explicit_nand->donor &&
                         explicit_nand->image_type == ImageType::BigBlock,
                     "relative explicit NAND resolves from the supplied working directory")) {
            return false;
        }

        args.input_path = fixture.path("explicit.bin");
        args.output_path = fixture.path("absolute-output.bin");
        args.build_ini = "build.ini";
        args.section = "falcon";
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        const auto absolute = BuildInputResolver(fixture.working_directory()).resolve(args);
        return require(absolute && absolute->input.image_type == ImageType::BigBlock &&
                           absolute->output_path == fixture.path("absolute-output.bin"),
                       "absolute explicit NAND and output paths remain absolute");
    }

    bool test_nand_errors_are_precise() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.input_path = "missing.bin";
        const auto missing = fixture.resolve_foundations(args);
        if (!require(!missing && missing.error().code == ResolutionErrorCode::InputReadFailed &&
                         missing.error().path == fixture.path("working/missing.bin"),
                     "missing explicit NAND reports its resolved path")) {
            return false;
        }

        fixture.write_binary("working/bad.bin", Bytes{0x00, 0x01, 0x02});
        args.input_path = "bad.bin";
        const auto invalid = fixture.resolve_foundations(args);
        return require(!invalid && invalid.error().code == ResolutionErrorCode::InvalidDonor &&
                           invalid.error().path == fixture.path("working/bad.bin"),
                       "unextractable NAND is reported as InvalidDonor");
    }

    bool test_nand_lookup_failure_does_not_fall_through() {
        ResolverFixture fixture;
        std::filesystem::create_directory(fixture.path("first/nanddump.bin"));
        fixture.write_binary("second/nanddump.bin", Bytes{0x00, 0x01});
        auto args = fixture.minimum_args();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};

        try {
            const auto result = fixture.resolve_foundations(args);
            return require(!result && result.error().code == ResolutionErrorCode::InputReadFailed &&
                               result.error().path == fixture.path("first/nanddump.bin") &&
                               result.error().item == "nanddump.bin",
                           "first-priority NAND inspection failure is structured and terminal");
        } catch (...) {
            return require(false, "NAND filesystem failures must not escape the resolver");
        }
    }

    bool test_malformed_supported_size_nand_is_invalid_donor() {
        ResolverFixture fixture;
        fixture.write_binary("working/malformed.bin", malformed_supported_size_nand());
        auto args = fixture.minimum_args();
        args.input_path = "malformed.bin";

        try {
            const auto result = fixture.resolve_foundations(args);
            return require(!result && result.error().code == ResolutionErrorCode::InvalidDonor &&
                               result.error().path == fixture.path("working/malformed.bin"),
                           "malformed supported-size NAND maps to InvalidDonor with provenance");
        } catch (...) {
            return require(false, "donor parser exceptions must not escape resolve_foundations");
        }
    }

    bool test_layout_override_only_clears_raw_backing() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin", donor_image(ImageType::SmallBlock, key));
        auto args = fixture.minimum_args();
        args.cpu_key = hex(key);
        args.image_type = ImageType::BigBlock;
        const auto result = fixture.resolve_foundations(args);
        return require(result && result->donor && result->image_type == ImageType::BigBlock &&
                           result->donor->image_type == ImageType::BigBlock,
                       "explicit layout overrides the donor layout") &&
               require(!result->donor->metadata.nand_image,
                       "layout mismatch clears only raw donor backing") &&
               require(result->donor->metadata.smc && result->donor->metadata.keyvault &&
                           !result->donor->bootloaders.cb_or_a.empty() &&
                           !result->donor->bootloaders.cd.empty(),
                       "layout mismatch retains all extracted donor components");
    }

    bool test_matching_or_implicit_layout_retains_raw_backing() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin", donor_image(ImageType::SmallBlock, key));
        auto args = fixture.minimum_args();
        args.cpu_key = hex(key);
        args.image_type = ImageType::SmallBlock;
        const auto matching = fixture.resolve_foundations(args);
        if (!require(matching && matching->donor && matching->donor->metadata.nand_image,
                     "matching explicit layout retains raw donor backing")) {
            return false;
        }

        args.image_type.reset();
        const auto detected = fixture.resolve_foundations(args);
        return require(detected && detected->donor && detected->donor->metadata.nand_image,
                       "detected donor layout retains raw donor backing");
    }

    bool test_layout_is_required_without_a_donor() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.image_type.reset();
        const auto missing = fixture.resolve_foundations(args);
        if (!require(!missing && missing.error().code == ResolutionErrorCode::BlockTypeRequired,
                     "block layout is required when no donor exists")) {
            return false;
        }

        args.image_type = ImageType::Emmc;
        const auto explicit_layout = fixture.resolve_foundations(args);
        return require(explicit_layout && !explicit_layout->donor &&
                           explicit_layout->image_type == ImageType::Emmc,
                       "explicit block layout permits donor-free foundations");
    }

    bool test_resolve_delegates_to_foundations() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        args.cpu_key.reset();
        const auto result = BuildInputResolver(fixture.working_directory()).resolve(args);
        return require(!result && result.error().code == ResolutionErrorCode::CpuKeyNotFound,
                       "Resolve exposes foundation failures before Task 7 phases");
    }

    bool test_resolve_anchors_relative_output_to_working_directory() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        args.output_path = "nested/result.bin";
        const auto result = BuildInputResolver(fixture.working_directory()).resolve(args);
        return require_resolved(result, "complete output-path fixture resolves") &&
               require(result->output_path == fixture.path("working/nested/result.bin"),
                       "Resolve anchors a relative output path to its working directory");
    }

    bool test_build_ini_is_required_readable_and_exact_section_is_selected() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        args.build_ini.clear();
        const auto missing_argument = fixture.resolve(args);
        if (!require(!missing_argument &&
                         missing_argument.error().code == ResolutionErrorCode::BuildIniReadFailed,
                     "a build INI path is mandatory")) {
            return false;
        }

        args.build_ini = "missing.ini";
        const auto missing_file = fixture.resolve(args);
        if (!require(!missing_file &&
                         missing_file.error().code == ResolutionErrorCode::BuildIniReadFailed &&
                         missing_file.error().path == fixture.path("working/missing.ini"),
                     "a relative missing INI reports its working-directory path")) {
            return false;
        }

        fixture.write_text("working/build.ini", "[falcon]\ncb.bin\ncd.bin\n");
        args.build_ini = "build.ini";
        const auto wrong_section = fixture.resolve(args);
        return require(!wrong_section &&
                           wrong_section.error().code == ResolutionErrorCode::SectionNotFound &&
                           wrong_section.error().path == fixture.path("working/build.ini") &&
                           wrong_section.error().item == "falconbl",
                       "the resolver requires exactly [<section stem>bl] without inference");
    }

    bool test_ini_sc_bootloader_reaches_resolved_input() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        const auto sc = *valid_bootloaders().sc;
        fixture.write_binary("first/sc_1.bin", sc);
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\nsc_1.bin\ncd.bin\n");

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "INI SC bootloader fixture resolves") ||
            !require(result->input.bootloaders.sc == sc,
                     "INI SC bytes are retained in the resolved Input")) {
            return false;
        }
        fixture.write_binary("first/nanddump.bin",
                             donor_image(ImageType::SmallBlock, valid_cpu_key()));
        auto replacement_sc = sc;
        replacement_sc.back() ^= 1;
        fixture.write_binary("first/3bl.bin", replacement_sc);
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\n3bl.bin\ncd.bin\n");
        const auto donor = fixture.resolve(args);
        if (!require_resolved(donor, "donor plus INI SC override resolves") ||
            !require(donor->input.bootloaders.sc == replacement_sc &&
                         donor->input.metadata.nand_image.has_value(),
                     "INI SC replaces donor SC while preserving donor backing")) {
            return false;
        }
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        const auto without_sc = fixture.resolve(args);
        return require_resolved(without_sc, "INI chain omitting SC resolves") &&
               require(!without_sc->input.bootloaders.sc,
                       "the selected INI chain does not inherit an omitted donor SC");
    }

    bool test_loose_donor_requires_and_populates_every_component() {
        ResolverFixture fixture;
        auto args = fixture.minimum_args();
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        args.build_ini = "build.ini";
        args.section = "falcon";

        const auto incomplete = fixture.resolve(args);
        if (!require(!incomplete &&
                         incomplete.error().code == ResolutionErrorCode::IncompleteLooseDonor &&
                         incomplete.error().item == "kv.bin",
                     "the first missing loose-donor component is reported precisely")) {
            return false;
        }

        const auto key = valid_cpu_key();
        const auto expected_keyvault = canonical_keyvault_filled(key, 0x48);
        fixture.write_binary("first/kv.bin", encrypted_keyvault(key, 0x48));
        fixture.write_binary("first/smc.bin", make_smc(0x49));
        fixture.write_text("working/options.ini", "cbldv=0x0a\ncfldv=11\npairing_data=a1b2c3\n");
        const auto complete = fixture.resolve(args);
        return require_resolved(complete, "a complete loose donor resolves") &&
               require(complete->input.metadata.keyvault == expected_keyvault,
                       "loose encrypted kv.bin becomes canonical plaintext input") &&
               require(complete->input.metadata.smc == make_smc(0x49),
                       "loose smc.bin populates the input") &&
               require(complete->input.metadata.cb_ldv == 10 &&
                           complete->input.metadata.cf_ldv == 11 &&
                           complete->input.metadata.pairing_data ==
                               std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3},
                       "loose donor metadata is fully parsed") &&
               require(complete->input.bootloaders.cb_or_a == Bytes{0xCB} &&
                           complete->input.bootloaders.cd == Bytes{0xCD},
                       "the exact INI section supplies the bootloader chain");
    }

    // A kv.bin that does not open under the CPU key is the console's keyvault in the clear, as
    // J-Runner supplies it for a console whose key is unknown; one of 0x3FF0 bytes lacks its
    // nonce. Any other length is refused.
    bool test_loose_keyvault_in_the_clear_is_taken_as_it_stands() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        const auto key = valid_cpu_key();
        const auto clear = canonical_keyvault_filled(key, 0x5A);
        fixture.write_binary("first/kv.bin", clear);
        const auto whole = fixture.resolve(args);
        if (!require_resolved(whole, "a kv.bin in the clear resolves") ||
            !require(whole->input.metadata.keyvault == clear,
                     "a kv.bin in the clear is the build's keyvault as it stands")) {
            return false;
        }

        fixture.write_binary("first/kv.bin", Bytes(clear.begin() + 0x10, clear.end()));
        const auto bare = fixture.resolve(args);
        Bytes zero_nonce = clear;
        std::fill(zero_nonce.begin(), zero_nonce.begin() + 0x10, 0);
        if (!require_resolved(bare, "a kv.bin without its nonce resolves") ||
            !require(bare->input.metadata.keyvault == zero_nonce,
                     "a kv.bin without its nonce gets sixteen zero bytes in front")) {
            return false;
        }

        // Sealed for another console, it opens under no key: xeBuild 1.21 reports it and still
        // takes it as the keyvault in the clear, and so does this.
        const auto foreign = encrypted_keyvault(valid_cpu_key(true), 0x5A);
        fixture.write_binary("first/kv.bin", foreign);
        const auto other = fixture.resolve(args);
        if (!require_resolved(other, "a kv.bin sealed under another key resolves") ||
            !require(other->input.metadata.keyvault == foreign,
                     "a kv.bin sealed under another key is taken as it stands")) {
            return false;
        }

        fixture.write_binary("first/kv.bin", Bytes(0x100, 0x5A));
        const auto wrong_length = fixture.resolve(args);
        return require(!wrong_length &&
                           wrong_length.error().code == ResolutionErrorCode::InvalidInput &&
                           wrong_length.error().item == "kv.bin",
                       "a kv.bin of another length is refused");
    }

    // Under the all-zero CPU key the donor's keyvault does not open; the donor still resolves,
    // and the console's kv.bin supplies the keyvault. Without one the build is refused.
    bool test_zero_cpu_key_donor_takes_the_keyvault_from_kv_bin() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin", donor_image(ImageType::SmallBlock, key));
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        args.cpu_key = std::string(32, '0');

        const auto without = fixture.resolve(args);
        if (!require(!without && without.error().code == ResolutionErrorCode::InvalidInput &&
                         without.error().item == "kv.bin",
                     "a zero-key donor without kv.bin is refused for want of a keyvault")) {
            return false;
        }

        const auto clear = canonical_keyvault_filled(key, 0x72);
        fixture.write_binary("first/kv.bin", clear);
        const auto with = fixture.resolve(args);
        return require_resolved(with, "a zero-key donor with kv.bin resolves") &&
               require(with->input.metadata.keyvault == clear &&
                           with->input.metadata.cpu_key == Bytes(16, 0) &&
                           with->input.metadata.nand_image.has_value(),
                       "the zero-key build carries the donor and the kv.bin's keyvault");
    }

    bool test_metadata_precedence_and_user_file_overrides() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin", donor_image(ImageType::SmallBlock, key));
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        fixture.write_text("working/options.ini",
                           "cbldv=7\ncfldv=8\npairing_data=010203\nnofcrt=true\n");
        fixture.write_binary("first/kv.bin", encrypted_keyvault(key, 0x44));
        fixture.write_binary("first/smc.bin", make_smc(0x45));
        fixture.write_binary("first/mobileA.bin", Bytes{0xA1});
        fixture.write_binary("first/mobileI.bin", Bytes{0xA9});

        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        const auto donor_layered = fixture.resolve(args);
        if (!require_resolved(donor_layered, "donor precedence fixture resolves") ||
            !require(donor_layered->input.metadata.cb_ldv == 0 &&
                         donor_layered->input.metadata.cf_ldv == 8 &&
                         donor_layered->input.metadata.pairing_data ==
                             std::array<uint8_t, 3>{0, 0, 0},
                     "donor metadata beats options.ini while absent donor values use defaults")) {
            return false;
        }

        args.config = {"cbldv=4", "cfldv=5", "pairing_data=0a0b0c", "nofcrt=false"};
        const auto result = fixture.resolve(args);
        return require_resolved(result, "donor plus user overlays resolves") &&
               require(result->input.metadata.keyvault == canonical_keyvault_filled(key, 0x44) &&
                           result->input.metadata.smc == make_smc(0x45),
                       "user KV and SMC replace donor values") &&
               require(*result->input.mobiles.slot(0x31) == Bytes{0xA1} &&
                           *result->input.mobiles.slot(0x39) == Bytes{0xA9},
                       "mobileA through mobileI map to slots 0x31 through 0x39") &&
               require(result->input.metadata.cb_ldv == 4 && result->input.metadata.cf_ldv == 5 &&
                           result->input.metadata.pairing_data ==
                               std::array<uint8_t, 3>{0x0A, 0x0B, 0x0C},
                       "CLI metadata overrides donor and options.ini") &&
               require(result->input.options.nofcrt == false,
                       "an explicit false CLI value remains present and wins");
    }

    bool test_flashfs_holds_ini_files_and_donor_secured_files_only() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        Input donor{};
        donor.image_type = ImageType::SmallBlock;
        donor.metadata.cpu_key = key;
        donor.metadata.smc = make_smc(0x61);
        donor.metadata.keyvault = canonical_keyvault_filled(key, 0x62);
        donor.bootloaders = valid_bootloaders();
        donor.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"Launch.ini", Bytes{0x10}},        {"launch.INI", Bytes{0x11}},
            {"SECDATA.BIN", Bytes(0x20, 0x20)}, {"extended.bin", Bytes(0x20, 0x22)},
            {"crl.bin", Bytes{0x23}},           {"fcrt.bin", Bytes{0x24}},
            {"listed.bin", Bytes{0x25}},        {"donor.bin", Bytes{0x30}},
            {"aac.xexp2", Bytes{0x31}},         {"aac.xexp1", Bytes{0x32}},
            {"sysupdate.xexp2", Bytes{0x33}}};
        const auto image = run_build(donor);
        if (!image) {
            return require(false, "FlashFS donor fixture builds");
        }
        // The donor's extended.bin was the wrong length, so its image carries a clean one.
        const auto donor_files = extract_all(*image, key);
        Bytes donor_extended;
        for (const auto& [name, data] : donor_files
                                            ? *donor_files->flashfs_sec
                                            : std::vector<std::pair<std::string, Bytes>>{}) {
            if (name == "extended.bin") {
                donor_extended = data;
            }
        }
        fixture.write_binary("first/nanddump.bin", *image);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_binary("first/launch.ini", Bytes{0x41});
        const auto plaintext_secdata = Bytes(0x20, 0x51);
        auto encrypted_secdata = plaintext_secdata;
        if (!gxbuild3::nand::crypt_secfile(key, encrypted_secdata)) {
            return require(false, "secure fixture encrypts");
        }
        fixture.write_binary("first/secdata.bin", encrypted_secdata);
        fixture.write_binary("first/new.bin", Bytes{0x61});
        fixture.write_binary("first/aac.xexp", Bytes{0x62});
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsecdata.bin\nextended.bin\n"
                           "[flashfs]\nlaunch.ini\nnew.bin\nlisted.bin\naac.xexp\n");

        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "INI FlashFS and security entries resolve") ||
            !require(result->input.flashfs_sec.has_value(), "resolved input has FlashFS files")) {
            return false;
        }
        const auto& files = *result->input.flashfs_sec;
        const auto find = [&](std::string_view name) {
            return std::find_if(files.begin(), files.end(), [name](const auto& file) {
                std::string lower = file.first;
                std::transform(lower.begin(), lower.end(), lower.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                return lower == name;
            });
        };
        const auto has = [&](std::string_view name, const Bytes& contents) {
            const auto file = find(name);
            return file != files.end() && file->second == contents;
        };
        // xeBuild 1.21 order: [flashfs] in INI order, then [security] in INI order, then the
        // console's secured files the INI does not name.
        const std::array<std::string_view, 8> order{"launch.ini", "new.bin",     "listed.bin",
                                                    "aac.xexp1",  "secdata.bin", "extended.bin",
                                                    "crl.bin",    "fcrt.bin"};
        bool ordered = files.size() == order.size();
        for (size_t i = 0; ordered && i < order.size(); ++i) {
            ordered = find(order[i]) == files.begin() + static_cast<std::ptrdiff_t>(i);
        }
        return require(files.size() == 8, "the FlashFS holds exactly the expected files") &&
               require(ordered, "the FlashFS lists [flashfs], then [security], then the "
                                "console's other secured files") &&
               require(has("launch.ini", Bytes{0x41}),
                       "an INI file from the source roots replaces the donor basename") &&
               require(has("secdata.bin", plaintext_secdata),
                       "a secure INI file from the source roots arrives as plaintext") &&
               require(donor_extended.size() == 0x4000 && has("extended.bin", donor_extended),
                       "an INI security file missing from the roots comes from the donor") &&
               require(has("crl.bin", Bytes{0x23}) && has("fcrt.bin", Bytes{0x24}),
                       "donor secured files are carried without an INI entry") &&
               require(has("listed.bin", Bytes{0x25}),
                       "an INI file missing from the roots comes from the donor") &&
               require(has("new.bin", Bytes{0x61}), "a new INI file is added") &&
               require(has("aac.xexp1", Bytes{0x62}),
                       "an INI patch file is suffixed and replaces the donor copy") &&
               require(find("donor.bin") == files.end() && find("aac.xexp2") == files.end() &&
                           find("sysupdate.xexp2") == files.end(),
                       "unlisted donor files, patch files and CG tails are dropped");
    }

    // An extended.bin or secdata.bin the INI's [security] names reaches run_build even when
    // nothing supplies it (empty) or it is too short to hold a nonce (as supplied); run_build makes
    // up a clean one for each.
    bool test_unsupplied_security_files_reach_the_build() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nextended.bin\nsecdata.bin\n");
        fixture.write_binary("first/extended.bin", Bytes(5, 0x45));
        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "a build whose security files are missing resolves") ||
            !require(result->input.flashfs_sec.has_value(), "resolved input has FlashFS files")) {
            return false;
        }
        const auto& files = *result->input.flashfs_sec;
        return require(files.size() == 2 && files[0].first == "extended.bin" &&
                           files[0].second == Bytes(5, 0x45),
                       "a short extended.bin is carried as supplied") &&
               require(files[1].first == "secdata.bin" && files[1].second.empty(),
                       "a missing secdata.bin is carried empty");
    }

    // fcrt.bin is in the FlashFS when the INI's [security] lists it and a source supplies it, as
    // xeBuild 1.21 puts it there. The keyvault's flag (none, 0x0020, 0x0200) and nofcrt neither
    // add it nor drop it; they only change what is said about a missing one.
    bool test_fcrt_follows_the_ini_not_the_keyvault() {
        const auto key = valid_cpu_key();
        bool passed = true;
        for (const uint16_t features : {0x0000, 0x0020, 0x0200}) {
            Bytes plain(Keyvault::kSize, 0x00);
            plain[0x1C] = static_cast<uint8_t>(features >> 8);
            plain[0x1D] = static_cast<uint8_t>(features);
            for (const bool listed : {true, false}) {
                for (const bool supplied : {true, false}) {
                    for (const bool nofcrt : {false, true}) {
                        ResolverFixture fixture;
                        auto args = fixture.complete_loose_args();
                        fixture.write_binary("first/kv.bin", keyvault_encrypt(key, plain).value());
                        fixture.write_text(
                            "working/build.ini",
                            std::string("[falconbl]\ncb_1.bin\ncd.bin\n[security]\n") +
                                (listed ? "fcrt.bin\n" : ";fcrt.bin,\n"));
                        const Bytes fcrt(0x4000, 0x46);
                        if (supplied) {
                            fixture.write_binary("first/fcrt.bin", fcrt);
                        }
                        if (nofcrt) {
                            args.config = {"nofcrt"};
                        }
                        const auto result = fixture.resolve(args);
                        if (!require_resolved(result,
                                              "a build with or without fcrt.bin resolves")) {
                            passed = false;
                            continue;
                        }
                        const auto& files = result->input.flashfs_sec;
                        const bool held =
                            files && std::any_of(files->begin(), files->end(), [&](const auto& f) {
                                return f.first == "fcrt.bin" && f.second == fcrt;
                            });
                        const bool any =
                            files && std::any_of(files->begin(), files->end(), [](const auto& f) {
                                return f.first == "fcrt.bin";
                            });
                        passed = require(held == (listed && supplied) && any == held,
                                         "fcrt.bin is in the FlashFS exactly when the INI lists it "
                                         "and a source supplies it") &&
                                 passed;
                    }
                }
            }
        }
        return passed;
    }

    bool test_metadata_values_require_full_valid_strings() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        fixture.write_text("working/options.ini", "cbldv=7tail\ncfldv=3\npairing_data=010203\n");
        const auto bad_ldv = fixture.resolve(args);
        if (!require(!bad_ldv && bad_ldv.error().code == ResolutionErrorCode::InvalidInput &&
                         bad_ldv.error().item == "cbldv",
                     "LDV parsing rejects trailing content")) {
            return false;
        }

        fixture.write_text("working/options.ini", "cbldv=2\ncfldv=3\npairing_data=01020304\n");
        const auto bad_pairing = fixture.resolve(args);
        return require(!bad_pairing &&
                           bad_pairing.error().code == ResolutionErrorCode::InvalidInput &&
                           bad_pairing.error().item == "pairing_data",
                       "pairing data must contain exactly three bytes");
    }

    bool test_metadata_parses_only_the_winning_precedence_source() {
        ResolverFixture donor_fixture;
        const auto key = valid_cpu_key();
        donor_fixture.write_binary("first/nanddump.bin",
                                   donor_image_with_metadata(ImageType::SmallBlock, key));
        donor_fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        donor_fixture.write_binary("first/cd.bin", Bytes{0xCD});
        donor_fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        donor_fixture.write_text("working/options.ini", "cbldv=bad\ncfldv=bad\npairing_data=bad\n");
        auto donor_args = donor_fixture.minimum_args();
        donor_args.build_ini = "build.ini";
        donor_args.section = "falcon";
        donor_args.image_type.reset();
        const auto donor = donor_fixture.resolve(donor_args);
        if (!require_resolved(donor, "donor metadata overrides malformed options.ini metadata") ||
            !require(donor->input.metadata.cb_ldv == 7 && donor->input.metadata.cf_ldv == 8 &&
                         donor->input.metadata.pairing_data ==
                             std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3},
                     "donor values are selected before parsing lower-precedence text")) {
            return false;
        }

        ResolverFixture cli_fixture;
        auto cli_args = cli_fixture.complete_loose_args();
        cli_fixture.write_text("working/options.ini", "cbldv=bad\ncfldv=bad\npairing_data=bad\n");
        cli_args.config = {"cbldv=9", "cfldv=10", "pairing_data=a1b2c3"};
        const auto cli = cli_fixture.resolve(cli_args);
        return require_resolved(cli, "CLI metadata overrides malformed options.ini metadata") &&
               require(cli->input.metadata.cb_ldv == 9 && cli->input.metadata.cf_ldv == 10 &&
                           cli->input.metadata.pairing_data ==
                               std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3},
                       "CLI metadata is parsed only after winning precedence is selected");
    }

    bool test_cli_pairing_override_reaches_the_cf_and_console_is_carried() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin",
                             donor_image_with_metadata(ImageType::SmallBlock, key));
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.console = ConsoleType::Falcon;
        args.image_type.reset();
        const auto donor = fixture.resolve(args);
        if (!require_resolved(donor, "donor CF pairing fixture resolves") ||
            !require(donor->input.metadata.cf_pairing_data ==
                         std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3},
                     "the donor CF pairing reaches the input") ||
            !require(donor->input.console == ConsoleType::Falcon,
                     "the selected console reaches the input")) {
            return false;
        }

        args.config = {"pairing_data=0a0b0c"};
        const auto overridden = fixture.resolve(args);
        return require_resolved(overridden, "CLI pairing override resolves") &&
               require(overridden->input.metadata.pairing_data ==
                               std::array<uint8_t, 3>{0x0A, 0x0B, 0x0C} &&
                           !overridden->input.metadata.cf_pairing_data,
                       "a CLI pairing override also replaces the donor CF pairing");
    }

    bool test_metadata_winner_errors_report_the_winning_source() {
        ResolverFixture file_fixture;
        auto file_args = file_fixture.complete_loose_args();
        file_fixture.write_text("working/options.ini", "cbldv=bad\ncfldv=3\npairing_data=010203\n");
        const auto file = file_fixture.resolve(file_args);
        if (!require(!file && file.error().code == ResolutionErrorCode::InvalidInput &&
                         file.error().path == file_fixture.working_directory() / "options.ini" &&
                         file.error().item == "cbldv",
                     "options.ini winning metadata error retains options.ini provenance")) {
            return false;
        }

        ResolverFixture cli_fixture;
        auto cli_args = cli_fixture.complete_loose_args();
        cli_args.config = {"cbldv=bad"};
        const auto cli = cli_fixture.resolve(cli_args);
        return require(!cli && cli.error().code == ResolutionErrorCode::InvalidInput &&
                           cli.error().path.empty() && cli.error().item == "cbldv",
                       "CLI winning metadata error retains CLI no-path provenance");
    }

    bool test_invalid_cli_metadata_retains_cli_provenance_in_loose_donor_mode() {
        struct Case {
            std::string config;
            std::string item;
        };
        const std::array cases{Case{"cbldv=7tail", "cbldv"}, Case{"cfldv=0x100", "cfldv"},
                               Case{"pairing_data=01020304", "pairing_data"}};
        for (const auto& test : cases) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args();
            args.config = {test.config};
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == test.item,
                         "invalid CLI metadata retains CLI rather than options.ini provenance")) {
                return false;
            }
        }
        return true;
    }

    bool test_ini_payload_lookup_failure_is_terminal() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsecdata.bin\n");
        std::filesystem::create_directory(fixture.path("first/secdata.bin"));
        auto later = Bytes(0x20, 0x63);
        if (!gxbuild3::nand::crypt_secfile(valid_cpu_key(), later)) {
            return require(false, "later secure fixture encrypts");
        }
        fixture.write_binary("second/secdata.bin", later);

        try {
            const auto result = fixture.resolve(args);
            return require(!result && result.error().code == ResolutionErrorCode::AssetNotFound &&
                               result.error().path == fixture.path("first/secdata.bin") &&
                               result.error().item == "secdata.bin",
                           "failed first-priority INI payload inspection is terminal");
        } catch (...) {
            return require(false, "INI payload lookup failures must not escape the resolver");
        }
    }

    bool test_ini_payload_is_required_unless_donor_supplies_same_basename() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        Input donor{};
        donor.image_type = ImageType::SmallBlock;
        donor.metadata.cpu_key = key;
        donor.metadata.smc = make_smc(0x61);
        donor.metadata.keyvault = canonical_keyvault_filled(key, 0x62);
        donor.bootloaders = valid_bootloaders();
        donor.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"DONOR-ONLY.BIN", Bytes{0x44}}};
        const auto donor_bytes = run_build(donor);
        if (!donor_bytes) {
            return require(false, "required-payload donor fixture builds");
        }
        fixture.write_binary("first/nanddump.bin", *donor_bytes);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\ndonor-only.bin\n");

        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        const auto fallback = fixture.resolve(args);
        if (!require_resolved(fallback, "donor FlashFS satisfies a named INI payload") ||
            !require(fallback->input.flashfs_sec && fallback->input.flashfs_sec->size() == 1 &&
                         fallback->input.flashfs_sec->front().second == Bytes{0x44},
                     "donor fallback uses the lowercase basename and preserves its bytes")) {
            return false;
        }

        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsub/missing-security.bin\n");
        const auto missing_security = fixture.resolve(args);
        if (!require(!missing_security &&
                         missing_security.error().code == ResolutionErrorCode::AssetNotFound &&
                         missing_security.error().path == fixture.path("working/build.ini") &&
                         missing_security.error().item == "sub/missing-security.bin",
                     "a missing named security payload is an exact error")) {
            return false;
        }

        fixture.write_text(
            "working/build.ini",
            "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\ndonor-only.bin\nsub/missing.bin\n");
        const auto missing = fixture.resolve(args);
        return require(!missing && missing.error().code == ResolutionErrorCode::AssetNotFound &&
                           missing.error().path == fixture.path("working/build.ini") &&
                           missing.error().item == "sub/missing.bin",
                       "a named INI payload absent from donor and roots is an exact error");
    }

    bool test_automatic_patchset_names_and_retail_devkit_behavior() {
        struct Case {
            BuildType type;
            std::string name;
        };
        const std::array cases{
            Case{BuildType::Jtag, "patches_falcon_test.bin"},
            Case{BuildType::Glitch, "patches_fat_test.bin"},
            Case{BuildType::Glitch2, "patches_g2falcon_test.bin"},
            Case{BuildType::Glitch2m, "patches_g2mfalcon_test.bin"},
            Case{BuildType::Glitch3, "patches_g3falcon_test.bin"},
        };
        // devgl's name is checked by test_devgl_resolve_finds_the_sb_key_and_builds_retail_fuses,
        // as it resolves only with an SB key.
        for (const auto& test : cases) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(test.type);
            args.patch_extension = "test";
            fixture.write_binary("first/bin/" + test.name, valid_glitch_patchset());
            if (test.type == BuildType::Jtag) {
                fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));
            } else if (test.type != BuildType::Retail && test.type != BuildType::Devkit) {
                fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
            }
            const auto result = fixture.resolve(args);
            if (!require_resolved(result, "automatic patch fixture resolves") ||
                !require(result->input.patches && result->input.patches->automatic &&
                             result->input.patches->automatic->name == test.name,
                         "automatic patch name uses the exact build-type table and suffix")) {
                return false;
            }
        }

        for (const auto type : {BuildType::Retail, BuildType::Devkit}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(type);
            fixture.write_binary("first/bin/patches_falcon.bin", valid_glitch_patchset());
            const auto result = fixture.resolve(args);
            if (!require(result && (!result->input.patches ||
                                    !result->input.patches->automatic.has_value()),
                         "retail and devkit do not auto-select patchsets")) {
                return false;
            }
        }
        return true;
    }

    // Lines 0-6 for kFuseCbWord, as xerunner's test_build.py states them; lines 1-2 come
    // from the CB, not from the falcon section, and 3-6 are the CPU key halves twice each.
    bool require_fuse_lines_from_cb_word(const Bytes& fuses, const std::string& name) {
        const auto key = valid_cpu_key();
        const Bytes head{0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x0F, 0x0F, 0x0F,
                         0x0F, 0x0F, 0xF0, 0xF0, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Bytes expected = head;
        expected.insert(expected.end(), key.begin(), key.begin() + 8);
        expected.insert(expected.end(), key.begin(), key.begin() + 8);
        expected.insert(expected.end(), key.begin() + 8, key.end());
        expected.insert(expected.end(), key.begin() + 8, key.end());
        return require(fuses.size() >= expected.size() &&
                           std::equal(expected.begin(), expected.end(), fuses.begin()),
                       name + " fuse lines 0-6 follow the CB word and CPU key");
    }

    bool test_jtag_resolve_populates_payloads() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.console = ConsoleType::Falcon;
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "JTAG fixture carrying xell-2f.bin resolves")) {
            return false;
        }
        const auto& payloads = result->input.payloads;
        return require(payloads.has_value(), "JTAG resolution populates input.payloads") &&
               require(payloads->xell && payloads->xell->size() == 0x40000,
                       "xell-2f.bin is loaded verbatim") &&
               require(payloads->rebooter && payloads->rebooter->size() == 0xd40,
                       "the embedded freeBOOT rebooter is loaded at 0xd40 bytes") &&
               require(*payloads->rebooter == gxbuild3::nand::freeboot_rebooter_for("17559"),
                       "the rebooter states the INI's kernel version") &&
               require(payloads->payload && payloads->payload->size() == 0x200,
                       "the embedded SMC payload is loaded at 0x200 bytes") &&
               require(*payloads->payload == gxbuild3::nand::freeboot_payload_for(0xd40),
                       "the payload loads exactly the rebooter") &&
               require(payloads->fuses && payloads->fuses->size() == 0x60,
                       "generated virtual fuses fill the 0x60-byte region") &&
               require_fuse_lines_from_cb_word(*payloads->fuses, "JTAG second CB");
    }

    bool test_jtag_resolve_fails_without_xell() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.console = ConsoleType::Falcon;
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());

        const auto result = fixture.resolve(args);
        return require(!result.has_value(), "JTAG without a XeLL is rejected") &&
               require(result.error().message.find("require a XeLL") != std::string::npos,
                       "the missing-XeLL error names the requirement");
    }

    bool test_glitch_resolve_populates_xell_only() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "glitch2 carrying xell-gggggg.bin resolves")) {
            return false;
        }
        const auto& payloads = result->input.payloads;
        return require(payloads && payloads->xell && payloads->xell->size() == 0x40000,
                       "xell-gggggg.bin is loaded") &&
               require(!payloads->rebooter && !payloads->payload,
                       "glitch carries no JTAG rebooter/payload") &&
               require(!payloads->fuses, "non-manufacturing glitch carries no fuses");
    }

    bool test_glitch2m_resolve_populates_fuses() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2m);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "glitch2m resolves")) {
            return false;
        }
        const auto& payloads = result->input.payloads;
        return require(payloads && payloads->xell && payloads->fuses &&
                           payloads->fuses->size() == 0x60,
                       "glitch2m loads XeLL and generated 0x60 fuses") &&
               require_fuse_lines_from_cb_word(*payloads->fuses, "glitch2m CB_B");
    }

    bool test_glitch2m_without_cb_b_is_refused() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2m);
        args.patch_extension = "test";
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        return require(!result.has_value() && result.error().item == "fuses" &&
                           result.error().message.find("CB_B") != std::string::npos,
                       "glitch2m fuses without a CB_B to read the word from are refused");
    }

    // A throwaway key whose file states the SB private key's CRC-32, so the resolver takes it.
    Bytes sb_key_stand_in() {
        return gxbuild3::test::xe_rsa::with_crc32(gxbuild3::test::xe_rsa::shared_private_key(),
                                                  gxbuild3::utils::kSbPrivateKeyCrc32);
    }

    bool test_devgl_resolve_finds_the_sb_key_and_builds_retail_fuses() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        const auto stand_in = sb_key_stand_in();
        // A root's own candidate of the wrong CRC-32 is passed over for its keys folder's.
        fixture.write_binary("first/SB_priv.bin", Bytes(stand_in.size(), 0x11));
        fixture.write_binary("first/keys/sb_PRV.bin", stand_in);

        const auto result = fixture.resolve(args);
        if (!require(gxbuild3::utils::crc32(stand_in) == gxbuild3::utils::kSbPrivateKeyCrc32,
                     "the stand-in key states the SB key's CRC-32") ||
            !require_resolved(result, "devgl resolves with an SB key in a keys folder")) {
            return false;
        }
        const auto& input = result->input;
        // Line 1 names the retail type, line 2 holds no allow bits, lines 7.. count cfldv=3.
        const Bytes type_line{0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xF0};
        const Bytes ldv_line{0xFF, 0xF0, 0, 0, 0, 0, 0, 0};
        const auto& fuses = input.payloads ? input.payloads->fuses : std::nullopt;
        return require(input.sb_private_key == stand_in, "the keys folder's SB key is taken") &&
               require(input.patches && input.patches->automatic &&
                           input.patches->automatic->name == "patches_g2mfalcon_test.bin",
                       "devgl reads the glitch2m patch file") &&
               require(input.payloads && !input.payloads->xell,
                       "devgl leaves XeLL to the FlashFS") &&
               require(fuses && fuses->size() == 0x60 &&
                           std::equal(type_line.begin(), type_line.end(), fuses->begin() + 8) &&
                           std::all_of(fuses->begin() + 0x10, fuses->begin() + 0x18,
                                       [](uint8_t byte) { return byte == 0; }) &&
                           std::equal(ldv_line.begin(), ldv_line.end(), fuses->begin() + 0x38),
                       "devgl fuses state the retail type, no allow bits and the CF LDV");
    }

    bool test_devgl_resolve_without_the_sb_key_is_refused() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        const auto absent = fixture.resolve(args);
        fixture.write_binary("first/keys/SB_priv.bin",
                             gxbuild3::test::xe_rsa::shared_private_key());
        const auto wrong = fixture.resolve(args);
        return require(!absent && absent.error().code == ResolutionErrorCode::SigningKeyNotFound &&
                           absent.error().message.find("No SB_priv.bin") != std::string::npos,
                       "devgl without an SB key is refused") &&
               require(!wrong && wrong.error().code == ResolutionErrorCode::SigningKeyNotFound &&
                           wrong.error().message.find("No candidate") != std::string::npos,
                       "devgl with only a key of another CRC-32 is refused");
    }

    bool test_glitch_resolve_fails_without_xell() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset());

        const auto result = fixture.resolve(args);
        return require(!result.has_value(), "glitch without a XeLL is rejected") &&
               require(result.error().message.find("require a XeLL") != std::string::npos,
                       "the missing-XeLL error names the requirement");
    }

    bool test_glitch3_searches_all_g3_roots_before_g2_fallback() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch3);
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset(0x22));
        fixture.write_binary("second/bin/patches_g3falcon_test.bin", valid_glitch_patchset(0x33));
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        const auto g3 = fixture.resolve(args);
        if (!require_resolved(g3, "glitch3 fixture resolves") ||
            !require(g3->input.patches && g3->input.patches->automatic &&
                         g3->input.patches->automatic->name == "patches_g3falcon_test.bin" &&
                         g3->input.patches->automatic->data.back() == 0x33,
                     "a later-root g3 patch beats an earlier-root g2 fallback")) {
            return false;
        }

        std::filesystem::remove(fixture.path("second/bin/patches_g3falcon_test.bin"));
        const auto fallback = fixture.resolve(args);
        return require(fallback && fallback->input.patches && fallback->input.patches->automatic &&
                           fallback->input.patches->automatic->name ==
                               "patches_g2falcon_test.bin" &&
                           fallback->input.patches->automatic->data.back() == 0x22,
                       "glitch3 falls back only after every g3 root is exhausted");
    }

    bool test_glitch3_prefers_g3_then_g2_and_fails_cleanly_without_either() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch3);
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto neither = fixture.resolve(args);
        if (!require(!neither && neither.error().code == ResolutionErrorCode::PatchsetNotFound &&
                         neither.error().item == "patches_g2falcon.bin" &&
                         neither.error().message.find("patches_g3falcon.bin") !=
                             std::string::npos &&
                         neither.error().message.find("patches_g2falcon.bin") != std::string::npos,
                     "glitch3 without a g3 or g2 patchset fails naming both files")) {
            return false;
        }

        fixture.write_binary("first/bin/patches_g2falcon.bin", valid_glitch_patchset(0x22));
        const auto g2_only = fixture.resolve(args);
        if (!require_resolved(g2_only, "glitch3 with only a g2 patchset resolves") ||
            !require(g2_only->input.patches && g2_only->input.patches->automatic &&
                         g2_only->input.patches->automatic->name == "patches_g2falcon.bin" &&
                         g2_only->input.patches->automatic->data.back() == 0x22,
                     "glitch3 uses the g2 patchset when no g3 patchset exists")) {
            return false;
        }

        fixture.write_binary("first/bin/patches_g3falcon.bin", valid_glitch_patchset(0x33));
        const auto both = fixture.resolve(args);
        return require_resolved(both, "glitch3 with both patchsets resolves") &&
               require(both->input.patches && both->input.patches->automatic &&
                           both->input.patches->automatic->name == "patches_g3falcon.bin" &&
                           both->input.patches->automatic->data.back() == 0x33,
                       "glitch3 prefers the g3 patchset over a g2 one in the same root");
    }

    bool test_missing_patchset_and_addon_errors_are_precise() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        const auto missing_patch = fixture.resolve(args);
        if (!require(!missing_patch &&
                         missing_patch.error().code == ResolutionErrorCode::PatchsetNotFound &&
                         missing_patch.error().item == "patches_g2falcon.bin",
                     "a missing required automatic patch names the exact file")) {
            return false;
        }

        fixture.write_binary("first/bin/patches_g2falcon.bin", valid_glitch_patchset());
        args.addons = {"missing"};
        const auto missing_addon = fixture.resolve(args);
        return require(!missing_addon &&
                           missing_addon.error().code == ResolutionErrorCode::AddonNotFound &&
                           missing_addon.error().item == "missing.bin",
                       "a missing add-on names the exact bin filename");
    }

    bool test_addons_resolve_from_root_bin_in_cli_order() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.addons = {"second-addon", "first-addon"};
        fixture.write_binary("first/bin/patches_g2falcon.bin", valid_glitch_patchset());
        fixture.write_binary("first/bin/second-addon.bin", Bytes{0x21});
        fixture.write_binary("second/bin/second-addon.bin", Bytes{0x99});
        fixture.write_binary("second/bin/first-addon.bin", Bytes{0x12});
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        const auto result = fixture.resolve(args);
        return require_resolved(result, "add-on fixture resolves") &&
               require(result->input.patches && result->input.patches->addons.size() == 2,
                       "both add-ons resolve") &&
               require(result->input.patches->addons[0].name == "second-addon.bin" &&
                           result->input.patches->addons[0].data == Bytes{0x21} &&
                           result->input.patches->addons[1].name == "first-addon.bin" &&
                           result->input.patches->addons[1].data == Bytes{0x12},
                       "add-ons preserve CLI order and first-root priority") &&
               [&] {
                   const auto merged =
                       parse_and_merge_patch_set(*result->input.patches, result->input.build_type);
                   if (!require(merged.has_value(), "resolved patches parse and merge")) {
                       return false;
                   }
                   const auto khv = std::find_if(
                       merged->sections.begin(), merged->sections.end(), [](const auto& section) {
                           return section.target == PatchSectionTarget::Khv;
                       });
                   return require(khv != merged->sections.end() && khv->raw_data.size() >= 3 &&
                                      std::equal(khv->raw_data.end() - 3, khv->raw_data.end(),
                                                 Bytes{0xA0, 0x21, 0x12}.begin()),
                                  "resolved add-ons append to KHV in CLI order");
               }();
    }

    bool test_retail_and_devkit_reject_addons_without_automatic_patchset() {
        for (const auto type : {BuildType::Retail, BuildType::Devkit}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(type);
            args.addons = {"extra"};
            fixture.write_binary("first/bin/extra.bin", Bytes{0x41});
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == "extra" &&
                             result.error().message ==
                                 "Add-ons require an automatic patchset and are not supported for "
                                 "retail or devkit builds",
                         "retail and devkit reject add-ons that cannot be applied")) {
                return false;
            }
        }
        return true;
    }

    bool test_direct_build_args_reject_unconfined_patch_components() {
        for (const std::string invalid :
             {"../outside", "/outside", "nested/addon", "addon.bin", "C:\\outside"}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(BuildType::Glitch2);
            args.addons = {invalid};
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == invalid,
                         "direct BuildArgs add-ons are bare ASCII logical names")) {
                return false;
            }
        }

        for (const std::string invalid : {"../falcon", "/falcon", "nested\\falcon", "C:\\falcon"}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(BuildType::Glitch2);
            args.section = invalid;
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == invalid,
                         "direct BuildArgs section cannot escape a filename component")) {
                return false;
            }
        }

        for (const std::string invalid :
             {"_test", "test.alt", "../test", "/test", "nested\\test", "C:\\test"}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(BuildType::Glitch2);
            args.patch_extension = invalid;
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == invalid,
                         "direct BuildArgs patch suffix is a safe non-underscored component")) {
                return false;
            }
        }

        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.patch_extension = "test_alt";
        fixture.write_binary("first/bin/patches_g2falcon_test_alt.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        const auto valid_internal_underscore = fixture.resolve(args);
        if (!require_resolved(valid_internal_underscore,
                              "an internal-underscore patch suffix resolves") ||
            !require(valid_internal_underscore->input.patches &&
                         valid_internal_underscore->input.patches->automatic &&
                         valid_internal_underscore->input.patches->automatic->name ==
                             "patches_g2falcon_test_alt.bin",
                     "safe internal underscores are retained in automatic patch names")) {
            return false;
        }
        return true;
    }

    bool test_glitch_khv_donor_does_not_resolve_ambiguous_fixed_payloads() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        Input donor{};
        donor.image_type = ImageType::SmallBlock;
        donor.build_type = BuildType::Glitch;
        donor.metadata.cpu_key = key;
        donor.metadata.smc = make_smc(0x63);
        donor.metadata.keyvault = canonical_keyvault_filled(key, 0x64);
        donor.bootloaders = valid_bootloaders();
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", valid_glitch_patchset(0xC4)};
        donor.patches = std::move(patches);
        const auto donor_bytes = run_build(donor);
        if (!require(donor_bytes.has_value(), "small-block Glitch KHV donor fixture builds")) {
            return false;
        }

        const auto extracted = extract_all(*donor_bytes, key);
        if (!require(
                extracted.has_value() && !extracted->payloads,
                "extract_all does not invent fixed payloads from ambiguous Glitch KHV bytes")) {
            return false;
        }

        auto args = fixture.complete_loose_args(BuildType::Glitch);
        args.image_type.reset();
        fixture.write_binary("first/nanddump.bin", *donor_bytes);
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        fixture.write_binary("first/bin/patches_fat.bin", valid_glitch_patchset(0xC4));
        const auto resolved = fixture.resolve(args);
        return require_resolved(resolved, "small-block Glitch KHV donor resolves") &&
               require(!resolved->input.payloads || (!resolved->input.payloads->rebooter &&
                                                     !resolved->input.payloads->fuses),
                       "resolver preserves the conservative ambiguous-KHV payload policy");
    }

    bool test_final_input_is_validated_before_return() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        fixture.write_binary("first/smc.bin", Bytes{});
        const auto result = fixture.resolve(args);
        return require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                           result.error().message == "SMC is required",
                       "validate_input failure becomes a structured InvalidInput error");
    }

    // One BuildRequest as golden lines: the output path relative to the fixture root (the root is
    // a fresh temporary directory), then every Input field through
    // tests/support/render/ExtractProjection.hpp: options, metadata scalars, the size and SHA-1 of
    // every byte vector, FlashFS names in order, patch file names, payloads, and only the size of
    // an SB key.
    std::string render_request(const std::string& label, const ResolverFixture& fixture,
                               const gxbuild3::cli::BuildRequest& request) {
        return label + " output_path=" +
               request.output_path.lexically_relative(fixture.root()).generic_string() + '\n' +
               gxbuild3::test::projection::render(label + ".input", request.input);
    }

    struct DigestCase {
        std::string text;
        bool stable = false;
    };

    // Resolves args twice; both requests must render identically.
    DigestCase digest_resolve(const std::string& label, const ResolverFixture& fixture,
                              const BuildArgs& args) {
        const auto first = fixture.resolve(args);
        const auto second = fixture.resolve(args);
        if (!require_resolved(first, label + " resolves") ||
            !require_resolved(second, label + " resolves again")) {
            return DigestCase{label + " resolution-error\n", false};
        }
        const auto once = render_request(label, fixture, *first);
        const bool stable = require(once == render_request(label, fixture, *second),
                                    label + " resolves to an identical BuildRequest twice");
        return DigestCase{stable ? once : label + " nondeterministic\n", stable};
    }

    // donor.retail: a pinned synthetic donor (CB/CF LDVs, pairing, CF/CG) under a falcon chain
    // of loose CB and CD, a [flashfs] file, a mobile slot, options.ini and a CLI override.
    DigestCase digest_donor_retail(const std::string& label) {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        const auto donor =
            pinned_donor_image(donor_input_with_metadata(ImageType::SmallBlock, key), label);
        if (!donor) {
            return DigestCase{label + " donor-build-error\n", false};
        }
        fixture.write_binary("first/nanddump.bin", *donor);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_binary("first/launch.ini", Bytes{0x41, 0x42});
        fixture.write_binary("first/mobileB.bin", Bytes{0xB2});
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\nlaunch.ini\n");
        fixture.write_text("working/options.ini", "nofcrt=true\ncbldv=3\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.console = ConsoleType::Falcon;
        args.image_type.reset();
        args.config = {"cfldv=5", "nomobile=false"};
        return digest_resolve(label, fixture, args);
    }

    // loose.retail: no donor; kv.bin sealed, smc.bin, options.ini metadata, a sealed secdata.bin
    // in [security], a [flashfs] file and a mobile slot.
    DigestCase digest_loose_retail(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        auto secdata = Bytes(0x20, 0x51);
        if (!gxbuild3::nand::crypt_secfile(valid_cpu_key(), secdata)) {
            return DigestCase{label + " secdata-seal-error\n", false};
        }
        fixture.write_binary("first/secdata.bin", secdata);
        fixture.write_binary("first/launch.ini", Bytes{0x43});
        fixture.write_binary("first/mobileA.bin", Bytes{0xA1, 0xA2});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\n"
                                                "launch.ini\n[security]\nsecdata.bin\n");
        return digest_resolve(label, fixture, args);
    }

    // loose.jtag: the falcon JTAG chain (second CB), [version] 17559, patches_falcon_test.bin and
    // xell-2f.bin; payloads carry XeLL, the embedded rebooter and payload, and generated fuses.
    DigestCase digest_loose_jtag(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));
        return digest_resolve(label, fixture, args);
    }

    // loose.devgl: the glitch2m patch file and the throwaway stand-in SB key (XeRsaTestKey.hpp,
    // made to state the SB key's CRC-32) found through the resolver's own lookup in a keys
    // folder. The real SB key is never read; the golden records only the key's size.
    DigestCase digest_loose_devgl(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/keys/SB_priv.bin", sb_key_stand_in());
        return digest_resolve(label, fixture, args);
    }

    // donor-glitch2.retail: a retail resolve from the pinned glitch2 donor (see
    // test_retail_resolve_keeps_donor_payloads_as_today).
    DigestCase digest_retail_from_glitch2_donor(const std::string& label) {
        ResolverFixture fixture;
        const auto donor = pinned_donor_image(glitch2_donor_input(valid_cpu_key()), label);
        if (!donor) {
            return DigestCase{label + " donor-build-error\n", false};
        }
        fixture.write_binary("first/nanddump.bin", *donor);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        return digest_resolve(label, fixture, args);
    }

    // The resolver's whole BuildRequest for a donor, a loose-donor, a JTAG, a devgl and a
    // retail-from-hacked-donor resolve, against tests/golden/resolver_build_requests.txt. Each
    // donor is built twice under a pinned time and nonces, and each case resolves twice; both
    // must be identical.
    bool test_resolution_digests(const gxbuild3::test::GoldenOptions& options) {
        using Digest = DigestCase (*)(const std::string&);
        const std::array<std::pair<std::string_view, Digest>, 5> cases{{
            {"donor.retail", digest_donor_retail},
            {"loose.retail", digest_loose_retail},
            {"loose.jtag", digest_loose_jtag},
            {"loose.devgl", digest_loose_devgl},
            {"donor-glitch2.retail", digest_retail_from_glitch2_donor},
        }};
        std::string rendered;
        size_t stable = 0;
        for (const auto& [label, digest] : cases) {
            const auto result = digest(std::string{label});
            rendered += result.text;
            stable += result.stable ? 1 : 0;
        }
        const bool matched =
            gxbuild3::test::check_golden(options, "resolver_build_requests", rendered);
        std::cout << "resolver BuildRequest digests: resolved twice and identical " << stable << '/'
                  << cases.size() << ", compared " << (matched ? stable : 0) << '/' << cases.size()
                  << " with tests/golden/resolver_build_requests.txt\n";
        return require(matched, "resolver BuildRequest digests match the golden") &&
               require(stable == cases.size(), "every resolver digest case is stable");
    }

    // Today's behaviour, deliberate until decided: resolve seeds its Input from the donor's
    // extract_all, and only the devgl and JTAG/glitch branches replace input.payloads, so a retail
    // resolve from a hacked donor keeps the donor's XeLL. Whether that is a bug is an open
    // question; this pin keeps a resolver split from changing it silently.
    bool test_retail_resolve_keeps_donor_payloads_as_today() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        const auto donor = pinned_donor_image(glitch2_donor_input(key), "glitch2 donor");
        if (!require(donor.has_value(), "the glitch2 donor builds")) {
            return false;
        }
        const auto extracted = extract_all(*donor, key);
        if (!require(extracted && extracted->payloads && extracted->payloads->xell,
                     "extract_all of the glitch2 donor carries its XeLL payload")) {
            return false;
        }
        fixture.write_binary("first/nanddump.bin", *donor);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "a retail resolve from the glitch2 donor")) {
            return false;
        }
        const auto& kept = result->input.payloads;
        const auto& source = *extracted->payloads;
        return require(result->input.build_type == BuildType::Retail,
                       "the resolve is a retail build") &&
               require(!result->input.patches, "a retail resolve carries no patch file") &&
               require(kept.has_value(), "a retail resolve keeps the donor's payloads (today)") &&
               require(kept->xell == source.xell && kept->rebooter == source.rebooter &&
                           kept->fuses == source.fuses && kept->patches == source.patches &&
                           kept->payload == source.payload,
                       "the kept payloads are exactly the donor's extract_all payloads");
    }

} // namespace

int main(int argc, char** argv) {
    const auto options = gxbuild3::test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }
    bool passed = true;
    passed = test_source_roots_are_all_validated() && passed;
    passed = test_source_roots_cannot_be_empty() && passed;
    passed = test_empty_source_root_path_is_rejected() && passed;
    passed = test_only_working_directory_options_are_loaded() && passed;
    passed = test_cli_options_preserve_bare_boolean_and_repeated_order() && passed;
    passed = test_invalid_options_are_precise() && passed;
    passed = test_empty_cli_option_is_rejected() && passed;
    passed = test_options_read_failure_is_distinct() && passed;
    passed = test_options_ini_edge_cases_through_the_file() && passed;
    passed = test_parse_options_text_edge_cases() && passed;
    passed = test_cpu_key_precedence_and_discovery_order() && passed;
    passed = test_relative_source_root_is_anchored_to_working_directory() && passed;
    passed = test_uppercase_and_corrected_cpu_keys_are_accepted() && passed;
    passed = test_cpu_key_errors_are_precise() && passed;
    passed = test_cpu_key_lookup_failure_does_not_fall_through() && passed;
    passed = test_nand_discovery_and_explicit_override() && passed;
    passed = test_nand_errors_are_precise() && passed;
    passed = test_nand_lookup_failure_does_not_fall_through() && passed;
    passed = test_malformed_supported_size_nand_is_invalid_donor() && passed;
    passed = test_layout_override_only_clears_raw_backing() && passed;
    passed = test_matching_or_implicit_layout_retains_raw_backing() && passed;
    passed = test_layout_is_required_without_a_donor() && passed;
    passed = test_resolve_delegates_to_foundations() && passed;
    passed = test_resolve_anchors_relative_output_to_working_directory() && passed;
    passed = test_build_ini_is_required_readable_and_exact_section_is_selected() && passed;
    passed = test_ini_sc_bootloader_reaches_resolved_input() && passed;
    passed = test_loose_donor_requires_and_populates_every_component() && passed;
    passed = test_metadata_precedence_and_user_file_overrides() && passed;
    passed = test_loose_keyvault_in_the_clear_is_taken_as_it_stands() && passed;
    passed = test_zero_cpu_key_donor_takes_the_keyvault_from_kv_bin() && passed;
    passed = test_flashfs_holds_ini_files_and_donor_secured_files_only() && passed;
    passed = test_unsupplied_security_files_reach_the_build() && passed;
    passed = test_fcrt_follows_the_ini_not_the_keyvault() && passed;
    passed = test_metadata_values_require_full_valid_strings() && passed;
    passed = test_metadata_parses_only_the_winning_precedence_source() && passed;
    passed = test_cli_pairing_override_reaches_the_cf_and_console_is_carried() && passed;
    passed = test_metadata_winner_errors_report_the_winning_source() && passed;
    passed = test_invalid_cli_metadata_retains_cli_provenance_in_loose_donor_mode() && passed;
    passed = test_ini_payload_lookup_failure_is_terminal() && passed;
    passed = test_ini_payload_is_required_unless_donor_supplies_same_basename() && passed;
    passed = test_automatic_patchset_names_and_retail_devkit_behavior() && passed;
    passed = test_jtag_resolve_populates_payloads() && passed;
    passed = test_jtag_resolve_fails_without_xell() && passed;
    passed = test_glitch_resolve_populates_xell_only() && passed;
    passed = test_glitch2m_resolve_populates_fuses() && passed;
    passed = test_glitch2m_without_cb_b_is_refused() && passed;
    passed = test_devgl_resolve_finds_the_sb_key_and_builds_retail_fuses() && passed;
    passed = test_devgl_resolve_without_the_sb_key_is_refused() && passed;
    passed = test_glitch_resolve_fails_without_xell() && passed;
    passed = test_glitch3_searches_all_g3_roots_before_g2_fallback() && passed;
    passed = test_glitch3_prefers_g3_then_g2_and_fails_cleanly_without_either() && passed;
    passed = test_missing_patchset_and_addon_errors_are_precise() && passed;
    passed = test_addons_resolve_from_root_bin_in_cli_order() && passed;
    passed = test_retail_and_devkit_reject_addons_without_automatic_patchset() && passed;
    passed = test_direct_build_args_reject_unconfined_patch_components() && passed;
    passed = test_glitch_khv_donor_does_not_resolve_ambiguous_fixed_payloads() && passed;
    passed = test_final_input_is_validated_before_return() && passed;
    passed = test_resolution_digests(*options) && passed;
    passed = test_retail_resolve_keeps_donor_payloads_as_today() && passed;
    return passed ? 0 : 1;
}
