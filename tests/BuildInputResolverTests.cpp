#include "BuildRunner.hpp"
#include "cli/BuildInputResolver.hpp"
#include "excrypt.h"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/Patchset.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

    Bytes valid_cpu_key(bool alternate = false) {
        std::array<uint8_t, 16> key{};
        const size_t first_bit = alternate ? 53 : 0;
        for (size_t bit = first_bit; bit < first_bit + 53; ++bit) {
            key[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
        }
        XeCryptUidEccEncode(key.data());
        return Bytes(key.begin(), key.end());
    }

    std::string key_hex(std::span<const uint8_t> key) {
        constexpr char digits[] = "0123456789abcdef";
        std::string result;
        result.reserve(key.size() * 2);
        for (const uint8_t byte : key) {
            result.push_back(digits[byte >> 4]);
            result.push_back(digits[byte & 0x0F]);
        }
        return result;
    }

    std::string uppercase(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });
        return value;
    }

    Bytes make_smc(uint8_t marker) {
        Bytes smc(0x300, marker);
        smc[0x100] = 0x10;
        return smc;
    }

    Bytes canonical_keyvault(std::span<const uint8_t> key, uint8_t marker) {
        return keyvault_decrypt(key, keyvault_encrypt(key, Bytes(Keyvault::kSize, marker)));
    }

    Bytes encrypted_keyvault(std::span<const uint8_t> key, uint8_t marker) {
        return keyvault_encrypt(key, canonical_keyvault(key, marker));
    }

    Bytes valid_glitch_patchset(uint8_t marker = 0xA0) {
        auto append_be32 = [](Bytes& bytes, uint32_t value) {
            bytes.push_back(static_cast<uint8_t>(value >> 24));
            bytes.push_back(static_cast<uint8_t>(value >> 16));
            bytes.push_back(static_cast<uint8_t>(value >> 8));
            bytes.push_back(static_cast<uint8_t>(value));
        };
        Bytes bytes;
        append_be32(bytes, 0x20);
        append_be32(bytes, 1);
        append_be32(bytes, 0x11223344);
        append_be32(bytes, 0xFFFFFFFF);
        append_be32(bytes, 0x30);
        append_be32(bytes, 1);
        append_be32(bytes, 0x55667788);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.push_back(marker);
        return bytes;
    }

    InputBootloaders valid_bootloaders() {
        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.data.resize(0x380, 0);
        cb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb.data.size());
        cb.decrypted = true;

        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.version = 1;
        sc.header.header.size = static_cast<uint32_t>(sizeof(sc_header) + 0x20);
        sc.data.assign(0x20, 0x53);
        sc.decrypted = true;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + 0x20);
        cd.header.ce_hash[0] = 1;
        cd.data.resize(0x20, 0x42);
        cd.decrypted = true;

        InputBootloaders result{};
        result.cb_or_a = cb.serialize();
        result.sc = sc.serialize();
        result.cd = cd.serialize();
        return result;
    }

    Bytes donor_image(ImageType type, std::span<const uint8_t> key) {
        Input input{};
        input.image_type = type;
        input.metadata.cpu_key.assign(key.begin(), key.end());
        input.metadata.smc = make_smc(0x61);
        input.metadata.keyvault =
            keyvault_decrypt(key, keyvault_encrypt(key, Bytes(Keyvault::kSize, 0x72)));
        input.bootloaders = valid_bootloaders();
        const auto built = RunBuild(input);
        if (!built) {
            std::abort();
        }
        return *built;
    }

    Bytes donor_image_with_metadata(ImageType type, std::span<const uint8_t> key) {
        Input input{};
        input.image_type = type;
        input.metadata.cpu_key.assign(key.begin(), key.end());
        input.metadata.smc = make_smc(0x61);
        input.metadata.keyvault =
            keyvault_decrypt(key, keyvault_encrypt(key, Bytes(Keyvault::kSize, 0x72)));
        input.bootloaders = valid_bootloaders();

        auto cb = BootloaderCb::parse(input.bootloaders.cb_or_a);
        cb.data.resize(sizeof(cb_header) - sizeof(generic_header), 0);
        cb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb.data.size());
        if (!cb.parse_perbox()) {
            std::abort();
        }
        cb.perbox->lockdown_value = 7;
        cb.perbox->pairing_data[0] = 0xA1;
        cb.perbox->pairing_data[1] = 0xB2;
        cb.perbox->pairing_data[2] = 0xC3;
        cb.serialize_perbox();
        input.bootloaders.cb_or_a = cb.serialize();

        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.data.assign(0x200, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = true;
        cf.parse_perbox();
        cf.perbox->lockdown_value = 8;
        cf.serialize_perbox();
        input.bootloaders.cf0 = cf.serialize();
        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.version = 1;
        cg.data.assign(0x40, 0);
        cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg.data.size());
        input.bootloaders.cg0 = cg.serialize();
        input.metadata.cb_ldv = 7;
        input.metadata.cf_ldv = 8;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

        const auto built = RunBuild(input);
        if (!built) {
            std::abort();
        }
        return *built;
    }

    Bytes malformed_supported_size_nand() {
        Bytes nand(17'301'504, 0);
        constexpr size_t logical_bootloader_offset = 0x8000;
        constexpr size_t raw_bootloader_offset =
            (logical_bootloader_offset / 512) * 528 + logical_bootloader_offset % 512;
        nand[raw_bootloader_offset] = 0x43;
        nand[raw_bootloader_offset + 1] = 0x44;
        nand[raw_bootloader_offset + 15] = 0x10;
        return nand;
    }

    struct ResolverFixture {
        std::filesystem::path root;
        std::filesystem::path working_directory;

        ResolverFixture() {
            const auto unique =
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            root = std::filesystem::temp_directory_path() / ("gxbuild3-resolver-" + unique);
            working_directory = root / "working";
            std::filesystem::create_directories(working_directory);
            std::filesystem::create_directories(root / "first");
            std::filesystem::create_directories(root / "second");
        }

        ~ResolverFixture() {
            std::error_code error;
            std::filesystem::remove_all(root, error);
        }

        std::filesystem::path path(std::string_view relative) const {
            return root / std::filesystem::path(relative);
        }

        void write_text(std::string_view relative, std::string_view content) const {
            const auto destination = path(relative);
            std::filesystem::create_directories(destination.parent_path());
            std::ofstream output(destination, std::ios::binary);
            output << content;
        }

        void write_binary(std::string_view relative, std::span<const uint8_t> content) const {
            const auto destination = path(relative);
            std::filesystem::create_directories(destination.parent_path());
            std::ofstream output(destination, std::ios::binary);
            output.write(reinterpret_cast<const char*>(content.data()),
                         static_cast<std::streamsize>(content.size()));
        }

        BuildArgs minimum_args() const {
            BuildArgs args{};
            args.source_dirs = {path("first")};
            args.cpu_key = key_hex(valid_cpu_key());
            args.image_type = ImageType::SmallBlock;
            args.output_path = "result.bin";
            return args;
        }

        BuildArgs complete_loose_args(BuildType build_type = BuildType::Retail,
                                      ImageType image_type = ImageType::SmallBlock) const {
            const auto key = valid_cpu_key();
            write_binary("first/kv.bin", encrypted_keyvault(key, 0x72));
            write_binary("first/smc.bin", make_smc(0x61));
            write_binary("first/cb_1.bin", Bytes{0xCB, 0x01});
            write_binary("first/cd.bin", Bytes{0xCD, 0x01});
            write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            write_text("working/options.ini", "cbldv=2\ncfldv=3\npairing_data=010203\n");

            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.build_type = build_type;
            args.image_type = image_type;
            return args;
        }

        auto resolve(const BuildArgs& args) const {
            return BuildInputResolver(working_directory).Resolve(args);
        }

        auto resolve_foundations(const BuildArgs& args) const {
            return BuildInputResolver(working_directory).ResolveFoundations(args);
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

    bool test_cpu_key_precedence_and_discovery_order() {
        ResolverFixture fixture;
        const auto first_key = valid_cpu_key();
        const auto second_key = valid_cpu_key(true);
        fixture.write_text("first/cpukey.txt", " \r\n" + key_hex(first_key) + "\t\n");
        fixture.write_text("second/cpukey.txt", key_hex(second_key));
        auto args = fixture.minimum_args();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.cpu_key.reset();
        const auto discovered = fixture.resolve_foundations(args);
        if (!require(discovered && discovered->cpu_key == first_key,
                     "the first source root supplies the discovered CPU key")) {
            return false;
        }

        args.cpu_key = "  " + key_hex(second_key) + "\r\n";
        const auto explicit_key = fixture.resolve_foundations(args);
        return require(explicit_key && explicit_key->cpu_key == second_key,
                       "an explicit trimmed CPU key overrides every source root");
    }

    bool test_relative_source_root_is_anchored_to_working_directory() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_text("first/cpukey.txt", key_hex(key));
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
        args.cpu_key = uppercase(key_hex(key));
        const auto uppercase_result = fixture.resolve_foundations(args);
        if (!require(uppercase_result && uppercase_result->cpu_key == key,
                     "uppercase hexadecimal CPU keys are accepted")) {
            return false;
        }

        auto correctable = key;
        correctable.front() ^= 0x01;
        args.cpu_key = key_hex(correctable);
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
        fixture.write_text("second/cpukey.txt", key_hex(valid_cpu_key()));
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
        args.cpu_key = key_hex(key);
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
        const auto absolute = BuildInputResolver(fixture.working_directory).Resolve(args);
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
            return require(false, "donor parser exceptions must not escape ResolveFoundations");
        }
    }

    bool test_layout_override_only_clears_raw_backing() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        fixture.write_binary("first/nanddump.bin", donor_image(ImageType::SmallBlock, key));
        auto args = fixture.minimum_args();
        args.cpu_key = key_hex(key);
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
        args.cpu_key = key_hex(key);
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
        const auto result = BuildInputResolver(fixture.working_directory).Resolve(args);
        return require(!result && result.error().code == ResolutionErrorCode::CpuKeyNotFound,
                       "Resolve exposes foundation failures before Task 7 phases");
    }

    bool test_resolve_anchors_relative_output_to_working_directory() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        args.output_path = "nested/result.bin";
        const auto result = BuildInputResolver(fixture.working_directory).Resolve(args);
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
        const auto expected_keyvault = canonical_keyvault(key, 0x48);
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
               require(result->input.metadata.keyvault == canonical_keyvault(key, 0x44) &&
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

    bool test_ini_flashfs_overlays_donor_by_lowercase_basename() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        Input donor{};
        donor.image_type = ImageType::SmallBlock;
        donor.metadata.cpu_key = key;
        donor.metadata.smc = make_smc(0x61);
        donor.metadata.keyvault = canonical_keyvault(key, 0x62);
        donor.bootloaders = valid_bootloaders();
        donor.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"Launch.ini", Bytes{0x10}},
                                                       {"launch.INI", Bytes{0x11}},
                                                       {"SECDATA.BIN", Bytes(0x20, 0x20)},
                                                       {"donor.bin", Bytes{0x30}}};
        const auto image = RunBuild(donor);
        if (!image) {
            return require(false, "FlashFS donor fixture builds");
        }
        fixture.write_binary("first/nanddump.bin", *image);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_binary("first/launch.ini", Bytes{0x41});
        const auto plaintext_secdata = Bytes(0x20, 0x51);
        auto encrypted_secdata = plaintext_secdata;
        if (!gxbuild3::NAND::crypt_secfile(key, encrypted_secdata)) {
            return require(false, "secure fixture encrypts");
        }
        fixture.write_binary("first/secdata.bin", encrypted_secdata);
        fixture.write_binary("first/new.bin", Bytes{0x61});
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsecdata.bin\n"
                           "[flashfs]\nlaunch.ini\nnew.bin\n");

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
        return require(files.size() == 4,
                       "case-insensitive overlays do not duplicate donor files") &&
               require(find("launch.ini") != files.end() &&
                           find("launch.ini")->second == Bytes{0x41},
                       "INI FlashFS replaces the donor basename") &&
               require(find("secdata.bin") != files.end() &&
                           find("secdata.bin")->second == plaintext_secdata,
                       "secure Input boundary contains plaintext") &&
               require(find("donor.bin") != files.end() && find("new.bin") != files.end(),
                       "unreplaced donor and new INI files are retained");
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

    bool test_metadata_winner_errors_report_the_winning_source() {
        ResolverFixture file_fixture;
        auto file_args = file_fixture.complete_loose_args();
        file_fixture.write_text("working/options.ini", "cbldv=bad\ncfldv=3\npairing_data=010203\n");
        const auto file = file_fixture.resolve(file_args);
        if (!require(!file && file.error().code == ResolutionErrorCode::InvalidInput &&
                         file.error().path == file_fixture.working_directory / "options.ini" &&
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
        if (!gxbuild3::NAND::crypt_secfile(valid_cpu_key(), later)) {
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
        donor.metadata.keyvault = canonical_keyvault(key, 0x62);
        donor.bootloaders = valid_bootloaders();
        donor.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"DONOR-ONLY.BIN", Bytes{0x44}}};
        const auto donor_bytes = RunBuild(donor);
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
            Case{BuildType::Jtag, "patches_fat_test.bin"},
            Case{BuildType::Glitch, "patches_falcon_test.bin"},
            Case{BuildType::Glitch2, "patches_g2falcon_test.bin"},
            Case{BuildType::Glitch2m, "patches_g2mfalcon_test.bin"},
            Case{BuildType::Glitch3, "patches_g3falcon_test.bin"},
        };
        for (const auto& test : cases) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(test.type);
            args.patch_extension = "test";
            fixture.write_binary("first/bin/" + test.name, valid_glitch_patchset());
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

    bool test_glitch3_searches_all_g3_roots_before_g2_fallback() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch3);
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset(0x22));
        fixture.write_binary("second/bin/patches_g3falcon_test.bin", valid_glitch_patchset(0x33));
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
                   const auto merged = BinaryParser::ParseAndMergePatchSet(
                       *result->input.patches, result->input.build_type);
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
        donor.metadata.keyvault = canonical_keyvault(key, 0x64);
        donor.bootloaders = valid_bootloaders();
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", valid_glitch_patchset(0xC4)};
        donor.patches = std::move(patches);
        const auto donor_bytes = RunBuild(donor);
        if (!require(donor_bytes.has_value(), "small-block Glitch KHV donor fixture builds")) {
            return false;
        }

        const auto extracted = ExtractAll(*donor_bytes, key);
        if (!require(extracted.has_value() && !extracted->payloads,
                     "ExtractAll does not invent fixed payloads from ambiguous Glitch KHV bytes")) {
            return false;
        }

        auto args = fixture.complete_loose_args(BuildType::Glitch);
        args.image_type.reset();
        fixture.write_binary("first/nanddump.bin", *donor_bytes);
        fixture.write_binary("first/bin/patches_falcon.bin", valid_glitch_patchset(0xC4));
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
                       "ValidateInput failure becomes a structured InvalidInput error");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_source_roots_are_all_validated() && passed;
    passed = test_source_roots_cannot_be_empty() && passed;
    passed = test_empty_source_root_path_is_rejected() && passed;
    passed = test_only_working_directory_options_are_loaded() && passed;
    passed = test_cli_options_preserve_bare_boolean_and_repeated_order() && passed;
    passed = test_invalid_options_are_precise() && passed;
    passed = test_empty_cli_option_is_rejected() && passed;
    passed = test_options_read_failure_is_distinct() && passed;
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
    passed = test_ini_flashfs_overlays_donor_by_lowercase_basename() && passed;
    passed = test_metadata_values_require_full_valid_strings() && passed;
    passed = test_metadata_parses_only_the_winning_precedence_source() && passed;
    passed = test_metadata_winner_errors_report_the_winning_source() && passed;
    passed = test_invalid_cli_metadata_retains_cli_provenance_in_loose_donor_mode() && passed;
    passed = test_ini_payload_lookup_failure_is_terminal() && passed;
    passed = test_ini_payload_is_required_unless_donor_supplies_same_basename() && passed;
    passed = test_automatic_patchset_names_and_retail_devkit_behavior() && passed;
    passed = test_glitch3_searches_all_g3_roots_before_g2_fallback() && passed;
    passed = test_missing_patchset_and_addon_errors_are_precise() && passed;
    passed = test_addons_resolve_from_root_bin_in_cli_order() && passed;
    passed = test_retail_and_devkit_reject_addons_without_automatic_patchset() && passed;
    passed = test_direct_build_args_reject_unconfined_patch_components() && passed;
    passed = test_glitch_khv_donor_does_not_resolve_ambiguous_fixed_payloads() && passed;
    passed = test_final_input_is_validated_before_return() && passed;
    return passed ? 0 : 1;
}
