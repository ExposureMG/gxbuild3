#include "cli/BuildInputResolver.hpp"

#include "BuildRunner.hpp"
#include "InputValidator.hpp"
#include "ini/IniParser.hpp"
#include "nand/objects/Keyvault.hpp"
#include "utils/FileManager.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace gxbuild3::cli {
    namespace {

        ResolutionError error(ResolutionErrorCode code, std::string message,
                              std::filesystem::path path = {}, std::string item = {}) {
            return {code, std::move(message), std::move(path), std::move(item)};
        }

        std::string_view trim_view(std::string_view value) {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
                value.remove_prefix(1);
            }
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
                value.remove_suffix(1);
            }
            return value;
        }

        std::string normalize_key(std::string_view value) {
            value = trim_view(value);
            while (!value.empty() && value.front() == '-') {
                value.remove_prefix(1);
            }
            std::string result;
            result.reserve(value.size());
            for (const char character : value) {
                result.push_back(
                    static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
            }
            return result;
        }

        bool is_legacy_non_option(std::string_view key) {
            static const std::unordered_set<std::string_view> legacy_keys{"type", "rev", "1blkey",
                                                                          "cpukey", "addon"};
            return legacy_keys.contains(key);
        }

        std::filesystem::path anchored(const std::filesystem::path& working_directory,
                                       const std::filesystem::path& path) {
            return path.is_absolute() ? path : working_directory / path;
        }

        std::expected<OptionsArgs, ResolutionError>
        load_options(const std::filesystem::path& options_path) {
            std::error_code status_error;
            const bool exists = std::filesystem::exists(options_path, status_error);
            if (status_error) {
                return std::unexpected(error(
                    ResolutionErrorCode::OptionsReadFailed,
                    "Could not inspect options.ini: " + status_error.message(), options_path));
            }
            if (!exists) {
                return OptionsArgs{};
            }
            if (!std::filesystem::is_regular_file(options_path, status_error)) {
                return std::unexpected(error(ResolutionErrorCode::OptionsReadFailed,
                                             "Could not read options.ini", options_path));
            }

            std::ifstream input(options_path, std::ios::binary);
            if (!input) {
                return std::unexpected(error(ResolutionErrorCode::OptionsReadFailed,
                                             "Could not read options.ini", options_path));
            }
            std::ostringstream contents;
            contents << input.rdbuf();
            if (input.fail() && !input.eof()) {
                return std::unexpected(error(ResolutionErrorCode::OptionsReadFailed,
                                             "Could not read options.ini", options_path));
            }

            OptionsManager options;
            const std::string content = contents.str();
            std::string_view remaining = content;
            size_t line_number = 0;
            while (!remaining.empty()) {
                ++line_number;
                const auto newline = remaining.find('\n');
                std::string_view line = trim_view(remaining.substr(0, newline));
                remaining = newline == std::string_view::npos ? std::string_view{}
                                                              : remaining.substr(newline + 1);
                if (line.empty() || line.front() == ';' || line.front() == '#') {
                    continue;
                }
                if (line.front() == '[') {
                    return std::unexpected(error(ResolutionErrorCode::InvalidOption,
                                                 "Sections are not valid in options.ini (line " +
                                                     std::to_string(line_number) + ")",
                                                 options_path, std::string(line)));
                }

                const auto equals = line.find('=');
                if (equals == std::string_view::npos) {
                    return std::unexpected(error(ResolutionErrorCode::InvalidOption,
                                                 "Expected key=value in options.ini (line " +
                                                     std::to_string(line_number) + ")",
                                                 options_path, std::string(line)));
                }
                const std::string key = normalize_key(line.substr(0, equals));
                std::string_view value = trim_view(line.substr(equals + 1));
                if (const auto comment = value.find(';'); comment != std::string_view::npos) {
                    value = trim_view(value.substr(0, comment));
                }
                if (is_legacy_non_option(key)) {
                    continue;
                }
                if (key.empty() || !OptionsManager::is_known_option(key) ||
                    !options.set(key, value)) {
                    return std::unexpected(error(ResolutionErrorCode::InvalidOption,
                                                 "Invalid option '" + key +
                                                     "' in options.ini (line " +
                                                     std::to_string(line_number) + ")",
                                                 options_path, key));
                }
            }
            return options.data();
        }

        std::expected<std::pair<OptionsArgs, OptionsArgs>, ResolutionError>
        apply_cli_options(OptionsArgs options, const std::vector<std::string>& raw_options) {
            OptionsManager effective(std::move(options));
            OptionsManager overrides;
            for (const auto& raw : raw_options) {
                if (trim_view(raw).empty()) {
                    return std::unexpected(error(ResolutionErrorCode::InvalidOption,
                                                 "Command-line configuration cannot be empty", {},
                                                 raw));
                }
                OptionsManager next_effective(effective.data());
                OptionsManager next_overrides(overrides.data());
                if (!next_effective.parse(raw) || !next_overrides.parse(raw)) {
                    return std::unexpected(error(ResolutionErrorCode::InvalidOption,
                                                 "Invalid command-line configuration '" + raw + "'",
                                                 {}, raw));
                }
                effective = std::move(next_effective);
                overrides = std::move(next_overrides);
            }
            return std::pair{effective.data(), overrides.data()};
        }

        std::expected<std::vector<uint8_t>, ResolutionError>
        parse_cpu_key(std::string_view raw, const std::filesystem::path& path) {
            raw = trim_view(raw);
            const auto parsed = validate_cpu_key_hex(raw);
            if (parsed.status == CpuKeyStatus::Invalid) {
                return std::unexpected(error(ResolutionErrorCode::InvalidCpuKey, parsed.message,
                                             path, std::string(raw)));
            }
            return parsed.key;
        }

        std::vector<std::filesystem::path>
        resolved_roots(const std::filesystem::path& working_directory, const BuildArgs& args) {
            std::vector<std::filesystem::path> roots;
            roots.reserve(args.source_dirs.size());
            for (const auto& root : args.source_dirs) {
                roots.push_back(anchored(working_directory, root));
            }
            return roots;
        }

        std::string lowercase_basename(std::string_view name) {
            std::string result = std::filesystem::path(name).filename().string();
            std::transform(result.begin(), result.end(), result.begin(), [](unsigned char value) {
                return static_cast<char>(std::tolower(value));
            });
            return result;
        }

        std::expected<std::optional<gxbuild3::utils::ResolvedFile>, ResolutionError>
        find_asset(std::string_view name, const std::vector<std::filesystem::path>& roots,
                   gxbuild3::utils::ScanOptions options = {},
                   gxbuild3::utils::AssetKind kind = gxbuild3::utils::AssetKind::Regular) {
            auto found = FileManager::FindFileDataDetailed(name, roots, options, kind);
            if (!found) {
                return std::unexpected(error(ResolutionErrorCode::AssetNotFound,
                                             found.error().message, found.error().source_path,
                                             std::string(name)));
            }
            return std::move(*found);
        }

        std::expected<uint8_t, ResolutionError>
        parse_ldv(std::string_view raw, std::string_view item,
                  const std::filesystem::path& source_path) {
            raw = trim_view(raw);
            int base = 10;
            if (raw.starts_with("0x") || raw.starts_with("0X")) {
                base = 16;
                raw.remove_prefix(2);
            }
            unsigned int value = 0;
            const auto parsed = std::from_chars(raw.data(), raw.data() + raw.size(), value, base);
            if (raw.empty() || parsed.ec != std::errc{} || parsed.ptr != raw.data() + raw.size() ||
                value > std::numeric_limits<uint8_t>::max()) {
                return std::unexpected(
                    error(ResolutionErrorCode::InvalidInput,
                          std::string(item) + " must be a complete numeric byte value", source_path,
                          std::string(item)));
            }
            return static_cast<uint8_t>(value);
        }

        std::expected<std::array<uint8_t, 3>, ResolutionError>
        parse_pairing_data(std::string_view raw, const std::filesystem::path& source_path) {
            raw = trim_view(raw);
            if (raw.starts_with("0x") || raw.starts_with("0X")) {
                raw.remove_prefix(2);
            }
            if (raw.size() != 6) {
                return std::unexpected(error(ResolutionErrorCode::InvalidInput,
                                             "pairing_data must contain exactly three bytes",
                                             source_path, "pairing_data"));
            }

            auto nibble = [](char value) -> std::optional<uint8_t> {
                if (value >= '0' && value <= '9') {
                    return static_cast<uint8_t>(value - '0');
                }
                value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
                if (value >= 'a' && value <= 'f') {
                    return static_cast<uint8_t>(value - 'a' + 10);
                }
                return std::nullopt;
            };

            std::array<uint8_t, 3> result{};
            for (size_t index = 0; index < result.size(); ++index) {
                const auto high = nibble(raw[index * 2]);
                const auto low = nibble(raw[index * 2 + 1]);
                if (!high || !low) {
                    return std::unexpected(
                        error(ResolutionErrorCode::InvalidInput,
                              "pairing_data must contain exactly three hexadecimal bytes",
                              source_path, "pairing_data"));
                }
                result[index] = static_cast<uint8_t>((*high << 4) | *low);
            }
            return result;
        }

        std::expected<void, ResolutionError>
        apply_winning_metadata(InputMetadata& metadata, const OptionsArgs& file_options,
                               const OptionsArgs& cli_overrides, bool has_donor,
                               const std::filesystem::path& options_path) {
            // Select a source before decoding it. In particular, malformed
            // options.ini text must be irrelevant when donor or CLI data wins.
            if (cli_overrides.cbldv) {
                auto value = parse_ldv(*cli_overrides.cbldv, "cbldv", {});
                if (!value) {
                    return std::unexpected(value.error());
                }
                metadata.cb_ldv = *value;
            } else if (!has_donor && file_options.cbldv) {
                auto value = parse_ldv(*file_options.cbldv, "cbldv", options_path);
                if (!value) {
                    return std::unexpected(value.error());
                }
                metadata.cb_ldv = *value;
            }

            if (cli_overrides.cfldv) {
                auto value = parse_ldv(*cli_overrides.cfldv, "cfldv", {});
                if (!value) {
                    return std::unexpected(value.error());
                }
                metadata.cf_ldv = *value;
            } else if ((!has_donor || !metadata.cf_ldv) && file_options.cfldv) {
                auto value = parse_ldv(*file_options.cfldv, "cfldv", options_path);
                if (!value) {
                    return std::unexpected(value.error());
                }
                metadata.cf_ldv = *value;
            }

            if (cli_overrides.pairing_data) {
                auto value = parse_pairing_data(*cli_overrides.pairing_data, {});
                if (!value) {
                    return std::unexpected(value.error());
                }
                metadata.pairing_data = *value;
            } else if (!has_donor && file_options.pairing_data) {
                auto value = parse_pairing_data(*file_options.pairing_data, options_path);
                if (!value) {
                    return std::unexpected(value.error());
                }
                metadata.pairing_data = *value;
            }
            return {};
        }

        std::string patch_name(std::string_view key, const std::optional<std::string>& extension) {
            std::string result = "patches_";
            result += key;
            if (extension) {
                result += '_';
                result += *extension;
            }
            result += ".bin";
            return result;
        }

        bool is_ascii_alphanumeric(char value) {
            return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
                   (value >= 'a' && value <= 'z');
        }

        bool is_filename_component(std::string_view value, bool allow_underscore) {
            if (value.empty() || value == "." || value == ".." ||
                value.find_first_of("/\\") != std::string_view::npos ||
                std::filesystem::path(value).is_absolute()) {
                return false;
            }
            return std::all_of(value.begin(), value.end(), [allow_underscore](char character) {
                return is_ascii_alphanumeric(character) || character == '-' || character == '.' ||
                       (allow_underscore && character == '_');
            });
        }

        bool is_patch_extension(std::string_view value) {
            return !value.empty() && value.front() != '_' &&
                   std::all_of(value.begin(), value.end(), [](char character) {
                       return is_ascii_alphanumeric(character) || character == '_' ||
                              character == '-';
                   });
        }

        std::expected<void, ResolutionError> validate_patch_components(const BuildArgs& args) {
            if (!is_filename_component(args.section, true)) {
                return std::unexpected(error(ResolutionErrorCode::InvalidInput,
                                             "Section must be a filename-safe component", {},
                                             args.section));
            }
            if (args.patch_extension && !is_patch_extension(*args.patch_extension)) {
                return std::unexpected(
                    error(ResolutionErrorCode::InvalidInput,
                          "Patch extension must be a filename-safe component without a leading "
                          "underscore",
                          {}, *args.patch_extension));
            }
            for (const auto& addon : args.addons) {
                if (addon.empty() || !std::all_of(addon.begin(), addon.end(), [](char character) {
                        return is_ascii_alphanumeric(character) || character == '_' ||
                               character == '-';
                    })) {
                    return std::unexpected(error(
                        ResolutionErrorCode::InvalidInput,
                        "Add-on must be a bare ASCII logical name using letters, digits, '_' or "
                        "'-'",
                        {}, addon));
                }
            }
            return {};
        }

        std::optional<std::string> automatic_patch_name(const BuildArgs& args,
                                                        bool glitch3_fallback = false) {
            switch (args.build_type) {
                case BuildType::Retail:
                case BuildType::Devkit:
                    return std::nullopt;
                case BuildType::Jtag:
                    return patch_name("fat", args.patch_extension);
                case BuildType::Glitch:
                    return patch_name(args.section, args.patch_extension);
                case BuildType::Glitch2:
                    return patch_name("g2" + args.section, args.patch_extension);
                case BuildType::Glitch2m:
                    return patch_name("g2m" + args.section, args.patch_extension);
                case BuildType::Glitch3:
                    return patch_name((glitch3_fallback ? "g2" : "g3") + args.section,
                                      args.patch_extension);
            }
            return std::nullopt;
        }

        struct DirectFile {
            std::filesystem::path path;
            std::vector<uint8_t> data;
        };

        std::expected<std::optional<DirectFile>, ResolutionError>
        find_bin_file(std::string_view filename, const std::vector<std::filesystem::path>& roots,
                      ResolutionErrorCode failure_code) {
            for (const auto& root : roots) {
                const auto bin_directory = (root / "bin").lexically_normal();
                const auto candidate = (bin_directory / filename).lexically_normal();
                if (candidate.parent_path() != bin_directory ||
                    candidate.filename() != std::filesystem::path(filename)) {
                    return std::unexpected(error(
                        ResolutionErrorCode::InvalidInput,
                        "Resolved patch or add-on must be an immediate child of the source bin "
                        "directory",
                        candidate, std::string(filename)));
                }
                std::error_code status_error;
                const auto status = std::filesystem::status(candidate, status_error);
                if (status.type() == std::filesystem::file_type::not_found) {
                    continue;
                }
                if (status_error) {
                    return std::unexpected(error(failure_code,
                                                 "Could not inspect '" + candidate.string() +
                                                     "': " + status_error.message(),
                                                 candidate, std::string(filename)));
                }
                if (!std::filesystem::is_regular_file(status)) {
                    return std::unexpected(error(failure_code,
                                                 "Resolved asset is not a readable regular file",
                                                 candidate, std::string(filename)));
                }
                auto data = Utils::read_file(candidate);
                if (!data) {
                    return std::unexpected(error(failure_code, "Could not read resolved asset",
                                                 candidate, std::string(filename)));
                }
                return std::optional<DirectFile>{DirectFile{candidate, std::move(*data)}};
            }
            return std::optional<DirectFile>{};
        }

        void overlay_flashfs(std::vector<std::pair<std::string, std::vector<uint8_t>>>& destination,
                             std::pair<std::string, std::vector<uint8_t>> file,
                             std::unordered_map<std::string, size_t>& positions) {
            const auto key = lowercase_basename(file.first);
            const auto [position, inserted] = positions.emplace(key, destination.size());
            if (inserted) {
                destination.push_back(std::move(file));
            } else {
                destination[position->second] = std::move(file);
            }
        }

    } // namespace

    BuildInputResolver::BuildInputResolver(std::filesystem::path working_directory)
        : working_directory_(std::move(working_directory)) {}

    std::expected<ResolvedFoundations, ResolutionError>
    BuildInputResolver::ResolveFoundations(const BuildArgs& args) const {
        if (args.source_dirs.empty()) {
            return std::unexpected(error(ResolutionErrorCode::InvalidSourceDirectory,
                                         "At least one source root is required"));
        }
        std::vector<std::filesystem::path> roots;
        roots.reserve(args.source_dirs.size());
        for (const auto& root : args.source_dirs) {
            if (root.empty()) {
                return std::unexpected(error(ResolutionErrorCode::InvalidSourceDirectory,
                                             "Source root path cannot be empty"));
            }
            auto resolved_root = anchored(working_directory_, root);
            std::error_code directory_error;
            if (!std::filesystem::is_directory(resolved_root, directory_error)) {
                std::string message = "Source root is not a directory";
                if (directory_error) {
                    message += ": " + directory_error.message();
                }
                return std::unexpected(error(ResolutionErrorCode::InvalidSourceDirectory,
                                             std::move(message), std::move(resolved_root)));
            }
            roots.push_back(std::move(resolved_root));
        }

        auto file_options = load_options(working_directory_ / "options.ini");
        if (!file_options) {
            return std::unexpected(file_options.error());
        }
        auto layered_options = apply_cli_options(*file_options, args.config);
        if (!layered_options) {
            return std::unexpected(layered_options.error());
        }

        std::expected<std::vector<uint8_t>, ResolutionError> cpu_key =
            std::unexpected(error(ResolutionErrorCode::CpuKeyNotFound,
                                  "No CPU key was supplied and cpukey.txt was not found"));
        if (args.cpu_key) {
            cpu_key = parse_cpu_key(*args.cpu_key, {});
        } else {
            auto discovered = FileManager::FindFileDataDetailed("cpukey.txt", roots);
            if (!discovered) {
                return std::unexpected(error(ResolutionErrorCode::CpuKeyReadFailed,
                                             discovered.error().message,
                                             discovered.error().source_path, "cpukey.txt"));
            }
            if (*discovered) {
                const std::string raw_key((*discovered)->data.begin(), (*discovered)->data.end());
                cpu_key = parse_cpu_key(raw_key, (*discovered)->source_path);
            }
        }
        if (!cpu_key) {
            return std::unexpected(cpu_key.error());
        }

        std::optional<std::filesystem::path> nand_path;
        std::optional<std::vector<uint8_t>> nand_data;
        if (args.input_path) {
            nand_path = anchored(working_directory_, *args.input_path);
            nand_data = Utils::read_file(*nand_path);
            if (!nand_data) {
                return std::unexpected(error(ResolutionErrorCode::InputReadFailed,
                                             "Could not read explicit donor NAND", *nand_path));
            }
        } else {
            auto discovered = FileManager::FindFileDataDetailed("nanddump.bin", roots);
            if (!discovered) {
                return std::unexpected(error(ResolutionErrorCode::InputReadFailed,
                                             discovered.error().message,
                                             discovered.error().source_path, "nanddump.bin"));
            }
            if (*discovered) {
                nand_path = (*discovered)->source_path;
                nand_data = std::move((*discovered)->data);
            }
        }

        std::optional<Input> donor;
        ImageType image_type{};
        if (nand_data) {
            try {
                donor = ExtractAll(*nand_data, *cpu_key);
            } catch (const std::exception& exception) {
                return std::unexpected(error(
                    ResolutionErrorCode::InvalidDonor,
                    "Could not parse donor NAND: " + std::string(exception.what()), *nand_path));
            } catch (...) {
                return std::unexpected(error(ResolutionErrorCode::InvalidDonor,
                                             "Could not parse donor NAND", *nand_path));
            }
            if (!donor) {
                return std::unexpected(
                    error(ResolutionErrorCode::InvalidDonor,
                          "Could not extract donor NAND with the resolved CPU key", *nand_path));
            }

            const ImageType detected_type = donor->image_type;
            image_type = args.image_type.value_or(detected_type);
            if (args.image_type && *args.image_type != detected_type) {
                donor->metadata.nand_image.reset();
                donor->image_type = *args.image_type;
            }
        } else {
            if (!args.image_type) {
                return std::unexpected(error(ResolutionErrorCode::BlockTypeRequired,
                                             "A block type is required without a donor NAND"));
            }
            image_type = *args.image_type;
        }

        auto [options, cli_overrides] = std::move(*layered_options);
        return ResolvedFoundations{.file_options = std::move(*file_options),
                                   .options = std::move(options),
                                   .cli_overrides = std::move(cli_overrides),
                                   .cpu_key = std::move(*cpu_key),
                                   .donor = std::move(donor),
                                   .image_type = image_type};
    }

    std::expected<BuildRequest, ResolutionError>
    BuildInputResolver::Resolve(const BuildArgs& args) const {
        try {
            auto foundations = ResolveFoundations(args);
            if (!foundations) {
                return std::unexpected(foundations.error());
            }
            const auto valid_components = validate_patch_components(args);
            if (!valid_components) {
                return std::unexpected(valid_components.error());
            }
            const auto roots = resolved_roots(working_directory_, args);

            if (args.build_ini.empty()) {
                return std::unexpected(
                    error(ResolutionErrorCode::BuildIniReadFailed, "A build INI path is required"));
            }
            const auto ini_path = anchored(working_directory_, args.build_ini);
            std::error_code ini_status_error;
            const auto ini_status = std::filesystem::status(ini_path, ini_status_error);
            if (ini_status.type() == std::filesystem::file_type::not_found || ini_status_error ||
                !std::filesystem::is_regular_file(ini_status)) {
                std::string message = "Build INI is not a readable regular file";
                if (ini_status_error &&
                    ini_status.type() != std::filesystem::file_type::not_found) {
                    message += ": " + ini_status_error.message();
                }
                return std::unexpected(
                    error(ResolutionErrorCode::BuildIniReadFailed, std::move(message), ini_path));
            }

            const auto ini_document = Ini::ParseFile(ini_path);
            if (!ini_document) {
                return std::unexpected(
                    error(ResolutionErrorCode::BuildIniReadFailed,
                          "Could not read build INI: " +
                              std::string(Ini::ParseErrorString(ini_document.error())),
                          ini_path));
            }
            if (args.section.empty()) {
                return std::unexpected(error(ResolutionErrorCode::SectionNotFound,
                                             "A build INI section stem is required", ini_path));
            }
            const std::string target_section = args.section + "bl";
            const auto* section = ini_document->get(target_section);
            if (!section) {
                return std::unexpected(
                    error(ResolutionErrorCode::SectionNotFound,
                          "Required build INI section [" + target_section + "] was not found",
                          ini_path, target_section));
            }

            const gxbuild3::utils::ScanOptions scan_options{
                .nosusecurity = foundations->options.nosusecurity.value_or(false)};
            std::unordered_set<std::string> donor_flashfs_names;
            if (foundations->donor && foundations->donor->flashfs_sec) {
                for (const auto& file : *foundations->donor->flashfs_sec) {
                    donor_flashfs_names.insert(lowercase_basename(file.first));
                }
            }
            for (const auto& entry : *section) {
                const auto key = lowercase_basename(entry.key);
                if (key.empty() || key == "none") {
                    continue;
                }
                auto found = find_asset(entry.key, roots, scan_options,
                                        gxbuild3::utils::AssetKind::Bootloader);
                if (!found) {
                    return std::unexpected(found.error());
                }
                if (!*found) {
                    return std::unexpected(error(
                        ResolutionErrorCode::AssetNotFound,
                        "Required INI bootloader '" + entry.key + "' from '" + ini_path.string() +
                            "' was not found",
                        ini_path, entry.key));
                }
            }
            for (const auto section_name : {"security", "flashfs"}) {
                const auto* payload_section = ini_document->get(section_name);
                if (!payload_section) {
                    continue;
                }
                for (const auto& entry : *payload_section) {
                    const auto key = lowercase_basename(entry.key);
                    if (key.empty() || key == "none") {
                        continue;
                    }
                    auto found = find_asset(entry.key, roots, scan_options);
                    if (!found) {
                        return std::unexpected(found.error());
                    }
                    if (!*found && !donor_flashfs_names.contains(key)) {
                        return std::unexpected(error(
                            ResolutionErrorCode::AssetNotFound,
                            "Required INI payload '" + entry.key + "' from '" + ini_path.string() +
                                "' was not found in the donor or source roots",
                            ini_path, entry.key));
                    }
                }
            }

            const auto ini_files =
                FileManager::ReadIniFiles(ini_path, target_section, roots, scan_options);
            if (!ini_files) {
                return std::unexpected(error(ResolutionErrorCode::AssetNotFound,
                                             "Could not resolve build INI assets", ini_path,
                                             target_section));
            }

            Input input = foundations->donor.value_or(Input{});
            input.build_type = args.build_type;
            input.image_type = foundations->image_type;
            input.options = foundations->options;
            input.metadata.cpu_key = foundations->cpu_key;

            const auto resolved_metadata = apply_winning_metadata(
                input.metadata, foundations->file_options, foundations->cli_overrides,
                foundations->donor.has_value(), working_directory_ / "options.ini");
            if (!resolved_metadata) {
                return std::unexpected(resolved_metadata.error());
            }

            auto keyvault = find_asset("kv.bin", roots, scan_options);
            if (!keyvault) {
                return std::unexpected(keyvault.error());
            }
            auto smc = find_asset("smc.bin", roots, scan_options);
            if (!smc) {
                return std::unexpected(smc.error());
            }

            if (!foundations->donor) {
                if (!*keyvault) {
                    return std::unexpected(error(ResolutionErrorCode::IncompleteLooseDonor,
                                                 "Loose donor requires kv.bin", {}, "kv.bin"));
                }
                if (!*smc) {
                    return std::unexpected(error(ResolutionErrorCode::IncompleteLooseDonor,
                                                 "Loose donor requires smc.bin", {}, "smc.bin"));
                }
                if (!foundations->file_options.cbldv && !foundations->cli_overrides.cbldv) {
                    return std::unexpected(error(ResolutionErrorCode::IncompleteLooseDonor,
                                                 "Loose donor requires cbldv", {}, "cbldv"));
                }
                if (!foundations->file_options.cfldv && !foundations->cli_overrides.cfldv) {
                    return std::unexpected(error(ResolutionErrorCode::IncompleteLooseDonor,
                                                 "Loose donor requires cfldv", {}, "cfldv"));
                }
                if (!foundations->file_options.pairing_data &&
                    !foundations->cli_overrides.pairing_data) {
                    return std::unexpected(error(ResolutionErrorCode::IncompleteLooseDonor,
                                                 "Loose donor requires pairing_data", {},
                                                 "pairing_data"));
                }
            }

            if (*keyvault) {
                try {
                    input.metadata.keyvault =
                        keyvault_decrypt(foundations->cpu_key, (**keyvault).data);
                } catch (const std::exception& exception) {
                    return std::unexpected(
                        error(ResolutionErrorCode::InvalidInput,
                              "Could not decrypt kv.bin: " + std::string(exception.what()),
                              (**keyvault).source_path, "kv.bin"));
                } catch (...) {
                    return std::unexpected(error(ResolutionErrorCode::InvalidInput,
                                                 "Could not decrypt kv.bin",
                                                 (**keyvault).source_path, "kv.bin"));
                }
            }
            if (*smc) {
                input.metadata.smc = std::move((**smc).data);
            }

            for (size_t index = 0; index < input.mobiles.slots.size(); ++index) {
                const std::string name =
                    "mobile" + std::string(1, static_cast<char>('A' + index)) + ".bin";
                auto mobile = find_asset(name, roots, scan_options);
                if (!mobile) {
                    return std::unexpected(mobile.error());
                }
                if (*mobile) {
                    input.mobiles.slots[index] = std::move((**mobile).data);
                }
            }

            input.bootloaders = ini_files->bootloaders;

            std::vector<std::pair<std::string, std::vector<uint8_t>>> flashfs;
            if (input.flashfs_sec) {
                flashfs = std::move(*input.flashfs_sec);
            }
            std::unordered_map<std::string, size_t> flashfs_positions;
            for (size_t index = 0; index < flashfs.size(); ++index) {
                flashfs_positions.try_emplace(lowercase_basename(flashfs[index].first), index);
            }
            for (auto file : ini_files->flashfs_sec) {
                const auto key = lowercase_basename(file.first);
                if ((key == "secdata.bin" || key == "extended.bin") &&
                    !gxbuild3::NAND::crypt_secfile(foundations->cpu_key, file.second)) {
                    return std::unexpected(
                        error(ResolutionErrorCode::InvalidInput,
                              "Could not decrypt secure INI file at the Input boundary", ini_path,
                              file.first));
                }
                overlay_flashfs(flashfs, std::move(file), flashfs_positions);
            }
            input.flashfs_sec = std::move(flashfs);

            if ((args.build_type == BuildType::Retail || args.build_type == BuildType::Devkit) &&
                !args.addons.empty()) {
                return std::unexpected(error(
                    ResolutionErrorCode::InvalidInput,
                    "Add-ons require an automatic patchset and are not supported for retail or "
                    "devkit builds",
                    {}, args.addons.front()));
            }

            InputPatches patches{};
            bool has_patches = false;
            if (const auto automatic_name = automatic_patch_name(args)) {
                auto automatic =
                    find_bin_file(*automatic_name, roots, ResolutionErrorCode::PatchsetNotFound);
                if (!automatic) {
                    return std::unexpected(automatic.error());
                }
                std::string selected_name = *automatic_name;
                if (!*automatic && args.build_type == BuildType::Glitch3) {
                    selected_name = *automatic_patch_name(args, true);
                    automatic =
                        find_bin_file(selected_name, roots, ResolutionErrorCode::PatchsetNotFound);
                    if (!automatic) {
                        return std::unexpected(automatic.error());
                    }
                }
                if (!*automatic) {
                    return std::unexpected(error(ResolutionErrorCode::PatchsetNotFound,
                                                 "Required automatic patchset was not found", {},
                                                 selected_name));
                }
                patches.automatic = InputPatchFile{selected_name, std::move((**automatic).data)};
                has_patches = true;
            }

            for (const auto& addon : args.addons) {
                const std::string filename = addon + ".bin";
                auto found = find_bin_file(filename, roots, ResolutionErrorCode::AddonNotFound);
                if (!found) {
                    return std::unexpected(found.error());
                }
                if (!*found) {
                    return std::unexpected(error(ResolutionErrorCode::AddonNotFound,
                                                 "Required add-on was not found", {}, filename));
                }
                patches.addons.push_back(InputPatchFile{filename, std::move((**found).data)});
                has_patches = true;
            }
            if (has_patches) {
                input.patches = std::move(patches);
            } else {
                input.patches.reset();
            }

            if (const auto validation = ValidateInput(input); !validation) {
                return std::unexpected(
                    error(ResolutionErrorCode::InvalidInput, validation.error().message));
            }
            return BuildRequest{.input = std::move(input),
                                .output_path = anchored(working_directory_, args.output_path)};
        } catch (const std::exception& exception) {
            return std::unexpected(
                error(ResolutionErrorCode::InvalidInput,
                      "Input resolution failed: " + std::string(exception.what())));
        } catch (...) {
            return std::unexpected(
                error(ResolutionErrorCode::InvalidInput, "Input resolution failed"));
        }
    }

} // namespace gxbuild3::cli
