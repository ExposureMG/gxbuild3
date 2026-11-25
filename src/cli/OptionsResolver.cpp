#include "cli/OptionsResolver.hpp"

#include "utils/Utils.hpp"

#include <array>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>
#include <system_error>
#include <unordered_set>

namespace gxbuild::cli {

    namespace {

        std::string normalize_key(std::string_view value) {
            value = utils::trim_view(value);
            while (!value.empty() && value.front() == '-') {
                value.remove_prefix(1);
            }
            return utils::to_lower(value);
        }

        // old config keys from legacy ini files that we just ignore
        bool is_legacy_non_option(std::string_view key) {
            static const std::unordered_set<std::string_view> legacy_keys{"type", "rev", "1blkey",
                                                                          "cpukey", "addon"};
            return legacy_keys.contains(key);
        }

        Result<uint8_t> parse_ldv(std::string_view raw, std::string_view item,
                                  const std::filesystem::path& source_path) {
            raw = utils::trim_view(raw);
            int base = 10;
            if (raw.starts_with("0x") || raw.starts_with("0X")) {
                base = 16;
                raw.remove_prefix(2);
            }
            unsigned int value = 0;
            const auto parsed = std::from_chars(raw.data(), raw.data() + raw.size(), value, base);
            if (raw.empty() || parsed.ec != std::errc{} || parsed.ptr != raw.data() + raw.size() ||
                value > std::numeric_limits<uint8_t>::max()) {
                return fail_with(ErrorCode::InvalidArgument,
                                 std::string(item) + " must be a complete numeric byte value",
                                 source_path, item);
            }
            return static_cast<uint8_t>(value);
        }

        Result<std::array<uint8_t, 3>>
        parse_pairing_data(std::string_view raw, const std::filesystem::path& source_path) {
            raw = utils::trim_view(raw);
            if (raw.starts_with("0x") || raw.starts_with("0X")) {
                raw.remove_prefix(2);
            }
            if (raw.size() != 6) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "pairing_data must contain exactly three bytes", source_path,
                                 "pairing_data");
            }

            const auto result = utils::decode_hex_bytes<3>(raw);
            if (!result) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "pairing_data must contain exactly three hexadecimal bytes",
                                 source_path, "pairing_data");
            }
            return *result;
        }

    } // namespace

    std::unexpected<Error> fail_with(ErrorCode code, std::string message,
                                     const std::filesystem::path& path, std::string_view item) {
        Error err{code, std::move(message)};
        if (!item.empty() && !err.message.contains(item)) {
            err.add_context(std::string(item));
        }
        if (!path.empty() && !err.message.contains(path.string())) {
            err.add_context(path.string());
        }
        return std::unexpected(std::move(err));
    }

    Result<OptionsArgs> load_options(const std::filesystem::path& options_path) {
        std::error_code status_error;
        const bool exists = std::filesystem::exists(options_path, status_error);
        if (status_error) {
            return fail_with(ErrorCode::IoError,
                             "Could not inspect options.ini: " + status_error.message(),
                             options_path);
        }
        if (!exists) {
            return OptionsArgs{};
        }
        const bool regular = std::filesystem::is_regular_file(options_path, status_error);
        if (status_error) {
            return fail_with(ErrorCode::IoError,
                             "Could not inspect options.ini: " + status_error.message(),
                             options_path);
        }
        if (!regular) {
            return fail_with(ErrorCode::IoError, "Could not read options.ini", options_path);
        }

        std::ifstream input(options_path, std::ios::binary);
        if (!input) {
            return fail_with(ErrorCode::IoError, "Could not read options.ini", options_path);
        }
        std::ostringstream contents;
        contents << input.rdbuf();
        if (input.fail() && !input.eof()) {
            return fail_with(ErrorCode::IoError, "Could not read options.ini", options_path);
        }

        return parse_options_text(contents.str(), options_path);
    }

    Result<std::pair<OptionsArgs, OptionsArgs>>
    apply_cli_options(OptionsArgs options, const std::vector<std::string>& raw_options) {
        OptionsManager effective(std::move(options));
        OptionsManager overrides;
        for (const auto& raw : raw_options) {
            if (utils::trim_view(raw).empty()) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "Command-line configuration cannot be empty", {}, raw);
            }
            OptionsManager next_effective(effective.data());
            OptionsManager next_overrides(overrides.data());
            if (!next_effective.parse(raw) || !next_overrides.parse(raw)) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "Invalid command-line configuration '" + raw + "'", {}, raw);
            }
            effective = std::move(next_effective);
            overrides = std::move(next_overrides);
        }
        return std::pair{effective.data(), overrides.data()};
    }

    Result<void> apply_winning_metadata(InputMetadata& metadata, const OptionsArgs& file_options,
                                        const OptionsArgs& cli_overrides, bool has_donor,
                                        const std::filesystem::path& options_path) {
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
            metadata.cf_pairing_data.reset();
        } else if (!has_donor && file_options.pairing_data) {
            auto value = parse_pairing_data(*file_options.pairing_data, options_path);
            if (!value) {
                return std::unexpected(value.error());
            }
            metadata.pairing_data = *value;
            metadata.cf_pairing_data.reset();
        }
        return {};
    }

    Result<OptionsArgs> parse_options_text(std::string_view text,
                                           const std::filesystem::path& source) {
        OptionsManager options;
        std::string_view remaining = text;
        size_t line_number = 0;
        while (!remaining.empty()) {
            ++line_number;
            const auto newline = remaining.find('\n');
            std::string_view line = utils::trim_view(remaining.substr(0, newline));
            remaining = newline == std::string_view::npos ? std::string_view{}
                                                          : remaining.substr(newline + 1);
            if (line.empty() || line.front() == ';' || line.front() == '#') {
                continue;
            }
            if (line.front() == '[') {
                return fail_with(ErrorCode::Malformed,
                                 "Sections are not valid in options.ini (line " +
                                     std::to_string(line_number) + ")",
                                 source, line);
            }

            const auto equals = line.find('=');
            if (equals == std::string_view::npos) {
                return fail_with(ErrorCode::Malformed,
                                 "Expected key=value in options.ini (line " +
                                     std::to_string(line_number) + ")",
                                 source, line);
            }
            const std::string key = normalize_key(line.substr(0, equals));
            std::string_view value = utils::trim_view(line.substr(equals + 1));
            if (const auto comment = value.find(';'); comment != std::string_view::npos) {
                value = utils::trim_view(value.substr(0, comment));
            }
            if (is_legacy_non_option(key)) {
                continue;
            }
            if (key.empty() || !OptionsManager::is_known_option(key) || !options.set(key, value)) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "Invalid option '" + key + "' in options.ini (line " +
                                     std::to_string(line_number) + ")",
                                 source, key);
            }
        }
        return options.data();
    }

} // namespace gxbuild::cli
