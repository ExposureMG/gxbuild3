#include "cli/CommandLine.hpp"

#include "Args.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::cli {
    namespace {

        ParseError error(ParseErrorCode code, std::string_view argument, std::string_view message,
                         size_t index) {
            return {code, std::string(argument), std::string(message), index};
        }

        std::string lowercase(std::string_view raw) {
            std::string result;
            result.reserve(raw.size());
            for (const char character : raw) {
                result.push_back(
                    static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
            }
            return result;
        }

        std::vector<std::string> split_list(std::string_view raw) {
            std::vector<std::string> values;
            size_t start = 0;
            for (size_t index = 0; index <= raw.size(); ++index) {
                if (index == raw.size() || raw[index] == ',' || raw[index] == ';') {
                    if (index == start) {
                        return {};
                    }
                    values.emplace_back(raw.substr(start, index - start));
                    start = index + 1;
                }
            }
            return values;
        }

        bool has_path_separator(std::string_view value) {
            return value.find_first_of("/\\") != std::string_view::npos;
        }

        bool is_addon_name(std::string_view value) {
            return !value.empty() &&
                   std::all_of(value.begin(), value.end(), [](unsigned char character) {
                       return std::isalnum(character) || character == '_' || character == '-';
                   });
        }

        bool is_extension(std::string_view value) {
            if (value.empty() || value.front() == '_' || has_path_separator(value)) {
                return false;
            }
            return std::all_of(value.begin(), value.end(), [](unsigned char character) {
                return (character >= '0' && character <= '9') ||
                       (character >= 'A' && character <= 'Z') ||
                       (character >= 'a' && character <= 'z') || character == '_' ||
                       character == '-';
            });
        }

        bool is_valid_config(std::string_view value) {
            const auto equals = value.find('=');
            const std::string_view key = value.substr(0, equals);
            if (key.empty() || !OptionsManager::is_known_option(key)) {
                return false;
            }

            OptionsManager options;
            if (equals == std::string_view::npos) {
                return options.set_bool(key, true);
            }
            return options.set(key, value.substr(equals + 1));
        }

        std::expected<std::string_view, ParseError>
        take_value(std::span<const std::string_view> argv, size_t& index) {
            const auto option = argv[index];
            if (index + 1 >= argv.size() || argv[index + 1].empty() ||
                argv[index + 1].front() == '-') {
                return std::unexpected(
                    error(ParseErrorCode::MissingValue, option, "missing option value", index));
            }
            ++index;
            return argv[index];
        }

    } // namespace

    std::expected<ParsedCommand, ParseError>
    ParseCommandLine(std::span<const std::string_view> argv) {
        BuildArgs args;
        args.output_path = std::filesystem::current_path() / "updflash.bin";

        bool saw_build = false;
        bool saw_build_ini = false;
        bool saw_section = false;
        bool saw_build_type = false;
        bool saw_input = false;
        bool saw_output = false;
        bool saw_cpu_key = false;
        bool saw_extension = false;
        bool saw_verbose = false;

        for (size_t index = argv.empty() ? 0 : 1; index < argv.size(); ++index) {
            const std::string_view token = argv[index];
            if (token == "build" && !saw_build) {
                saw_build = true;
                continue;
            }
            if (token == "-h" || token == "--help") {
                return HelpCommand{};
            }
            if (token == "--version") {
                return VersionCommand{};
            }
            if (token == "-v" || token == "--verbose") {
                if (std::exchange(saw_verbose, true)) {
                    return std::unexpected(
                        error(ParseErrorCode::DuplicateArgument, token, "duplicate option", index));
                }
                args.verbose = true;
                continue;
            }
            if (token != "-b" && token != "--buildini" && token != "-s" && token != "--section" &&
                token != "-t" && token != "--buildtype" && token != "-d" && token != "--dir" &&
                token != "-i" && token != "--input" && token != "-o" && token != "--output" &&
                token != "-p" && token != "--cpukey" && token != "-e" && token != "--ext" &&
                token != "-c" && token != "--config" && token != "-a" && token != "--addon") {
                return std::unexpected(error(ParseErrorCode::UnknownArgument, token,
                                             "unknown argument '" + std::string(token) + "'", index));
            }

            const auto value = take_value(argv, index);
            if (!value) {
                return std::unexpected(value.error());
            }
            if (token == "-b" || token == "--buildini") {
                if (std::exchange(saw_build_ini, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                args.build_ini = *value;
            } else if (token == "-s" || token == "--section") {
                if (std::exchange(saw_section, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                args.section = *value;
            } else if (token == "-t" || token == "--buildtype") {
                if (std::exchange(saw_build_type, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                const auto colon = value->find(':');
                if (colon != value->npos && value->find(':', colon + 1) != value->npos) {
                    return std::unexpected(error(ParseErrorCode::InvalidBlockType, *value,
                                                 "invalid block type", index));
                }
                std::string type = lowercase(value->substr(0, colon));
                if (type == "glitch1" || type == "gg") {
                    type = "glitch";
                }
                const auto type_it = kBuildTypeMap.find(type);
                if (type_it == kBuildTypeMap.end()) {
                    return std::unexpected(error(ParseErrorCode::InvalidBuildType, *value,
                                                 "invalid build type", index));
                }
                args.build_type = type_it->second;
                if (colon != value->npos) {
                    const std::string block = lowercase(value->substr(colon + 1));
                    if (block == "xsb") {
                        args.image_type = ImageType::SmallBlock;
                    } else if (block == "psb") {
                        args.image_type = ImageType::NewSmallBlock;
                    } else if (block == "bb") {
                        args.image_type = ImageType::BigBlock;
                    } else if (block == "emmc") {
                        args.image_type = ImageType::Emmc;
                    } else {
                        return std::unexpected(error(ParseErrorCode::InvalidBlockType, *value,
                                                     "invalid block type", index));
                    }
                }
            } else if (token == "-d" || token == "--dir") {
                const auto values = split_list(*value);
                if (values.empty()) {
                    return std::unexpected(
                        error(ParseErrorCode::InvalidList, *value, "invalid list", index));
                }
                for (const auto& directory : values) {
                    args.source_dirs.emplace_back(directory);
                }
            } else if (token == "-i" || token == "--input") {
                if (std::exchange(saw_input, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                args.input_path = std::filesystem::path(*value);
            } else if (token == "-o" || token == "--output") {
                if (std::exchange(saw_output, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                args.output_path = std::filesystem::path(*value);
            } else if (token == "-p" || token == "--cpukey") {
                if (std::exchange(saw_cpu_key, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                args.cpu_key = std::string(*value);
            } else if (token == "-e" || token == "--ext") {
                if (std::exchange(saw_extension, true)) {
                    return std::unexpected(error(ParseErrorCode::DuplicateArgument, token,
                                                 "duplicate option", index - 1));
                }
                if (!is_extension(*value)) {
                    return std::unexpected(error(ParseErrorCode::InvalidExtension, *value,
                                                 "invalid patch extension", index));
                }
                args.patch_extension = std::string(*value);
            } else if (token == "-c" || token == "--config") {
                const auto values = split_list(*value);
                if (values.empty() || !std::all_of(values.begin(), values.end(), is_valid_config)) {
                    return std::unexpected(
                        error(ParseErrorCode::InvalidList, *value, "invalid config list", index));
                }
                args.config.insert(args.config.end(), values.begin(), values.end());
            } else if (token == "-a" || token == "--addon") {
                const auto values = split_list(*value);
                if (values.empty() || !std::all_of(values.begin(), values.end(), is_addon_name)) {
                    return std::unexpected(
                        error(ParseErrorCode::InvalidAddon, *value, "invalid add-on", index));
                }
                args.addons.insert(args.addons.end(), values.begin(), values.end());
            }
        }

        if (!saw_build_ini) {
            return std::unexpected(error(ParseErrorCode::MissingRequiredArgument, "--buildini",
                                         "missing required build INI", 0));
        }
        if (!saw_section) {
            return std::unexpected(error(ParseErrorCode::MissingRequiredArgument, "--section",
                                         "missing required section", 0));
        }
        if (!saw_build_type) {
            return std::unexpected(error(ParseErrorCode::MissingRequiredArgument, "--buildtype",
                                         "missing required build type", 0));
        }
        if (args.source_dirs.empty()) {
            return std::unexpected(error(ParseErrorCode::MissingRequiredArgument, "--dir",
                                         "missing required source directory", 0));
        }
        return ParsedCommand{std::move(args)};
    }

} // namespace gxbuild3::cli
