#pragma once

#include "cli/BuildArgs.hpp"

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace gxbuild3::cli {

    struct HelpCommand {};
    struct VersionCommand {};
    using ParsedCommand = std::variant<BuildArgs, HelpCommand, VersionCommand>;

    enum class ParseErrorCode {
        UnknownArgument,
        MissingValue,
        DuplicateArgument,
        MissingRequiredArgument,
        InvalidBuildType,
        InvalidBlockType,
        InvalidList,
        InvalidAddon,
        InvalidExtension,
    };

    struct ParseError {
        ParseErrorCode code;
        std::string argument;
        std::string message;
        size_t index{0};
    };

    std::expected<ParsedCommand, ParseError>
    ParseCommandLine(std::span<const std::string_view> argv);

} // namespace gxbuild3::cli
