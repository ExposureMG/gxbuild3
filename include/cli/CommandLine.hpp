#pragma once

#include "cli/BuildArgs.hpp"
#include "gxbuild/Error.hpp"

#include <span>
#include <string_view>
#include <variant>

namespace gxbuild::cli {

    struct HelpCommand {};
    struct VersionCommand {};
    using ParsedCommand = std::variant<BuildArgs, HelpCommand, VersionCommand>;

    [[nodiscard]] Result<ParsedCommand>
    parse_command_line(std::span<const std::string_view> argv);

} // namespace gxbuild::cli
