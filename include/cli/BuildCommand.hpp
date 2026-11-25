#pragma once

#include "core/BuildRunner.hpp"
#include "cli/BuildArgs.hpp"
#include "cli/BuildInputResolver.hpp"
#include "gxbuild/Error.hpp"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace gxbuild::cli {

    struct BuildCommandServices {
        std::function<Result<BuildRequest>(const BuildArgs&)> resolve;
        std::function<Result<std::vector<uint8_t>>(const Input&)> build;
        std::function<Result<void>(const std::filesystem::path&, const std::vector<uint8_t>&)>
            write;
    };

    struct CommandResult {
        int exit_code{0};
        std::string message;
    };

    CommandResult run_build_command(const BuildArgs& args, const BuildCommandServices& services);
    BuildCommandServices default_build_command_services(const std::filesystem::path& cwd);

} // namespace gxbuild::cli
