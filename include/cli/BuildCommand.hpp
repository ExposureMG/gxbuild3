#pragma once

#include "BuildRunner.hpp"
#include "cli/BuildArgs.hpp"
#include "cli/BuildInputResolver.hpp"

#include <expected>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace gxbuild3::cli {

    struct BuildCommandServices {
        std::function<std::expected<BuildRequest, ResolutionError>(const BuildArgs&)> resolve;
        std::function<BuildResult(const Input&)> build;
        std::function<bool(const std::filesystem::path&, const std::vector<uint8_t>&)> write;
    };

    struct CommandResult {
        int exit_code{0};
        std::string message;
    };

    CommandResult RunBuildCommand(const BuildArgs& args, const BuildCommandServices& services);
    BuildCommandServices DefaultBuildCommandServices(const std::filesystem::path& cwd);

} // namespace gxbuild3::cli
