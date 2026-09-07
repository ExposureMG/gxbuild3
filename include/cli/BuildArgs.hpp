#pragma once

#include "Args.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace gxbuild3::cli {

    struct BuildArgs {
        std::filesystem::path build_ini;
        std::string section;
        BuildType build_type{BuildType::Retail};
        std::optional<ImageType> image_type;
        std::vector<std::filesystem::path> source_dirs;
        std::optional<std::filesystem::path> input_path;
        std::optional<std::string> cpu_key;
        std::vector<std::string> config;
        std::vector<std::string> addons;
        std::optional<std::string> patch_extension;
        std::filesystem::path output_path;
        bool verbose{false};
    };

} // namespace gxbuild3::cli
