#pragma once

#include "Args.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace gxbuild3::utils {

    struct IniFilesResult {
        InputBootloaders bootloaders;
        std::vector<std::pair<std::string, std::vector<uint8_t>>> flashfs_sec;
    };

    std::optional<IniFilesResult> ReadIniFiles(
        std::string_view version,
        std::string_view type,
        std::string_view target_section,
        const std::filesystem::path& fw_dir = {}
    );

} // namespace gxbuild3::utils

namespace FileManager {
    using namespace gxbuild3::utils;
}
