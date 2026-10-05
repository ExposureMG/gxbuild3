#pragma once

#include "Endian.hpp"

#include <cassert>
#include <concepts>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace gxbuild3::utils {

    std::string bytes_to_hex(std::span<const uint8_t> bytes);

    std::optional<std::vector<uint8_t>> read_file(const fs::path& path);
    std::optional<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    bool write_file(const fs::path& path, const std::vector<uint8_t>& data);

    bool directory_exists(const fs::path& path);
    bool create_directory(const fs::path& path);

} // namespace gxbuild3::utils

namespace Utils {
    using namespace gxbuild3::utils;
}
