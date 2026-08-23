#pragma once

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

#include "Endian.hpp"

namespace fs = std::filesystem;

namespace gxbuild3::utils {

    std::string bytes_to_hex(std::span<const uint8_t> bytes);
    std::string bytes_to_hex(const uint8_t* data, size_t size);
    std::vector<uint8_t> hex_string_to_bytes(const std::string& hex_string);

    std::optional<std::vector<uint8_t>> read_file(const fs::path& path);
    std::optional<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    bool write_file(const fs::path& path, const std::vector<uint8_t>& data);
    bool write_file(const fs::path& path, const uint8_t* data, size_t length);

    bool directory_exists(const fs::path& path);
    bool create_directory(const fs::path& path);

    std::optional<std::vector<fs::path>> list_files(const fs::path& path);
    std::optional<std::vector<fs::path>> list_files_recursive(const fs::path& path);

} // namespace gxbuild3::utils

namespace Utils {
    using namespace gxbuild3::utils;
}
