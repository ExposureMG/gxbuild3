#pragma once

#include "Error.hpp"

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

namespace gxbuild3::utils {

    namespace fs = std::filesystem;

    std::string bytes_to_hex(std::span<const uint8_t> bytes);

    [[nodiscard]] Result<std::vector<uint8_t>> read_file(const fs::path& path);
    [[nodiscard]] Result<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    [[nodiscard]] Result<void> write_file(const fs::path& path, const std::vector<uint8_t>& data);

    [[nodiscard]] bool directory_exists(const fs::path& path);
    [[nodiscard]] Result<void> create_directory(const fs::path& path);

} // namespace gxbuild3::utils
