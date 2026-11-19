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

    // Reads a whole file. A missing file fails with NotFound, any other failure with IoError;
    // the message carries the path and the OS reason.
    [[nodiscard]] Result<std::vector<uint8_t>> read_file(const fs::path& path);
    // As read_file, truncating the returned bytes to at most max_length.
    [[nodiscard]] Result<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    // Writes data to path, creating missing parent directories first. Fails with IoError.
    [[nodiscard]] Result<void> write_file(const fs::path& path, const std::vector<uint8_t>& data);

    [[nodiscard]] bool directory_exists(const fs::path& path);
    // Creates path and any missing parents; an existing directory is a success.
    [[nodiscard]] Result<void> create_directory(const fs::path& path);

} // namespace gxbuild3::utils
