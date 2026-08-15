#pragma once

#include <Log.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace gxbuild3::utils {

    /// @brief Converts a hex string to bytes
    /// @param hex_string Hex string (e.g., "AABBCCDD")
    /// @return Vector of bytes, empty on error
    std::vector<uint8_t> hex_string_to_bytes(const std::string& hex_string);

    /// @brief Reads entire file contents into a vector
    /// @param path File path
    /// @return File data as vector of bytes, or nullopt on error
    std::optional<std::vector<uint8_t>> read_file(const fs::path& path);

    /// @brief Reads file with maximum length limit
    /// @param path File path
    /// @param max_length Maximum bytes to read
    /// @return File data (up to max_length bytes), or nullopt on error
    std::optional<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    /// @brief Writes data to a file
    /// @param path File path
    /// @param data Data to write
    /// @return true on success, false on error
    bool write_file(const fs::path& path, const std::vector<uint8_t>& data);

    /// @brief Writes data to a file
    /// @param path File path
    /// @param data Pointer to data
    /// @param length Number of bytes to write
    /// @return true on success, false on error
    bool write_file(const fs::path& path, const uint8_t* data, size_t length);

    /// @brief Checks if a directory exists
    /// @param path Directory path
    /// @return true if directory exists, false otherwise
    bool directory_exists(const fs::path& path);

    /// @brief Creates a directory (and parent directories if needed)
    /// @param path Directory path
    /// @return true on success, false on error
    bool create_directory(const fs::path& path);

    /// @brief Lists all files in a directory
    /// @param path Directory path
    /// @return Vector of file paths, or nullopt on error
    std::optional<std::vector<fs::path>> list_files(const fs::path& path);

    /// @brief Gets all files in a directory recursively
    /// @param path Root directory path
    /// @return Vector of file paths, or nullopt on error
    std::optional<std::vector<fs::path>> list_files_recursive(const fs::path& path);

} // namespace gxbuild3::utils