#include "utils/Utils.hpp"

#include "utils/Log.hpp"
#include <algorithm>
#include <cctype>
#include <system_error>

namespace gxbuild3::utils {

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    static constexpr char hex_chars[] = "0123456789ABCDEF";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        hex.push_back(hex_chars[(b >> 4) & 0x0F]);
        hex.push_back(hex_chars[b & 0x0F]);
    }
    return hex;
}

std::string bytes_to_hex(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return "";
    }
    return bytes_to_hex(std::span<const uint8_t>(data, size));
}

std::vector<uint8_t> hex_string_to_bytes(const std::string& hex_string) {
    std::vector<uint8_t> bytes;

    std::string cleaned;
    cleaned.reserve(hex_string.size());
    for (char c : hex_string) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            cleaned += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }

    if (cleaned.size() % 2 != 0) {
        Log::Warn("Odd number of hex digits in hex string");
        return bytes;
    }

    bytes.reserve(cleaned.size() / 2);
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        std::string byte_string = cleaned.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_string, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception&) {
            Log::Warn("Invalid hex byte at position {}", i);
            return {};
        }
    }

    return bytes;
}

std::optional<std::vector<uint8_t>> read_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        Log::Trace("Failed to open file: '{}'", path.string());
        return std::nullopt;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size < 0) {
        Log::Warn("Failed to determine file size: '{}'", path.string());
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        Log::Warn("Failed to read file: '{}'", path.string());
        return std::nullopt;
    }

    return buffer;
}

std::optional<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length) {
    auto result = read_file(path);
    if (!result) {
        return std::nullopt;
    }

    if (result->size() > max_length) {
        result->resize(max_length);
    }

    return result;
}

bool write_file(const fs::path& path, const std::vector<uint8_t>& data) {
    return write_file(path, data.data(), data.size());
}

bool write_file(const fs::path& path, const uint8_t* data, size_t length) {
    if (path.has_parent_path() && !gxbuild3::utils::directory_exists(path.parent_path())) {
        if (!gxbuild3::utils::create_directory(path.parent_path())) {
            Log::Error("Failed to create parent directory for: '{}'", path.string());
            return false;
        }
    }

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        Log::Error("Failed to open file for writing: '{}'", path.string());
        return false;
    }

    file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(length));
    if (!file.good()) {
        Log::Error("Failed to write to file: '{}'", path.string());
        return false;
    }

    return true;
}

bool directory_exists(const fs::path& path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

bool create_directory(const fs::path& path) {
    std::error_code ec;
    if (fs::is_directory(path, ec)) {
        return true;
    }
    return fs::create_directories(path, ec);
}

std::optional<std::vector<fs::path>> list_files(const fs::path& path) {
    if (!directory_exists(path)) {
        Log::Error("Directory does not exist: '{}'", path.string());
        return std::nullopt;
    }

    std::vector<fs::path> files;
    std::error_code ec;

    for (const auto& entry : fs::directory_iterator(path, ec)) {
        if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }
    }

    if (ec) {
        Log::Error("Error iterating directory '{}': {}", path.string(), ec.message());
        return std::nullopt;
    }

    return files;
}

std::optional<std::vector<fs::path>> list_files_recursive(const fs::path& path) {
    if (!directory_exists(path)) {
        Log::Error("Directory does not exist: '{}'", path.string());
        return std::nullopt;
    }

    std::vector<fs::path> files;
    std::error_code ec;

    for (const auto& entry : fs::recursive_directory_iterator(path, ec)) {
        if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }
    }

    if (ec) {
        Log::Error("Error iterating directory '{}': {}", path.string(), ec.message());
        return std::nullopt;
    }

    return files;
}

} // namespace gxbuild3::utils
