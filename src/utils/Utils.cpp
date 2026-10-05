#include "utils/Utils.hpp"

#include "utils/Log.hpp"

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

        file.write(reinterpret_cast<const char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));
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

} // namespace gxbuild3::utils
