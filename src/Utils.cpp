#include "Utils.hpp"

#include <Log.hpp>
#include <algorithm>
#include <cctype>
#include <system_error>

namespace Utils {

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
            Log::Warn("hex_string_to_bytes: odd number of hex digits");
            return bytes;
        }

        bytes.reserve(cleaned.size() / 2);
        for (size_t i = 0; i < cleaned.size(); i += 2) {
            std::string byte_string = cleaned.substr(i, 2);
            try {
                uint8_t byte = static_cast<uint8_t>(std::stoul(byte_string, nullptr, 16));
                bytes.push_back(byte);
            } catch (const std::exception&) {
                Log::Warn("hex_string_to_bytes: invalid hex byte at position {}", i);
                return {};
            }
        }

        return bytes;
    }

    std::optional<std::vector<uint8_t>> read_file(const fs::path& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            Log::Error("read_file: failed to open file: {}", path.string());
            return std::nullopt;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size < 0) {
            Log::Error("read_file: failed to determine file size: {}", path.string());
            return std::nullopt;
        }

        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            Log::Error("read_file: failed to read file: {}", path.string());
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
        if (path.has_parent_path() && !Utils::directory_exists(path.parent_path())) {
            if (!Utils::create_directory(path.parent_path())) {
                Log::Error("write_file: failed to create parent directory for: {}", path.string());
                return false;
            }
        }

        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            Log::Error("write_file: failed to open file for writing: {}", path.string());
            return false;
        }

        file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(length));
        if (!file.good()) {
            Log::Error("write_file: failed to write to file: {}", path.string());
            return false;
        }

        return true;
    }

    bool directory_exists(const fs::path& path) {
        try {
            return fs::exists(path) && fs::is_directory(path);
        } catch (const fs::filesystem_error& e) {
            Log::Error("directory_exists: filesystem error: {}", e.what());
            return false;
        }
    }

    bool create_directory(const fs::path& path) {
        try {
            if (fs::exists(path)) {
                if (fs::is_directory(path)) {
                    return true;
                }
                Log::Error("create_directory: path exists but is not a directory: {}",
                           path.string());
                return false;
            }
            return fs::create_directories(path);
        } catch (const fs::filesystem_error& e) {
            Log::Error("create_directory: filesystem error: {}", e.what());
            return false;
        }
    }

    std::optional<std::vector<fs::path>> list_files(const fs::path& path) {
        std::vector<fs::path> files;

        try {
            if (!fs::exists(path) || !fs::is_directory(path)) {
                Log::Error("list_files: path is not a valid directory: {}", path.string());
                return std::nullopt;
            }

            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
        } catch (const fs::filesystem_error& e) {
            Log::Error("list_files: filesystem error: {}", e.what());
            return std::nullopt;
        }

        return files;
    }

    std::optional<std::vector<fs::path>> list_files_recursive(const fs::path& path) {
        std::vector<fs::path> files;

        try {
            if (!fs::exists(path) || !fs::is_directory(path)) {
                Log::Error("list_files_recursive: path is not a valid directory: {}",
                           path.string());
                return std::nullopt;
            }

            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
        } catch (const fs::filesystem_error& e) {
            Log::Error("list_files_recursive: filesystem error: {}", e.what());
            return std::nullopt;
        }

        return files;
    }

} // namespace Utils
