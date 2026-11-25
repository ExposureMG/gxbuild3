#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <random>
#include <string_view>
#include <system_error>

namespace gxbuild::utils {

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

    std::optional<std::vector<uint8_t>> decode_hex(std::string_view hex) {
        if (hex.size() % 2 != 0) {
            return std::nullopt;
        }
        std::vector<uint8_t> out(hex.size() / 2);
        for (size_t i = 0; i < out.size(); ++i) {
            const int hi = detail::hex_nibble(hex[i * 2]);
            const int lo = detail::hex_nibble(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                return std::nullopt;
            }
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return out;
    }

    std::string_view trim_view(std::string_view value) noexcept {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.remove_prefix(1);
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.remove_suffix(1);
        }
        return value;
    }

    std::string to_lower(std::string_view value) {
        std::string result;
        result.reserve(value.size());
        for (const char ch : value) {
            result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        }
        return result;
    }

    uint32_t crc32(std::span<const uint8_t> bytes) {
        uint32_t crc = 0xFFFFFFFFU;
        for (const uint8_t byte : bytes) {
            crc ^= byte;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
            }
        }
        return ~crc;
    }

    void fill_random(std::span<uint8_t> out) {
        std::random_device source;
        for (size_t i = 0; i < out.size(); i += sizeof(uint32_t)) {
            const auto word = static_cast<uint32_t>(source());
            std::memcpy(out.data() + i, &word, std::min(sizeof(word), out.size() - i));
        }
    }

    namespace {

        std::unexpected<Error> open_failure(const fs::path& path, int saved_errno,
                                            std::string_view action) {
            if (saved_errno != 0) {
                return from_error_code(std::error_code(saved_errno, std::generic_category()), path);
            }
            return fail(ErrorCode::IoError, "{}: could not open the file for {}", path.string(),
                        action);
        }

    } // namespace

    Result<std::vector<uint8_t>> read_file(const fs::path& path) {
        errno = 0;
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            const int saved_errno = errno;
            std::error_code status_error;
            if (!fs::exists(path, status_error) && !status_error) {
                return from_error_code(std::make_error_code(std::errc::no_such_file_or_directory),
                                       path);
            }
            return open_failure(path, saved_errno, "reading");
        }

        const std::streamsize size = file.tellg();
        if (size < 0) {
            return fail(ErrorCode::IoError, "{}: could not determine the file size", path.string());
        }
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return fail(ErrorCode::IoError, "{}: could not read {} bytes", path.string(), size);
        }

        return buffer;
    }

    Result<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length) {
        auto result = read_file(path);
        if (result && result->size() > max_length) {
            result->resize(max_length);
        }
        return result;
    }

    Result<void> write_file(const fs::path& path, const std::vector<uint8_t>& data) {
        if (path.has_parent_path() && !directory_exists(path.parent_path())) {
            if (auto created = utils::create_directory(path.parent_path()); !created) {
                return with_context(std::move(created),
                                    "creating the parent directory of " + path.string());
            }
        }

        errno = 0;
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return open_failure(path, errno, "writing");
        }

        file.write(reinterpret_cast<const char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));
        file.flush();
        file.close();
        if (file.fail()) {
            return fail(ErrorCode::IoError, "{}: could not write {} bytes", path.string(),
                        data.size());
        }

        return {};
    }

    bool directory_exists(const fs::path& path) {
        std::error_code ec;
        return fs::is_directory(path, ec);
    }

    Result<void> create_directory(const fs::path& path) {
        std::error_code ec;
        if (fs::is_directory(path, ec)) {
            return {};
        }
        fs::create_directories(path, ec);
        if (ec) {
            return from_error_code(ec, path);
        }
        if (!fs::is_directory(path, ec)) {
            return fail(ErrorCode::IoError, "{}: exists and is not a directory", path.string());
        }
        return {};
    }

} // namespace gxbuild::utils
