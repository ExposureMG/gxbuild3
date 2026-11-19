#pragma once

#include "Args.hpp"

#include <cassert>
#include <concepts>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if defined(_MSC_VER)
#include <cstdlib>
#include <intrin.h>
#endif

namespace fs = std::filesystem;

[[nodiscard]] inline uint32_t swap32(uint32_t x) noexcept {
    return (x & 0xFF000000U) >> 24 | (x & 0x00FF0000U) >> 8 | (x & 0x0000FF00U) << 8 |
           (x & 0x000000FFU) << 24;
}

#if defined(_MSC_VER)
[[nodiscard]] inline uint16_t bswap16(uint16_t x) noexcept {
    return _byteswap_ushort(x);
}
[[nodiscard]] inline uint32_t bswap32(uint32_t x) noexcept {
    return _byteswap_ulong(x);
}
[[nodiscard]] inline uint64_t bswap64(uint64_t x) noexcept {
    return _byteswap_uint64(x);
}
#else
[[nodiscard]] inline uint16_t bswap16(uint16_t x) noexcept {
    return __builtin_bswap16(x);
}
[[nodiscard]] inline uint32_t bswap32(uint32_t x) noexcept {
    return __builtin_bswap32(x);
}
[[nodiscard]] inline uint64_t bswap64(uint64_t x) noexcept {
    return __builtin_bswap64(x);
}
#endif

namespace Utils {

    std::vector<uint8_t> hex_string_to_bytes(const std::string& hex_string);

    std::optional<std::vector<uint8_t>> read_file(const fs::path& path);

    std::optional<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    bool write_file(const fs::path& path, const std::vector<uint8_t>& data);

    bool write_file(const fs::path& path, const uint8_t* data, size_t length);

    bool directory_exists(const fs::path& path);

    bool create_directory(const fs::path& path);

    std::optional<std::vector<fs::path>> list_files(const fs::path& path);

    std::optional<std::vector<fs::path>> list_files_recursive(const fs::path& path);

} // namespace Utils
