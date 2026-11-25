#pragma once

#include "gxbuild/Error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild::utils {

    namespace fs = std::filesystem;

    namespace detail {

        [[nodiscard]] constexpr int hex_nibble(char c) noexcept {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            return -1;
        }

    } // namespace detail

    std::string bytes_to_hex(std::span<const uint8_t> bytes);
    [[nodiscard]] std::optional<std::vector<uint8_t>> decode_hex(std::string_view hex);

    template <size_t N>
    [[nodiscard]] std::optional<std::array<uint8_t, N>>
    decode_hex_bytes(std::string_view hex) noexcept {
        if (hex.size() != N * 2) {
            return std::nullopt;
        }
        std::array<uint8_t, N> out{};
        for (size_t i = 0; i < N; ++i) {
            const int hi = detail::hex_nibble(hex[i * 2]);
            const int lo = detail::hex_nibble(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                return std::nullopt;
            }
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return out;
    }

    [[nodiscard]] std::string_view trim_view(std::string_view value) noexcept;
    [[nodiscard]] std::string to_lower(std::string_view value);
    [[nodiscard]] uint32_t crc32(std::span<const uint8_t> bytes);
    inline constexpr uint32_t kSbPrivateKeyCrc32 = 0x490C9D35;
    void fill_random(std::span<uint8_t> out);

    [[nodiscard]] Result<std::vector<uint8_t>> read_file(const fs::path& path);
    [[nodiscard]] Result<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length);

    [[nodiscard]] Result<void> write_file(const fs::path& path, const std::vector<uint8_t>& data);

    [[nodiscard]] bool directory_exists(const fs::path& path);
    [[nodiscard]] Result<void> create_directory(const fs::path& path);

} // namespace gxbuild::utils
