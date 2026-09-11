#pragma once
#include <concepts>
#include <cstdint>
#include <cstddef>

#if defined(_MSC_VER)
#include <cstdlib>
#include <intrin.h>
#endif

[[nodiscard]] inline uint32_t swap32(uint32_t x) noexcept {
    return (x & 0xFF000000U) >> 24 | (x & 0x00FF0000U) >> 8 | (x & 0x0000FF00U) << 8 |
           (x & 0x000000FFU) << 24;
}

[[nodiscard]] inline std::uint16_t readBE16(const std::byte* ptr) noexcept {
    return (static_cast<std::uint16_t>(ptr[0]) << 8) | static_cast<std::uint16_t>(ptr[1]);
}

[[nodiscard]] inline std::uint32_t readBE32(const std::byte* ptr) noexcept {
    return (static_cast<std::uint32_t>(ptr[0]) << 24) |
    (static_cast<std::uint32_t>(ptr[1]) << 16) |
    (static_cast<std::uint32_t>(ptr[2]) << 8) | static_cast<std::uint32_t>(ptr[3]);
}

[[nodiscard]] inline std::uint64_t readBE64(const std::byte* ptr) noexcept {
    std::uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = (result << 8) | static_cast<std::uint64_t>(ptr[i]);
    }
    return result;
}

[[nodiscard]] inline std::uint16_t readLE16(const std::byte* ptr) noexcept {
    return static_cast<std::uint16_t>(ptr[0]) | (static_cast<std::uint16_t>(ptr[1]) << 8);
}

[[nodiscard]] inline std::uint32_t readUInt24BE(const std::byte* ptr) noexcept {
    return (static_cast<std::uint32_t>(ptr[0]) << 16) |
    (static_cast<std::uint32_t>(ptr[1]) << 8) | static_cast<std::uint32_t>(ptr[2]);
}

[[nodiscard]] inline std::uint32_t readUInt24LE(const std::byte* ptr) noexcept {
    return static_cast<std::uint32_t>(ptr[0]) | (static_cast<std::uint32_t>(ptr[1]) << 8) |
    (static_cast<std::uint32_t>(ptr[2]) << 16);
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
