#pragma once
#include <concepts>
#include <cstdint>

#if defined(_MSC_VER)
#include <cstdlib>
#include <intrin.h>
#endif

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