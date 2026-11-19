#pragma once

// Byte helpers shared by the tests: hex and digests for messages and goldens, big-endian
// field access for hand-built records, and the two deterministic fill patterns.

#include "Expect.hpp"
#include "Sha256.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace gxbuild3::test {

    // Lowercase, two digits per byte, no separators.
    [[nodiscard]] std::string hex(std::span<const uint8_t> bytes);

    // SHA-1 (GxCrypt's ExCryptSha) as lowercase hex.
    [[nodiscard]] std::string sha1_hex(std::span<const uint8_t> bytes);
    [[nodiscard]] std::string sha1_hex(std::span<const std::byte> bytes);

    // Big-endian fields. put_* and be* record a test failure, and write nothing or read 0,
    // when the field does not fit inside the buffer.
    void put_be16(std::span<uint8_t> bytes, size_t offset, uint16_t value);
    void put_be32(std::span<uint8_t> bytes, size_t offset, uint32_t value);
    [[nodiscard]] uint16_t be16(std::span<const uint8_t> bytes, size_t offset);
    [[nodiscard]] uint32_t be32(std::span<const uint8_t> bytes, size_t offset);
    void append_be32(Bytes& bytes, uint32_t value);

    // The two fill patterns stay separate on purpose: goldens depend on each one's bytes.
    // flashfs_pattern: byte i = (i * seed + (i >> 9) + seed) & 0xFF (FlashFileSystemTests).
    [[nodiscard]] Bytes flashfs_pattern(size_t size, uint32_t seed);
    // image_pattern: byte i = (seed + i * 7 + (i >> 9)) & 0xFF (FlashImageGoldenTests).
    [[nodiscard]] Bytes image_pattern(size_t size, uint8_t seed);

} // namespace gxbuild3::test
