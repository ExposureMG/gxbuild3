#include "Bytes.hpp"

#include "excrypt.h"

#include <array>

namespace gxbuild3::test {

    namespace {
        bool fits(size_t buffer_size, size_t offset, size_t width) {
            if (offset > buffer_size || buffer_size - offset < width) {
                ADD_FAILURE() << "a " << width << "-byte field at offset " << offset
                              << " does not fit in " << buffer_size << " bytes";
                return false;
            }
            return true;
        }
    } // namespace

    std::string hex(std::span<const uint8_t> bytes) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(bytes.size() * 2);
        for (const uint8_t b : bytes) {
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 0xF]);
        }
        return out;
    }

    std::string sha1_hex(std::span<const uint8_t> bytes) {
        std::array<uint8_t, 20> digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        return hex(digest);
    }

    std::string sha1_hex(std::span<const std::byte> bytes) {
        return sha1_hex(std::span{reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()});
    }

    void put_be16(std::span<uint8_t> bytes, size_t offset, uint16_t value) {
        if (!fits(bytes.size(), offset, 2)) {
            return;
        }
        bytes[offset] = static_cast<uint8_t>(value >> 8);
        bytes[offset + 1] = static_cast<uint8_t>(value);
    }

    void put_be32(std::span<uint8_t> bytes, size_t offset, uint32_t value) {
        if (!fits(bytes.size(), offset, 4)) {
            return;
        }
        bytes[offset] = static_cast<uint8_t>(value >> 24);
        bytes[offset + 1] = static_cast<uint8_t>(value >> 16);
        bytes[offset + 2] = static_cast<uint8_t>(value >> 8);
        bytes[offset + 3] = static_cast<uint8_t>(value);
    }

    uint16_t be16(std::span<const uint8_t> bytes, size_t offset) {
        if (!fits(bytes.size(), offset, 2)) {
            return 0;
        }
        return static_cast<uint16_t>(bytes[offset] << 8 | bytes[offset + 1]);
    }

    uint32_t be32(std::span<const uint8_t> bytes, size_t offset) {
        if (!fits(bytes.size(), offset, 4)) {
            return 0;
        }
        return uint32_t{bytes[offset]} << 24 | uint32_t{bytes[offset + 1]} << 16 |
               uint32_t{bytes[offset + 2]} << 8 | uint32_t{bytes[offset + 3]};
    }

    void append_be32(Bytes& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>(value >> 24));
        bytes.push_back(static_cast<uint8_t>(value >> 16));
        bytes.push_back(static_cast<uint8_t>(value >> 8));
        bytes.push_back(static_cast<uint8_t>(value));
    }

    Bytes flashfs_pattern(size_t size, uint32_t seed) {
        Bytes bytes(size);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = static_cast<uint8_t>((i * seed + (i >> 9) + seed) & 0xFF);
        }
        return bytes;
    }

    Bytes image_pattern(size_t size, uint8_t seed) {
        Bytes bytes(size);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = static_cast<uint8_t>(seed + i * 7 + (i >> 9));
        }
        return bytes;
    }

} // namespace gxbuild3::test
