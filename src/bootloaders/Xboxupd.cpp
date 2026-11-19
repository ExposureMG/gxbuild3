#include "bootloaders/Xboxupd.hpp"

#include "Utils.hpp"

#include <cstring>
#include <stdexcept>

namespace gxbuild3::bootloaders {
namespace {

constexpr std::size_t kBootloaderHeaderSize = 0x20;

uint16_t read_be16(std::span<const uint8_t> data, std::size_t offset) {
    uint16_t value = 0;
    std::memcpy(&value, data.data() + static_cast<std::ptrdiff_t>(offset), sizeof(value));
    return bswap16(value);
}

uint32_t read_be32(std::span<const uint8_t> data, std::size_t offset) {
    uint32_t value = 0;
    std::memcpy(&value, data.data() + static_cast<std::ptrdiff_t>(offset), sizeof(value));
    return bswap32(value);
}

std::vector<uint8_t> bytes_to_u8(std::span<const std::byte> data) {
    std::vector<uint8_t> out;
    out.reserve(data.size());
    for (const auto byte : data) {
        out.push_back(std::to_integer<uint8_t>(byte));
    }
    return out;
}

} // namespace

XboxupdParts split_xboxupd_raw(std::span<const uint8_t> xboxupd_bytes) {
    if (xboxupd_bytes.size() < 0x20) {
        throw std::runtime_error("xboxupd buffer too small to split");
    }

    const uint16_t cf_magic = read_be16(xboxupd_bytes, 0);
    if ((cf_magic & 0x0FFF) != 0x346) {
        throw std::runtime_error("CF header not found. invalid xboxupd.bin?");
    }

    const uint32_t cf_size = read_be32(xboxupd_bytes, 0x0C);
    if (cf_size < kBootloaderHeaderSize || xboxupd_bytes.size() < cf_size) {
        throw std::runtime_error("xboxupd buffer too small to contain full CF");
    }

    const uint32_t cg_size = read_be32(xboxupd_bytes, 0x1C);
    const std::size_t cg_offset = cf_size;
    if (cg_size < kBootloaderHeaderSize || xboxupd_bytes.size() < (cg_offset + cg_size)) {
        throw std::runtime_error("xboxupd buffer too small to contain full CG");
    }

    const uint16_t cg_magic = read_be16(xboxupd_bytes.subspan(cg_offset), 0);
    if ((cg_magic & 0x0FFF) != 0x347) {
        throw std::runtime_error("CG header not found. invalid xboxupd.bin?");
    }

    XboxupdParts parts;
    parts.cf_raw.assign(xboxupd_bytes.begin(), xboxupd_bytes.begin() + static_cast<std::ptrdiff_t>(cf_size));
    parts.cg_raw.assign(xboxupd_bytes.begin() + static_cast<std::ptrdiff_t>(cg_offset),
                        xboxupd_bytes.begin() +
                            static_cast<std::ptrdiff_t>(cg_offset + cg_size));
    return parts;
}

XboxupdParts split_xboxupd_raw(std::span<const std::byte> xboxupd_bytes) {
    return split_xboxupd_raw(std::span<const uint8_t>(bytes_to_u8(xboxupd_bytes)));
}

} // namespace gxbuild3::bootloaders
