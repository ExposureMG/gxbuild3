#include "Patchsets.hpp"

#include "support/Bytes.hpp"

namespace gxbuild3::test {

    Bytes glitch_patchset(uint32_t first_address, uint32_t first_word, uint32_t cd_address,
                          uint32_t cd_word, std::span<const uint8_t> khv) {
        Bytes bytes;
        append_be32(bytes, first_address);
        append_be32(bytes, 1);
        append_be32(bytes, first_word);
        append_be32(bytes, 0xFFFFFFFF);
        append_be32(bytes, cd_address);
        append_be32(bytes, 1);
        append_be32(bytes, cd_word);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), khv.begin(), khv.end());
        return bytes;
    }

    Bytes valid_glitch_patchset(uint8_t marker) {
        return glitch_patchset(0x20, 0x11223344, 0x30, 0x55667788, Bytes{marker});
    }

    Bytes jtag_patchset(std::span<const uint8_t> section4) {
        Bytes bytes(4, 0x10);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x11);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x12);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), section4.begin(), section4.end());
        return bytes;
    }

    void append_patch_entry(Bytes& bytes, uint32_t address, uint32_t word) {
        append_be32(bytes, address);
        append_be32(bytes, 1);
        append_be32(bytes, word);
        append_be32(bytes, 0xFFFFFFFF);
    }

} // namespace gxbuild3::test
