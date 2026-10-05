#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::nand {

    // Embedded freeBOOT JTAG arrays (freeboot/freeboot.h, freeboot/payload.h), the loaders
    // xeBuild 1.21 carries inside itself.
    std::span<const uint8_t> freeboot_rebooter(); // 0xd40 bytes
    std::span<const uint8_t> freeboot_payload();  // 0x200 bytes

    // The core with the release's kernel version, zero-padded, over the thirty-two X's it
    // carries for one, and for 9199 the old hold address 0x80000000001FFFF8 in place of
    // 0x8000000001003078 (xeBuild 1.21 "patching freeboot.bin with kernel version string").
    std::vector<uint8_t> freeboot_rebooter_for(std::string_view version);

    // The payload with the core's length in words, rounded up, as the operand of its
    // `li r4` at +0x50 (xeBuild 1.21 "patching payload.bin to load size").
    std::vector<uint8_t> freeboot_payload_for(size_t core_length);

} // namespace gxbuild3::nand
