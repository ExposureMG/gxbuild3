#pragma once

#include <cstdint>
#include <span>

namespace gxbuild3::NAND {

    // Embedded freeBOOT JTAG arrays (freeboot/freeboot.h, freeboot/payload.h).
    std::span<const uint8_t> freeboot_rebooter(); // 0xd40 bytes
    std::span<const uint8_t> freeboot_payload();  // 0x200 bytes

} // namespace gxbuild3::NAND
