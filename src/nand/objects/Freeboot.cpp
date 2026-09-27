#include "nand/objects/Freeboot.hpp"

#include "freeboot.h"
#include "payload.h"

namespace gxbuild3::NAND {

    std::span<const uint8_t> freeboot_rebooter() {
        return {freeboot, freeboot_size};
    }
    std::span<const uint8_t> freeboot_payload() {
        return {payload, payload_size};
    }

} // namespace gxbuild3::NAND
