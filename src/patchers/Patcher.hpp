#pragma once

#include "nand/objects/Patchset.hpp"

#include <cstdint>

namespace gxbuild3::patchers {
    bool apply_patch(uint8_t* data, uint32_t dataSize, uint32_t address, uint32_t length,
                     const uint32_t* patchWords);

    bool apply_patch_entry(uint8_t* data, uint32_t dataSize, const nand::XePatchEntry& entry);

    bool apply_patch_section(uint8_t* data, uint32_t dataSize, const nand::XePatchSection& section);
} // namespace gxbuild3::patchers