#pragma once

#include "Error.hpp"
#include "nand/objects/Patchset.hpp"

#include <cstdint>

namespace gxbuild3::patchers {
    [[nodiscard]] Result<> apply_patch(uint8_t* data, uint32_t dataSize, uint32_t address,
                                       uint32_t length, const uint32_t* patchWords);

    [[nodiscard]] Result<> apply_patch_entry(uint8_t* data, uint32_t dataSize,
                                             const nand::XePatchEntry& entry);

    // Applies every entry in order. On failure the entries before the failing one stay applied.
    [[nodiscard]] Result<> apply_patch_section(uint8_t* data, uint32_t dataSize,
                                               const nand::XePatchSection& section);
} // namespace gxbuild3::patchers
