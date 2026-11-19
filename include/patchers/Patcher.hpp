#pragma once

#include "BinaryParser.hpp"

#include <cstdint>

namespace Source {
    bool ApplyPatch(uint8_t* data, uint32_t dataSize, uint32_t offset, const uint8_t* payload,
                    uint32_t payloadSize);
}

namespace XePatch {
    bool ApplyPatch(uint8_t* data, uint32_t dataSize, uint32_t address, uint32_t length,
                    const uint32_t* patchWords);

    bool ApplyPatchEntry(uint8_t* data, uint32_t dataSize, const XePatchEntry& entry);

    bool ApplyPatchSection(uint8_t* data, uint32_t dataSize, const XePatchSection& section);
} // namespace XePatch