#pragma once

#include <cstdint>
#include <string>
#include <vector>
// Inspired by [c0z]'s SMC autopatcher

struct SigByte {
    bool isWildcard;
    uint8_t value;
};

namespace Signature {
    std::vector<SigByte> ParsePattern(const std::string& patternStr);

    uint32_t ApplyPatch(uint8_t* data, uint32_t dataSize, const std::string& searchPatternStr,
                        const std::string& replacePatternStr);
} // namespace Signature