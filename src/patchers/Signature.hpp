#pragma once

#include <cstdint>
#include <string>
#include <vector>
// Inspired by [c0z]'s SMC autopatcher

namespace gxbuild3::patchers {
    struct SigByte {
        bool isWildcard;
        uint8_t value;
    };

    std::vector<SigByte> parse_signature_pattern(const std::string& patternStr);

    uint32_t apply_signature_patch(uint8_t* data, uint32_t dataSize,
                                   const std::string& searchPatternStr,
                                   const std::string& replacePatternStr);
} // namespace gxbuild3::patchers