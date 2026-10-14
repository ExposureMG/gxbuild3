#pragma once

#include "Error.hpp"

#include <cstdint>
#include <string>
#include <vector>
// Inspired by [c0z]'s SMC autopatcher

namespace gxbuild3::patchers {
    struct SigByte {
        bool isWildcard;
        uint8_t value;
    };

    // Parses a whitespace-separated pattern. Each token is a wildcard ("?" or "??") or one or
    // two hex digits; any other token fails with Malformed.
    [[nodiscard]] Result<std::vector<SigByte>>
    parse_signature_pattern(const std::string& patternStr);

    // Replaces every non-overlapping match of the search pattern and returns the match count;
    // 0 means only that nothing matched. Null data, an empty or malformed pattern, a replace
    // longer than the search and a buffer shorter than the search fail instead.
    [[nodiscard]] Result<uint32_t> apply_signature_patch(uint8_t* data, uint32_t dataSize,
                                                         const std::string& searchPatternStr,
                                                         const std::string& replacePatternStr);
} // namespace gxbuild3::patchers
