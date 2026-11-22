#pragma once

#include "Error.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gxbuild3::patchers {
    struct SigByte {
        bool isWildcard;
        uint8_t value;
    };

    [[nodiscard]] Result<std::vector<SigByte>>
    parse_signature_pattern(const std::string& patternStr);

    [[nodiscard]] Result<uint32_t> apply_signature_patch(uint8_t* data, uint32_t dataSize,
                                                         const std::string& searchPatternStr,
                                                         const std::string& replacePatternStr);
} // namespace gxbuild3::patchers
