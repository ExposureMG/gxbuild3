#include "patchers/Signature.hpp"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>

namespace Signature {

    std::vector<SigByte> ParsePattern(const std::string& patternStr) {
        std::vector<SigByte> pattern;
        std::stringstream ss(patternStr);
        std::string token;

        while (ss >> token) {
            SigByte sigByte;
            if (token.find('?') != std::string::npos) {
                sigByte.isWildcard = true;
                sigByte.value = 0x00;
            } else {
                sigByte.isWildcard = false;
                try {
                    sigByte.value = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                } catch (...) {
                    sigByte.isWildcard = true;
                    sigByte.value = 0x00;
                }
            }
            pattern.push_back(sigByte);
        }

        return pattern;
    }

    uint32_t ApplyPatch(uint8_t* data, uint32_t dataSize, const std::string& searchPatternStr,
                        const std::string& replacePatternStr) {
        if (!data || dataSize == 0) {
            return 0;
        }

        std::vector<SigByte> searchPattern = ParsePattern(searchPatternStr);
        std::vector<SigByte> replacePattern = ParsePattern(replacePatternStr);

        if (searchPattern.empty()) {
            return 0;
        }

        if (replacePattern.size() > searchPattern.size()) {
            return 0;
        }

        if (dataSize < searchPattern.size()) {
            return 0;
        }

        uint32_t matchesCount = 0;

        for (uint32_t i = 0; i <= dataSize - static_cast<uint32_t>(searchPattern.size()); i++) {
            bool isMatch = true;
            for (size_t j = 0; j < searchPattern.size(); j++) {
                if (!searchPattern[j].isWildcard && data[i + j] != searchPattern[j].value) {
                    isMatch = false;
                    break;
                }
            }

            if (isMatch) {
                for (size_t j = 0; j < replacePattern.size(); j++) {
                    if (!replacePattern[j].isWildcard) {
                        data[i + j] = replacePattern[j].value;
                    }
                }
                matchesCount++;
                i += static_cast<uint32_t>(searchPattern.size()) - 1;
            }
        }

        return matchesCount;
    }

} // namespace Signature