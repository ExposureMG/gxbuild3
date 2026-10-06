#include "patchers/Signature.hpp"

#include "utils/Log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>

namespace gxbuild3::patchers {

    namespace {

        bool is_wildcard_token(const std::string& token) {
            return token.size() <= 2 && std::ranges::all_of(token, [](char c) { return c == '?'; });
        }

        bool is_hex_token(const std::string& token) {
            return token.size() <= 2 && std::ranges::all_of(token, [](char c) {
                       return std::isxdigit(static_cast<unsigned char>(c)) != 0;
                   });
        }

    } // namespace

    Result<std::vector<SigByte>> parse_signature_pattern(const std::string& patternStr) {
        std::vector<SigByte> pattern;
        std::stringstream ss(patternStr);
        std::string token;

        while (ss >> token) {
            if (is_wildcard_token(token)) {
                pattern.push_back(SigByte{true, 0x00});
            } else if (is_hex_token(token)) {
                pattern.push_back(
                    SigByte{false, static_cast<uint8_t>(std::stoul(token, nullptr, 16))});
            } else {
                return fail(ErrorCode::Malformed, "invalid signature token '{}' at byte {}", token,
                            pattern.size());
            }
        }

        return pattern;
    }

    Result<uint32_t> apply_signature_patch(uint8_t* data, uint32_t dataSize,
                                           const std::string& searchPatternStr,
                                           const std::string& replacePatternStr) {
        if (!data) {
            return fail(ErrorCode::InvalidArgument, "signature patch target is null");
        }

        auto searchPattern =
            with_context(parse_signature_pattern(searchPatternStr), "parsing the search pattern");
        if (!searchPattern) {
            return std::unexpected(std::move(searchPattern.error()));
        }
        auto replacePattern =
            with_context(parse_signature_pattern(replacePatternStr), "parsing the replace pattern");
        if (!replacePattern) {
            return std::unexpected(std::move(replacePattern.error()));
        }

        if (searchPattern->empty()) {
            return fail(ErrorCode::InvalidArgument, "signature search pattern is empty");
        }

        if (replacePattern->size() > searchPattern->size()) {
            return fail(ErrorCode::InvalidArgument,
                        "signature replace pattern ({} bytes) is longer than its search ({} bytes)",
                        replacePattern->size(), searchPattern->size());
        }

        if (dataSize < searchPattern->size()) {
            return fail(ErrorCode::InvalidArgument,
                        "signature patch target (0x{:X} bytes) is shorter than its search "
                        "pattern ({} bytes)",
                        dataSize, searchPattern->size());
        }

        uint32_t matchesCount = 0;

        for (uint32_t i = 0; i <= dataSize - static_cast<uint32_t>(searchPattern->size()); i++) {
            bool isMatch = true;
            for (size_t j = 0; j < searchPattern->size(); j++) {
                if (!(*searchPattern)[j].isWildcard && data[i + j] != (*searchPattern)[j].value) {
                    isMatch = false;
                    break;
                }
            }

            if (isMatch) {
                for (size_t j = 0; j < replacePattern->size(); j++) {
                    if (!(*replacePattern)[j].isWildcard) {
                        data[i + j] = (*replacePattern)[j].value;
                    }
                }
                matchesCount++;
                i += static_cast<uint32_t>(searchPattern->size()) - 1;
            }
        }

        Log::Debug("Signature pattern matched and applied {} time(s)", matchesCount);
        return matchesCount;
    }

} // namespace gxbuild3::patchers
