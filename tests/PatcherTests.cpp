#include "patchers/Patcher.hpp"
#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

    using gxbuild3::ErrorCode;
    using gxbuild3::patchers::smc_patch_t;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    struct NamedPattern {
        std::string_view name;
        const smc_patch_t& patch;
    };

    // Every signature pattern shipped in the tree. A new one belongs here.
    const std::vector<NamedPattern>& in_tree_patterns() {
        static const std::vector<NamedPattern> patterns = {
            {"Glitch", gxbuild3::patchers::Glitch},
            {"NoDriveBlink", gxbuild3::patchers::NoDriveBlink},
            {"NoDriveBlink_KSB", gxbuild3::patchers::NoDriveBlink_KSB},
            {"EjectDisable", gxbuild3::patchers::EjectDisable},
            {"EjectDisable_KSB", gxbuild3::patchers::EjectDisable_KSB},
        };
        return patterns;
    }

    bool is_hex_byte(std::string_view token) {
        return token.size() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) &&
               std::isxdigit(static_cast<unsigned char>(token[1]));
    }

    std::vector<std::string> split_tokens(const std::string& pattern) {
        std::vector<std::string> tokens;
        std::istringstream stream(pattern);
        std::string token;
        while (stream >> token) {
            tokens.push_back(token);
        }
        return tokens;
    }

    // Each token is either "??" or exactly two hex digits, and the parser agrees with that
    // reading token for token, so no in-tree pattern relies on a bad token becoming a wildcard.
    bool pattern_is_well_formed(std::string_view name, std::string_view role,
                                const std::string& pattern) {
        const std::string label = std::string(name) + " " + std::string(role);
        const auto tokens = split_tokens(pattern);
        const auto parsed = gxbuild3::patchers::parse_signature_pattern(pattern);
        if (!require(parsed.has_value(), label + " parses") ||
            !require(!tokens.empty(), label + " is not empty") ||
            !require(parsed->size() == tokens.size(), label + " parses one byte per token")) {
            return false;
        }
        for (size_t i = 0; i < tokens.size(); ++i) {
            const auto& token = tokens[i];
            const bool wildcard = token == "??";
            if (!require(wildcard || is_hex_byte(token),
                         label + " token '" + token + "' is ?? or two hex digits")) {
                return false;
            }
            if (!require((*parsed)[i].isWildcard == wildcard,
                         label + " token '" + token + "' parses with the right wildcard flag")) {
                return false;
            }
            if (!wildcard && !require((*parsed)[i].value == std::stoul(token, nullptr, 16),
                                      label + " token '" + token + "' parses to its value")) {
                return false;
            }
        }
        return true;
    }

    bool test_every_in_tree_pattern_parses() {
        bool passed = true;
        for (const auto& [name, patch] : in_tree_patterns()) {
            passed = pattern_is_well_formed(name, "search", patch.addr) && passed;
            passed = pattern_is_well_formed(name, "replace", patch.value) && passed;
            passed = require(split_tokens(patch.value).size() <= split_tokens(patch.addr).size(),
                             std::string(name) + " replace is no longer than its search") &&
                     passed;
        }
        return passed;
    }

    // Behaviour pin: a token that is neither a wildcard nor one or two hex digits used to become
    // a silent wildcard; it now fails the parse, and the patch it belongs to.
    bool test_bad_token_fails_instead_of_becoming_a_wildcard() {
        bool passed = true;
        for (const std::string pattern : {"05 G1 E5", "05 ?A E5", "05 FFF E5", "05 0x1 E5"}) {
            const auto parsed = gxbuild3::patchers::parse_signature_pattern(pattern);
            passed = require(!parsed && parsed.error().code == ErrorCode::Malformed,
                             "'" + pattern + "' is malformed") &&
                     passed;
        }
        std::array<uint8_t, 4> data{0x05, 0x11, 0xE5, 0x00};
        const auto applied =
            gxbuild3::patchers::apply_signature_patch(data.data(), data.size(), "05 ZZ E5", "00");
        passed = require(!applied && applied.error().code == ErrorCode::Malformed,
                         "a patch with a bad search token fails") &&
                 require(data[0] == 0x05, "a failed patch leaves the buffer alone") && passed;
        const auto single = gxbuild3::patchers::parse_signature_pattern("? A ??");
        passed = require(single && single->size() == 3 && (*single)[0].isWildcard &&
                             !(*single)[1].isWildcard && (*single)[1].value == 0x0A &&
                             (*single)[2].isWildcard,
                         "one-character wildcards and hex digits still parse") &&
                 passed;
        return passed;
    }

    bool test_signature_patch_counts_matches() {
        std::array<uint8_t, 8> data{0x05, 0x11, 0xE5, 0x22, 0x05, 0x33, 0xE5, 0x44};
        const auto applied = gxbuild3::patchers::apply_signature_patch(data.data(), data.size(),
                                                                       "05 ?? E5", "00 ?? 01");
        const std::array<uint8_t, 8> expected{0x00, 0x11, 0x01, 0x22, 0x00, 0x33, 0x01, 0x44};
        const auto missed =
            gxbuild3::patchers::apply_signature_patch(data.data(), data.size(), "AA BB", "00");
        return require(applied && *applied == 2, "both matches are counted") &&
               require(data == expected, "both matches are patched, wildcards kept") &&
               require(missed && *missed == 0, "no match is 0, not an error");
    }

    bool test_signature_patch_rejects_bad_arguments() {
        std::array<uint8_t, 2> data{0x05, 0x11};
        const auto is_invalid = [](const gxbuild3::Result<uint32_t>& result) {
            return !result && result.error().code == ErrorCode::InvalidArgument;
        };
        return require(
                   is_invalid(gxbuild3::patchers::apply_signature_patch(nullptr, 2, "05", "00")),
                   "null data is an invalid argument") &&
               require(is_invalid(gxbuild3::patchers::apply_signature_patch(data.data(),
                                                                            data.size(), "", "")),
                       "an empty search is an invalid argument") &&
               require(is_invalid(gxbuild3::patchers::apply_signature_patch(
                           data.data(), data.size(), "05", "00 00")),
                       "a replace longer than its search is an invalid argument") &&
               require(is_invalid(gxbuild3::patchers::apply_signature_patch(
                           data.data(), data.size(), "05 11 E5", "00")),
                       "a buffer shorter than the search is an invalid argument");
    }

    bool test_patch_section_overflow_fails() {
        std::array<uint8_t, 8> data{};
        const gxbuild3::nand::XePatchSection fits{"CB", {{0x4, 1, {0x11223344}}}};
        const gxbuild3::nand::XePatchSection overflows{"CD", {{0x4, 2, {0x1, 0x2}}}};
        const gxbuild3::nand::XePatchSection short_words{"CE", {{0x0, 2, {0x1}}}};
        const auto applied =
            gxbuild3::patchers::apply_patch_section(data.data(), data.size(), fits);
        const std::array<uint8_t, 8> expected{0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44};
        const auto overflowed =
            gxbuild3::patchers::apply_patch_section(data.data(), data.size(), overflows);
        const auto shorted =
            gxbuild3::patchers::apply_patch_section(data.data(), data.size(), short_words);
        return require(applied.has_value(), "a section inside the buffer applies") &&
               require(data == expected, "patch words are written big-endian") &&
               require(!overflowed && overflowed.error().code == ErrorCode::OutOfRange,
                       "a section past the buffer end is out of range") &&
               require(overflowed.has_value() ||
                           overflowed.error().describe().starts_with("section 'CD' entry 0: "),
                       "the failing section and entry are named in the context") &&
               require(!shorted && shorted.error().code == ErrorCode::Malformed,
                       "an entry with too few words is malformed") &&
               require(data == expected, "failed sections leave the buffer alone");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_every_in_tree_pattern_parses() && passed;
    passed = test_bad_token_fails_instead_of_becoming_a_wildcard() && passed;
    passed = test_signature_patch_counts_matches() && passed;
    passed = test_signature_patch_rejects_bad_arguments() && passed;
    passed = test_patch_section_overflow_fails() && passed;
    if (!passed) {
        return 1;
    }
    std::cout << "Patcher tests passed\n";
    return 0;
}
