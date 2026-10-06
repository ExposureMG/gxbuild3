#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"

#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

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
        if (!require(!tokens.empty(), label + " is not empty") ||
            !require(parsed.size() == tokens.size(), label + " parses one byte per token")) {
            return false;
        }
        for (size_t i = 0; i < tokens.size(); ++i) {
            const auto& token = tokens[i];
            const bool wildcard = token == "??";
            if (!require(wildcard || is_hex_byte(token),
                         label + " token '" + token + "' is ?? or two hex digits")) {
                return false;
            }
            if (!require(parsed[i].isWildcard == wildcard,
                         label + " token '" + token + "' parses with the right wildcard flag")) {
                return false;
            }
            if (!wildcard && !require(parsed[i].value == std::stoul(token, nullptr, 16),
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

} // namespace

int main() {
    bool passed = true;
    passed = test_every_in_tree_pattern_parses() && passed;
    if (!passed) {
        return 1;
    }
    std::cout << "Patcher tests passed\n";
    return 0;
}
