// src/patchers: SMC signature patterns ("??" or two hex digits per token), the signature patch
// that replaces every match of one, and patch sections written big-endian into a buffer.

#include "Error.hpp"
#include "patchers/Patcher.hpp"
#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"
#include "support/Expect.hpp"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::patchers {
    namespace {

        struct NamedPattern {
            const char* name;
            const smc_patch_t* patch;
        };
        GX_PRINT_ROW_AS_NAME(NamedPattern)

        // Every signature pattern shipped in the tree. A new one belongs here.
        const std::array<NamedPattern, 5> kInTreePatterns{{
            {"Glitch", &Glitch},
            {"NoDriveBlink", &NoDriveBlink},
            {"NoDriveBlink_KSB", &NoDriveBlink_KSB},
            {"EjectDisable", &EjectDisable},
            {"EjectDisable_KSB", &EjectDisable_KSB},
        }};

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
        // reading token for token, so no in-tree pattern relies on a bad token becoming a
        // wildcard. The first failure ends the pattern's checks.
        void expect_well_formed(std::string_view name, std::string_view role,
                                const std::string& pattern) {
            const std::string label = std::string(name) + " " + std::string(role);
            const auto tokens = split_tokens(pattern);
            const auto parsed = parse_signature_pattern(pattern);
            ASSERT_OK(parsed) << label + " parses";
            ASSERT_FALSE(tokens.empty()) << label + " is not empty";
            ASSERT_EQ(parsed->size(), tokens.size()) << label + " parses one byte per token";
            for (size_t i = 0; i < tokens.size(); ++i) {
                const auto& token = tokens[i];
                const bool wildcard = token == "??";
                ASSERT_TRUE(wildcard || is_hex_byte(token))
                    << label + " token '" + token + "' is ?? or two hex digits";
                ASSERT_EQ((*parsed)[i].isWildcard, wildcard)
                    << label + " token '" + token + "' parses with the right wildcard flag";
                if (!wildcard) {
                    ASSERT_EQ((*parsed)[i].value, std::stoul(token, nullptr, 16))
                        << label + " token '" + token + "' parses to its value";
                }
            }
        }

        class SignaturePattern : public ::testing::TestWithParam<NamedPattern> {};

        TEST_P(SignaturePattern, IsWellFormedAndItsReplaceIsNoLongerThanItsSearch) {
            const auto& [name, patch] = GetParam();
            expect_well_formed(name, "search", patch->addr);
            expect_well_formed(name, "replace", patch->value);
            EXPECT_LE(split_tokens(patch->value).size(), split_tokens(patch->addr).size())
                << std::string(name) + " replace is no longer than its search";
        }

        INSTANTIATE_TEST_SUITE_P(Pattern, SignaturePattern, ::testing::ValuesIn(kInTreePatterns),
                                 test::RowName{});

        // Behaviour pin: a token that is neither a wildcard nor one or two hex digits used to
        // become a silent wildcard; it now fails the parse, and the patch it belongs to.
        struct BadTokenRow {
            const char* name;
            const char* pattern;
        };
        GX_PRINT_ROW_AS_NAME(BadTokenRow)

        class SignaturePatternBadToken : public ::testing::TestWithParam<BadTokenRow> {};

        TEST_P(SignaturePatternBadToken, IsMalformedInsteadOfAWildcard) {
            const std::string pattern = GetParam().pattern;
            EXPECT_ERROR(parse_signature_pattern(pattern), ErrorCode::Malformed)
                << "'" + pattern + "' is malformed";
        }

        INSTANTIATE_TEST_SUITE_P(Row, SignaturePatternBadToken,
                                 ::testing::Values(BadTokenRow{"G1", "05 G1 E5"},
                                                   BadTokenRow{"QuestionA", "05 ?A E5"},
                                                   BadTokenRow{"Fff", "05 FFF E5"},
                                                   BadTokenRow{"HexPrefix", "05 0x1 E5"}),
                                 test::RowName{});

        TEST(SignaturePatternEdge, ABadSearchTokenFailsThePatchAndLeavesTheBufferAlone) {
            std::array<uint8_t, 4> data{0x05, 0x11, 0xE5, 0x00};
            EXPECT_ERROR(apply_signature_patch(data.data(), data.size(), "05 ZZ E5", "00"),
                         ErrorCode::Malformed)
                << "a patch with a bad search token fails";
            EXPECT_EQ(data[0], 0x05) << "a failed patch leaves the buffer alone";
        }

        TEST(SignaturePatternEdge, OneCharacterWildcardsAndHexDigitsStillParse) {
            const auto single = parse_signature_pattern("? A ??");
            ASSERT_OK(single) << "one-character wildcards and hex digits still parse";
            ASSERT_EQ(single->size(), 3u) << "one-character wildcards and hex digits still parse";
            EXPECT_TRUE((*single)[0].isWildcard)
                << "one-character wildcards and hex digits still parse";
            EXPECT_FALSE((*single)[1].isWildcard)
                << "one-character wildcards and hex digits still parse";
            EXPECT_EQ((*single)[1].value, 0x0A)
                << "one-character wildcards and hex digits still parse";
            EXPECT_TRUE((*single)[2].isWildcard)
                << "one-character wildcards and hex digits still parse";
        }

        TEST(SignaturePatch, CountsEveryMatchAndKeepsWildcardBytes) {
            std::array<uint8_t, 8> data{0x05, 0x11, 0xE5, 0x22, 0x05, 0x33, 0xE5, 0x44};
            const auto applied =
                apply_signature_patch(data.data(), data.size(), "05 ?? E5", "00 ?? 01");
            const std::array<uint8_t, 8> expected{0x00, 0x11, 0x01, 0x22, 0x00, 0x33, 0x01, 0x44};
            const auto missed = apply_signature_patch(data.data(), data.size(), "AA BB", "00");
            ASSERT_OK(applied) << "both matches are counted";
            EXPECT_EQ(*applied, 2u) << "both matches are counted";
            EXPECT_EQ(data, expected) << "both matches are patched, wildcards kept";
            ASSERT_OK(missed) << "no match is 0, not an error";
            EXPECT_EQ(*missed, 0u) << "no match is 0, not an error";
        }

        TEST(SignaturePatch, BadArgumentsAreInvalidArguments) {
            std::array<uint8_t, 2> data{0x05, 0x11};
            EXPECT_ERROR(apply_signature_patch(nullptr, 2, "05", "00"), ErrorCode::InvalidArgument)
                << "null data is an invalid argument";
            EXPECT_ERROR(apply_signature_patch(data.data(), data.size(), "", ""),
                         ErrorCode::InvalidArgument)
                << "an empty search is an invalid argument";
            EXPECT_ERROR(apply_signature_patch(data.data(), data.size(), "05", "00 00"),
                         ErrorCode::InvalidArgument)
                << "a replace longer than its search is an invalid argument";
            EXPECT_ERROR(apply_signature_patch(data.data(), data.size(), "05 11 E5", "00"),
                         ErrorCode::InvalidArgument)
                << "a buffer shorter than the search is an invalid argument";
        }

        TEST(PatchSection, OverflowAndShortWordsFailAndLeaveTheBufferAlone) {
            std::array<uint8_t, 8> data{};
            const nand::XePatchSection fits{"CB", {{0x4, 1, {0x11223344}}}};
            const nand::XePatchSection overflows{"CD", {{0x4, 2, {0x1, 0x2}}}};
            const nand::XePatchSection short_words{"CE", {{0x0, 2, {0x1}}}};
            const std::array<uint8_t, 8> expected{0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44};

            const auto applied = apply_patch_section(data.data(), data.size(), fits);
            EXPECT_OK(applied) << "a section inside the buffer applies";
            EXPECT_EQ(data, expected) << "patch words are written big-endian";

            const auto overflowed = apply_patch_section(data.data(), data.size(), overflows);
            const auto shorted = apply_patch_section(data.data(), data.size(), short_words);
            EXPECT_ERROR(overflowed, ErrorCode::OutOfRange)
                << "a section past the buffer end is out of range";
            EXPECT_TRUE(overflowed.has_value() ||
                        overflowed.error().describe().starts_with("section 'CD' entry 0: "))
                << "the failing section and entry are named in the context";
            EXPECT_ERROR(shorted, ErrorCode::Malformed)
                << "an entry with too few words is malformed";
            EXPECT_EQ(data, expected) << "failed sections leave the buffer alone";
        }

    } // namespace
} // namespace gxbuild3::patchers
