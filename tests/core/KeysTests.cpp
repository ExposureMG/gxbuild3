// Pins the CPU keys of tests/support/Keys.hpp: the two spelled-out keys against the texts the
// scripts pass with -p, and the two derived keys against the searches BuildRunnerTests.cpp
// ran (valid_cpu_key, different_valid_cpu_key), so the derived keys keep their bytes.

#include "excrypt.h"
#include "nand/objects/Keyvault.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string_view>

namespace gxbuild3::core {
    namespace {

        // 32 hex characters as a key; nullopt for anything else.
        std::optional<test::CpuKey> parse_key(std::string_view text) {
            const auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') {
                    return c - '0';
                }
                if (c >= 'a' && c <= 'f') {
                    return c - 'a' + 10;
                }
                if (c >= 'A' && c <= 'F') {
                    return c - 'A' + 10;
                }
                return -1;
            };
            test::CpuKey key{};
            if (text.size() != key.size() * 2) {
                return std::nullopt;
            }
            for (size_t i = 0; i < key.size(); ++i) {
                const int high = nibble(text[2 * i]);
                const int low = nibble(text[2 * i + 1]);
                if (high < 0 || low < 0) {
                    return std::nullopt;
                }
                key[i] = static_cast<uint8_t>(high << 4 | low);
            }
            return key;
        }

        TEST(Keys, BuildAllCpuKeyIsTheKeyBuildAllShPasses) {
            const auto expected = parse_key("93FB9D011930AFC453AA75B183EFAC09");
            ASSERT_TRUE(expected.has_value());
            EXPECT_BYTES_EQ(*expected, test::kBuildAllCpuKey);
            EXPECT_TRUE(nand::cpukey_valid(test::kBuildAllCpuKey));
        }

        TEST(Keys, CliFixtureCpuKeyIsTheKeyTheIntegrationScriptPasses) {
            const auto expected = parse_key("ffffffffffff1f0000000000006ce58d");
            ASSERT_TRUE(expected.has_value());
            EXPECT_BYTES_EQ(*expected, test::kCliFixtureCpuKey);
            EXPECT_TRUE(nand::cpukey_valid(test::kCliFixtureCpuKey));
        }

        // BuildRunnerTests.cpp valid_cpu_key(): the first run of low set bits that, ECC-encoded,
        // is a valid key other than the all-zero one.
        TEST(Keys, ValidCpuKeyIsTheFirstEccEncodedBitPrefix) {
            std::optional<test::CpuKey> found;
            size_t found_bits = 0;
            for (size_t bit_count = 0; bit_count <= 106 && !found; ++bit_count) {
                std::array<uint8_t, 16> candidate{};
                for (size_t bit = 0; bit < bit_count; ++bit) {
                    candidate[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
                }
                XeCryptUidEccEncode(candidate.data());
                if (!nand::is_zero_cpu_key(candidate) && nand::cpukey_valid(candidate)) {
                    found = candidate;
                    found_bits = bit_count;
                }
            }
            ASSERT_TRUE(found.has_value());
            EXPECT_EQ(found_bits, 53u);
            EXPECT_BYTES_EQ(*found, test::valid_cpu_key());
        }

        // BuildRunnerTests.cpp different_valid_cpu_key(): bits 53..105 set, ECC-encoded.
        TEST(Keys, DifferentValidCpuKeyIsBits53To105) {
            std::array<uint8_t, 16> candidate{};
            for (size_t bit = 53; bit < 106; ++bit) {
                candidate[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
            }
            XeCryptUidEccEncode(candidate.data());
            const auto key = test::different_valid_cpu_key();
            EXPECT_BYTES_EQ(candidate, key);
            EXPECT_TRUE(nand::cpukey_valid(key));
            EXPECT_FALSE(std::ranges::equal(key, test::valid_cpu_key()));
        }

    } // namespace
} // namespace gxbuild3::core
