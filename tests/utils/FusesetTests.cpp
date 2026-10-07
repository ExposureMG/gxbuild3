// src/utils/FusesetGenerator.hpp: the twelve 8-byte fuse lines a console's fuseset holds, made from
// the CB's console-type word, the CPU key and the lockdown (CF LDV) count, and the word read off
// the CB.
//
// Every vector below is xerunner's tests/xebuild/test_chain.py TheFusesALoaderHandsOver, with
// its key bytes(range(0x10)).

#include "support/Expect.hpp"
#include "utils/FusesetGenerator.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace gxbuild3::utils {
    namespace {

        using test::Bytes;

        Bytes test_key() {
            Bytes key(16);
            for (size_t index = 0; index < key.size(); ++index) {
                key[index] = static_cast<uint8_t>(index);
            }
            return key;
        }

        Bytes line(const std::vector<uint8_t>& fuses, size_t index) {
            return Bytes(fuses.begin() + static_cast<ptrdiff_t>(index * 8),
                         fuses.begin() + static_cast<ptrdiff_t>(index * 8 + 8));
        }

        TEST(Fuseset, EveryLineOfARetailSlimConsole) {
            const auto key = test_key();
            const auto fuses = generate_fuseset(0x03000003, key, 17);
            ASSERT_OK(fuses) << "a retail slim fuseset is 0x60 bytes";
            ASSERT_EQ(fuses->size(), 0x60U) << "a retail slim fuseset is 0x60 bytes";
            const Bytes key_hi(key.begin(), key.begin() + 8);
            const Bytes key_lo(key.begin() + 8, key.end());
            EXPECT_BYTES_EQ((Bytes{0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
                            line(*fuses, 0))
                << "line 0 is C0FFFFFFFFFFFFFF";
            EXPECT_BYTES_EQ((Bytes{0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xF0, 0xF0}),
                            line(*fuses, 1))
                << "line 1 names a retail slim console";
            EXPECT_BYTES_EQ((Bytes{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
                            line(*fuses, 2))
                << "line 2 has one nibble per allow bit, bit 0 on top";
            EXPECT_BYTES_EQ(key_hi, line(*fuses, 3))
                << "lines 3-6 are the CPU key halves, each twice";
            EXPECT_BYTES_EQ(key_hi, line(*fuses, 4))
                << "lines 3-6 are the CPU key halves, each twice";
            EXPECT_BYTES_EQ(key_lo, line(*fuses, 5))
                << "lines 3-6 are the CPU key halves, each twice";
            EXPECT_BYTES_EQ(key_lo, line(*fuses, 6))
                << "lines 3-6 are the CPU key halves, each twice";
            EXPECT_BYTES_EQ(Bytes(8, 0xFF), line(*fuses, 7)) << "line 7 holds sixteen LDV nibbles";
            EXPECT_BYTES_EQ((Bytes{0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
                            line(*fuses, 8))
                << "line 8 holds the seventeenth LDV nibble";
            for (size_t index = 9; index < 12; ++index) {
                SCOPED_TRACE(index);
                EXPECT_BYTES_EQ(Bytes(8, 0x00), line(*fuses, index)) << "lines 9-11 are zero";
            }
        }

        TEST(Fuseset, DevkitTypeAndNoLockdown) {
            const auto fuses = generate_fuseset(0, test_key(), 0);
            ASSERT_OK(fuses) << "a devkit fuseset is generated";
            // Not an old check: a guard so line() never reads past a short fuseset.
            ASSERT_GE(fuses->size(), size_t{9 * 8}) << "a devkit fuseset reaches line 8";
            EXPECT_BYTES_EQ(Bytes(8, 0x0F), line(*fuses, 1)) << "line 1 names a devkit";
            EXPECT_BYTES_EQ(Bytes(8, 0x00), line(*fuses, 7)) << "no lockdown leaves lines 7-8 zero";
            EXPECT_BYTES_EQ(Bytes(8, 0x00), line(*fuses, 8)) << "no lockdown leaves lines 7-8 zero";
        }

        TEST(Fuseset, WordComesOffTheCbAndAnUnknownTypeIsRefused) {
            Bytes cb(0x400, 0x00);
            cb[0x3B0] = 0x02;
            cb[0x3B1] = 0x00;
            cb[0x3B2] = 0x12;
            cb[0x3B3] = 0x34;
            const auto word = read_cb_word(cb);
            EXPECT_FALSE(read_cb_word(Bytes(0x3B3, 0x00)).has_value())
                << "a CB too short for the word is refused";
            EXPECT_FALSE(generate_fuseset(0x07000000, test_key(), 0).has_value())
                << "a console type the original does not know is refused";
            ASSERT_OK(word) << "the CB word is read big-endian at 0x3B0";
            EXPECT_EQ(*word, 0x02001234U) << "the CB word is read big-endian at 0x3B0";
        }

    } // namespace
} // namespace gxbuild3::utils
