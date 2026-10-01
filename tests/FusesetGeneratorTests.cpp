#include "utils/FusesetGenerator.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
    using Bytes = std::vector<uint8_t>;
    using gxbuild3::utils::generate_fuseset;
    using gxbuild3::utils::read_cb_word;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
        }
        return condition;
    }

    // Every vector below is xerunner's tests/xebuild/test_chain.py TheFusesALoaderHandsOver,
    // with its key bytes(range(0x10)).
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

    bool test_every_line_of_a_retail_slim_console() {
        const auto key = test_key();
        const auto fuses = generate_fuseset(0x03000003, key, 17);
        if (!require(fuses && fuses->size() == 0x60, "a retail slim fuseset is 0x60 bytes")) {
            return false;
        }
        const Bytes key_hi(key.begin(), key.begin() + 8);
        const Bytes key_lo(key.begin() + 8, key.end());
        bool ok = require(line(*fuses, 0) == Bytes{0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                          "line 0 is C0FFFFFFFFFFFFFF");
        ok = require(line(*fuses, 1) == Bytes{0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xF0, 0xF0},
                     "line 1 names a retail slim console") &&
             ok;
        ok = require(line(*fuses, 2) == Bytes{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                     "line 2 has one nibble per allow bit, bit 0 on top") &&
             ok;
        ok = require(line(*fuses, 3) == key_hi && line(*fuses, 4) == key_hi &&
                         line(*fuses, 5) == key_lo && line(*fuses, 6) == key_lo,
                     "lines 3-6 are the CPU key halves, each twice") &&
             ok;
        ok = require(line(*fuses, 7) == Bytes(8, 0xFF), "line 7 holds sixteen LDV nibbles") && ok;
        ok = require(line(*fuses, 8) == Bytes{0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                     "line 8 holds the seventeenth LDV nibble") &&
             ok;
        for (size_t index = 9; index < 12; ++index) {
            ok = require(line(*fuses, index) == Bytes(8, 0x00), "lines 9-11 are zero") && ok;
        }
        return ok;
    }

    bool test_a_devkit_type_and_no_lockdown() {
        const auto fuses = generate_fuseset(0, test_key(), 0);
        if (!require(fuses.has_value(), "a devkit fuseset is generated")) {
            return false;
        }
        return require(line(*fuses, 1) == Bytes(8, 0x0F), "line 1 names a devkit") &&
               require(line(*fuses, 7) == Bytes(8, 0x00) && line(*fuses, 8) == Bytes(8, 0x00),
                       "no lockdown leaves lines 7-8 zero");
    }

    bool test_the_word_comes_off_the_cb_and_an_unknown_type_is_refused() {
        Bytes cb(0x400, 0x00);
        cb[0x3B0] = 0x02;
        cb[0x3B1] = 0x00;
        cb[0x3B2] = 0x12;
        cb[0x3B3] = 0x34;
        const auto word = read_cb_word(cb);
        return require(word && *word == 0x02001234, "the CB word is read big-endian at 0x3B0") &&
               require(!read_cb_word(Bytes(0x3B3, 0x00)),
                       "a CB too short for the word is refused") &&
               require(!generate_fuseset(0x07000000, test_key(), 0),
                       "a console type the original does not know is refused");
    }
} // namespace

int main() {
    bool passed = true;
    passed = test_every_line_of_a_retail_slim_console() && passed;
    passed = test_a_devkit_type_and_no_lockdown() && passed;
    passed = test_the_word_comes_off_the_cb_and_an_unknown_type_is_refused() && passed;
    if (!passed) {
        return 1;
    }
    std::cout << "FusesetGenerator tests passed\n";
    return 0;
}
