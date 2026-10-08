#pragma once

// The sample record shared by the src/Wire.hpp tests: one field of every wire type (big and
// little 16/24/32/64-bit, byte and char arrays), a constexpr builder and its on-disk image.
// Its layout is pinned in WireLayoutPins.cpp.

#include "Wire.hpp"

#include <array>
#include <cstdint>

namespace gxbuild3::core {

    struct sample_record {
        wire::be16 magic;
        wire::be16 version;
        wire::le32 count;
        std::uint8_t tag[4];
        wire::be64 stamp;
        wire::be24 block;
        std::uint8_t flags;
        wire::le24 hash_block;
        char name[5];
    };

    constexpr sample_record make_sample() {
        sample_record r{};
        r.magic = 0x4342;
        r.version = 0x1F42;
        r.count = 0x11223344;
        r.tag[0] = 't';
        r.tag[1] = 'a';
        r.tag[2] = 'g';
        r.tag[3] = '!';
        r.stamp = 0x0102030405060708ULL;
        r.block = 0xABCDEF;
        r.flags = 0x5A;
        r.hash_block = 0x123456;
        r.name[0] = 'w';
        r.name[1] = 'i';
        r.name[2] = 'r';
        r.name[3] = 'e';
        r.name[4] = '\0';
        return r;
    }

    inline constexpr std::array<std::uint8_t, 0x20> kSampleImage = {
        0x43, 0x42, 0x1F, 0x42,                         // magic, version (big)
        0x44, 0x33, 0x22, 0x11,                         // count (little)
        't',  'a',  'g',  '!',                          // tag
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // stamp (big)
        0xAB, 0xCD, 0xEF,                               // block (be24)
        0x5A,                                           // flags
        0x56, 0x34, 0x12,                               // hash_block (le24)
        'w',  'i',  'r',  'e',  0x00,                   // name
    };

} // namespace gxbuild3::core
