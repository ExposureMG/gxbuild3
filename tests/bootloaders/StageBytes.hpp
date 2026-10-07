#pragma once

// Hand-built stage images for the bootloader tests: `total` bytes whose generic header carries
// `magic` (big-endian at 0) and the declared size `declared` (big-endian at 0xC). The two fills
// are the two shapes the old tests built: Zero (CryptoReferenceTests.cpp) and Counting, byte i
// = i * 7 + 3 under the header fields (StageTests.cpp). Neither feeds a golden.

#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <cstdint>

namespace gxbuild3::bootloaders {

    enum class Fill : uint8_t {
        Zero,
        Counting,
    };

    [[nodiscard]] inline test::Bytes stage_bytes(uint16_t magic, size_t total, uint32_t declared,
                                                 Fill fill) {
        test::Bytes bytes(total, 0);
        if (fill == Fill::Counting) {
            for (size_t i = 0; i < total; ++i) {
                bytes[i] = static_cast<uint8_t>(i * 7 + 3);
            }
        }
        test::put_be16(bytes, 0, magic);
        test::put_be32(bytes, 0xC, declared);
        return bytes;
    }

} // namespace gxbuild3::bootloaders
