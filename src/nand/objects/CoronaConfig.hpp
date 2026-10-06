#pragma once

#include "Error.hpp"
#include "Wire.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    // An anchor block: what an eMMC image keeps in place of the spare bytes a NAND is scanned
    // by. Two copies sit at fixed offsets near the top of the 48 MB image. Big-endian on disk:
    //
    //   0x00  20  SHA-1 of bytes 0x14..0x200, no key
    //   0x14   4  zero
    //   0x18   4  which anchor this is
    //   0x1C   2  the block the filesystem table went to
    //   0x1E   2  zero
    //   0x20  16  four settings blobs, each a block and a length in bytes
    //   0x30      zero to 0x200
    //
    // A blob's slot is its type, not its turn: slot = type - 0x31, and an absent blob leaves
    // its slot zero.
    struct corona_anchor_blob {
        wire::be16 block;  // in 0x4000-byte blocks
        wire::be16 length; // in bytes
    };

    struct corona_anchor {
        uint8_t digest[0x14];
        wire::be32 reserved0;
        wire::be32 number;
        wire::be16 table;
        wire::be16 reserved1;
        corona_anchor_blob blobs[4];
        uint8_t tail[0x1D0];
    };

    static_assert(wire::WireLayout<corona_anchor_blob> && sizeof(corona_anchor_blob) == 4);
    static_assert(wire::WireLayout<corona_anchor> && sizeof(corona_anchor) == 0x200);
    static_assert(offsetof(corona_anchor, reserved0) == 0x14);
    static_assert(offsetof(corona_anchor, number) == 0x18);
    static_assert(offsetof(corona_anchor, table) == 0x1C);
    static_assert(offsetof(corona_anchor, reserved1) == 0x1E);
    static_assert(offsetof(corona_anchor, blobs) == 0x20);
    static_assert(offsetof(corona_anchor, tail) == 0x30);

    struct CoronaConfig {
        static constexpr size_t kSize = 0x200;
        static constexpr size_t kBlobSlots = 4;
        static constexpr uint8_t kFirstBlobType = 0x31;

        // Where the two copies sit, and how much room each is given. Each copy owns its
        // 0x4000-byte block; past kSpan the block is erased (0xFF).
        static constexpr std::array<size_t, 2> kOffsets = {0x2FE8000, 0x2FEC000};
        static constexpr size_t kSpan = 0x1000;
        static constexpr size_t kBlockSize = 0x4000;

        struct Blob {
            uint16_t block = 0;  // in 0x4000-byte blocks
            uint16_t length = 0; // in bytes
        };

        uint32_t number = 0;
        uint16_t table = 0;
        std::array<Blob, kBlobSlots> blobs{};

        // Refuses a block that is short (Truncated) or whose hash does not match what follows
        // it (HashMismatch).
        [[nodiscard]] static Result<CoronaConfig> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<CoronaConfig> parse(const std::vector<uint8_t>& bytes);

        // The anchor a console would believe: the highest number among the copies that parse.
        [[nodiscard]] static std::optional<CoronaConfig>
        choose(const std::array<std::span<const uint8_t>, 2>& copies);

        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    static_assert(sizeof(corona_anchor) == CoronaConfig::kSize);
    static_assert(std::size(corona_anchor{}.blobs) == CoronaConfig::kBlobSlots);

} // namespace gxbuild3::nand
