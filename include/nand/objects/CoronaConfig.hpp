#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

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

        // Refuses a block that is short or whose hash does not match what follows it.
        static std::optional<CoronaConfig> parse(std::span<const uint8_t> bytes);
        static std::optional<CoronaConfig> parse(const std::vector<uint8_t>& bytes);

        // The anchor a console would believe: the highest number among the copies that parse.
        static std::optional<CoronaConfig>
        choose(const std::array<std::span<const uint8_t>, 2>& copies);

        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::NAND
