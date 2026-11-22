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

    struct corona_anchor_blob {
        wire::be16 block;
        wire::be16 length;
    };

    // emmc anchor block that stores the flashfs root block and up to four mobile data locations
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

        static constexpr std::array<size_t, 2> kOffsets = {0x2FE8000, 0x2FEC000};
        static constexpr size_t kSpan = 0x1000;
        static constexpr size_t kBlockSize = 0x4000;

        struct Blob {
            uint16_t block = 0;
            uint16_t length = 0;
        };

        uint32_t number = 0;
        uint16_t table = 0;
        std::array<Blob, kBlobSlots> blobs{};

        [[nodiscard]] static Result<CoronaConfig> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<CoronaConfig> parse(const std::vector<uint8_t>& bytes);

        [[nodiscard]] static std::optional<CoronaConfig>
        choose(const std::array<std::span<const uint8_t>, 2>& copies);

        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    static_assert(sizeof(corona_anchor) == CoronaConfig::kSize);
    static_assert(std::size(corona_anchor{}.blobs) == CoronaConfig::kBlobSlots);

} // namespace gxbuild3::nand
