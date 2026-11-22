#pragma once

#include "Wire.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace gxbuild3::nand {

    struct nand_header {
        wire::be16 magic;
        wire::be16 version;
        wire::be16 pairing;
        wire::be16 flags;
        wire::be32 entrypoint;
        wire::be32 size;
        uint8_t copyright[0x38];
        wire::be32 hack_flags;
        // packs [dualboot, boot_options, xellbutton2, xellbutton] from high byte to low byte
        wire::be32 boot_flags;
        uint8_t reserved[0x10];
        wire::be32 kv_size;
        wire::be32 cf_offset;
        wire::be16 patch_slots;
        wire::be16 kv_version;
        wire::be32 kv_addr;
        wire::be32 fs_addr;
        wire::be32 smc_config_offset;
        wire::be32 smc_boot_size;
        wire::be32 smc_boot_offset;
    };

    static_assert(wire::WireLayout<nand_header>);
    static_assert(sizeof(nand_header) == 0x80);
    static_assert(offsetof(nand_header, magic) == 0x00);
    static_assert(offsetof(nand_header, version) == 0x02);
    static_assert(offsetof(nand_header, pairing) == 0x04);
    static_assert(offsetof(nand_header, flags) == 0x06);
    static_assert(offsetof(nand_header, entrypoint) == 0x08);
    static_assert(offsetof(nand_header, size) == 0x0C);
    static_assert(offsetof(nand_header, copyright) == 0x10);
    static_assert(offsetof(nand_header, hack_flags) == 0x48);
    static_assert(offsetof(nand_header, boot_flags) == 0x4C);
    static_assert(offsetof(nand_header, reserved) == 0x50);
    static_assert(offsetof(nand_header, kv_size) == 0x60);
    static_assert(offsetof(nand_header, cf_offset) == 0x64);
    static_assert(offsetof(nand_header, patch_slots) == 0x68);
    static_assert(offsetof(nand_header, kv_version) == 0x6A);
    static_assert(offsetof(nand_header, kv_addr) == 0x6C);
    static_assert(offsetof(nand_header, fs_addr) == 0x70);
    static_assert(offsetof(nand_header, smc_config_offset) == 0x74);
    static_assert(offsetof(nand_header, smc_boot_size) == 0x78);
    static_assert(offsetof(nand_header, smc_boot_offset) == 0x7C);

    struct MobileBlockPlacement {
        uint8_t block_type = 0;
        uint16_t start_block = 0;
        uint16_t first_page = 0;
        uint16_t page_count = 0;
        uint8_t free_count = 0;
        uint32_t sequence = 1;
        uint32_t data_size = 0;
    };

    struct SpareOverride {
        size_t offset;
        size_t index;
        std::vector<uint8_t> bytes;
    };

    struct NandLayout {
        std::optional<uint16_t> fs_root_block;
        uint32_t fs_version = 1;
        std::optional<uint16_t> big_fs_size;
        std::vector<MobileBlockPlacement> mobile_blocks;
        std::vector<uint16_t> fs_data_blocks;
        // regions that still get a type-0 spare stamp even when their data bytes are all 0xFF
        std::vector<std::pair<size_t, size_t>> programmed_ranges;
        std::vector<SpareOverride> spare_overrides;
    };

} // namespace gxbuild3::nand
