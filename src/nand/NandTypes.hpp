#pragma once

#include "Wire.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace gxbuild3::nand {

    // The NAND header at offset 0 (big-endian on disk).
    struct nand_header {
        wire::be16 magic;
        wire::be16 version;
        wire::be16 pairing;
        wire::be16 flags;
        wire::be32 entrypoint;
        wire::be32 size;
        uint8_t copyright[0x38];
        // 1 on a hacked image (the glitch types and JTAG), 0 on retail and devkit.
        wire::be32 hack_flags;
        // The XeLL and boot switches the hacked CB/CD read, high byte first: 0x4C dualboot
        // reason, 0x4D boot options, 0x4E second XeLL reason, 0x4F XeLL reason. Zero on retail
        // and devkit.
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

    // One settings blob copy (mobile type 0x31-0x39). On NAND it fills `page_count` pages from
    // `first_page` of `start_block`, and only those pages carry its spare: the type, the version,
    // the length in bytes and how much of the block is left free after it, in pages on small
    // block and in 0x800-byte slots on big block. On eMMC it starts at `start_block` and the
    // anchor blocks say where it is.
    struct MobileBlockPlacement {
        uint8_t block_type = 0;
        uint16_t start_block = 0;
        uint16_t first_page = 0;
        uint16_t page_count = 0;
        uint8_t free_count = 0;
        uint32_t sequence = 1;
        uint32_t data_size = 0;
    };

    // Bytes xeBuild leaves in one page's spare that no stamp sets.
    struct SpareOverride {
        size_t offset;
        size_t index;
        std::vector<uint8_t> bytes;
    };

    struct NandLayout {
        std::optional<uint16_t> fs_root_block;
        uint32_t fs_version = 1;
        // The size stamp of a big-block root block; FlashFsMetadata::kBigFsSize when unset.
        std::optional<uint16_t> big_fs_size;
        std::vector<MobileBlockPlacement> mobile_blocks;
        // Physical blocks holding FlashFS file data; FlashFileSystem::save stamps their spare.
        std::vector<uint16_t> fs_data_blocks;
        // Byte ranges (offset, length) of the image that xeBuild programs even where they are all
        // 0xFF, so their pages carry a type-0 spare stamp instead of an erased one.
        std::vector<std::pair<size_t, size_t>> programmed_ranges;
        // Written into the spare of the page holding `offset`, after the block stamps and before
        // the page's ECC is computed.
        std::vector<SpareOverride> spare_overrides;
    };

} // namespace gxbuild3::nand
