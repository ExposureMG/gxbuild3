#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <optional>

#pragma pack(push, 1)

// ECC spare data used on 1st gen NAND controllers
struct spare_sb {
    // uint16_t block_id : 12;
    uint8_t block_id_1;
    uint8_t block_id_0 : 4;

    uint8_t fs_unused : 4;
    uint8_t fs_sequence_0;
    uint8_t fs_sequence_1;
    uint8_t fs_sequence_2;
    uint8_t bad_block;
    uint8_t fs_sequence_3;

    // uint16_t fs_size;
    uint8_t fs_size_1;
    uint8_t fs_size_0;

    uint8_t fs_page_count;
    uint8_t fs_unused_2[2];
    uint8_t fs_block_type : 6;

    // 14-bit ECC data
    uint8_t ecc3 : 2;
    uint8_t ecc2;
    uint8_t ecc1;
    uint8_t ecc0;
};

// ECC spare data used on 2nd gen NAND controllers (16/64MB)
struct spare_new_sb {
    uint8_t fs_sequence_0;

    // uint16_t block_id : 12;
    uint8_t block_id_1;
    uint8_t block_id_0 : 4;

    uint8_t fs_unused : 4;
    uint8_t fs_sequence_1;
    uint8_t fs_sequence_2;
    uint8_t bad_block;
    uint8_t fs_sequence_3;

    // uint16_t fs_size;
    uint8_t fs_size_1;
    uint8_t fs_size_0;

    uint8_t fs_page_count;
    uint8_t fs_unused_2[2];
    uint8_t fs_block_type : 6;

    // 14-bit ECC data
    uint8_t ecc3 : 2;
    uint8_t ecc2;
    uint8_t ecc1;
    uint8_t ecc0;
};

// ECC spare data used on 2nd gen NAND controllers (256/512MB)
struct spare_bb {
    uint8_t bad_block;

    // uint16_t block_id : 12;
    uint8_t block_id_1;
    uint8_t block_id_0 : 4;

    uint8_t fs_unused : 4;
    uint8_t fs_sequence_2;
    uint8_t fs_sequence_1;
    uint8_t fs_sequence_0;
    uint8_t fs_unused_2;

    // uint16_t fs_size;
    uint8_t fs_size_1;
    uint8_t fs_size_0;

    uint8_t fs_page_count;
    uint8_t fs_unused_3[2];
    uint8_t fs_block_type : 6;

    // 14-bit ECC data
    uint8_t ecc3 : 2;
    uint8_t ecc2;
    uint8_t ecc1;
    uint8_t ecc0;
};

struct small_page {
    std::array<std::byte, 512> main;
    spare_sb spare;
};

struct new_small_page {
    std::array<std::byte, 512> main;
    spare_new_sb spare;
};

struct big_page {
    std::array<std::byte, 512> main;
    spare_bb spare;
};

typedef struct _nand_header {
    uint16_t magic;
    uint16_t version;
    uint16_t pairing;
    uint16_t flags;
    uint32_t entrypoint;
    uint32_t size;
    uint8_t copyright[0x40];
    uint8_t reserved[0x10];
    uint32_t kv_size;
    uint32_t cf_offset;
    uint16_t patch_slots;
    uint16_t kv_version;
    uint32_t kv_addr;
    uint32_t fs_addr;
    uint32_t smc_config_offset;
    uint32_t smc_boot_size;
    uint32_t smc_boot_offset;
} nand_header;

#pragma pack(pop)

struct MobileBlockPlacement {
    uint8_t block_type = 0;
    uint16_t start_block = 0;
    uint16_t block_count = 0;
    uint32_t sequence = 1;
    uint32_t data_size = 0;
};

struct NandLayout {
    std::optional<uint16_t> fs_root_block;
    uint32_t fs_version = 1;
    uint16_t fs_size = 0;
    std::vector<MobileBlockPlacement> mobile_blocks;
};
