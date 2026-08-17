#include <array>
#include <cstddef>
#include <cstdint>

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

#pragma pack(pop)