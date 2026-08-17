#pragma once

#include "excrypt.h"

#include <array>
#include <optional>
#include <stdbool.h>
#include <stdint.h>
#include <vector>

// NOTE: This file is derived from InvoxiPlayGames's xenon-bltool.
// As its just a set of struct definitions and data types,
// it should fall under fair use / technical info and not violate the GPL license.
// If i am wrong then open a github issue or contact me at
// EMAIL: exposuremg@protonmail.com
// DISCORD: xenon_kitchen

// Big thanks to invoxiplaygames <3

// RC4/AES key used for decrypting bootloader stages.
inline constexpr uint8_t key_1bl[0x10] = {0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                                          0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};

// The public key used to verify integrity of bootloader stages.
inline constexpr uint8_t rsa_1bl[0x110] = {
    0x00, 0x00, 0x00, 0x20,                         // key size
    0x00, 0x01, 0x00, 0x01,                         // exponent
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
    // public key in big endian
    0xE9, 0x8D, 0xB5, 0xDC, 0xAF, 0x38, 0x8E, 0xF1, 0x38, 0x9E, 0x28, 0xCB, 0x4A, 0x11, 0xC8, 0x22,
    0x52, 0xE1, 0x1F, 0x53, 0x45, 0x56, 0x60, 0xA2, 0x52, 0xD4, 0xD1, 0x68, 0x4E, 0xCC, 0x80, 0x99,
    0xD7, 0x5C, 0x40, 0xC5, 0xAF, 0x73, 0x0C, 0xCF, 0x44, 0x06, 0xB0, 0x6D, 0x16, 0x91, 0x08, 0x38,
    0xB3, 0x00, 0x2D, 0xBC, 0xEB, 0x1D, 0x0C, 0x1D, 0xC5, 0xC6, 0x68, 0x0B, 0x80, 0x4C, 0x62, 0x0B,
    0x7E, 0xE8, 0x72, 0x0C, 0xCF, 0x1D, 0xB4, 0xBD, 0xEE, 0x4B, 0x11, 0x36, 0xD1, 0xC9, 0x92, 0x1F,
    0xE9, 0xAE, 0xC0, 0x51, 0x52, 0x51, 0xF7, 0x23, 0xD6, 0xBC, 0xF4, 0xE9, 0x58, 0x87, 0x40, 0xB1,
    0x02, 0x66, 0x5A, 0x43, 0xEB, 0x67, 0x5F, 0x50, 0x94, 0x32, 0x34, 0x7A, 0xA7, 0x50, 0xD9, 0xB4,
    0x14, 0x4E, 0xB0, 0x02, 0x31, 0x8B, 0xA7, 0x00, 0x9A, 0x12, 0xC8, 0x3B, 0x8F, 0x76, 0xE4, 0x8F,
    0x33, 0xB5, 0xCD, 0x0C, 0x24, 0x6D, 0x2A, 0xE5, 0x57, 0xA0, 0x44, 0x76, 0x78, 0x41, 0xF4, 0x8F,
    0xCB, 0x3A, 0xB5, 0x0E, 0xA1, 0xA2, 0x56, 0x6D, 0x17, 0xDB, 0x32, 0xCC, 0xB8, 0x5A, 0x5F, 0xAE,
    0xED, 0x9A, 0x62, 0x31, 0x5D, 0x88, 0x7F, 0x6D, 0x9A, 0x53, 0x80, 0xB0, 0x34, 0xC7, 0x42, 0x51,
    0x2D, 0x94, 0x4D, 0x86, 0x09, 0x32, 0x8F, 0x71, 0xA7, 0xBA, 0x16, 0x6C, 0xE6, 0xDC, 0x6B, 0x64,
    0x61, 0x7D, 0x16, 0xB5, 0x20, 0x51, 0xD0, 0xB1, 0x1F, 0xFE, 0x1E, 0x35, 0x56, 0x9A, 0x76, 0x4D,
    0x62, 0x7F, 0x5D, 0xF4, 0xB8, 0x7D, 0xC4, 0x18, 0x2C, 0x81, 0xB7, 0xAF, 0xE4, 0x7D, 0x13, 0x5D,
    0xF4, 0x0F, 0x63, 0x05, 0x3F, 0x1A, 0xED, 0xED, 0x4B, 0xEE, 0xFD, 0x6D, 0x74, 0xE6, 0xA5, 0x92,
    0xA7, 0x99, 0x81, 0x73, 0x95, 0xD8, 0xC7, 0xA5, 0xA1, 0xC7, 0x7B, 0x09, 0x05, 0x85, 0x41, 0x04};

#pragma pack(push, 1)

typedef struct _bl_header {
    uint16_t magic;
    uint16_t version;
    uint16_t pairing; // 0x8000 = devkit?
    uint16_t flags;   // 0x0001 = mfg, 0x0800 = cba?
    uint32_t entrypoint;
    uint32_t size;
} bl_header;

typedef struct _nand_header {
    bl_header header;
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
} nand_header_t;

// used by SC/3BL, XKE, etc
typedef struct _generic_header {
    bl_header header;
    uint8_t key[0x10];
    EXCRYPT_SIG signature;
} generic_header;

/*
typedef struct _bl2_header {
    bl_header header;
    uint8_t key[0x10]; // Per Box Digest?
    uint64_t padding_or_args[4];
    EXCRYPT_SIG signature;
    uint8_t globals[0x128]; // "find out whats in here"
    EXCRYPT_RSAPUB_2048 devkit_pubkey; // RSA Pub Key
    uint8_t sc_key[0x10]; // nonce_3bl
    char sc_salt[10]; // salt_3bl
    char sd_salt[10]; // salt_4bl
    uint8_t cd_cbb_hash[0x14];  // CB_A has CB_B hash, CB_B has CD hash
    uint8_t more_globals[0x10]; // more_globals[1] has LDV
} bl2_header;
*/

typedef struct _bl2_metadata {
    std::optional<uint16_t> b_flags;
    std::optional<uint8_t> lockdown_value;
    std::optional<std::array<uint8_t, 3>> pairing_data;
    std::optional<std::array<uint8_t, 4>> console_allow;
    std::optional<uint64_t> post_output_addr;
    std::optional<uint64_t> sb_flash_addr;
    std::optional<uint64_t> soc_mmio_addr;
} bl2_metadata;

typedef struct _bl2_header {
    bl_header header;
    uint8_t per_box_digest[0x10];
    uint64_t padding_or_args[4];
    EXCRYPT_SIG signature;
    uint8_t globals[0x128];
    EXCRYPT_RSAPUB_2048 rsa_pub_key;
    uint8_t nonce_3bl[0x10];
    char salt_3bl[10];
    char salt_4bl[10];
    uint8_t digest[0x14]; // For CB_B or CD
    uint8_t more_globals[0x10];
    uint8_t reserved_per_box[0xC];
} bl2_header;

typedef generic_header bl3_header;

/*
typedef struct _bl4_header {
    bl_header header;
    uint8_t key[0x10];
    EXCRYPT_SIG signature;
    uint8_t idk_yet[0x120]; // unused?
    char cf_salt[10];
    uint16_t unused2;
    uint8_t ce_hash[0x14];
} bl4_header;
*/

typedef struct _bl4_header {
    bl_header header;
    uint8_t rsa_pub_key[0x10];
    EXCRYPT_SIG signature;   // only valid on devkits
    uint8_t nonce_6bl[0x10]; // Not listed in bltool?
    char salt_6bl[10];
    uint8_t digest_5bl[0x14];
} bl4_header;

typedef struct _bl5_header {
    bl_header header;
    uint8_t key[0x10];
    uint64_t target_address;
    uint32_t uncompressed_size;
    uint32_t unknown; // think this is unused
} bl5_header;

typedef struct _bl6_header {
    bl_header header;
    uint16_t base_ver;
    uint16_t base_flags; // unsure, 0x8000 for devkit
    uint16_t target_ver;
    uint16_t target_flags; // unsure, 0x8000 for devkit
    uint32_t unknown;      // think this is unused
    uint32_t cg_size;
    uint8_t key[0x10];
    uint16_t cg_block_count;
    uint16_t cg_blocks[223];
    uint8_t reserved1[0x2B];
    uint8_t update_slot;
    uint8_t pairing_data[3];
    uint8_t lockdown_value;
    uint8_t mac[0x10];

    EXCRYPT_SIG signature;
    uint8_t cg_key[0x10];
    uint8_t cg_hash[0x14];
} bl6_header;

struct CfMetadata {
    // Plain - Offset 0x0 in payload / 0x10 Absolute
    uint16_t source_version;  // base_ver
    uint16_t target_version;  // target_ver
    uint32_t reserved_prefix; // bltool - "Unknown" ?
    uint32_t cg_size;
    uint8_t hmac_salt[16];
};

struct CfMetadataDecrypted {
    // Decrypted 0x30
    uint16_t cg_blocks_used;
    std::vector<uint16_t> cg_block_numbers; // 223 entries
    EXCRYPT_SIG signature;
    uint8_t cg_nonce[0x10];  // cg_hmac
    uint8_t cg_digest[0x14]; // cg_hash

    // PerBoxData
    uint8_t reserved_per_box[0x2B];
    uint8_t update_slot;
    uint8_t pairing_data[3];
    uint8_t lockdown_value;
    uint8_t per_box_digest[0x10]; // key?
};

typedef struct _7bl_header {
    bl_header header;
    uint8_t key[0x10];
    uint32_t original_size;
    uint8_t original_hash[0x14];
    uint32_t new_size;
    uint8_t new_hash[0x14];
} bl7_header;

#pragma pack(pop)

typedef enum _bl_type {
    CB = 0x342,
    SC = 0x343,
    CD = 0x344,
    CE = 0x345,
    CF = 0x346,
    CG = 0x347,
    XKE = 0xD4D,
    KV = 0xE4E
} bl_type;
