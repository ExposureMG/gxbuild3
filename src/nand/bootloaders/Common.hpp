#pragma once

#include "Error.hpp"
#include "Wire.hpp"
#include "excrypt.h"
#include "exkeys.h"

#include <array>
#include <cstddef>
#include <limits>
#include <optional>
#include <stdbool.h>
#include <stdint.h>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {

    void ExCryptRandom(uint8_t* dest, size_t size);

    inline constexpr uint8_t key_1bl[0x10] = {0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                                              0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};

    enum NANDBootloaderMagic : uint16_t {
        FlashHeader = 0xFF4F,
        _1BL = 0x0341,
        CB = 0x4342,
        CD = 0x4344,
        CE = 0x4345,
        CF = 0x4346,
        CG = 0x4347,
        SB = 0x5342,
        SC = 0x5343,
        SD = 0x5344,
        SE = 0x5345,
        SF = 0x5346,
        SG = 0x5347
    };

    // Bootloader stage records are wire structs (src/Wire.hpp): they hold their numeric fields in
    // on-disk big-endian order, so sizeof and offsetof are the on-disk layout and a stage header
    // is serialized by copying its bytes.
    struct generic_header {
        wire::be16 magic;
        wire::be16 version;
        wire::be16 pairing;
        wire::be16 flags;
        wire::be32 entrypoint;
        wire::be32 size;
    };
    static_assert(wire::WireLayout<generic_header>);

    struct cb_perbox {
        uint8_t pairing_data[3];
        uint8_t lockdown_value;
        uint8_t reserved[0xC];
        uint8_t per_box_digest[0x10];
    };
    static_assert(wire::WireLayout<cb_perbox>);

    struct ConsoleTypeSeqAllow {
        uint8_t console_type;
        uint8_t console_sequence;
        wire::be16 console_sequence_allow;
    };
    static_assert(wire::WireLayout<ConsoleTypeSeqAllow>);

    struct cb_header {
        generic_header header;
        uint8_t key[0x10];
        uint8_t padding_or_args[0x20];
        uint8_t signature[0x100];
        uint8_t globals[0x128];
        uint8_t dev_pub_key[0x110];
        uint8_t nonce_3bl[0x10];
        char salt_3bl[10];
        char salt_4bl[10];
        uint8_t next_hash[0x14];
        ConsoleTypeSeqAllow console_seq_allow;
        uint8_t reserved[0xC];
    };
    static_assert(wire::WireLayout<cb_header>);

    struct sc_header {
        generic_header header;
        uint8_t key[0x10];
        uint8_t signature[0x100];
    };
    static_assert(wire::WireLayout<sc_header>);

    // The salt a CD stores at 0x240 for the 6BL key derivation. It lies in the encrypted part of
    // the stage, so it reads as this constant only in a plaintext CD (the 42 tracked plaintext
    // CD/SD images all carry it; ciphertext matches it with probability 2^-80).
    inline constexpr std::array<char, 10> kRomSalt6bl{'X', 'B', 'O', 'X', '_',
                                                      'R', 'O', 'M', '_', '6'};

    struct cd_header {
        generic_header header;
        uint8_t key[0x10];
        uint8_t signature[0x100];
        uint8_t rsa_pub_key[0x110];
        uint8_t nonce_6bl[0x10];
        char salt_6bl[10];
        wire::be16 padding;
        uint8_t ce_hash[0x14];
    };
    static_assert(wire::WireLayout<cd_header>);

    struct ce_header {
        generic_header header;
        uint8_t key[0x10];
        wire::be64 address;
        wire::be32 size;
        wire::be32 padding;
    };
    static_assert(wire::WireLayout<ce_header>);

    struct cf_perbox {
        uint8_t reserved_per_box[0x2B];
        uint8_t update_slot;
        uint8_t pairing_data[3];
        uint8_t lockdown_value;
        uint8_t per_box_digest[0x10];
    };
    static_assert(wire::WireLayout<cf_perbox>);

    struct cf_header {
        generic_header header;
        wire::be16 source_version;
        wire::be16 source_qfe;
        wire::be16 target_version;
        wire::be16 target_qfe;
        wire::be32 reserved;
        wire::be32 cg_size;
        uint8_t fixpoint_nonce[0x10]; // CF+0x20: self-referential HMAC fixpoint, not the CG key
    };
    static_assert(wire::WireLayout<cf_header>);

    // The CG/7BL RC4 key is HMAC-SHA1 of the 7BL nonce stored in the decrypted CF payload
    // at absolute offset 0x330 (cf_header is 0x30 bytes, so this is payload offset 0x300),
    // never the header fixpoint above. RGBuild/build360/nandtool/J-Runner agree on 0x330.
    inline constexpr size_t kCfCgNonceOffset = 0x330;

    // A CG too long for its update slot spills its tail into logical 16 KiB FlashFS clusters.
    // The decrypted CF payload opens (CF + 0x30) with the table naming them in order: a count
    // and up to kMaxCgClusters cluster numbers, the rest zero. The record is a lossless codec;
    // the cap and the needed-count checks stay with the callers.
    inline constexpr size_t kMaxCgClusters = 223;
    inline constexpr size_t kCgClusterSize = 0x4000;

    struct cf_continuation_table {
        wire::be16 count;
        wire::be16 clusters[kMaxCgClusters];
    };
    static_assert(wire::WireLayout<cf_continuation_table>);

    inline constexpr size_t kCfTableSize = sizeof(cf_continuation_table);
    static_assert(kCfTableSize == 0x1C0);

    struct cg_header {
        generic_header header;
        uint8_t key[0x10];
        wire::be32 source_size;
        uint8_t source_hash[0x14];
        wire::be32 target_size;
        uint8_t target_hash[0x14];
    };
    static_assert(wire::WireLayout<cg_header>);

    // A stage's declared size rounded up to the 16-byte crypt granularity. It fails when the
    // declared size cannot hold `min_size` bytes (the stage's own header), which keeps the
    // payload arithmetic of every parse, decrypt and encrypt from underflowing.
    [[nodiscard]] inline Result<size_t> aligned_stage_size(uint32_t declared_size, size_t min_size,
                                                           std::string_view stage) {
        const uint64_t aligned = (uint64_t{declared_size} + 0xF) & ~uint64_t{0xF};
        if (aligned > std::numeric_limits<uint32_t>::max()) {
            return fail(ErrorCode::Malformed, "{} declared size 0x{:X} overflows when aligned",
                        stage, declared_size);
        }
        if (aligned < min_size) {
            return fail(ErrorCode::Malformed,
                        "{} declared size 0x{:X} is smaller than its 0x{:X}-byte header", stage,
                        declared_size, min_size);
        }
        return static_cast<size_t>(aligned);
    }

} // namespace gxbuild3::nand
