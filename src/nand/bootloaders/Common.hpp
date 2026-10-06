#pragma once

#include "Endian.hpp"
#include "Error.hpp"
#include "excrypt.h"
#include "exkeys.h"

#include <array>
#include <cstddef>
#include <limits>
#include <optional>
#include <stdbool.h>
#include <stdexcept>
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

#pragma pack(push, 1)

    struct generic_header {
        uint16_t magic;
        uint16_t version;
        uint16_t pairing;
        uint16_t flags;
        uint32_t entrypoint;
        uint32_t size;
    };

    // Bootloader headers are serialized big-endian, while every Bootloader* instance stores these
    // numeric fields in host order. The conversion is involutive, so this one helper is used at
    // each parse, serialization, and temporary crypt-buffer boundary.
    inline void byteswap_generic_header(generic_header& header) noexcept {
        header.magic = bswap16(header.magic);
        header.version = bswap16(header.version);
        header.pairing = bswap16(header.pairing);
        header.flags = bswap16(header.flags);
        header.entrypoint = bswap32(header.entrypoint);
        header.size = bswap32(header.size);
    }

    struct cb_perbox {
        uint8_t pairing_data[3];
        uint8_t lockdown_value;
        uint8_t reserved[0xC];
        uint8_t per_box_digest[0x10];
    };

    struct ConsoleTypeSeqAllow {
        uint8_t console_type;
        uint8_t console_sequence;
        uint16_t console_sequence_allow;
    };

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

    inline void byteswap_cb_header_numeric_fields(cb_header& header) noexcept {
        header.console_seq_allow.console_sequence_allow =
            bswap16(header.console_seq_allow.console_sequence_allow);
    }

    struct sc_header {
        generic_header header;
        uint8_t key[0x10];
        uint8_t signature[0x100];
    };

    struct cd_header {
        generic_header header;
        uint8_t key[0x10];
        uint8_t signature[0x100];
        uint8_t rsa_pub_key[0x110];
        uint8_t nonce_6bl[0x10];
        char salt_6bl[10];
        uint16_t padding;
        uint8_t ce_hash[0x14];
    };

    inline void byteswap_cd_header_numeric_fields(cd_header& header) noexcept {
        header.padding = bswap16(header.padding);
    }

    struct ce_header {
        generic_header header;
        uint8_t key[0x10];
        uint64_t address;
        uint32_t size;
        uint32_t padding;
    };

    inline void byteswap_ce_header_numeric_fields(ce_header& header) noexcept {
        header.address = bswap64(header.address);
        header.size = bswap32(header.size);
        header.padding = bswap32(header.padding);
    }

    struct cf_perbox {
        uint8_t reserved_per_box[0x2B];
        uint8_t update_slot;
        uint8_t pairing_data[3];
        uint8_t lockdown_value;
        uint8_t per_box_digest[0x10];
    };

    struct cf_header {
        generic_header header;
        uint16_t source_version;
        uint16_t source_qfe;
        uint16_t target_version;
        uint16_t target_qfe;
        uint32_t reserved;
        uint32_t cg_size;
        uint8_t fixpoint_nonce[0x10]; // CF+0x20: self-referential HMAC fixpoint, not the CG key
    };

    // The CG/7BL RC4 key is HMAC-SHA1 of the 7BL nonce stored in the decrypted CF payload
    // at absolute offset 0x330 (cf_header is 0x30 bytes, so this is payload offset 0x300),
    // never the header fixpoint above. RGBuild/build360/nandtool/J-Runner agree on 0x330.
    inline constexpr size_t kCfCgNonceOffset = 0x330;

    inline void byteswap_cf_header_numeric_fields(cf_header& header) noexcept {
        header.source_version = bswap16(header.source_version);
        header.source_qfe = bswap16(header.source_qfe);
        header.target_version = bswap16(header.target_version);
        header.target_qfe = bswap16(header.target_qfe);
        header.reserved = bswap32(header.reserved);
        header.cg_size = bswap32(header.cg_size);
    }

    struct cg_header {
        generic_header header;
        uint8_t key[0x10];
        uint32_t source_size;
        uint8_t source_hash[0x14];
        uint32_t target_size;
        uint8_t target_hash[0x14];
    };

    inline void byteswap_cg_header_numeric_fields(cg_header& header) noexcept {
        header.source_size = bswap32(header.source_size);
        header.target_size = bswap32(header.target_size);
    }

#pragma pack(pop)

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

    namespace detail {

        // TODO(test-phase): the test-only *_or_throw bootloader shims unwrap the Result API
        // through these; the test rewrite deletes both. tests/ErrorConventionGuard.cmake keeps
        // them out of the rest of src/.
        template <class T> [[nodiscard]] T value_or_throw(Result<T>&& result) {
            if (!result) {
                throw std::runtime_error(result.error().describe());
            }
            return std::move(*result);
        }

        inline void value_or_throw(Result<void>&& result) {
            if (!result) {
                throw std::runtime_error(result.error().describe());
            }
        }

    } // namespace detail

} // namespace gxbuild3::nand
