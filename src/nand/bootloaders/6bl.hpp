#pragma once
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCf {
      public:
        cf_header header;
        std::optional<cf_perbox> perbox;
        std::vector<uint8_t> data;
        bool decrypted = false;

        static BootloaderCf parse_or_throw(const std::vector<uint8_t>& bytes);

        void decrypt_or_throw(const uint8_t onebl_key[16]);
        void encrypt_or_throw(const uint8_t onebl_key[16]);
        void calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]);

        bool is_decrypted() const;
        bool verify_signature() const;
        // The CG/7BL RC4 key material: the 7BL nonce in the decrypted CF payload at
        // kCfCgNonceOffset (0x330), never the header fixpoint at +0x20. Empty while the CF is
        // still encrypted or too short to carry the nonce.
        std::optional<std::array<uint8_t, 16>> cg_key() const;
        bool parse_perbox();
        bool serialize_perbox();
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
