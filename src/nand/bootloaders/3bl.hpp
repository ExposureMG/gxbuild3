#pragma once
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderSc {
      public:
        sc_header header;
        std::vector<uint8_t> data;
        // Runtime key handed to SD: HMAC(secret, nonce). header.key retains the on-disk nonce.
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        static BootloaderSc parse(const std::vector<uint8_t>& bytes);

        // The secret is sixteen zero bytes on every console (kZeroSecret).
        void decrypt(const uint8_t secret[16]);
        void encrypt(const uint8_t secret[16]);

        static constexpr uint8_t kZeroSecret[16] = {};

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
