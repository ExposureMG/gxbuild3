#pragma once
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCd {
      public:
        cd_header header;
        std::vector<uint8_t> data;
        // Runtime key handed to CE. header.key retains the on-disk CD nonce.
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        static BootloaderCd parse_or_throw(const std::vector<uint8_t>& bytes);

        void decrypt_or_throw(const uint8_t parent_key[16], const uint8_t cpu_key[16] = nullptr);
        void encrypt_or_throw(const uint8_t parent_key[16], const uint8_t cpu_key[16] = nullptr);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
