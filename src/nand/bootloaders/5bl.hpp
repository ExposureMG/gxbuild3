#pragma once
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCe {
      public:
        ce_header header;
        std::vector<uint8_t> data;
        bool decrypted = false;

        static BootloaderCe parse_or_throw(const std::vector<uint8_t>& bytes);

        void decrypt_or_throw(const uint8_t cd_key[16]);
        void encrypt_or_throw(const uint8_t cd_key[16]);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
