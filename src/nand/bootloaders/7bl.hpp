#pragma once
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCg {
      public:
        cg_header header;
        std::vector<uint8_t> data;
        bool decrypted = false;

        static BootloaderCg parse_or_throw(const std::vector<uint8_t>& bytes);

        void decrypt_or_throw(const uint8_t cg_hmac[16]);
        void encrypt_or_throw(const uint8_t cg_hmac[16]);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
