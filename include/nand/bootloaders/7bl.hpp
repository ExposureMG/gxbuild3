#pragma once
#include "gxbuild/Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild::nand {

    class BootloaderCg {
      public:
        cg_header header;
        std::vector<uint8_t> data;
        bool decrypted = false;

        [[nodiscard]] static Result<BootloaderCg> parse(std::span<const uint8_t> bytes);

        [[nodiscard]] Result<void> decrypt(const uint8_t cg_hmac[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t cg_hmac[16]);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild::nand
