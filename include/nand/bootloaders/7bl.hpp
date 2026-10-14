#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCg {
      public:
        cg_header header;
        std::vector<uint8_t> data;
        bool decrypted = false;

        // Fails when the bytes or the declared size cannot hold cg_header.
        [[nodiscard]] static Result<BootloaderCg> parse(std::span<const uint8_t> bytes);

        // Each is a no-op when the stage is already in the requested state, and fails before
        // touching the payload.
        [[nodiscard]] Result<void> decrypt(const uint8_t cg_hmac[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t cg_hmac[16]);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
