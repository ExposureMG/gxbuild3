#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCe {
      public:
        ce_header header;
        std::vector<uint8_t> data;
        bool decrypted = false;

        // Fails when the bytes or the declared size cannot hold ce_header.
        [[nodiscard]] static Result<BootloaderCe> parse(std::span<const uint8_t> bytes);

        // Each is a no-op when the stage is already in the requested state, and fails before
        // touching the payload.
        [[nodiscard]] Result<void> decrypt(const uint8_t cd_key[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t cd_key[16]);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
