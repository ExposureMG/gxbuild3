#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCd {
      public:
        cd_header header;
        std::vector<uint8_t> data;
        // Runtime key handed to CE. header.key retains the on-disk CD nonce.
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        // Fails when the bytes or the declared size cannot hold cd_header.
        [[nodiscard]] static Result<BootloaderCd> parse(std::span<const uint8_t> bytes);

        // Each is a no-op when the stage is already in the requested state, and fails before
        // touching the payload.
        [[nodiscard]] Result<void> decrypt(const uint8_t parent_key[16],
                                           const uint8_t cpu_key[16] = nullptr);
        [[nodiscard]] Result<void> encrypt(const uint8_t parent_key[16],
                                           const uint8_t cpu_key[16] = nullptr);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;

      private:
        // RC4s the stage from 0x20 on under the stage key and keeps that derived key.
        [[nodiscard]] Result<void> crypt_stage(const uint8_t parent_key[16],
                                               const uint8_t cpu_key[16]);
    };

} // namespace gxbuild3::nand
