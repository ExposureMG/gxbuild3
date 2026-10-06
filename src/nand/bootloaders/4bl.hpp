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

        // Throwing shims over the Result API (std::runtime_error carrying Error::describe()).
        // TODO(test-phase): test-only; src must not call them (ErrorConventionGuard.cmake).
        static BootloaderCd parse_or_throw(const std::vector<uint8_t>& bytes) {
            return detail::value_or_throw(parse(bytes));
        }
        void decrypt_or_throw(const uint8_t parent_key[16], const uint8_t cpu_key[16] = nullptr) {
            detail::value_or_throw(decrypt(parent_key, cpu_key));
        }
        void encrypt_or_throw(const uint8_t parent_key[16], const uint8_t cpu_key[16] = nullptr) {
            detail::value_or_throw(encrypt(parent_key, cpu_key));
        }

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;

      private:
        // Returns the payload length the declared size calls for, after validating it.
        [[nodiscard]] Result<size_t> required_data_size() const;
        // RC4s header tail and payload under the stage key and keeps that derived key.
        [[nodiscard]] Result<void> crypt_stage(const uint8_t parent_key[16],
                                               const uint8_t cpu_key[16]);
    };

} // namespace gxbuild3::nand
