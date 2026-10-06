#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderSc {
      public:
        sc_header header;
        std::vector<uint8_t> data;
        // Runtime key handed to SD: HMAC(secret, nonce). header.key retains the on-disk nonce.
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        // Fails when the bytes or the declared size cannot hold sc_header.
        [[nodiscard]] static Result<BootloaderSc> parse(std::span<const uint8_t> bytes);

        // The secret is sixteen zero bytes on every console (kZeroSecret). Each is a no-op when
        // the stage is already in the requested state, and fails before touching the payload.
        [[nodiscard]] Result<void> decrypt(const uint8_t secret[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t secret[16]);

        // Throwing shims over the Result API (std::runtime_error carrying Error::describe()).
        // TODO(test-phase): test-only; src must not call them (ErrorConventionGuard.cmake).
        static BootloaderSc parse_or_throw(const std::vector<uint8_t>& bytes) {
            return detail::value_or_throw(parse(bytes));
        }
        void decrypt_or_throw(const uint8_t secret[16]) { detail::value_or_throw(decrypt(secret)); }
        void encrypt_or_throw(const uint8_t secret[16]) { detail::value_or_throw(encrypt(secret)); }

        static constexpr uint8_t kZeroSecret[16] = {};

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;

      private:
        // Validates the declared size and pads the payload to it.
        [[nodiscard]] Result<void> prepare_payload();
        // RC4s header tail and payload under HMAC(secret, nonce) and keeps that derived key.
        [[nodiscard]] Result<void> crypt_stage(const uint8_t secret[16]);
    };

} // namespace gxbuild3::nand
