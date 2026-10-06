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

        // Throwing shims over the Result API (std::runtime_error carrying Error::describe()).
        // TODO(test-phase): test-only; src must not call them (ErrorConventionGuard.cmake).
        static BootloaderCg parse_or_throw(const std::vector<uint8_t>& bytes) {
            return detail::value_or_throw(parse(bytes));
        }
        void decrypt_or_throw(const uint8_t cg_hmac[16]) {
            detail::value_or_throw(decrypt(cg_hmac));
        }
        void encrypt_or_throw(const uint8_t cg_hmac[16]) {
            detail::value_or_throw(encrypt(cg_hmac));
        }

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;

      private:
        // Validates the declared size and pads the payload to it.
        [[nodiscard]] Result<void> prepare_payload();
        // RC4s header tail and payload under HMAC(cg_hmac, nonce).
        [[nodiscard]] Result<void> crypt_stage(const uint8_t cg_hmac[16]);
    };

} // namespace gxbuild3::nand
