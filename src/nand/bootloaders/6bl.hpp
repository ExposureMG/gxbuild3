#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCf {
      public:
        cf_header header;
        std::optional<cf_perbox> perbox;
        std::vector<uint8_t> data;
        bool decrypted = false;

        // Fails when the bytes or the declared size cannot hold cf_header.
        [[nodiscard]] static Result<BootloaderCf> parse(std::span<const uint8_t> bytes);

        // Each is a no-op when the stage is already in the requested state, and fails before
        // touching the payload.
        [[nodiscard]] Result<void> decrypt(const uint8_t onebl_key[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t onebl_key[16]);
        // Binds the plaintext CF to the console: writes HMAC(cpu_key, first 0x220 bytes, with
        // the stage key in place of the fixpoint) into the per-box digest. Fails, touching
        // nothing, on a null key or a payload too short to hold the per-box block.
        [[nodiscard]] Result<void> calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]);

        bool is_decrypted() const;
        // The CG/7BL RC4 key material: the 7BL nonce in the decrypted CF payload at
        // kCfCgNonceOffset (0x330), never the header fixpoint at +0x20. Empty while the CF is
        // still encrypted or too short to carry the nonce.
        std::optional<std::array<uint8_t, 16>> cg_key() const;
        // Reads the per-box block out of the plaintext payload into `perbox`.
        [[nodiscard]] Result<void> parse_perbox();
        // Writes `perbox` back into the plaintext payload.
        [[nodiscard]] Result<void> serialize_perbox();
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
