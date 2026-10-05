#pragma once

#include "utils/BigUint.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::utils {

    // The XeCrypt RSA-2048 private key as XeCrypt stores it: a 0x10-byte header (digit count
    // and public exponent, big-endian), the modulus in 0x100 bytes, then p, q, d mod (p-1),
    // d mod (q-1) and q^-1 mod p in 0x80 bytes each, every number in XeCrypt's digit layout.
    inline constexpr size_t kXeRsa2048PrivateKeySize = 0x390;
    inline constexpr size_t kXeRsa2048PublicKeySize = 0x110;
    inline constexpr size_t kXeRsa2048SignatureSize = 0x100;

    // The SB private key that signs a development SD (Xbox-360-Crypto keystore.py,
    // CKSM_SB_PRV). gxbuild3 never ships it; a user supplies SB_priv.bin.
    inline constexpr uint32_t kSbPrivateKeyCrc32 = 0x490C9D35;
    // The salt an SD (4BL) signature is made with (Xbox-360-Crypto XECRYPT_SD_SALT).
    inline constexpr std::string_view kSdSignatureSalt = "XBOX_ROM_4";

    // The CRC-32 zlib computes (reflected, polynomial 0xEDB88320).
    uint32_t crc32(std::span<const uint8_t> bytes);

    class XeRsaPrivateKey {
      public:
        // The key, when the bytes hold a well-formed RSA-2048 private key whose parts agree.
        static std::optional<XeRsaPrivateKey> parse(std::span<const uint8_t> bytes);

        // The public part, as XeCrypt stores an RSA-2048 public key.
        const std::array<uint8_t, kXeRsa2048PublicKeySize>& public_key() const noexcept {
            return public_key_;
        }

        // XeCryptBnQwBeSigCreate followed by the private-key operation, as Xbox-360-Crypto's
        // XeCryptRsaKey.sig_create makes a signature: a deterministic function of the hash
        // and salt (at most ten bytes).
        std::optional<std::array<uint8_t, kXeRsa2048SignatureSize>>
        sign(std::span<const uint8_t, 20> hash, std::span<const uint8_t> salt) const;

      private:
        std::array<uint8_t, kXeRsa2048PublicKeySize> public_key_{};
        BigUint n_;
        BigUint p_;
        BigUint q_;
        BigUint dp_;
        BigUint dq_;
        BigUint u_;
        BigUint r_;
    };

    // XeCryptBnQwBeSigVerify against an RSA-2048 public key in XeCrypt's layout.
    bool xe_rsa_verify(std::span<const uint8_t> signature, std::span<const uint8_t, 20> hash,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t, kXeRsa2048PublicKeySize> public_key);

    // An SD (4BL) signature covers XeCryptRotSumSha over the stage's first 0x10 bytes and
    // everything from 0x120, so neither the nonce at 0x10 nor the signature at 0x20..0x11F
    // is part of it (Xbox-360-Crypto build_lib.py sign_sd_4bl / verify_sd_4bl).
    bool verify_sd_signature(std::span<const uint8_t> sd,
                             std::span<const uint8_t, kXeRsa2048PublicKeySize> public_key);
    // Signs the SD in place, as sd_signer.py does: the stage is padded with zeros to 16 bytes,
    // its header states that length, and the signature goes to 0x20. False when the stage is
    // too short to hold a signature.
    bool sign_sd(std::vector<uint8_t>& sd, const XeRsaPrivateKey& key);

} // namespace gxbuild3::utils
