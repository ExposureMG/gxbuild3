#pragma once

#include "Error.hpp"
#include "utils/BigUint.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::utils {

    // 0x10 header, 0x100 modulus, and five 0x80 crt prime fields in xecrypt's 64-bit digit layout
    inline constexpr size_t kXeRsa2048PrivateKeySize = 0x390;
    inline constexpr size_t kXeRsa2048PublicKeySize = 0x110;
    inline constexpr size_t kXeRsa2048SignatureSize = 0x100;

    inline constexpr uint32_t kSbPrivateKeyCrc32 = 0x490C9D35;
    inline constexpr std::string_view kSdSignatureSalt = "XBOX_ROM_4";

    [[nodiscard]] uint32_t crc32(std::span<const uint8_t> bytes);

    class XeRsaPrivateKey {
      public:
        [[nodiscard]] static Result<XeRsaPrivateKey> parse(std::span<const uint8_t> bytes);

        const std::array<uint8_t, kXeRsa2048PublicKeySize>& public_key() const noexcept {
            return public_key_;
        }

        [[nodiscard]] Result<std::array<uint8_t, kXeRsa2048SignatureSize>>
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

    [[nodiscard]] Result<void>
    xe_rsa_verify(std::span<const uint8_t> signature, std::span<const uint8_t, 20> hash,
                  std::span<const uint8_t> salt,
                  std::span<const uint8_t, kXeRsa2048PublicKeySize> public_key);

    [[nodiscard]] Result<void>
    verify_sd_signature(std::span<const uint8_t> sd,
                        std::span<const uint8_t, kXeRsa2048PublicKeySize> public_key);
    [[nodiscard]] Result<void> sign_sd(std::vector<uint8_t>& sd, const XeRsaPrivateKey& key);

} // namespace gxbuild3::utils
