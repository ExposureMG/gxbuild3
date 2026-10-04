#include "utils/XeRsa.hpp"

#include "excrypt.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace gxbuild3::utils {

    namespace {

        constexpr size_t kDigitCount = 0x20;
        constexpr size_t kModulusSize = kDigitCount * 8;
        constexpr size_t kPrimeSize = kModulusSize / 2;
        // XeCrypt signature salts are ten bytes long.
        constexpr size_t kSaltSize = 10;
        // An SD's signature sits at 0x20 and its hash resumes at 0x120.
        constexpr size_t kSdSignatureOffset = 0x20;
        constexpr size_t kSdHashResume = kSdSignatureOffset + kXeRsa2048SignatureSize;

        uint32_t read_be32(std::span<const uint8_t> bytes, size_t offset) {
            return (uint32_t{bytes[offset]} << 24) | (uint32_t{bytes[offset + 1]} << 16) |
                   (uint32_t{bytes[offset + 2]} << 8) | uint32_t{bytes[offset + 3]};
        }

        std::array<uint8_t, 20> sd_hash(std::span<const uint8_t> sd) {
            std::vector<uint8_t> covered(sd.begin(), sd.begin() + 0x10);
            covered.insert(covered.end(), sd.begin() + kSdHashResume, sd.end());
            std::array<uint8_t, 20> hash{};
            ExCryptRotSumSha(covered.data(), static_cast<uint32_t>(covered.size()), covered.data(),
                             0, hash.data(), static_cast<uint32_t>(hash.size()));
            return hash;
        }

    } // namespace

    uint32_t crc32(std::span<const uint8_t> bytes) {
        uint32_t crc = 0xFFFFFFFFU;
        for (const uint8_t byte : bytes) {
            crc ^= byte;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
            }
        }
        return ~crc;
    }

    std::optional<XeRsaPrivateKey> XeRsaPrivateKey::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() != kXeRsa2048PrivateKeySize || read_be32(bytes, 0) != kDigitCount) {
            return std::nullopt;
        }
        const uint32_t exponent = read_be32(bytes, 4);
        if (exponent < 3 || (exponent & 1) == 0) {
            return std::nullopt;
        }

        XeRsaPrivateKey key;
        std::copy_n(bytes.begin(), key.public_key_.size(), key.public_key_.begin());
        size_t at = 0x10;
        const auto take = [&bytes, &at](size_t size) {
            const auto value = BigUint::from_xe_digits(bytes.subspan(at, size));
            at += size;
            return value;
        };
        key.n_ = take(kModulusSize);
        key.p_ = take(kPrimeSize);
        key.q_ = take(kPrimeSize);
        key.dp_ = take(kPrimeSize);
        key.dq_ = take(kPrimeSize);
        key.u_ = take(kPrimeSize);

        // The parts must make one key: n = pq, each exponent inverts e for its prime, and u
        // inverts q mod p.
        const BigUint one{1};
        const BigUint e{exponent};
        if (key.n_.bit_length() <= kModulusSize * 8 - 8 || key.p_ <= one || key.q_ <= one ||
            key.p_ * key.q_ != key.n_ || (e * key.dp_) % (key.p_ - one) != one ||
            (e * key.dq_) % (key.q_ - one) != one || (key.u_ * key.q_) % key.p_ != one) {
            return std::nullopt;
        }
        // XeCrypt multiplies the formatted signature by 2^(2048 (e - 1)) before the private
        // operation, which its Montgomery verification divides out again.
        key.r_ = BigUint::pow_mod(BigUint{2}, BigUint{uint64_t{exponent - 1} << 11}, key.n_);
        return key;
    }

    std::optional<std::array<uint8_t, kXeRsa2048SignatureSize>>
    XeRsaPrivateKey::sign(std::span<const uint8_t, 20> hash, std::span<const uint8_t> salt) const {
        if (salt.size() != kSaltSize) {
            return std::nullopt;
        }
        EXCRYPT_SIG formatted{};
        ExCryptBnQwBeSigFormat(&formatted, hash.data(), salt.data());
        std::array<uint8_t, kXeRsa2048SignatureSize> formatted_bytes{};
        std::memcpy(formatted_bytes.data(), &formatted, formatted_bytes.size());

        const auto message = BigUint::from_xe_digits(formatted_bytes);
        if (message >= n_) {
            return std::nullopt;
        }
        const auto scaled = (message * r_) % n_;
        // The private operation through the primes, as XeCryptBnQwNeModExpRoot does it.
        const auto m1 = BigUint::pow_mod(scaled, dp_, p_);
        const auto m2 = BigUint::pow_mod(scaled, dq_, q_);
        const auto h = (u_ * ((m1 + p_ - m2 % p_) % p_)) % p_;
        const auto signature = (m2 + h * q_).to_xe_digits(kXeRsa2048SignatureSize);
        if (!signature) {
            return std::nullopt;
        }
        std::array<uint8_t, kXeRsa2048SignatureSize> out{};
        std::copy(signature->begin(), signature->end(), out.begin());
        return out;
    }

    bool xe_rsa_verify(std::span<const uint8_t> signature, std::span<const uint8_t, 20> hash,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t, kXeRsa2048PublicKeySize> public_key) {
        if (signature.size() != kXeRsa2048SignatureSize || salt.size() != kSaltSize) {
            return false;
        }
        EXCRYPT_SIG sig{};
        std::memcpy(&sig, signature.data(), sizeof(sig));
        EXCRYPT_RSAPUB_2048 key{};
        std::memcpy(&key, public_key.data(), sizeof(key));
        return ExCryptBnQwBeSigVerify(&sig, hash.data(), salt.data(),
                                      reinterpret_cast<const EXCRYPT_RSA*>(&key)) != 0;
    }

    bool verify_sd_signature(std::span<const uint8_t> sd,
                             std::span<const uint8_t, kXeRsa2048PublicKeySize> public_key) {
        if (sd.size() < kSdHashResume) {
            return false;
        }
        const auto hash = sd_hash(sd);
        const auto salt = std::span(reinterpret_cast<const uint8_t*>(kSdSignatureSalt.data()),
                                    kSdSignatureSalt.size());
        return xe_rsa_verify(sd.subspan(kSdSignatureOffset, kXeRsa2048SignatureSize), hash, salt,
                             public_key);
    }

    bool sign_sd(std::vector<uint8_t>& sd, const XeRsaPrivateKey& key) {
        if (sd.size() < kSdHashResume) {
            return false;
        }
        sd.resize((sd.size() + 0x0F) & ~size_t{0x0F}, 0);
        const auto size = static_cast<uint32_t>(sd.size());
        for (size_t index = 0; index < 4; ++index) {
            sd[0x0C + index] = static_cast<uint8_t>(size >> (24 - 8 * index));
        }
        const auto hash = sd_hash(sd);
        const auto salt = std::span(reinterpret_cast<const uint8_t*>(kSdSignatureSalt.data()),
                                    kSdSignatureSalt.size());
        const auto signature = key.sign(hash, salt);
        if (!signature) {
            return false;
        }
        std::copy(signature->begin(), signature->end(),
                  sd.begin() + static_cast<std::ptrdiff_t>(kSdSignatureOffset));
        return true;
    }

} // namespace gxbuild3::utils
