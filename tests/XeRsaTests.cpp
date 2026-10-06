#include "XeRsaTestKey.hpp"
#include "excrypt.h"
#include "utils/BigUint.hpp"
#include "utils/XeRsa.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <random>
#include <span>
#include <string_view>
#include <vector>

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::utils::BigUint;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    BigUint random_value(std::mt19937_64& random, size_t bytes) {
        Bytes value(bytes);
        for (auto& byte : value) {
            byte = static_cast<uint8_t>(random());
        }
        return BigUint::from_be_bytes(value);
    }

    bool test_division_reconstructs_its_operands() {
        std::mt19937_64 random(1);
        for (int round = 0; round < 400; ++round) {
            const auto dividend = random_value(random, 1 + random() % 96);
            auto divisor = random_value(random, 1 + random() % 48);
            if (divisor.is_zero()) {
                divisor = BigUint{7};
            }
            const auto [quotient, remainder] = BigUint::divmod(dividend, divisor);
            if (!require(remainder < divisor && quotient * divisor + remainder == dividend,
                         "dividend = quotient * divisor + remainder with remainder < divisor")) {
                return false;
            }
        }
        return true;
    }

    bool test_pow_mod_and_digit_layout() {
        const auto power = BigUint::pow_mod(BigUint{4}, BigUint{13}, BigUint{497});
        // 2^64 as XeCrypt digits: the low digit zero, the next one 1, each big-endian.
        Bytes digits(16, 0);
        digits[15] = 1;
        const auto value = BigUint::from_xe_digits(digits);
        const auto expected = BigUint{1ULL << 32} * BigUint{1ULL << 32};
        const auto round_trip = expected.to_xe_digits(16);
        return require(power == BigUint{445}, "4^13 mod 497 is 445") &&
               require(value == expected, "XeCrypt digits read least significant first") &&
               require(round_trip && *round_trip == digits, "XeCrypt digits write back") &&
               require(!expected.to_xe_digits(8), "a value too long for its digits is refused");
    }

    bool test_crc32_matches_zlib() {
        const std::string_view check = "123456789";
        return require(
            gxbuild3::utils::crc32(std::span(reinterpret_cast<const uint8_t*>(check.data()),
                                             check.size())) == 0xCBF43926U,
            "CRC-32 of the check string is zlib's");
    }

    // A plaintext SD-shaped stage: header, nonce, a signature area and a body.
    Bytes synthetic_sd() {
        Bytes sd(0x2F4, 0);
        sd[0] = 'S';
        sd[1] = 'D';
        for (size_t index = 0x120; index < sd.size(); ++index) {
            sd[index] = static_cast<uint8_t>(index * 7);
        }
        std::fill(sd.begin() + 0x10, sd.begin() + 0x20, uint8_t{0x5A});
        return sd;
    }

    bool test_sd_signature_round_trips_and_covers_the_body() {
        const auto key = gxbuild3::utils::XeRsaPrivateKey::parse(xe_rsa_test::shared_private_key());
        if (!require(key.has_value(), "a generated RSA-2048 key parses")) {
            return false;
        }
        auto sd = synthetic_sd();
        if (!require(!gxbuild3::utils::verify_sd_signature(sd, key->public_key()),
                     "an unsigned SD fails its check") ||
            !require(gxbuild3::utils::sign_sd(sd, *key).has_value(), "the SD is signed")) {
            return false;
        }
        const uint32_t stated = (uint32_t{sd[0x0C]} << 24) | (uint32_t{sd[0x0D]} << 16) |
                                (uint32_t{sd[0x0E]} << 8) | sd[0x0F];
        auto renonced = sd;
        std::fill(renonced.begin() + 0x10, renonced.begin() + 0x20, uint8_t{0xC3});
        auto tampered = sd;
        tampered[0x200] ^= 1;
        auto signed_again = synthetic_sd();
        const auto resigned = gxbuild3::utils::sign_sd(signed_again, *key);
        const auto tampered_check =
            gxbuild3::utils::verify_sd_signature(tampered, key->public_key());
        const auto short_check =
            gxbuild3::utils::verify_sd_signature(Bytes(0x100, 0x00), key->public_key());
        auto short_sd = Bytes(0x100, 0x00);
        const auto short_sign = gxbuild3::utils::sign_sd(short_sd, *key);
        return require(resigned.has_value(), "the SD is signed again") &&
               require(sd.size() == 0x300 && stated == 0x300,
                       "signing pads the stage to 16 bytes and states that length") &&
               require(gxbuild3::utils::verify_sd_signature(sd, key->public_key()).has_value(),
                       "XeCrypt's own verification accepts the signature") &&
               require(
                   gxbuild3::utils::verify_sd_signature(renonced, key->public_key()).has_value(),
                   "the nonce at 0x10 is not covered") &&
               require(!tampered_check &&
                           tampered_check.error().code == gxbuild3::ErrorCode::SignatureMismatch,
                       "a changed body byte fails the check as a signature mismatch") &&
               require(!short_check && short_check.error().code == gxbuild3::ErrorCode::Truncated,
                       "an SD too short for a signature is refused, not called a mismatch") &&
               require(!short_sign && short_sign.error().code == gxbuild3::ErrorCode::Truncated,
                       "an SD too short for a signature is not signed") &&
               require(signed_again == sd, "the signature is a deterministic function");
    }

    bool test_signature_agrees_with_xecrypt_format() {
        const auto key = gxbuild3::utils::XeRsaPrivateKey::parse(xe_rsa_test::shared_private_key());
        std::array<uint8_t, 20> hash{};
        hash.fill(0x42);
        const std::string_view salt = "XBOX_ROM_4";
        const auto salt_bytes =
            std::span(reinterpret_cast<const uint8_t*>(salt.data()), salt.size());
        if (!require(key.has_value(), "a generated RSA-2048 key parses")) {
            return false;
        }
        const auto signature = key->sign(hash, salt_bytes);
        if (!require(signature.has_value(), "a hash is signed")) {
            return false;
        }
        auto other_hash = hash;
        other_hash[0] ^= 1;
        const auto other_check =
            gxbuild3::utils::xe_rsa_verify(*signature, other_hash, salt_bytes, key->public_key());
        const auto short_salt_check = gxbuild3::utils::xe_rsa_verify(
            *signature, hash, salt_bytes.first(4), key->public_key());
        return require(
                   gxbuild3::utils::xe_rsa_verify(*signature, hash, salt_bytes, key->public_key())
                       .has_value(),
                   "ExCryptBnQwBeSigVerify accepts the signature") &&
               require(!other_check &&
                           other_check.error().code == gxbuild3::ErrorCode::SignatureMismatch,
                       "another hash is refused as a signature mismatch") &&
               require(!short_salt_check &&
                           short_salt_check.error().code == gxbuild3::ErrorCode::InvalidArgument,
                       "a salt that is not ten bytes cannot be checked") &&
               require(!key->sign(hash, salt_bytes.first(4)),
                       "a salt that is not ten bytes is refused");
    }

    bool test_inconsistent_keys_are_refused() {
        auto key = xe_rsa_test::shared_private_key();
        auto wrong_prime = key;
        wrong_prime[0x110 + 0x7F] ^= 0x02;
        auto wrong_size = key;
        wrong_size.pop_back();
        auto wrong_digits = key;
        wrong_digits[3] = 0x10;
        return require(gxbuild3::utils::XeRsaPrivateKey::parse(key).has_value(),
                       "the generated key parses") &&
               require(!gxbuild3::utils::XeRsaPrivateKey::parse(wrong_prime),
                       "a key whose primes do not make its modulus is refused") &&
               require(!gxbuild3::utils::XeRsaPrivateKey::parse(wrong_size),
                       "a key of another size is refused") &&
               require(!gxbuild3::utils::XeRsaPrivateKey::parse(wrong_digits),
                       "a key that is not RSA-2048 is refused");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_division_reconstructs_its_operands() && passed;
    passed = test_pow_mod_and_digit_layout() && passed;
    passed = test_crc32_matches_zlib() && passed;
    passed = test_sd_signature_round_trips_and_covers_the_body() && passed;
    passed = test_signature_agrees_with_xecrypt_format() && passed;
    passed = test_inconsistent_keys_are_refused() && passed;
    if (!passed) {
        return 1;
    }
    std::cout << "XeRsa tests passed\n";
    return 0;
}
