// src/utils/BigUint.hpp and src/utils/XeRsa.hpp: BigUint division, pow_mod and the XeCrypt digit
// layout, zlib's CRC-32, and XeCrypt RSA-2048 signing: an SD (4BL) signature made with a private
// key, checked by XeCrypt's own verification, and the keys whose parts do not agree.
//
// The private key is a throwaway generated from a fixed seed (support/XeRsaTestKey.hpp), about
// half a second per process: the XeRsaSd cases run as one bundled ctest entry, so it is made once.

#include "Error.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/XeRsaTestKey.hpp"
#include "utils/BigUint.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <random>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::utils {
    namespace {

        using test::Bytes;

        BigUint random_value(std::mt19937_64& random, size_t bytes) {
            Bytes value(bytes);
            for (auto& byte : value) {
                byte = static_cast<uint8_t>(random());
            }
            return BigUint::from_be_bytes(value);
        }

        // ---- BigUint
        // -----------------------------------------------------------------------------

        TEST(BigUint, DivisionReconstructsItsOperands) {
            std::mt19937_64 random(1);
            for (int round = 0; round < 400; ++round) {
                SCOPED_TRACE(round);
                const auto dividend = random_value(random, 1 + random() % 96);
                auto divisor = random_value(random, 1 + random() % 48);
                if (divisor.is_zero()) {
                    divisor = BigUint{7};
                }
                const auto [quotient, remainder] = BigUint::divmod(dividend, divisor);
                ASSERT_TRUE(remainder < divisor)
                    << "dividend = quotient * divisor + remainder with remainder < divisor";
                ASSERT_TRUE(quotient * divisor + remainder == dividend)
                    << "dividend = quotient * divisor + remainder with remainder < divisor";
            }
        }

        TEST(BigUint, PowModAndXeCryptDigitLayout) {
            const auto power = BigUint::pow_mod(BigUint{4}, BigUint{13}, BigUint{497});
            // 2^64 as XeCrypt digits: the low digit zero, the next one 1, each big-endian.
            Bytes digits(16, 0);
            digits[15] = 1;
            const auto value = BigUint::from_xe_digits(digits);
            const auto expected = BigUint{1ULL << 32} * BigUint{1ULL << 32};
            EXPECT_TRUE(power == BigUint{445}) << "4^13 mod 497 is 445";
            EXPECT_TRUE(value == expected) << "XeCrypt digits read least significant first";
            EXPECT_EQ(expected.to_xe_digits(16), std::optional<Bytes>{digits})
                << "XeCrypt digits write back";
            EXPECT_FALSE(expected.to_xe_digits(8).has_value())
                << "a value too long for its digits is refused";
        }

        // ---- CRC-32
        // ------------------------------------------------------------------------------

        TEST(Crc32, MatchesZlibOnTheCheckString) {
            const std::string_view check = "123456789";
            EXPECT_EQ(
                crc32(std::span(reinterpret_cast<const uint8_t*>(check.data()), check.size())),
                0xCBF43926U)
                << "CRC-32 of the check string is zlib's";
        }

        // ---- XeCrypt RSA-2048 signatures
        // ---------------------------------------------------------

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

        TEST(XeRsaSd, SignatureRoundTripsAndCoversTheBody) {
            const auto key = XeRsaPrivateKey::parse(test::xe_rsa::shared_private_key());
            ASSERT_OK(key) << "a generated RSA-2048 key parses";
            auto sd = synthetic_sd();
            EXPECT_FALSE(verify_sd_signature(sd, key->public_key()).has_value())
                << "an unsigned SD fails its check";
            ASSERT_OK(sign_sd(sd, *key)) << "the SD is signed";
            const uint32_t stated = test::be32(sd, 0x0C);
            auto renonced = sd;
            std::ranges::fill(std::span(renonced).subspan(0x10, 0x10), uint8_t{0xC3});
            auto tampered = sd;
            tampered[0x200] ^= 1;
            auto signed_again = synthetic_sd();
            const auto resigned = sign_sd(signed_again, *key);
            const auto tampered_check = verify_sd_signature(tampered, key->public_key());
            const auto short_check = verify_sd_signature(Bytes(0x100, 0x00), key->public_key());
            auto short_sd = Bytes(0x100, 0x00);
            const auto short_sign = sign_sd(short_sd, *key);
            EXPECT_OK(resigned) << "the SD is signed again";
            EXPECT_EQ(sd.size(), 0x300U)
                << "signing pads the stage to 16 bytes and states that length";
            EXPECT_EQ(stated, 0x300U)
                << "signing pads the stage to 16 bytes and states that length";
            EXPECT_OK(verify_sd_signature(sd, key->public_key()))
                << "XeCrypt's own verification accepts the signature";
            EXPECT_OK(verify_sd_signature(renonced, key->public_key()))
                << "the nonce at 0x10 is not covered";
            EXPECT_ERROR(tampered_check, ErrorCode::SignatureMismatch)
                << "a changed body byte fails the check as a signature mismatch";
            EXPECT_ERROR(short_check, ErrorCode::Truncated)
                << "an SD too short for a signature is refused, not called a mismatch";
            EXPECT_ERROR(short_sign, ErrorCode::Truncated)
                << "an SD too short for a signature is not signed";
            EXPECT_BYTES_EQ(sd, signed_again) << "the signature is a deterministic function";
        }

        TEST(XeRsaSd, SignatureAgreesWithXeCryptFormat) {
            const auto key = XeRsaPrivateKey::parse(test::xe_rsa::shared_private_key());
            std::array<uint8_t, 20> hash{};
            hash.fill(0x42);
            const std::string_view salt = "XBOX_ROM_4";
            const auto salt_bytes =
                std::span(reinterpret_cast<const uint8_t*>(salt.data()), salt.size());
            ASSERT_OK(key) << "a generated RSA-2048 key parses";
            const auto signature = key->sign(hash, salt_bytes);
            ASSERT_OK(signature) << "a hash is signed";
            auto other_hash = hash;
            other_hash[0] ^= 1;
            const auto other_check =
                xe_rsa_verify(*signature, other_hash, salt_bytes, key->public_key());
            const auto short_salt_check =
                xe_rsa_verify(*signature, hash, salt_bytes.first(4), key->public_key());
            EXPECT_OK(xe_rsa_verify(*signature, hash, salt_bytes, key->public_key()))
                << "ExCryptBnQwBeSigVerify accepts the signature";
            EXPECT_ERROR(other_check, ErrorCode::SignatureMismatch)
                << "another hash is refused as a signature mismatch";
            EXPECT_ERROR(short_salt_check, ErrorCode::InvalidArgument)
                << "a salt that is not ten bytes cannot be checked";
            EXPECT_FALSE(key->sign(hash, salt_bytes.first(4)).has_value())
                << "a salt that is not ten bytes is refused";
        }

        TEST(XeRsaSd, InconsistentKeysAreRefused) {
            auto key = test::xe_rsa::shared_private_key();
            auto wrong_prime = key;
            wrong_prime[0x110 + 0x7F] ^= 0x02;
            const auto wrong_size = std::span(key).first(key.size() - 1);
            auto wrong_digits = key;
            wrong_digits[3] = 0x10;
            EXPECT_OK(XeRsaPrivateKey::parse(key)) << "the generated key parses";
            EXPECT_FALSE(XeRsaPrivateKey::parse(wrong_prime).has_value())
                << "a key whose primes do not make its modulus is refused";
            EXPECT_FALSE(XeRsaPrivateKey::parse(wrong_size).has_value())
                << "a key of another size is refused";
            EXPECT_FALSE(XeRsaPrivateKey::parse(wrong_digits).has_value())
                << "a key that is not RSA-2048 is refused";
        }

    } // namespace
} // namespace gxbuild3::utils
