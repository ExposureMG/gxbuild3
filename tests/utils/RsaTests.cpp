#include "core/Wire.hpp"
#include "excrypt.h"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/XeRsaTestKey.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild::utils {
    namespace {

        using test::Bytes;

        EXCRYPT_RSAPRV_2048 load_test_key() {
            EXCRYPT_RSAPRV_2048 key{};
            const auto& raw = test::xe_rsa::shared_private_key();
            std::memcpy(&key, raw.data(), sizeof(key));
            return key;
        }

        std::array<uint8_t, 20> sd_digest(std::span<const uint8_t> sd) {
            constexpr size_t kSigOffset = 0x20;
            constexpr size_t kSigEnd = kSigOffset + sizeof(EXCRYPT_SIG);
            Bytes covered(sd.begin(), sd.begin() + 0x10);
            covered.insert(covered.end(), sd.begin() + kSigEnd, sd.end());
            std::array<uint8_t, 20> hash{};
            ExCryptRotSumSha(covered.data(), static_cast<uint32_t>(covered.size()), covered.data(),
                             0, hash.data(), static_cast<uint32_t>(hash.size()));
            return hash;
        }

        bool verify_sd(std::span<const uint8_t> sd, const EXCRYPT_RSA* pubkey) {
            constexpr size_t kSigOffset = 0x20;
            if (sd.size() < kSigOffset + sizeof(EXCRYPT_SIG)) {
                return false;
            }
            const auto hash = sd_digest(sd);
            EXCRYPT_SIG sig{};
            std::memcpy(&sig, sd.data() + kSigOffset, sizeof(sig));
            static constexpr std::array<uint8_t, 10> kSalt{'X', 'B', 'O', 'X', '_',
                                                           'R', 'O', 'M', '_', '4'};
            return ExCryptBnQwBeSigVerify(&sig, hash.data(), kSalt.data(), pubkey) != 0;
        }

        bool sign_sd(Bytes& sd, const EXCRYPT_RSAPRV_2048& key) {
            constexpr size_t kSigOffset = 0x20;
            if (sd.size() < kSigOffset + sizeof(EXCRYPT_SIG)) {
                return false;
            }
            sd.resize((sd.size() + 0x0F) & ~size_t{0x0F}, 0);
            if (!wire::write<wire::be32>(std::span<uint8_t>(sd), 0x0C,
                                         wire::be32(static_cast<uint32_t>(sd.size())), "SD size")) {
                return false;
            }
            const auto hash = sd_digest(sd);
            EXCRYPT_SIG sig{};
            static constexpr std::array<uint8_t, 10> kSalt{'X', 'B', 'O', 'X', '_',
                                                           'R', 'O', 'M', '_', '4'};
            if (ExCryptBnQwBeSigCreate(&sig, hash.data(), kSalt.data(), &key.rsa) == 0) {
                return false;
            }
            std::memcpy(sd.data() + kSigOffset, &sig, sizeof(sig));
            return true;
        }

        TEST(Crc32, MatchesZlibOnTheCheckString) {
            const std::string_view check = "123456789";
            EXPECT_EQ(
                crc32(std::span(reinterpret_cast<const uint8_t*>(check.data()), check.size())),
                0xCBF43926U)
                << "CRC-32 of the check string is zlib's";
        }

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
            const auto key = load_test_key();
            ASSERT_NE(ExCryptBnQwBeRsaPrvValidate(&key.rsa), 0)
                << "the test RSA-2048 key validates";
            auto sd = synthetic_sd();
            EXPECT_FALSE(verify_sd(sd, &key.rsa)) << "an unsigned SD fails its check";
            ASSERT_TRUE(sign_sd(sd, key)) << "the SD is signed";
            const uint32_t stated = test::be32(sd, 0x0C);
            auto renonced = sd;
            std::ranges::fill(std::span(renonced).subspan(0x10, 0x10), uint8_t{0xC3});
            auto tampered = sd;
            tampered[0x200] ^= 1;
            auto signed_again = synthetic_sd();
            ASSERT_TRUE(sign_sd(signed_again, key)) << "the SD is signed again";
            EXPECT_EQ(sd.size(), 0x300U)
                << "signing pads the stage to 16 bytes and states that length";
            EXPECT_EQ(stated, 0x300U)
                << "signing pads the stage to 16 bytes and states that length";
            EXPECT_TRUE(verify_sd(sd, &key.rsa))
                << "ExCryptBnQwBeSigVerify accepts the signature";
            EXPECT_TRUE(verify_sd(renonced, &key.rsa))
                << "the nonce at 0x10 is not covered";
            EXPECT_FALSE(verify_sd(tampered, &key.rsa))
                << "a changed body byte fails the signature check";
            EXPECT_BYTES_EQ(sd, signed_again) << "the signature is deterministic";
        }

        TEST(XeRsaSd, SignatureAgreesWithXeCryptFormat) {
            const auto key = load_test_key();
            ASSERT_NE(ExCryptBnQwBeRsaPrvValidate(&key.rsa), 0);
            std::array<uint8_t, 20> hash{};
            hash.fill(0x42);
            static constexpr std::array<uint8_t, 10> kSalt{'X', 'B', 'O', 'X', '_',
                                                           'R', 'O', 'M', '_', '4'};
            EXCRYPT_SIG sig{};
            ASSERT_NE(ExCryptBnQwBeSigCreate(&sig, hash.data(), kSalt.data(), &key.rsa), 0)
                << "ExCryptBnQwBeSigCreate signs the hash";
            EXCRYPT_SIG check_good = sig;
            EXPECT_NE(ExCryptBnQwBeSigVerify(&check_good, hash.data(), kSalt.data(), &key.rsa), 0)
                << "ExCryptBnQwBeSigVerify accepts the signature";
            auto other_hash = hash;
            other_hash[0] ^= 1;
            EXCRYPT_SIG check_other = sig;
            EXPECT_EQ(
                ExCryptBnQwBeSigVerify(&check_other, other_hash.data(), kSalt.data(), &key.rsa), 0)
                << "another hash is refused";
        }

        TEST(XeRsaSd, InconsistentKeysAreRefused) {
            const auto key = load_test_key();
            auto wrong_prime = key;
            wrong_prime.prime1[0] ^= 2;
            auto wrong_digits = key;
            wrong_digits.rsa.num_digits = 0x10000000U;
            EXPECT_NE(ExCryptBnQwBeRsaPrvValidate(&key.rsa), 0) << "the test key validates";
            EXPECT_EQ(ExCryptBnQwBeRsaPrvValidate(&wrong_prime.rsa), 0)
                << "a key whose primes do not make its modulus is refused";
            EXPECT_EQ(ExCryptBnQwBeRsaPrvValidate(&wrong_digits.rsa), 0)
                << "a key that is not RSA-2048 is refused";
        }

    } // namespace
} // namespace gxbuild::utils
