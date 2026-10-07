// src/nand/objects/Keyvault.hpp: the all-zero CPU key is a usable key; a loose kv.bin is opened
// when sealed under the CPU key and otherwise taken as it stands, its form saying how xeBuild
// 1.21 sees it; and the keyvault HMAC covers the big-endian keyvault version, checked against
// independent Python vectors.

#include "Error.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <ostream>
#include <vector>

namespace gxbuild3::nand {
    // Found by ADL: a failed comparison names the enumerator instead of printing raw bytes.
    // Internal linkage: these printers belong to this file only.
    [[maybe_unused]] static void PrintTo(CpuKeyStatus status, std::ostream* os) {
        switch (status) {
            case CpuKeyStatus::Valid:
                *os << "Valid";
                return;
            case CpuKeyStatus::Corrected:
                *os << "Corrected";
                return;
            case CpuKeyStatus::Invalid:
                *os << "Invalid";
                return;
        }
        *os << "CpuKeyStatus(" << static_cast<int>(status) << ")";
    }

    [[maybe_unused]] static void PrintTo(LooseKeyvault::Form form, std::ostream* os) {
        switch (form) {
            case LooseKeyvault::Form::Sealed:
                *os << "Sealed";
                return;
            case LooseKeyvault::Form::Clear:
                *os << "Clear";
                return;
            case LooseKeyvault::Form::StaleNonce:
                *os << "StaleNonce";
                return;
            case LooseKeyvault::Form::Unopened:
                *os << "Unopened";
                return;
        }
        *os << "Form(" << static_cast<int>(form) << ")";
    }
} // namespace gxbuild3::nand

namespace gxbuild3::objects {
    namespace {

        using nand::CpuKeyStatus;
        using nand::keyvault_decrypt;
        using nand::keyvault_encrypt;
        using nand::open_loose_keyvault;
        using test::Bytes;
        using test::kCliFixtureCpuKey;
        using Form = nand::LooseKeyvault::Form;

        constexpr std::array<uint8_t, 16> kZeroCpuKey{};

        // The all-zero CPU key is accepted as a key: an image bound to no console is built under
        // it.
        TEST(KeyvaultCpuKey, AllZeroKeyIsAccepted) {
            const auto parsed = nand::validate_cpu_key_hex("00000000000000000000000000000000");
            EXPECT_EQ(parsed.status, CpuKeyStatus::Valid) << "the all-zero CPU key validates";
            EXPECT_BYTES_EQ(kZeroCpuKey, parsed.key) << "the all-zero CPU key validates";

            EXPECT_TRUE(nand::cpukey_valid(kZeroCpuKey))
                << "the all-zero CPU key is usable and recognised";
            EXPECT_TRUE(nand::is_zero_cpu_key(kZeroCpuKey))
                << "the all-zero CPU key is usable and recognised";
            EXPECT_FALSE(nand::is_zero_cpu_key(kCliFixtureCpuKey))
                << "the all-zero CPU key is usable and recognised";

            EXPECT_EQ(nand::validate_cpu_key_hex("00000000000000000000000000000001").status,
                      CpuKeyStatus::Invalid)
                << "a key that is neither zero nor ECC-valid is still refused";
        }

        // A kv.bin sealed under the CPU key is opened; any other copy of 0x4000 bytes (or 0x3FF0
        // without its nonce) is taken as it stands, and its form says how xeBuild 1.21 sees it;
        // any other length is refused. Each case opens one form of the same keyvault.
        class LooseKeyvault : public ::testing::Test {
          protected:
            void SetUp() override {
                plain_.resize(nand::Keyvault::kSize);
                for (size_t index = 0; index < plain_.size(); ++index) {
                    plain_[index] = static_cast<uint8_t>(index * 7);
                }
                // A keyvault's reserved bytes, 0x38-0x8F, are zero.
                std::fill(plain_.begin() + 0x38, plain_.begin() + 0x90, 0);
                ASSERT_OK_AND_ASSIGN(sealed_, keyvault_encrypt(kCliFixtureCpuKey, plain_));
                ASSERT_OK_AND_ASSIGN(canonical_, keyvault_decrypt(kCliFixtureCpuKey, sealed_));
            }

            // The keyvault in the clear under a nonce the CPU key does not derive.
            Bytes plain_;
            // plain_ sealed under the CPU key.
            Bytes sealed_;
            // sealed_ opened again: the body in the clear under the nonce the CPU key derives.
            Bytes canonical_;
        };

        TEST_F(LooseKeyvault, ASealedKvBinIsOpened) {
            const auto opened = open_loose_keyvault(kCliFixtureCpuKey, sealed_);
            ASSERT_OK(opened) << "a sealed kv.bin is opened";
            EXPECT_EQ(opened->form, Form::Sealed) << "a sealed kv.bin is opened";
            EXPECT_BYTES_EQ(canonical_, opened->plain) << "a sealed kv.bin is opened";
        }

        TEST_F(LooseKeyvault, AKvBinInTheClearUnderAStaleNonceIsTakenAsItStands) {
            const auto stale = open_loose_keyvault(kCliFixtureCpuKey, plain_);
            ASSERT_OK(stale) << "a kv.bin in the clear under a stale nonce is taken as it stands";
            EXPECT_EQ(stale->form, Form::StaleNonce)
                << "a kv.bin in the clear under a stale nonce is taken as it stands";
            EXPECT_BYTES_EQ(plain_, stale->plain)
                << "a kv.bin in the clear under a stale nonce is taken as it stands";
        }

        TEST_F(LooseKeyvault, AKvBinInTheClearUnderItsOwnNonceIsTakenAsItStands) {
            const auto own_nonce = open_loose_keyvault(kCliFixtureCpuKey, canonical_);
            ASSERT_OK(own_nonce)
                << "a kv.bin in the clear under its own nonce is taken as it stands";
            EXPECT_EQ(own_nonce->form, Form::Clear)
                << "a kv.bin in the clear under its own nonce is taken as it stands";
            EXPECT_BYTES_EQ(canonical_, own_nonce->plain)
                << "a kv.bin in the clear under its own nonce is taken as it stands";
        }

        TEST_F(LooseKeyvault, A0x3FF0KvBinGetsSixteenZeroBytesInFront) {
            const Bytes body(plain_.begin() + 0x10, plain_.end());
            Bytes zero_nonce = plain_;
            std::fill(zero_nonce.begin(), zero_nonce.begin() + 0x10, 0);

            const auto bare = open_loose_keyvault(kCliFixtureCpuKey, body);
            ASSERT_OK(bare) << "a 0x3FF0 kv.bin gets sixteen zero bytes in front";
            EXPECT_EQ(bare->form, Form::Clear)
                << "a 0x3FF0 kv.bin gets sixteen zero bytes in front";
            EXPECT_BYTES_EQ(zero_nonce, bare->plain)
                << "a 0x3FF0 kv.bin gets sixteen zero bytes in front";
        }

        TEST_F(LooseKeyvault, AKvBinSealedUnderTheAllZeroCpuKeyOpensUnderIt) {
            ASSERT_OK_AND_ASSIGN(const Bytes sealed_under_zero,
                                 keyvault_encrypt(kZeroCpuKey, plain_));
            const auto under_zero = open_loose_keyvault(kZeroCpuKey, sealed_under_zero);
            ASSERT_OK(under_zero) << "a kv.bin sealed under the all-zero CPU key opens under it";
            EXPECT_EQ(under_zero->form, Form::Sealed)
                << "a kv.bin sealed under the all-zero CPU key opens under it";
        }

        TEST_F(LooseKeyvault, AKvBinSealedUnderAnotherKeyIsTakenAsItStandsUnopened) {
            ASSERT_OK_AND_ASSIGN(const Bytes other, keyvault_encrypt(kZeroCpuKey, plain_));
            const auto foreign = open_loose_keyvault(kCliFixtureCpuKey, other);
            ASSERT_OK(foreign)
                << "a kv.bin sealed under another key is taken as it stands, unopened";
            EXPECT_EQ(foreign->form, Form::Unopened)
                << "a kv.bin sealed under another key is taken as it stands, unopened";
            EXPECT_BYTES_EQ(other, foreign->plain)
                << "a kv.bin sealed under another key is taken as it stands, unopened";
        }

        TEST_F(LooseKeyvault, ASealedBodyBehindAZeroNonceIsTakenAsItStandsUnopened) {
            Bytes unnonced = sealed_;
            std::fill(unnonced.begin(), unnonced.begin() + 0x10, 0);
            const auto sealed_bare = open_loose_keyvault(kCliFixtureCpuKey, unnonced);
            ASSERT_OK(sealed_bare) << "so is a sealed body behind a zero nonce";
            EXPECT_EQ(sealed_bare->form, Form::Unopened)
                << "so is a sealed body behind a zero nonce";
            EXPECT_BYTES_EQ(unnonced, sealed_bare->plain)
                << "so is a sealed body behind a zero nonce";
        }

        TEST_F(LooseKeyvault, AKvBinOfAnotherLengthIsRefused) {
            EXPECT_FALSE(open_loose_keyvault(kCliFixtureCpuKey, Bytes(0x100)).has_value())
                << "a kv.bin of another length is refused";
        }

        TEST_F(LooseKeyvault, AnUnusableCpuKeyIsAnErrorNotAnUnopenedKvBin) {
            EXPECT_ERROR(open_loose_keyvault(Bytes(8), sealed_), ErrorCode::InvalidArgument)
                << "an unusable CPU key is an error, not an unopened kv.bin";
        }

        // Independent Python hashlib/hmac + RC4 vectors for payload bytes 00..0f under
        // kCliFixtureCpuKey. Nonce = HMAC-SHA1(cpu_key, payload || version_be)[:16].
        // RC4 key = HMAC-SHA1(cpu_key, nonce)[:16]. No private console data.
        struct VersionVector {
            const char* name;
            uint16_t version;
            std::array<uint8_t, 32> encrypted;
        };
        GX_PRINT_ROW_AS_NAME(VersionVector)

        constexpr VersionVector kVersionVectors[]{
            {"Version0x0712",
             0x0712,
             {
                 0x78, 0x79, 0xd3, 0xd4, 0xd4, 0xe3, 0xa9, 0x1f, 0xa8, 0x5d, 0x1c,
                 0x88, 0x62, 0x33, 0x61, 0x1b, 0xf2, 0x58, 0xb6, 0x8d, 0xf1, 0xff,
                 0xef, 0x2e, 0x4e, 0xb8, 0xde, 0x6f, 0xc8, 0xbc, 0x44, 0xd2,
             }},
            {"Version0x1234",
             0x1234,
             {
                 0xff, 0xda, 0xb6, 0x58, 0xd2, 0xb5, 0xf5, 0x1f, 0xbf, 0x3b, 0xc1,
                 0xaf, 0xa2, 0x5e, 0xdb, 0xe6, 0x17, 0x90, 0x39, 0x2a, 0x46, 0x2c,
                 0x67, 0x95, 0xb4, 0xf9, 0x7c, 0x3a, 0xe5, 0x46, 0x1d, 0xf2,
             }},
        };

        class KeyvaultVersionVector : public ::testing::TestWithParam<VersionVector> {
          protected:
            // The vector's nonce (its first 16 bytes) followed by the payload bytes 00..0f.
            static Bytes plaintext(const VersionVector& vector) {
                Bytes bytes(vector.encrypted.begin(), vector.encrypted.begin() + 16);
                for (uint8_t byte = 0; byte < 16; ++byte) {
                    bytes.push_back(byte);
                }
                return bytes;
            }
        };

        TEST_P(KeyvaultVersionVector, EncryptIncludesBigEndianVersion) {
            const auto& vector = GetParam();
            const auto encrypted =
                keyvault_encrypt(kCliFixtureCpuKey, plaintext(vector), vector.version);
            ASSERT_OK(encrypted) << "encryption must include the big-endian version";
            EXPECT_BYTES_EQ(vector.encrypted, *encrypted)
                << "encryption must include the big-endian version";
        }

        TEST_P(KeyvaultVersionVector, DecryptMatchesIndependentPlaintext) {
            const auto& vector = GetParam();
            const auto decrypted =
                keyvault_decrypt(kCliFixtureCpuKey, vector.encrypted, vector.version);
            ASSERT_OK(decrypted) << "decryption differs from independent plaintext";
            EXPECT_BYTES_EQ(plaintext(vector), *decrypted)
                << "decryption differs from independent plaintext";
        }

        TEST_P(KeyvaultVersionVector, WrongVersionFailsAuthentication) {
            const auto& vector = GetParam();
            EXPECT_ERROR_MSG(keyvault_decrypt(kCliFixtureCpuKey, vector.encrypted,
                                              static_cast<uint16_t>(vector.version ^ 1)),
                             ErrorCode::AuthFailed, "Keyvault authentication failed")
                << "wrong version must fail authentication";
        }

        INSTANTIATE_TEST_SUITE_P(Vector, KeyvaultVersionVector,
                                 ::testing::ValuesIn(kVersionVectors), test::RowName{});

    } // namespace
} // namespace gxbuild3::objects
