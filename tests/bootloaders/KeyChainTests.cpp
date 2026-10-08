// The CB/CD key chain: a single-CB chain from build 1920 on (paired) derives the CD key from the
// parent-key HMAC and then the CPU key; a split chain uses only the CB_B-derived parent key; and
// FlashImage::encrypt_all refuses a chain whose key is missing before it mutates any stage.
//
// The expected CD bytes are made with GxCrypt's ExCryptHmacSha and ExCryptRc4 directly, never
// through the bootloader code under test.

#include "Error.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

namespace gxbuild3::bootloaders {
    namespace {

        TEST(KeyChain, CdCpuKeyDerivationMatchesSingleCbChain) {
            nand::BootloaderCd cd{};
            cd.header.header.magic = nand::NANDBootloaderMagic::CD;
            cd.header.header.version = 1920;
            cd.header.header.size = sizeof(nand::cd_header) + 0x20;
            for (size_t i = 0; i < sizeof(cd.header.key); ++i) {
                cd.header.key[i] = static_cast<uint8_t>(0x10 + i);
            }
            std::fill_n(reinterpret_cast<uint8_t*>(&cd.header) + 0x20,
                        sizeof(nand::cd_header) - 0x20, 0x5A);
            cd.header.nonce_6bl[0] = 0xA5;
            cd.header.ce_hash[0] = 0xC3;
            cd.data.resize(0x20, 0x6B);
            cd.decrypted = true;

            const std::array<uint8_t, 16> parent_key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                                     0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                                                     0x0C, 0x0D, 0x0E, 0x0F};
            const std::array<uint8_t, 16> cpu_key{0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
                                                  0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};

            const auto plaintext = cd.serialize();
            auto expected = plaintext;
            uint8_t parent_digest[20]{};
            uint8_t rc4_key[20]{};
            ExCryptHmacSha(parent_key.data(), parent_key.size(), plaintext.data() + 0x10, 0x10,
                           nullptr, 0, nullptr, 0, parent_digest, sizeof(parent_digest));
            ExCryptHmacSha(cpu_key.data(), cpu_key.size(), parent_digest, 0x10, nullptr, 0, nullptr,
                           0, rc4_key, sizeof(rc4_key));
            ExCryptRc4(rc4_key, 0x10, expected.data() + 0x20,
                       static_cast<uint32_t>(expected.size() - 0x20));

            ASSERT_OK(cd.encrypt(parent_key.data(), cpu_key.data()));
            ASSERT_BYTES_EQ(expected, cd.serialize())
                << "single-CB CD encryption must apply the CPU-key HMAC after the parent-key HMAC";

            ASSERT_OK(cd.decrypt(parent_key.data(), cpu_key.data()));
            ASSERT_BYTES_EQ(plaintext, cd.serialize())
                << "single-CB CD decryption must reverse the CPU-key-derived encryption";

            auto expected_split_chain = plaintext;
            ExCryptRc4(parent_digest, 0x10, expected_split_chain.data() + 0x20,
                       static_cast<uint32_t>(expected_split_chain.size() - 0x20));
            ASSERT_OK(cd.encrypt(parent_key.data()));
            ASSERT_BYTES_EQ(expected_split_chain, cd.serialize())
                << "split-CB CD encryption must use only the CB_B-derived parent key";

            ASSERT_OK(cd.decrypt(parent_key.data()));
            EXPECT_BYTES_EQ(plaintext, cd.serialize())
                << "split-CB CD decryption must reverse the default parent-key encryption";
        }

        TEST(KeyChain, SingleCbUsesTheCpuKeyForCdOnlyWhenPairedFromBuild1920) {
            nand::BootloaderCb cb{};
            cb.header.header.version = 1920;
            cb.data.resize(0x30, 0);
            cb.data[0x10] = 1;
            EXPECT_TRUE(cb.requires_cpu_key_for_cd())
                << "non-zero-paired single CB build 1920 must use the CPU key for CD";

            cb.header.header.version = 1919;
            EXPECT_FALSE(cb.requires_cpu_key_for_cd())
                << "single CB builds before 1920 must not use the CPU key for CD";

            cb.header.header.version = 1920;
            std::fill(cb.data.begin() + 0x10, cb.data.begin() + 0x30, 0);
            EXPECT_FALSE(cb.requires_cpu_key_for_cd())
                << "zero-paired single CB must not use the CPU key for CD";
        }

        TEST(KeyChain, FlashImageRejectsSplitChainWithoutCbBKey) {
            nand::FlashImage image{};
            image.cb_section.cb_or_A.derived_key = std::array<uint8_t, 16>{0x11};
            image.cb_section.cb_B = nand::BootloaderCb{};

            image.kernel_section.cd.header.header.size = sizeof(nand::cd_header) + 0x20;
            image.kernel_section.cd.header.key[0] = 1;
            image.kernel_section.cd.data.resize(0x20, 0x6B);
            image.kernel_section.cd.decrypted = true;
            const auto cd_before = image.kernel_section.cd.serialize();

            const auto encrypted = image.encrypt_all(std::array<uint8_t, 16>{});
            ASSERT_FALSE(encrypted.has_value())
                << "split-CB chain must reject a missing CB_B-derived key";
            EXPECT_BYTES_EQ(cd_before, image.kernel_section.cd.serialize())
                << "failed split-CB encryption must not fall back to the CB_A-derived key";
        }

        TEST(KeyChain, MissingSingleCbCpuKeyDoesNotMutateEncryptionState) {
            nand::FlashImage image{};
            auto& cb = image.cb_section.cb_or_A;
            cb.header.header.version = 1920;
            cb.header.header.size = sizeof(nand::generic_header) + 0x30;
            cb.data.resize(0x30, 0);
            cb.data[0] = 0xA5;
            cb.data[0x10] = 1;
            cb.perbox = nand::cb_perbox{};
            cb.perbox->pairing_data[0] = 1;
            cb.decrypted = true;

            image.kernel_section.cd.header.header.size = sizeof(nand::cd_header) + 0x20;
            image.kernel_section.cd.header.key[0] = 1;
            image.kernel_section.cd.data.resize(0x20, 0x6B);
            image.kernel_section.cd.decrypted = true;

            const auto cb_before = cb.serialize();
            const auto cd_before = image.kernel_section.cd.serialize();
            const auto encrypted = image.encrypt_all({});
            ASSERT_ERROR(encrypted, ErrorCode::InvalidArgument)
                << "qualifying single-CB encryption must reject a missing CPU key";
            EXPECT_BYTES_EQ(cb_before, cb.serialize())
                << "missing CPU key must be detected before CB encryption mutates state";
            EXPECT_BYTES_EQ(cd_before, image.kernel_section.cd.serialize())
                << "missing CPU key must leave CD encryption state unchanged";
        }

    } // namespace
} // namespace gxbuild3::bootloaders
