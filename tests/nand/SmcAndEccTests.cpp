#include "nand/FlashDriver.hpp"
#include "nand/objects/SMC.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <utility>
#include <vector>

namespace gxbuild::nand_crypto_tests {
    namespace {

        using test::Bytes;

        TEST(SmcDetection, EncryptionIsDetectedByTheZeroTailNotTheMotherboardNibble) {
            Bytes plain(0x3000, 0);
            for (size_t i = 0; i < 0x2F00; ++i) {
                plain[i] = static_cast<uint8_t>(i * 7 + 3);
            }
            plain[0x100] = 0x41; // Jasper
            Bytes sealed;
            for (unsigned seed = 0; seed < 0x100; ++seed) {
                plain[0] = static_cast<uint8_t>(seed);
                sealed = nand::smc_encrypt(plain);
                const uint8_t nibble = sealed[0x100] >> 4;
                if (nibble >= 1 && nibble <= 7) {
                    break;
                }
            }
            ASSERT_TRUE((sealed[0x100] >> 4) >= 1 && (sealed[0x100] >> 4) <= 7)
                << "constructed SMC ciphertext has a motherboard-like nibble at 0x100";

            EXPECT_FALSE(nand::smc_is_encrypted(plain)) << "zero-tail plaintext SMC is plaintext";
            EXPECT_TRUE(nand::smc_is_encrypted(sealed))
                << "SMC ciphertext is detected as encrypted";

            auto parsed = nand::Smc::parse(sealed);
            ASSERT_OK(parsed) << "Smc::parse marks the ciphertext encrypted";
            EXPECT_TRUE(parsed->encrypted) << "Smc::parse marks the ciphertext encrypted";
            EXPECT_EQ(parsed->motherboard, nand::SmcMotherboard::Jasper)
                << "Smc::parse reads metadata from the plaintext";
            parsed->encrypt();
            EXPECT_BYTES_EQ(sealed, parsed->data)
                << "encrypt() does not seal an encrypted SMC twice";
        }

        TEST(SmcCrypto, EncryptDecryptRoundTripRestoresPlaintext) {
            Bytes plain(0x3000, 0);
            for (size_t i = 0; i < 0x2F00; ++i) {
                plain[i] = static_cast<uint8_t>(i * 11 + 5);
            }
            plain[0x100] = 0x52; // Trinity

            const Bytes sealed = nand::smc_encrypt(plain);
            ASSERT_EQ(sealed.size(), plain.size());
            EXPECT_NE(sealed, plain);
            EXPECT_TRUE(nand::smc_is_encrypted(sealed));

            const Bytes decrypted = nand::smc_decrypt(sealed);
            EXPECT_BYTES_EQ(plain, decrypted);
        }

        TEST(DriverEcc, FinalizeComputesSpareEdcAndLeavesRawBytesConst) {
            nand::Driver driver(nand::Driver::ImageSize::Smallblock, nand::Driver::DriverMode::Small);

            std::array<uint8_t, 512> page_data{};
            for (size_t i = 0; i < page_data.size(); ++i) {
                page_data[i] = static_cast<uint8_t>((i * 13 + 7) & 0xFF);
            }
            driver.write_page(0, page_data);

            const auto& raw_before = std::as_const(driver).raw_bytes();
            ASSERT_GE(raw_before.size(), 528u);
            EXPECT_EQ(raw_before[0x205], 0xFF);
            const std::array<uint8_t, 4> unfinalized_edc{raw_before[0x20C], raw_before[0x20D],
                                                         raw_before[0x20E], raw_before[0x20F]};
            EXPECT_EQ(unfinalized_edc, (std::array<uint8_t, 4>{0, 0, 0, 0}));

            const Bytes first_finalized = driver.finalize();
            const std::array<uint8_t, 4> edc_before{first_finalized[0x20C], first_finalized[0x20D],
                                                    first_finalized[0x20E], first_finalized[0x20F]};
            EXPECT_NE(edc_before, unfinalized_edc);

            const auto& second_finalized = driver.finalize();
            EXPECT_BYTES_EQ(first_finalized, second_finalized);

            page_data[0] ^= 0x01;
            driver.write_page(0, page_data);
            const auto& modified_finalized = driver.finalize();
            const std::array<uint8_t, 4> edc_after{
                modified_finalized[0x20C], modified_finalized[0x20D], modified_finalized[0x20E],
                modified_finalized[0x20F]};
            EXPECT_NE(edc_after, edc_before);
            EXPECT_BYTES_EQ(modified_finalized, std::as_const(driver).raw_bytes());
        }

        TEST(DriverEcc, EmmcFinalizeLeavesRaw512BytePagesUntouched) {
            nand::Driver driver(nand::Driver::ImageSize::Emmcblock, nand::Driver::DriverMode::Emmc);

            std::array<uint8_t, 512> page_data{};
            for (size_t i = 0; i < page_data.size(); ++i) {
                page_data[i] = static_cast<uint8_t>((i * 17 + 9) & 0xFF);
            }
            driver.write_page(0, page_data);

            const Bytes before = std::as_const(driver).raw_bytes();
            const auto& finalized = driver.finalize();

            EXPECT_BYTES_EQ(before, finalized);
            EXPECT_BYTES_EQ(page_data, driver.read_page(0));
            EXPECT_EQ(std::as_const(driver).raw_bytes().size(), before.size());
        }

    } // namespace
} // namespace gxbuild::nand_crypto_tests
