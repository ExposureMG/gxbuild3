// How a parsed CD is told to be plaintext. Past its first 0x20 bytes a sealed CD is ciphertext,
// so a test of two header bytes (the first 6BL nonce byte and the first CE hash byte) took about
// 1 sealed CD in 256 for plaintext: the kernel was then not opened, CE was opened with the wrong
// key, and the CD was sealed a second time. Only the 6BL salt at 0x240, which a plaintext CD
// stores as the ROM constant, tells the two apart.

#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <utility>

namespace gxbuild3::bootloaders {
    namespace {

        // A CD whose header carries `salt`, serialized with room for a small payload.
        test::Bytes cd_bytes_with_salt(const std::array<char, 10>& salt, uint8_t nonce_byte,
                                       uint8_t ce_hash_byte) {
            nand::BootloaderCd cd{};
            cd.header.header.magic = nand::NANDBootloaderMagic::CD;
            cd.header.header.version = 1;
            cd.header.header.size = static_cast<uint32_t>(sizeof(nand::cd_header) + 0x20);
            cd.header.nonce_6bl[0] = nonce_byte;
            cd.header.ce_hash[0] = ce_hash_byte;
            std::ranges::copy(salt, cd.header.salt_6bl);
            cd.data.assign(0x20, 0x42);
            return cd.serialize();
        }

        TEST(CdPlaintextDetection, TheRomSaltMarksAPlaintextCd) {
            ASSERT_OK_AND_ASSIGN(const auto cd, nand::BootloaderCd::parse(cd_bytes_with_salt(
                                                    nand::kRomSalt6bl, 0x00, 0x55)));
            EXPECT_TRUE(cd.decrypted) << "parse takes the state from the salt";
            EXPECT_TRUE(cd.is_decrypted());
        }

        // The former test needed a zero first nonce byte and a nonzero CE hash byte, so it
        // refused this plaintext CD.
        TEST(CdPlaintextDetection, APlaintextCdIsRecognisedWhateverItsNonceAndHashBytes) {
            ASSERT_OK_AND_ASSIGN(const auto cd, nand::BootloaderCd::parse(cd_bytes_with_salt(
                                                    nand::kRomSalt6bl, 0x9C, 0x00)));
            EXPECT_TRUE(cd.decrypted);
            EXPECT_TRUE(cd.is_decrypted());
        }

        // The former test, nonce_6bl[0] == 0 and ce_hash[0] != 0, held for this header, which
        // carries the salt bytes of the sealed tracked cd_1920.bin. A sealed CD can be any bytes.
        TEST(CdPlaintextDetection, ASealedCdWithAZeroNonceByteIsNotMistakenForPlaintext) {
            constexpr std::array<char, 10> sealed_salt{'\x5c', '\xe2', '\x1a', '\xaf', '\x63',
                                                       '\x51', '\x9b', '\x6e', '\x79', '\xf7'};
            ASSERT_OK_AND_ASSIGN(const auto cd, nand::BootloaderCd::parse(
                                                    cd_bytes_with_salt(sealed_salt, 0x00, 0x55)));
            EXPECT_FALSE(cd.decrypted) << "parse leaves a salt that is not the ROM constant sealed";
            EXPECT_FALSE(cd.is_decrypted())
                << "a zero first nonce byte and a nonzero CE hash byte no longer mean plaintext";
        }

        TEST(CdPlaintextDetection, AnExplicitDecryptedFlagStillWins) {
            constexpr std::array<char, 10> sealed_salt{};
            ASSERT_OK_AND_ASSIGN(
                auto cd, nand::BootloaderCd::parse(cd_bytes_with_salt(sealed_salt, 0x00, 0x55)));
            ASSERT_FALSE(cd.is_decrypted());
            cd.decrypted = true;
            EXPECT_TRUE(cd.is_decrypted())
                << "a CD a caller has opened (or declared plaintext) stays plaintext";
        }

        // Parses a tracked common/ image and reports whether it counts as plaintext.
        Result<bool> tracked_cd_is_plaintext(const char* name) {
            auto bytes = test::read_support_file(std::string("common/") + name);
            if (!bytes)
                return std::unexpected(std::move(bytes.error()));
            auto cd = nand::BootloaderCd::parse(*bytes);
            if (!cd)
                return std::unexpected(std::move(cd.error()));
            return cd->is_decrypted();
        }

        // cd_1920 and cd_5766 are the two sealed CDs among the tracked common/ images; cd_1888
        // and SD_17489 are plaintext ones.
        TEST(CdPlaintextDetection, TrackedSealedCdsAreNotPlaintext) {
            ASSERT_OK_AND_ASSIGN(const bool cd_1920, tracked_cd_is_plaintext("cd_1920.bin"));
            ASSERT_OK_AND_ASSIGN(const bool cd_5766, tracked_cd_is_plaintext("cd_5766.bin"));
            EXPECT_FALSE(cd_1920);
            EXPECT_FALSE(cd_5766);
        }

        TEST(CdPlaintextDetection, TrackedPlaintextCdsAreRecognised) {
            ASSERT_OK_AND_ASSIGN(const bool cd_1888, tracked_cd_is_plaintext("cd_1888.bin"));
            ASSERT_OK_AND_ASSIGN(const bool sd_17489, tracked_cd_is_plaintext("SD_17489.bin"));
            EXPECT_TRUE(cd_1888);
            EXPECT_TRUE(sd_17489);
        }

    } // namespace
} // namespace gxbuild3::bootloaders
