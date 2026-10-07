// src/nand/objects/SecuredFiles.hpp: crl.bin, dae.bin, extended.bin and secdata.bin sealed for
// the console as xeBuild 1.21 seals them, checked against the independent oracle in
// SecuredFilesOracle.hpp; their stamp, the clean copies a build makes up, the loose copies the
// Input boundary carries in the clear, and the sealing drawn when no console copy supplies it.

#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "objects/SecuredFilesOracle.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <utility>

namespace gxbuild3::objects {
    namespace {

        using nand::clean_extended;
        using nand::clean_secdata;
        using nand::crl_sealing;
        using nand::crypt_secfile;
        using nand::dae_sealing;
        using nand::extended_opened;
        using nand::kExtendedSize;
        using nand::kSecdataSize;
        using nand::open_loose_extended;
        using nand::open_loose_secdata;
        using nand::reseal_crl;
        using nand::reseal_dae;
        using nand::reseal_extended;
        using nand::reseal_secdata;
        using nand::secdata_head;
        using nand::secdata_opened;
        using nand::secured_file_stamp;
        using secured_oracle::a_record;
        using secured_oracle::aes_cbc_decrypt;
        using secured_oracle::Bytes;
        using secured_oracle::clear_dae;
        using secured_oracle::hmac;
        using secured_oracle::kBuild;
        using secured_oracle::kCpuKey;
        using secured_oracle::kCrlSealing;
        using secured_oracle::kDaeSealing;
        using secured_oracle::Key;
        using secured_oracle::kOtherKey;
        using secured_oracle::kRetailXexKey;

        using Head = std::array<uint8_t, 8>;

        // An extended.bin (`extended`) or secdata.bin in the clear: a counting plaintext behind
        // the nonce the CPU key derives from it.
        Bytes clear_keyvault_style(size_t length, uint8_t fill, bool extended) {
            Bytes plain(length - 0x10);
            for (size_t at = 0; at < plain.size(); ++at) {
                plain[at] = static_cast<uint8_t>(at + fill);
            }
            static constexpr uint8_t kTail[2] = {0x07, 0x12};
            const auto nonce =
                extended ? hmac(kCpuKey, plain, kTail) : hmac(kCpuKey, plain, std::span<uint8_t>{});
            Bytes out(nonce.begin(), nonce.end());
            out.insert(out.end(), plain.begin(), plain.end());
            return out;
        }

        TEST(SecuredFileStamp, TheStampIsTheBuildTimePlusTwoSecondsToTheEvenSecond) {
            // 0x5A123458 seconds after 1970 as 100 ns ticks after 1601, big-endian.
            const uint64_t ticks = (uint64_t{0x5A123458} + 11644473600ULL) * 10000000ULL;
            std::array<uint8_t, 8> expected{};
            for (size_t index = 0; index < expected.size(); ++index) {
                expected[index] = static_cast<uint8_t>(ticks >> (56 - 8 * index));
            }
            EXPECT_BYTES_EQ(expected, secured_file_stamp(0x5A123456))
                << "an even build time is stamped two seconds later";
            EXPECT_BYTES_EQ(expected, secured_file_stamp(0x5A123457))
                << "an odd build time is stamped down to the even second";
        }

        TEST(CrlSeal, ACrlIsSealedUnderTheGivenVectorAndFileKey) {
            const auto clear = a_record("CRLP", 0xA00, 1);
            const auto sealed = reseal_crl(clear, kCpuKey, kCrlSealing, kBuild);
            ASSERT_OK(sealed) << "a clear crl.bin is sealed";
            ASSERT_EQ(sealed->size(), clear.size()) << "a clear crl.bin is sealed";

            const auto opened = crl_sealing(*sealed, kCpuKey);
            const auto body = aes_cbc_decrypt(kCrlSealing.file_key, kCrlSealing.iv,
                                              std::span(*sealed).subspan(0x140));
            const auto stamp = secured_file_stamp(kBuild.build_seconds);
            EXPECT_BYTES_EQ(std::span(clear).first(0x120), std::span(*sealed).first(0x120))
                << "the header up to the vector is the content's";
            EXPECT_OK(opened) << "its vector and file key are read back under the CPU key";
            EXPECT_BYTES_EQ(kCrlSealing.iv, opened.value_or(nand::CrlSealing{}).iv)
                << "its vector and file key are read back under the CPU key";
            EXPECT_BYTES_EQ(kCrlSealing.file_key, opened.value_or(nand::CrlSealing{}).file_key)
                << "its vector and file key are read back under the CPU key";
            EXPECT_FALSE(crl_sealing(*sealed, kOtherKey).has_value())
                << "another console's key does not open it";
            EXPECT_BYTES_EQ(stamp, std::span(body).first(stamp.size()))
                << "the body carries the stamp at 0x00";
            EXPECT_EQ(body[0x0F], kBuild.lockdown_value) << "and the lockdown value at 0x0F";
            EXPECT_BYTES_EQ(std::span(clear).subspan(0x150), std::span(body).subspan(0x10))
                << "and the content behind them";
        }

        TEST(CrlSeal, ACrlFromAnUpdatePackageIsResealedForTheConsole) {
            const auto clear = a_record("CRLP", 0xA00, 1);
            const auto shipped = reseal_crl(clear, kRetailXexKey, kCrlSealing, {0, 0});
            const auto from_clear = reseal_crl(clear, kCpuKey, kCrlSealing, kBuild);
            const auto devkit = reseal_crl(clear, Key{}, kCrlSealing, {0, 0});
            ASSERT_OK(from_clear) << "a copy under the retail XEX key opens and seals as the "
                                     "clear one";
            ASSERT_OK(shipped)
                << "a copy under the retail XEX key opens and seals as the clear one";
            ASSERT_OK(devkit) << "a copy under the all-zero development XEX key opens too";
            const auto from_shipped = reseal_crl(*shipped, kCpuKey, kCrlSealing, kBuild);
            const auto from_devkit = reseal_crl(*devkit, kCpuKey, kCrlSealing, kBuild);
            auto damaged = clear;
            damaged[0x200] ^= 1;

            EXPECT_OK(from_shipped)
                << "a copy under the retail XEX key opens and seals as the clear one";
            EXPECT_BYTES_EQ(*from_clear, from_shipped.value_or(Bytes{}))
                << "a copy under the retail XEX key opens and seals as the clear one";
            EXPECT_FALSE(crl_sealing(*shipped, kCpuKey).has_value())
                << "a shipped copy carries no console sealing";
            EXPECT_OK(from_devkit) << "a copy under the all-zero development XEX key opens too";
            EXPECT_BYTES_EQ(*from_clear, from_devkit.value_or(Bytes{}))
                << "a copy under the all-zero development XEX key opens too";
            EXPECT_FALSE(reseal_crl(damaged, kCpuKey, kCrlSealing, kBuild).has_value())
                << "a copy whose hash does not hold opens under no key";
        }

        TEST(DaeSeal, ADaeIsSealedRecordByRecord) {
            const auto clear = clear_dae();
            const auto sealed = reseal_dae(clear, kCpuKey, kDaeSealing, kBuild);
            ASSERT_OK(sealed) << "a clear dae.bin is sealed";
            ASSERT_EQ(sealed->size(), clear.size()) << "a clear dae.bin is sealed";

            auto field = kDaeSealing.field;
            field[1] |= 0x01;
            const auto stamp = secured_file_stamp(kBuild.build_seconds);
            for (const auto& [at, length] : {std::pair<size_t, size_t>{0, 0x400}, {0x400, 0x300}}) {
                SCOPED_TRACE(std::format("the record at 0x{:X}", at));
                const auto record = std::span(*sealed).subspan(at, length);
                const auto body = aes_cbc_decrypt(kCpuKey, Key{}, record.subspan(0x130));
                const auto mac = hmac(kCpuKey, field, std::span(body).first(0x10));
                EXPECT_BYTES_EQ(field, record.subspan(0x120, field.size()))
                    << "each header carries the field with bit 0 of its second byte set";
                EXPECT_BYTES_EQ(stamp, std::span(body).first(stamp.size()))
                    << "each body carries the stamp, the head and the lockdown value";
                EXPECT_BYTES_EQ(kDaeSealing.head,
                                std::span(body).subspan(0x08, kDaeSealing.head.size()))
                    << "each body carries the stamp, the head and the lockdown value";
                EXPECT_EQ(body[0x0F], kBuild.lockdown_value)
                    << "each body carries the stamp, the head and the lockdown value";
                EXPECT_BYTES_EQ(mac, std::span(body).subspan(0x10, mac.size()))
                    << "and HMAC-SHA(CPU key, field + preamble) at 0x10";
                EXPECT_BYTES_EQ(std::span(clear).subspan(at + 0x150, length - 0x150),
                                std::span(body).subspan(0x20))
                    << "and the content behind the preamble";
            }

            const auto own = dae_sealing(*sealed, kCpuKey);
            EXPECT_OK(own) << "the head and field are read back under the CPU key";
            EXPECT_BYTES_EQ(kDaeSealing.head, own.value_or(nand::DaeSealing{}).head)
                << "the head and field are read back under the CPU key";
            EXPECT_BYTES_EQ(field, own.value_or(nand::DaeSealing{}).field)
                << "the head and field are read back under the CPU key";
            EXPECT_FALSE(dae_sealing(*sealed, kOtherKey).has_value())
                << "another console's key does not open it";
            ASSERT_OK(own) << "a sealed dae.bin seals again to the same bytes";
            const auto again = reseal_dae(*sealed, kCpuKey, *own, kBuild);
            EXPECT_OK(again) << "a sealed dae.bin seals again to the same bytes";
            EXPECT_BYTES_EQ(*sealed, again.value_or(Bytes{}))
                << "a sealed dae.bin seals again to the same bytes";
        }

        TEST(DaeSeal, ADaeWhoseRecordsDoNotCoverItIsRefused) {
            auto clear = clear_dae();
            clear.push_back(0);
            auto wrong_magic = clear_dae();
            wrong_magic[0x400] = 'X';
            EXPECT_FALSE(reseal_dae(clear, kCpuKey, kDaeSealing, kBuild).has_value())
                << "trailing bytes after the last record are refused";
            EXPECT_FALSE(reseal_dae(wrong_magic, kCpuKey, kDaeSealing, kBuild).has_value())
                << "a record without the DAEP magic is refused";
        }

        TEST(ExtendedSeal, ExtendedTakesTheKeyvaultHeadAndDerivesItsNonce) {
            const auto clear = clear_keyvault_style(0x4000, 5, true);
            const Head head{1, 2, 3, 4, 5, 6, 7, 8};
            const auto sealed = reseal_extended(clear, kCpuKey, head);
            ASSERT_OK(sealed) << "extended.bin is sealed";
            ASSERT_EQ(sealed->size(), clear.size()) << "extended.bin is sealed";
            auto opened = *sealed;
            ASSERT_OK(crypt_secfile(kCpuKey, opened));

            EXPECT_TRUE(extended_opened(clear, kCpuKey)) << "an opened extended.bin is recognised";
            EXPECT_FALSE(extended_opened(clear, kOtherKey)) << "under its own key only";
            EXPECT_TRUE(extended_opened(opened, kCpuKey))
                << "its nonce is the one its plaintext derives";
            EXPECT_BYTES_EQ(head, std::span(opened).subspan(0x10, head.size()))
                << "its head is the keyvault's";
            EXPECT_BYTES_EQ(std::span(clear).subspan(0x18), std::span(opened).subspan(0x18))
                << "and the rest is its own";
        }

        // xeBuild 1.21's clean extended.bin: 0x4000 bytes, the plaintext zero but the keyvault's
        // head, under the nonce HMAC-SHA(CPU key, plaintext + 07 12).
        TEST(ExtendedSeal, ACleanExtendedIsZeroButTheKeyvaultHead) {
            const Head head{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
            const auto sealed = clean_extended(kCpuKey, head);
            ASSERT_OK(sealed) << "a clean extended.bin is made";
            ASSERT_EQ(sealed->size(), kExtendedSize) << "a clean extended.bin is made";
            auto opened = *sealed;
            ASSERT_OK(crypt_secfile(kCpuKey, opened));
            Bytes plain(kExtendedSize - 0x10);
            std::copy(head.begin(), head.end(), plain.begin());
            static constexpr uint8_t kTail[2] = {0x07, 0x12};
            const auto nonce = hmac(kCpuKey, plain, kTail);
            const auto again = clean_extended(kCpuKey, head);

            EXPECT_BYTES_EQ(nonce, std::span(*sealed).first(nonce.size()))
                << "its nonce is HMAC-SHA(CPU key, plaintext + 07 12)";
            EXPECT_BYTES_EQ(plain, std::span(opened).subspan(0x10))
                << "its plaintext is zero but the keyvault's head";
            EXPECT_TRUE(extended_opened(opened, kCpuKey)) << "it opens under the CPU key";
            EXPECT_OK(again) << "it is deterministic";
            EXPECT_BYTES_EQ(*sealed, again.value_or(Bytes{})) << "it is deterministic";
            EXPECT_FALSE(clean_extended(Bytes(8), head).has_value())
                << "a CPU key that is not 16 bytes fails";
        }

        TEST(SecdataSeal, SecdataTakesTheBuildFieldsAndDerivesItsNonce) {
            const auto clear = clear_keyvault_style(0x400, 9, false);
            const Head head{8, 7, 6, 5, 4, 3, 2, 1};
            const auto sealed = reseal_secdata(clear, kCpuKey, head, kBuild);
            const auto kept = reseal_secdata(clear, kCpuKey, std::nullopt, kBuild);
            ASSERT_OK(sealed) << "secdata.bin is sealed";
            ASSERT_OK(kept) << "secdata.bin is sealed";
            auto opened = *sealed;
            ASSERT_OK(crypt_secfile(kCpuKey, opened));
            auto opened_kept = *kept;
            ASSERT_OK(crypt_secfile(kCpuKey, opened_kept));
            ASSERT_GE(opened.size(), 0x28u) << "secdata.bin is sealed";
            const auto stamp = secured_file_stamp(kBuild.build_seconds);
            const auto own_head = secdata_head(clear);
            const auto kept_head = secdata_head(opened_kept);

            EXPECT_TRUE(secdata_opened(clear, kCpuKey))
                << "secdata.bin's nonce takes nothing behind the plaintext";
            EXPECT_FALSE(extended_opened(clear, kCpuKey))
                << "secdata.bin's nonce takes nothing behind the plaintext";
            EXPECT_TRUE(secdata_opened(opened, kCpuKey))
                << "its nonce is the one its plaintext derives";
            EXPECT_BYTES_EQ(head, std::span(opened).subspan(0x10, head.size()))
                << "a given head is written";
            ASSERT_OK(own_head) << "else its own is kept";
            EXPECT_OK(kept_head) << "else its own is kept";
            EXPECT_BYTES_EQ(*own_head, kept_head.value_or(Head{})) << "else its own is kept";
            EXPECT_EQ(opened[0x18], 0x01) << "it states 1 and the lockdown value at 0x08";
            EXPECT_EQ(opened[0x19], kBuild.lockdown_value)
                << "it states 1 and the lockdown value at 0x08";
            EXPECT_BYTES_EQ(stamp, std::span(opened).subspan(0x20, stamp.size()))
                << "and the stamp at 0x10";
            EXPECT_BYTES_EQ(std::span(clear).subspan(0x28), std::span(opened).subspan(0x28))
                << "and the rest is its own";
        }

        // xeBuild 1.21's clean secdata.bin: 0x400 bytes, the plaintext zero but the head, 1, the
        // lockdown value and the stamp, under the nonce HMAC-SHA(CPU key, plaintext).
        TEST(SecdataSeal, ACleanSecdataIsZeroButTheBuildFields) {
            const Head head{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
            const auto sealed = clean_secdata(kCpuKey, head, kBuild);
            ASSERT_OK(sealed) << "a clean secdata.bin is made";
            ASSERT_EQ(sealed->size(), kSecdataSize) << "a clean secdata.bin is made";
            auto opened = *sealed;
            ASSERT_OK(crypt_secfile(kCpuKey, opened));
            Bytes plain(kSecdataSize - 0x10);
            std::copy(head.begin(), head.end(), plain.begin());
            plain[0x08] = 0x01;
            plain[0x09] = kBuild.lockdown_value;
            const auto stamp = secured_file_stamp(kBuild.build_seconds);
            std::copy(stamp.begin(), stamp.end(), plain.begin() + 0x10);
            const auto nonce = hmac(kCpuKey, plain);
            const auto opened_head = secdata_head(opened);

            EXPECT_BYTES_EQ(nonce, std::span(*sealed).first(nonce.size()))
                << "its nonce is HMAC-SHA(CPU key, plaintext)";
            EXPECT_BYTES_EQ(plain, std::span(opened).subspan(0x10))
                << "its plaintext is zero but the head, 1, the lockdown value and the stamp";
            EXPECT_TRUE(secdata_opened(opened, kCpuKey))
                << "it opens under the CPU key with the given head";
            EXPECT_OK(opened_head) << "it opens under the CPU key with the given head";
            EXPECT_BYTES_EQ(head, opened_head.value_or(Head{}))
                << "it opens under the CPU key with the given head";
            EXPECT_FALSE(clean_secdata(Bytes(8), head, kBuild).has_value())
                << "a CPU key that is not 16 bytes fails";
        }

        TEST(LooseSecuredFiles, LooseCopiesReachTheInputBoundaryInTheClear) {
            const auto clear = clear_keyvault_style(0x400, 9, false);
            auto sealed = clear;
            ASSERT_OK(crypt_secfile(kCpuKey, sealed));
            auto zero_nonce = clear;
            std::fill(zero_nonce.begin(), zero_nonce.begin() + 0x10, uint8_t{0});
            auto stale = sealed;
            std::fill(stale.begin(), stale.begin() + 0x10, uint8_t{0x51});
            auto stale_opened = stale;
            ASSERT_OK(crypt_secfile(kCpuKey, stale_opened));
            const auto extended = clear_keyvault_style(0x4000, 5, true);
            auto zero_extended = extended;
            std::fill(zero_extended.begin(), zero_extended.begin() + 0x10, uint8_t{0});

            const auto from_sealed = open_loose_secdata(sealed, kCpuKey);
            EXPECT_OK(from_sealed) << "a sealed secdata.bin is opened";
            EXPECT_BYTES_EQ(clear, from_sealed.value_or(Bytes{}))
                << "a sealed secdata.bin is opened";

            const auto from_clear = open_loose_secdata(clear, kCpuKey);
            EXPECT_OK(from_clear) << "one in the clear behind its derived nonce is kept";
            EXPECT_BYTES_EQ(clear, from_clear.value_or(Bytes{}))
                << "one in the clear behind its derived nonce is kept";

            const auto from_zero_nonce = open_loose_secdata(zero_nonce, kCpuKey);
            EXPECT_OK(from_zero_nonce)
                << "one in the clear behind a zero nonce gets its derived nonce";
            EXPECT_BYTES_EQ(clear, from_zero_nonce.value_or(Bytes{}))
                << "one in the clear behind a zero nonce gets its derived nonce";

            const auto from_zero_extended = open_loose_extended(zero_extended, kCpuKey);
            EXPECT_OK(from_zero_extended)
                << "so does an extended.bin in the clear behind a zero nonce";
            EXPECT_BYTES_EQ(extended, from_zero_extended.value_or(Bytes{}))
                << "so does an extended.bin in the clear behind a zero nonce";

            const auto from_stale = open_loose_secdata(stale, kCpuKey);
            EXPECT_OK(from_stale) << "anything else is opened under the nonce it carries";
            EXPECT_BYTES_EQ(stale_opened, from_stale.value_or(Bytes{}))
                << "anything else is opened under the nonce it carries";

            EXPECT_FALSE(open_loose_secdata(Bytes(8), kCpuKey).has_value())
                << "a file shorter than a nonce fails";
        }

        // Probabilistic: two draws collide with a chance of about 2^-64 (the head) and 2^-128
        // (the keys), so a failure means the draws are not random.
        TEST(SecuredFileDraws, DrawnSealingDiffersBetweenDraws) {
            const auto first = nand::random_crl_sealing();
            const auto second = nand::random_crl_sealing();
            const auto dae_first = nand::random_dae_sealing();
            const auto dae_second = nand::random_dae_sealing();
            // Compared without printing: the drawn values are key material.
            EXPECT_TRUE(nand::random_secdata_head() != nand::random_secdata_head())
                << "a drawn secdata.bin head differs between draws";
            EXPECT_TRUE(first.iv != second.iv)
                << "a drawn crl.bin vector and file key differ between draws";
            EXPECT_TRUE(first.file_key != second.file_key)
                << "a drawn crl.bin vector and file key differ between draws";
            EXPECT_TRUE(dae_first.field != dae_second.field)
                << "a drawn dae.bin field differs between draws";
        }

    } // namespace
} // namespace gxbuild3::objects
