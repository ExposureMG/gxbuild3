// The extract_* cores (src/BuildRunner.cpp) and the public GxBuild::Extract* shims
// (src/Library.cpp). ExtractAll: a donor's complete baseline (image, SMC, keyvault, mobiles) and
// its exact SC bytes come back, and decrypt_all tells a sealed SC from a zero-key plaintext one.
// ExtractInfo: extract_some_info reads the public metadata without a CPU key; extract_all_info
// reports the block type, the keyvault's fcrt.bin flag and the keyvault summary at its on-disk
// offsets. ExtractionFailure: a CD record shorter than its header is refused by every entry point
// without an exception, and the cores return their reason while the shims return nullopt.
// Size/KeyvaultSummaryOsig: the OSIG is read only when raw_data holds all 28 bytes (one bundled
// ctest entry, three rows); every other case is its own ctest entry (each runs run_build).

#include "BuildRunner.hpp"
#include "Library.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Keyvault.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Stages.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using nand::Driver;
        using test::Bytes;

        // The OSIG ends at 0xCAE: the KeyvaultSummaryOsig rows straddle that bound.
        static_assert(nand::Keyvault::kOsigOffset + nand::Keyvault::kOsigLength == 0xCAE);

        // ---- ExtractAll ---------------------------------------------------------------------

        TEST(ExtractAll, PreservesCompleteDonorBaseline) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(const auto donor,
                                 test::make_donor(source, {{0x31, Bytes{3}}, {0x39, Bytes{9}}}));

            const auto extracted = extract_all(donor, source.metadata.cpu_key);
            ASSERT_OK(extracted) << "donor baseline extracts";
            ASSERT_TRUE(extracted->metadata.nand_image.has_value())
                << "extraction retains backing donor image";
            EXPECT_BYTES_EQ(donor, *extracted->metadata.nand_image)
                << "extraction retains backing donor image";
            EXPECT_EQ(extracted->image_type, ImageType::SmallBlock)
                << "extraction maps small donor mode to small image type";
            EXPECT_TRUE(extracted->metadata.smc.has_value()) << "extraction retains donor SMC";
            EXPECT_TRUE(extracted->metadata.keyvault.has_value())
                << "extraction retains donor keyvault";
            EXPECT_EQ(*extracted->mobiles.slot(0x31), Bytes{3})
                << "extraction retains first mobile slot";
            EXPECT_EQ(*extracted->mobiles.slot(0x39), Bytes{9})
                << "extraction retains last mobile slot";
        }

        TEST(ExtractAll, ScSurvivesExtractionAndBackingClearedLayoutOverride) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(const auto donor, test::make_donor(source, {}));
            auto extracted = extract_all(donor, source.metadata.cpu_key);
            ASSERT_OK(extracted) << "extraction preserves exact SC bytes";
            ASSERT_TRUE(extracted->bootloaders.sc.has_value())
                << "extraction preserves exact SC bytes";
            ASSERT_BYTES_EQ(*source.bootloaders.sc, *extracted->bootloaders.sc)
                << "extraction preserves exact SC bytes";
            extracted->metadata.nand_image.reset();
            extracted->image_type = ImageType::BigBlock;
            const auto rebuilt = run_build(*extracted);
            ASSERT_OK(rebuilt) << "SC survives backing-cleared layout override";
            const auto parsed = parse_image(*rebuilt);
            ASSERT_TRUE(parsed.has_value() && parsed->cb_section.sc.has_value())
                << "SC survives backing-cleared layout override";
            EXPECT_BYTES_EQ(*source.bootloaders.sc, parsed->cb_section.sc->serialize())
                << "SC survives backing-cleared layout override";
        }

        // An SC is sealed under HMAC(16 zero bytes, nonce), whatever its parent.
        TEST(ExtractAll, DecryptAllDistinguishesEncryptedAndZeroKeyPlaintextSc) {
            auto encrypted_source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(auto encrypted_sc,
                                 nand::BootloaderSc::parse(*encrypted_source.bootloaders.sc));
            const auto expected_encrypted_sc_data = encrypted_sc.data;
            encrypted_sc.decrypted = true;
            ASSERT_OK(encrypted_sc.encrypt(nand::BootloaderSc::kZeroSecret));
            encrypted_source.bootloaders.sc = encrypted_sc.serialize();

            const auto encrypted_build = run_build(encrypted_source);
            ASSERT_OK(encrypted_build) << "decrypt_all decrypts explicitly encrypted SC";
            auto encrypted_image = parse_image(*encrypted_build);
            ASSERT_TRUE(encrypted_image.has_value())
                << "decrypt_all decrypts explicitly encrypted SC";
            ASSERT_OK(encrypted_image->decrypt_all(encrypted_source.metadata.cpu_key))
                << "decrypt_all decrypts explicitly encrypted SC";
            ASSERT_TRUE(encrypted_image->cb_section.sc.has_value())
                << "decrypt_all decrypts explicitly encrypted SC";
            EXPECT_TRUE(encrypted_image->cb_section.sc->is_decrypted())
                << "decrypt_all decrypts explicitly encrypted SC";
            EXPECT_BYTES_EQ(expected_encrypted_sc_data, encrypted_image->cb_section.sc->data)
                << "decrypt_all restores the exact encrypted SC plaintext";

            auto plaintext_source = test::fresh_input(ImageType::SmallBlock);
            const auto expected_plaintext_sc = *plaintext_source.bootloaders.sc;
            const auto plaintext_build = run_build(plaintext_source);
            ASSERT_OK(plaintext_build) << "decrypt_all preserves zero-key plaintext SC bytes";
            const auto plaintext_extracted =
                extract_all(*plaintext_build, plaintext_source.metadata.cpu_key);
            ASSERT_OK(plaintext_extracted) << "decrypt_all preserves zero-key plaintext SC bytes";
            ASSERT_TRUE(plaintext_extracted->bootloaders.sc.has_value())
                << "decrypt_all preserves zero-key plaintext SC bytes";
            EXPECT_BYTES_EQ(expected_plaintext_sc, *plaintext_extracted->bootloaders.sc)
                << "decrypt_all preserves zero-key plaintext SC bytes";
        }

        // ---- ExtractInfo --------------------------------------------------------------------

        TEST(ExtractInfo, SomeInfoReadsPublicNandMetadataWithoutCpuKey) {
            auto input = test::fresh_input(ImageType::BigBlock);

            nand::BootloaderCe ce{};
            ce.header.header.magic = nand::NANDBootloaderMagic::CE;
            ce.header.header.version = 5;
            ce.header.header.size = static_cast<uint32_t>(sizeof(nand::ce_header) + 0x20);
            ce.data.assign(0x20, 0xCE);
            input.bootloaders.ce = ce.serialize();

            const auto [cf0, cg0] = test::valid_system_update(0x41);
            input.bootloaders.cf0 = cf0;
            input.bootloaders.cg0 = cg0;

            const auto built = run_build(input);
            ASSERT_OK(built) << "public NAND metadata extracts without a CPU key";
            const auto info = extract_some_info(*built);
            ASSERT_OK(info) << "public NAND metadata extracts without a CPU key";
            EXPECT_EQ(info->block_type, std::optional{ImageType::BigBlock})
                << "public NAND metadata reports the detected block type";
            EXPECT_TRUE(info->smc.present && !info->smc.version.empty())
                << "public NAND metadata reports the SMC version";
            EXPECT_FALSE(info->smc.type_name.empty())
                << "public NAND metadata reports the SMC type";
            EXPECT_TRUE(info->bootloaders.cb_a.has_value() && info->bootloaders.cb_a->version == 1)
                << "public NAND metadata reports the bootloader version";
            EXPECT_TRUE(info->bootloaders.sc.has_value() && info->bootloaders.sc->version == 1)
                << "public NAND metadata reports the SC version";
            EXPECT_TRUE(info->bootloaders.cd.has_value() && info->bootloaders.cd->version == 1)
                << "public NAND metadata reports the kernel version";
            EXPECT_TRUE(info->bootloaders.ce.has_value() && info->bootloaders.ce->version == 5)
                << "public NAND metadata reports the hypervisor version";
            EXPECT_TRUE(info->bootloaders.cf_0.has_value() && info->bootloaders.cg_0.has_value())
                << "public NAND metadata reports the update versions";
            EXPECT_TRUE(info->cpu_key.empty() && !info->raw_keyvault.has_value() &&
                        !info->keyvault.present)
                << "public NAND metadata omits CPU-key-dependent keyvault data";
        }

        TEST(ExtractInfo, AllInfoReportsTheDetectedBlockType) {
            const auto input = test::fresh_input(ImageType::NewSmallBlock);
            const auto built = run_build(input);
            ASSERT_OK(built) << "full NAND metadata extracts";
            const auto info = extract_all_info(*built, input.metadata.cpu_key);
            ASSERT_OK(info) << "full NAND metadata extracts";
            EXPECT_EQ(info->block_type, std::optional{ImageType::NewSmallBlock})
                << "full NAND metadata reports the detected block type";
        }

        // The keyvault's fcrt.bin flag is read as xeBuild 1.21 reads it: bits 0x0320 of the
        // big-endian OddFeatures word at 0x1C.
        TEST(ExtractInfo, AllInfoReadsTheFcrtFlagBigEndian) {
            for (const auto& [features, required] : {std::pair<uint16_t, bool>{0x0020, true},
                                                     {0x0200, true},
                                                     {0x2000, false},
                                                     {0x0000, false}}) {
                SCOPED_TRACE(std::format("OddFeatures 0x{:04X}", features));
                auto input = test::fresh_input(ImageType::SmallBlock);
                Bytes plain(nand::Keyvault::kSize, 0x00);
                plain[0x1C] = static_cast<uint8_t>(features >> 8);
                plain[0x1D] = static_cast<uint8_t>(features);
                input.metadata.keyvault = test::canonical_keyvault(input.metadata.cpu_key, plain);
                const auto built = run_build(input);
                ASSERT_OK(built) << "full NAND metadata reports the keyvault's fcrt.bin flag";
                const auto info = extract_all_info(*built, input.metadata.cpu_key);
                ASSERT_OK(info) << "full NAND metadata reports the keyvault's fcrt.bin flag";
                EXPECT_TRUE(info->keyvault.present)
                    << "full NAND metadata reports the keyvault's fcrt.bin flag";
                EXPECT_EQ(info->keyvault.fcrt_required, required)
                    << "full NAND metadata reports the keyvault's fcrt.bin flag";
            }
        }

        // A plaintext keyvault written by hand at its on-disk offsets (not through
        // XE_KEYVAULT_DATA), for the summary pins below.
        Bytes hand_made_keyvault(uint16_t odd_features, uint16_t region, std::string_view osig,
                                 uint8_t last_tail_byte) {
            const auto put = [](Bytes& plain, size_t at, std::string_view text) {
                std::copy(text.begin(), text.end(),
                          plain.begin() + static_cast<std::ptrdiff_t>(at));
            };
            Bytes plain(nand::Keyvault::kSize, 0x00);
            plain[0x1C] = static_cast<uint8_t>(odd_features >> 8);
            plain[0x1D] = static_cast<uint8_t>(odd_features);
            put(plain, 0xB0, "123456789012");
            plain[0xBC] = 'X'; // the padding after the serial is not part of it
            plain[0xC8] = static_cast<uint8_t>(region >> 8);
            plain[0xC9] = static_cast<uint8_t>(region);
            for (size_t i = 0; i < 0x10; ++i) {
                plain[0x100 + i] = static_cast<uint8_t>(0xD0 + i);
            }
            const std::array<uint8_t, 5> console_id{0x12, 0x34, 0x56, 0x78, 0x9A};
            std::copy(console_id.begin(), console_id.end(), plain.begin() + 0x9CA);
            put(plain, 0x9E4, "09-14-10");
            put(plain, 0xC92, osig);
            // A byte that is neither 0x00 nor 0xFF just before the tail does not count.
            plain[0x1EEF] = 0x5A;
            for (size_t i = 0; i < 8; ++i) {
                plain[0x1EF0 + i] = (i % 2 == 0) ? 0xFF : 0x00;
            }
            plain[0x1EF7] = last_tail_byte;
            return plain;
        }

        struct KeyvaultSummaryCase {
            std::string_view name;
            Bytes plain;
            uint16_t region_raw;
            std::string_view region_name;
            std::string_view osig;
            uint8_t kv_type;
            bool fcrt_required;
        };

        // One keyvault case of AllInfoPinsTheKeyvaultSummaryAtItsOffsets: an ASSERT ends this
        // case only, as the old loop went on to the next.
        void expect_keyvault_summary(const KeyvaultSummaryCase& test_case) {
            SCOPED_TRACE(test_case.name);
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.keyvault =
                test::canonical_keyvault(input.metadata.cpu_key, test_case.plain);
            const auto built = run_build(input);
            ASSERT_OK(built) << "full NAND metadata has the keyvault";
            const auto info = extract_all_info(*built, input.metadata.cpu_key);
            ASSERT_OK(info) << "full NAND metadata has the keyvault";
            ASSERT_TRUE(info->keyvault.present && info->keyvault.decrypted)
                << "full NAND metadata has the keyvault";
            const auto& kv = info->keyvault;
            EXPECT_EQ(kv.serial_number, "123456789012") << "serial_number at 0xB0";
            EXPECT_EQ(kv.region_raw, test_case.region_raw)
                << "region_raw is the big-endian word at 0xC8";
            EXPECT_EQ(kv.region_name, test_case.region_name) << "region_name";
            EXPECT_EQ(kv.dvd_key, "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF") << "dvd_key at 0x100";
            EXPECT_EQ(kv.console_id_raw, "123456789A") << "console_id_raw at 0x9CA";
            // 0x123456789 printed in 11 digits, then the low nibble of the fifth byte.
            EXPECT_EQ(kv.console_id_friendly, "0488671834510") << "console_id_friendly";
            EXPECT_EQ(kv.mfr_date, "09-14-10") << "mfr_date at 0x9E4";
            EXPECT_EQ(kv.osig, test_case.osig) << "osig at 0xC92";
            EXPECT_EQ(kv.kv_type, test_case.kv_type) << "kv_type from the 0x1EF0 tail";
            EXPECT_EQ(kv.fcrt_required, test_case.fcrt_required)
                << "fcrt_required from OddFeatures at 0x1C";
        }

        // The keyvault summary of the full NAND metadata, pinned against a plaintext keyvault
        // written by hand at its on-disk offsets, so a moved field, a dropped byte swap or a
        // changed bound shows up here:
        //   0x01C OddFeatures (big-endian)       0x0B0 serial, 12 chars, no terminator needed
        //   0x0C8 game region (big-endian)       0x100 DVD key
        //   0x9CA console id (5 bytes)           0x9E4 manufacturing date (8 chars)
        //   0xC92 OSIG text (28 chars at most)   0x1EF0..0x1EF7 last 8 bytes of the special
        //                                        signature
        // kv_type is 1 when every byte of that 8-byte tail is 0x00 or 0xFF, and 2 otherwise.
        TEST(ExtractInfo, AllInfoPinsTheKeyvaultSummaryAtItsOffsets) {
            const std::array<KeyvaultSummaryCase, 2> cases{{
                {"type-1 keyvault",
                 hand_made_keyvault(0x0020, 0x01FE, "GXB SYNTHETIC OSIG 01", 0x00), 0x01FE,
                 "NTSC/JAP", "GXB SYNTHETIC OSIG 01", 1, true},
                // The OSIG runs past 28 chars with no terminator: the summary stops at 28.
                {"type-2 keyvault",
                 hand_made_keyvault(0x0000, 0x02FE, "GXB SYNTHETIC OSIG TEXT 0123456789", 0x01),
                 0x02FE, "PAL/EU", "GXB SYNTHETIC OSIG TEXT 0123", 2, false},
            }};
            for (const auto& test_case : cases) {
                expect_keyvault_summary(test_case);
            }
        }

        // ---- Size/KeyvaultSummaryOsig -------------------------------------------------------

        // The OSIG is read only when raw_data holds all 28 bytes at 0xC92, so through 0xCAD: one
        // byte short (0xCAD bytes) gives an empty OSIG without reading past the buffer, even with
        // no NUL in the bytes it has, and exactly 0xCAE bytes gives all 28. A parsed keyvault is
        // always kSize bytes; this pins the bound for a hand-made one. Run under ASan to see the
        // bound.
        struct OsigBoundCase {
            const char* name;
            size_t size;
            std::string_view osig;
        };
        GX_PRINT_ROW_AS_NAME(OsigBoundCase)

        constexpr std::array kOsigBoundCases{
            OsigBoundCase{"RawData0xCAD", 0xCAD, ""},
            OsigBoundCase{"RawData0xCAE", 0xCAE, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            OsigBoundCase{"RawData0xCAF", 0xCAF, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        };

        class KeyvaultSummaryOsig : public ::testing::TestWithParam<OsigBoundCase> {};

        TEST_P(KeyvaultSummaryOsig, IsReadOnlyWhenRawDataHoldsAllTwentyEightBytes) {
            const auto& row = GetParam();
            nand::Keyvault kv{};
            kv.encrypted = false;
            kv.raw_data.assign(row.size, static_cast<uint8_t>('A'));
            const auto summary = nand::summarize_keyvault(kv);
            const auto label = std::format("raw_data of 0x{:X} bytes", row.size);
            EXPECT_TRUE(summary.present && summary.decrypted)
                << label << ": the summary is present and decrypted";
            EXPECT_EQ(summary.osig, row.osig)
                << label << ": osig is "
                << (row.osig.empty() ? std::string("empty") : "the 28 bytes at 0xC92");
        }

        INSTANTIATE_TEST_SUITE_P(Size, KeyvaultSummaryOsig, ::testing::ValuesIn(kOsigBoundCases),
                                 test::RowName{});

        // ---- ExtractionFailure --------------------------------------------------------------

        // The image with its CD record's header stating 0x20 bytes, which is shorter than a CD
        // header. Empty when the chain from the entry offset reaches no CD record.
        Bytes with_short_cd_record(Bytes image) {
            constexpr size_t kEntryOffset = 0x8000;
            constexpr uint16_t kCdMagic = 0x4344;
            constexpr size_t kMaxRecords = 8;
            Driver driver(std::move(image));
            size_t cursor = kEntryOffset;
            for (size_t record = 0; record < kMaxRecords; ++record) {
                const auto header = driver.read_clean(cursor, sizeof(nand::generic_header));
                if (header.size() < sizeof(nand::generic_header)) {
                    return {};
                }
                const uint32_t size = test::be32(header, offsetof(nand::generic_header, size));
                if (test::be16(header, offsetof(nand::generic_header, magic)) == kCdMagic) {
                    const std::array<uint8_t, 4> short_size{0x00, 0x00, 0x00, 0x20};
                    if (!driver.write_offset(cursor + offsetof(nand::generic_header, size),
                                             short_size)) {
                        return {};
                    }
                    return driver.serialize();
                }
                if (size == 0) {
                    return {};
                }
                cursor += align_16(size);
            }
            return {};
        }

        // A malformed bootloader record makes its parser throw. Each extraction entry point
        // reports that as a failure and lets no exception escape.
        TEST(ExtractionFailure, ReportsACdRecordShorterThanItsHeader) {
            const auto input = test::fresh_input(ImageType::SmallBlock);
            const auto built = run_build(input);
            ASSERT_OK(built) << "the image to damage builds";
            const auto malformed = with_short_cd_record(*built);
            ASSERT_FALSE(malformed.empty()) << "the built image has a CD record to damage";

            const auto& cpu_key = input.metadata.cpu_key;
            bool some_info = false;
            EXPECT_NO_THROW(some_info = !extract_some_info(malformed).has_value())
                << "extract_some_info refuses a short CD record";
            EXPECT_TRUE(some_info) << "extract_some_info refuses a short CD record";
            bool metadata = false;
            EXPECT_NO_THROW(metadata = !extract_metadata(malformed, cpu_key).has_value())
                << "extract_metadata refuses a short CD record";
            EXPECT_TRUE(metadata) << "extract_metadata refuses a short CD record";
            bool all_info = false;
            EXPECT_NO_THROW(all_info = !extract_all_info(malformed, cpu_key).has_value())
                << "extract_all_info refuses a short CD record";
            EXPECT_TRUE(all_info) << "extract_all_info refuses a short CD record";
            bool all = false;
            EXPECT_NO_THROW(all = !extract_all(malformed, cpu_key).has_value())
                << "extract_all refuses a short CD record";
            EXPECT_TRUE(all) << "extract_all refuses a short CD record";
        }

        // The extraction cores return their reason and log nothing; the public GxBuild::Extract*
        // shims log that reason once and return std::nullopt.
        TEST(ExtractionFailure, CoresReturnTheirReasonAndTheShimsReturnNullopt) {
            const auto input = test::fresh_input(ImageType::SmallBlock);
            const auto built = run_build(input);
            ASSERT_OK(built) << "the image to extract builds";
            const auto& cpu_key = input.metadata.cpu_key;
            const Bytes short_key(cpu_key.begin(), cpu_key.begin() + 15);
            const auto malformed = with_short_cd_record(*built);
            EXPECT_ERROR_HAS(extract_all(*built, short_key), ErrorCode::InvalidArgument, "16 bytes")
                << "extract_all names a CPU key of the wrong length";
            EXPECT_ERROR_HAS(extract_some_info(Bytes{}), ErrorCode::InvalidArgument, "empty")
                << "extract_some_info names an empty image";
            const auto malformed_all = extract_all(malformed, cpu_key);
            ASSERT_FALSE(malformed_all.has_value())
                << "extract_all puts the parse context on a malformed record";
            EXPECT_TRUE(malformed_all.error().describe().contains(
                "Failed to parse the NAND image structure"))
                << "extract_all puts the parse context on a malformed record: "
                << malformed_all.error().describe();
            EXPECT_FALSE(GxBuild::ExtractAll(*built, short_key).has_value())
                << "the public Extract* shims return nullopt exactly when the core fails";
            EXPECT_FALSE(GxBuild::ExtractSomeInfo(Bytes{}).has_value())
                << "the public Extract* shims return nullopt exactly when the core fails";
            EXPECT_FALSE(GxBuild::ExtractAll(malformed, cpu_key).has_value())
                << "the public Extract* shims return nullopt exactly when the core fails";
            EXPECT_TRUE(GxBuild::ExtractAll(*built, cpu_key).has_value())
                << "the public Extract* shims return nullopt exactly when the core fails";
        }

    } // namespace
} // namespace gxbuild3::orchestration
