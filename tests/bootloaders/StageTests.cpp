// Direct tests for src/nand/bootloaders/Stage.hpp, covering what the bootloader corpus
// (tests/golden/wire_corpus_bootloaders.txt) does not reach through the stage classes: the
// parse failures and their messages, payload padding, crypt_stage_record against a plain
// crypt_single_bl over the serialized stage (crypt starts 0x20 and 0x30), its failure path
// leaving the stage untouched, and randomize_zero_nonce on zero and set nonces.

#include "Error.hpp"
#include "bootloaders/StageBytes.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string_view>

namespace gxbuild3::bootloaders {
    namespace {

        namespace stage = nand::stage;
        using test::Bytes;

        TEST(Stage, ParseStageKeepsHeaderAndPayloadAndRefusesShortOrUndersizedStages) {
            const Bytes short_image(sizeof(nand::sc_header) - 1, 0);
            EXPECT_ERROR_MSG(stage::parse_stage<nand::sc_header>(short_image, "SC/3BL"),
                             ErrorCode::Truncated, "SC/3BL data too short")
                << "parse_stage refuses bytes shorter than the header with the stage message";

            const Bytes undersized =
                stage_bytes(nand::CG, sizeof(nand::cg_header) + 0x20, 0x10, Fill::Counting);
            const auto undersized_parse = stage::parse_stage<nand::cg_header>(undersized, "CG/7BL");
            EXPECT_ERROR(undersized_parse, ErrorCode::Malformed)
                << "parse_stage refuses a declared size smaller than the header";
            EXPECT_TRUE(
                !undersized_parse.has_value() &&
                undersized_parse.error().describe().starts_with("CG/7BL declared size 0x10"))
                << "parse_stage refuses a declared size smaller than the header";

            const Bytes image =
                stage_bytes(nand::SC, sizeof(nand::sc_header) + 0x40,
                            static_cast<uint32_t>(sizeof(nand::sc_header) + 0x40), Fill::Counting);
            const auto parsed = stage::parse_stage<nand::sc_header>(image, "SC/3BL");
            ASSERT_OK(parsed) << "parse_stage accepts a well-formed SC";
            EXPECT_EQ(parsed->header.header.magic, nand::SC) << "parse_stage decodes the magic";
            EXPECT_EQ(parsed->header.header.size, sizeof(nand::sc_header) + 0x40)
                << "parse_stage decodes the declared size";
            EXPECT_BYTES_EQ(Bytes(image.begin() + sizeof(nand::sc_header), image.end()),
                            parsed->data)
                << "parse_stage keeps the bytes after the header as the payload";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(parsed->header, parsed->data))
                << "serialize_stage reproduces the parsed image";
        }

        TEST(Stage, PayloadSizeIsTheAlignedSizeMinusTheHeaderAndPaddingOnlyGrowsWithZeros) {
            nand::sc_header header{};
            header.header.size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x31);
            const auto size = stage::stage_payload_size(header, "SC/3BL");
            EXPECT_OK(size) << "stage_payload_size is the aligned size minus the header";
            EXPECT_EQ(size.value_or(0), 0x40u)
                << "stage_payload_size is the aligned size minus the header";

            header.header.size = 0x10;
            EXPECT_ERROR(stage::stage_payload_size(header, "SC/3BL"), ErrorCode::Malformed)
                << "stage_payload_size refuses a declared size smaller than the header";

            Bytes data(0x10, 0xAB);
            stage::pad_payload(data, 0x40);
            Bytes padded(0x40, 0x00);
            std::fill_n(padded.begin(), 0x10, uint8_t{0xAB});
            EXPECT_BYTES_EQ(padded, data) << "pad_payload grows the payload with zeros";
            stage::pad_payload(data, 0x20);
            EXPECT_EQ(data.size(), 0x40u) << "pad_payload never shrinks the payload";
        }

        // crypt_stage_record must give exactly what crypt_single_bl gives over the serialized
        // stage. Its ASSERTs end the calling case.
        template <class H>
        void check_crypt_matches_packer(const Bytes& image, size_t crypt_start,
                                        nand::HmacType hmac_type, const uint8_t* cpu_key,
                                        std::string_view label) {
            const std::array<uint8_t, 16> key = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                                                 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
            const auto parsed = stage::parse_stage<H>(image, label);
            ASSERT_OK(parsed) << label << " parses";

            Bytes expected = image;
            std::array<uint8_t, 16> expected_key = key;
            ASSERT_OK(nand::crypt_single_bl(expected, hmac_type, expected_key.data(), cpu_key,
                                            nullptr, crypt_start))
                << label << " crypt_single_bl succeeds";

            H header = parsed->header;
            Bytes data = parsed->data;
            const auto derived = stage::crypt_stage_record(header, data, hmac_type, key.data(),
                                                           cpu_key, crypt_start, label);
            ASSERT_OK(derived) << label << " crypt_stage_record succeeds";
            EXPECT_BYTES_EQ(expected, stage::serialize_stage(header, data))
                << label << " crypt_stage_record matches crypt_single_bl byte for byte";
            EXPECT_BYTES_EQ(expected_key, *derived)
                << label << " crypt_stage_record returns the derived key";

            EXPECT_OK(stage::crypt_stage_record(header, data, hmac_type, key.data(), cpu_key,
                                                crypt_start, label))
                << label << " a second crypt_stage_record restores the image";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(header, data))
                << label << " a second crypt_stage_record restores the image";
        }

        TEST(StageCryptRecord, ScMatchesCryptSingleBlFromCryptStart0x20) {
            const auto sc_size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x60);
            check_crypt_matches_packer<nand::sc_header>(
                stage_bytes(nand::SC, sc_size, sc_size, Fill::Counting), 0x20,
                nand::HmacType::Default, nullptr, "SC/3BL");
        }

        TEST(StageCryptRecord, CdMatchesCryptSingleBlUnderTheCpuKeyedHmac1920) {
            const std::array<uint8_t, 16> cpu_key = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
                                                     0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
                                                     0xCC, 0xCD, 0xCE, 0xCF};
            const auto cd_size = static_cast<uint32_t>(sizeof(nand::cd_header) + 0x40);
            check_crypt_matches_packer<nand::cd_header>(
                stage_bytes(nand::CD, cd_size, cd_size, Fill::Counting), 0x20,
                nand::HmacType::Hmac1920, cpu_key.data(), "CD/4BL");
        }

        TEST(StageCryptRecord, CfMatchesCryptSingleBlFromCryptStart0x30) {
            const auto cf_size = static_cast<uint32_t>(sizeof(nand::cf_header) + 0x200);
            check_crypt_matches_packer<nand::cf_header>(
                stage_bytes(nand::CF, cf_size, cf_size, Fill::Counting), 0x30,
                nand::HmacType::Default, nullptr, "CF/6BL");
        }

        TEST(StageCryptRecord, AFailedCryptLeavesHeaderAndPayloadUntouched) {
            const auto size = static_cast<uint32_t>(sizeof(nand::sc_header) + 0x20);
            const Bytes image = stage_bytes(nand::SC, size, size, Fill::Counting);
            const auto parsed = stage::parse_stage<nand::sc_header>(image, "SC/3BL");
            ASSERT_OK(parsed) << "failure fixture parses";
            const uint8_t key[16] = {};
            nand::sc_header header = parsed->header;
            Bytes data = parsed->data;

            // Hmac1920 without a CPU key is refused by crypt_single_bl before it writes anything.
            EXPECT_ERROR_MSG(stage::crypt_stage_record(header, data, nand::HmacType::Hmac1920, key,
                                                       nullptr, 0x20, "SC/3BL"),
                             ErrorCode::InvalidArgument,
                             "SC/3BL: bootloader HMAC type needs a CPU key")
                << "crypt_stage_record adds the stage context to a crypt failure";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(header, data))
                << "a failed crypt_stage_record leaves header and payload untouched";

            // A crypt start past the end of the stage is Truncated.
            EXPECT_ERROR(stage::crypt_stage_record(header, data, nand::HmacType::Default, key,
                                                   nullptr, image.size() + 1, "SC/3BL"),
                         ErrorCode::Truncated)
                << "crypt_stage_record refuses a crypt start past the stage";
            EXPECT_BYTES_EQ(image, stage::serialize_stage(header, data))
                << "a truncated crypt_stage_record leaves header and payload untouched";
        }

        TEST(StageNonce, ANonceWithAnySetByteIsKept) {
            std::array<uint8_t, 16> set_nonce{};
            set_nonce[15] = 0x01;
            const auto kept = set_nonce;
            stage::randomize_zero_nonce(set_nonce);
            EXPECT_BYTES_EQ(kept, set_nonce)
                << "randomize_zero_nonce keeps a nonce with any set byte";
        }

        TEST(StageNonce, AnAllZeroNonceGetsAFreshDraw) {
            std::array<uint8_t, 16> zero_nonce{};
            stage::randomize_zero_nonce(zero_nonce);
            EXPECT_TRUE(std::any_of(zero_nonce.begin(), zero_nonce.end(), [](uint8_t b) {
                return b != 0;
            })) << "randomize_zero_nonce draws a fresh nonce for an all-zero one";
        }

    } // namespace
} // namespace gxbuild3::bootloaders
