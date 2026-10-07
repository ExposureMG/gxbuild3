// The E8a behaviour changes in the bootloader stages: parse refuses a declared size that cannot
// hold the stage's own header (decrypt and encrypt used to underflow the payload length); a crypt
// that cannot run leaves the stage as it was instead of flipping `decrypted` over an untouched or
// underflowing payload; crypt_single_bl reports short data instead of returning a bool every
// stage ignored, touching neither the data nor the key; and calc_mac reports what stops it
// instead of silently skipping.

#include "Error.hpp"
#include "bootloaders/StageBytes.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "support/Expect.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::bootloaders {
    namespace {

        using test::Bytes;

        // Parses `bytes` as Stage and keeps only whether it parsed.
        template <class Stage> Result<> parse_as(std::span<const uint8_t> bytes) {
            return Stage::parse(bytes).transform([](const Stage&) {});
        }

        // One stage image each: the refusal parse gives it, or none when it parses.
        struct DeclaredSizeRow {
            const char* name;
            Result<> (*parse)(std::span<const uint8_t>);
            Bytes image;
            std::optional<ErrorCode> refusal;
            const char* message;
        };
        GX_PRINT_ROW_AS_NAME(DeclaredSizeRow)

        std::vector<DeclaredSizeRow> declared_size_rows() {
            using namespace nand;
            return {
                {"CbShorterThanItsGenericHeader", parse_as<BootloaderCb>, Bytes(8, 0),
                 ErrorCode::Truncated, "CB shorter than its generic header is truncated"},
                {"CbDeclaringLessThanItsGenericHeader", parse_as<BootloaderCb>,
                 stage_bytes(CB, 0x40, 0, Fill::Zero), ErrorCode::Malformed,
                 "CB declaring less than its generic header is refused"},
                {"CbDeclaringItsOwnLength", parse_as<BootloaderCb>,
                 stage_bytes(CB, 0x40, 0x40, Fill::Zero), std::nullopt,
                 "CB declaring its own length parses"},
                {"ScDeclaringLessThanItsHeader", parse_as<BootloaderSc>,
                 stage_bytes(SC, sizeof(sc_header) + 0x20, 0x20, Fill::Zero), ErrorCode::Malformed,
                 "SC declaring less than its header is refused"},
                {"CdDeclaringLessThanItsHeader", parse_as<BootloaderCd>,
                 stage_bytes(CD, sizeof(cd_header) + 0x20, 0x20, Fill::Zero), ErrorCode::Malformed,
                 "CD declaring less than its header is refused"},
                {"CdDeclaringASizeThatOverflowsWhenAligned", parse_as<BootloaderCd>,
                 stage_bytes(CD, sizeof(cd_header) + 0x20, 0xFFFFFFF8, Fill::Zero),
                 ErrorCode::Malformed,
                 "CD declaring a size that overflows when aligned is refused"},
                {"CeDeclaringLessThanItsHeader", parse_as<BootloaderCe>,
                 stage_bytes(CE, sizeof(ce_header) + 0x20, 0x10, Fill::Zero), ErrorCode::Malformed,
                 "CE declaring less than its header is refused"},
                {"CfDeclaringLessThanItsHeader", parse_as<BootloaderCf>,
                 stage_bytes(CF, 0x430, 0x10, Fill::Zero), ErrorCode::Malformed,
                 "CF declaring less than its header is refused"},
                {"CgDeclaringLessThanItsHeader", parse_as<BootloaderCg>,
                 stage_bytes(CG, sizeof(cg_header) + 0x20, 0x10, Fill::Zero), ErrorCode::Malformed,
                 "CG declaring less than its header is refused"},
            };
        }

        class StageDeclaredSize : public ::testing::TestWithParam<DeclaredSizeRow> {};

        TEST_P(StageDeclaredSize, ParsesOnlyADeclaredSizeThatHoldsTheStageHeader) {
            const auto& row = GetParam();
            if (row.refusal.has_value()) {
                EXPECT_ERROR(row.parse(row.image), *row.refusal) << row.message;
            } else {
                EXPECT_OK(row.parse(row.image)) << row.message;
            }
        }

        INSTANTIATE_TEST_SUITE_P(Row, StageDeclaredSize, ::testing::ValuesIn(declared_size_rows()),
                                 test::RowName{});

        TEST(StageCryptFailure, ACdCryptWithAnUndersizedDeclaredSizeLeavesTheStageUnchanged) {
            const uint8_t key[16] = {};
            ASSERT_OK_AND_ASSIGN(auto cd, nand::BootloaderCd::parse(stage_bytes(
                                              nand::CD, sizeof(nand::cd_header) + 0x20,
                                              sizeof(nand::cd_header) + 0x20, Fill::Zero)));
            cd.header.header.size = 0x10;
            const Bytes cd_data = cd.data;
            const bool cd_was_decrypted = cd.decrypted;
            EXPECT_ERROR(cd_was_decrypted ? cd.encrypt(key) : cd.decrypt(key), ErrorCode::Malformed)
                << "CD crypt with an undersized declared size fails";
            EXPECT_EQ(cd.decrypted, cd_was_decrypted)
                << "failed CD crypt leaves the stage unchanged";
            EXPECT_BYTES_EQ(cd_data, cd.data) << "failed CD crypt leaves the stage unchanged";
            EXPECT_FALSE(cd.derived_key.has_value())
                << "failed CD crypt leaves the stage unchanged";
        }

        TEST(StageCryptFailure, ACbDecryptOfAHeaderOnlyCbLeavesTheStageUnchanged) {
            const uint8_t key[16] = {};
            ASSERT_OK_AND_ASSIGN(
                auto cb, nand::BootloaderCb::parse(stage_bytes(nand::CB, 0x40, 0x40, Fill::Zero)));
            cb.header.header.size = 0x10;
            const Bytes cb_data = cb.data;
            EXPECT_ERROR(cb.decrypt(key), ErrorCode::Malformed)
                << "CB decrypt of a header-only CB fails and leaves the stage";
            EXPECT_FALSE(cb.decrypted)
                << "CB decrypt of a header-only CB fails and leaves the stage";
            EXPECT_BYTES_EQ(cb_data, cb.data)
                << "CB decrypt of a header-only CB fails and leaves the stage";
            EXPECT_FALSE(cb.derived_key.has_value())
                << "CB decrypt of a header-only CB fails and leaves the stage";
        }

        TEST(StageCryptFailure, ACgDecryptWithAnUndersizedDeclaredSizeLeavesTheStageUnchanged) {
            const uint8_t key[16] = {};
            ASSERT_OK_AND_ASSIGN(auto cg, nand::BootloaderCg::parse(stage_bytes(
                                              nand::CG, sizeof(nand::cg_header) + 0x20,
                                              sizeof(nand::cg_header) + 0x20, Fill::Zero)));
            cg.decrypted = false;
            cg.header.header.size = 0x10;
            const Bytes cg_data = cg.data;
            EXPECT_ERROR(cg.decrypt(key), ErrorCode::Malformed)
                << "CG decrypt with an undersized declared size fails and leaves the stage";
            EXPECT_FALSE(cg.decrypted)
                << "CG decrypt with an undersized declared size fails and leaves the stage";
            EXPECT_BYTES_EQ(cg_data, cg.data)
                << "CG decrypt with an undersized declared size fails and leaves the stage";
        }

        TEST(CryptSingleBl, RefusesShortDataOrAMissingCpuKeyAndTouchesNeitherDataNorKey) {
            Bytes data(0x1F, 0xA5);
            const Bytes original = data;
            uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            const std::array<uint8_t, 16> original_key = {1, 2,  3,  4,  5,  6,  7,  8,
                                                          9, 10, 11, 12, 13, 14, 15, 16};

            EXPECT_ERROR(nand::crypt_single_bl(data, nand::HmacType::Default, key),
                         ErrorCode::Truncated)
                << "crypt_single_bl refuses data shorter than its crypt start";
            EXPECT_BYTES_EQ(original, data)
                << "refused crypt_single_bl leaves data and key untouched";
            EXPECT_BYTES_EQ(original_key, key)
                << "refused crypt_single_bl leaves data and key untouched";

            Bytes cf_sized(0x2F, 0);
            EXPECT_ERROR(nand::crypt_single_bl(cf_sized, nand::HmacType::Default, key, nullptr,
                                               nullptr, 0x30),
                         ErrorCode::Truncated)
                << "crypt_single_bl refuses data shorter than a 0x30 crypt start";

            Bytes full(0x40, 0);
            EXPECT_ERROR(nand::crypt_single_bl(full, nand::HmacType::Hmac1920, key),
                         ErrorCode::InvalidArgument)
                << "crypt_single_bl refuses a CPU-keyed HMAC without a CPU key";
            EXPECT_OK(nand::crypt_single_bl(full, nand::HmacType::Default, key))
                << "crypt_single_bl crypts data that holds its crypt start";

            std::vector<nand::BootloaderBlock> chain(1);
            chain[0].magic = 0x4342;
            chain[0].data.assign(0x10, 0);
            EXPECT_ERROR(nand::crypt_bootloaders(chain, {}), ErrorCode::Truncated)
                << "crypt_bootloaders reports a block too short to crypt";
        }

        TEST(CfCalcMac, ReportsWhatStopsItAndBindsACfThatHoldsItsPerBoxBlock) {
            const uint8_t onebl[16] = {};
            const uint8_t cpu[16] = {1};

            nand::BootloaderCf cf{};
            cf.header.header.magic = nand::CF;
            cf.data.assign(0x1F0, 0);
            cf.header.header.size = static_cast<uint32_t>(sizeof(nand::cf_header) + cf.data.size());
            cf.decrypted = true;
            const Bytes original = cf.data;
            EXPECT_ERROR(cf.calc_mac(onebl, cpu), ErrorCode::Truncated)
                << "calc_mac refuses a CF too short for its per-box block";
            EXPECT_BYTES_EQ(original, cf.data)
                << "calc_mac refuses a CF too short for its per-box block";
            EXPECT_ERROR(cf.calc_mac(onebl, nullptr), ErrorCode::InvalidArgument)
                << "calc_mac refuses a missing CPU key";

            cf.data.assign(0x340, 0);
            cf.header.header.size = static_cast<uint32_t>(sizeof(nand::cf_header) + cf.data.size());
            ASSERT_OK(cf.parse_perbox()) << "calc_mac binds a CF that holds its per-box block";
            ASSERT_OK(cf.calc_mac(onebl, cpu))
                << "calc_mac binds a CF that holds its per-box block";
            ASSERT_TRUE(cf.perbox.has_value())
                << "calc_mac binds a CF that holds its per-box block";
            EXPECT_BYTES_EQ(
                cf.perbox->per_box_digest,
                std::span<const uint8_t>(cf.data).subspan(0x1F0, sizeof(cf.perbox->per_box_digest)))
                << "calc_mac writes the digest to both the payload and the per-box copy";
        }

    } // namespace
} // namespace gxbuild3::bootloaders
