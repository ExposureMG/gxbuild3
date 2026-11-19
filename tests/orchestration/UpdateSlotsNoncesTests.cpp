// run_build's update slots and stage nonces (src/BuildRunner.cpp, src/nand/FlashImage.cpp):
// UpdateSlots: a slot-zero CG too large for its slot spills while both supplied update slots
// survive. StageNonces: a fresh build seals CB, CD and CE under freshly drawn nonces (two builds,
// probabilistic and never pinned), the donor nonces seal the stages by chain position and every
// update slot alike, and extraction takes the CF LDV, pairing and CF/CG nonces from the donor slot
// stating the largest LDV, which a rebuild over the donor reuses. ClearBootloaderChain: clearing a
// donor's chain clears header-only CB and CD records, and a header-only required CD in the Input
// is refused. One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BootloaderCb;
        using nand::BootloaderCd;
        using nand::BootloaderCg;
        using nand::FlashImage;
        using nand::NANDBootloaderMagic;
        using test::Bytes;

        // Whether `nonce` is present and holds the nonce slot (first 0x10 bytes) of `stage`.
        ::testing::AssertionResult holds_nonce_of(const std::optional<BootloaderNonce>& nonce,
                                                  std::span<const uint8_t> stage) {
            if (!nonce) {
                return ::testing::AssertionFailure() << "the nonce is absent";
            }
            const auto expected = test::nonce_bytes(stage);
            if (!std::equal(nonce->begin(), nonce->end(), expected.begin(), expected.end())) {
                return ::testing::AssertionFailure() << "the nonce differs from the stage's";
            }
            return ::testing::AssertionSuccess();
        }

        TEST(UpdateSlots, SlotZeroSpillsAndPreservesSlotOne) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            const auto [cf0, ignored_cg0] = test::valid_system_update(0x51);
            const auto [cf1, cg1] = test::valid_system_update(0x61);
            BootloaderCg cg0{};
            cg0.header.header.magic = NANDBootloaderMagic::CG;
            cg0.header.header.version = 1;
            cg0.data.assign(0x10000, 0x7A);
            cg0.header.header.size =
                static_cast<uint32_t>(sizeof(nand::cg_header) + cg0.data.size());
            input.bootloaders.cf0 = cf0;
            input.bootloaders.cg0 = cg0.serialize();
            input.bootloaders.cf1 = cf1;
            input.bootloaders.cg1 = cg1;

            input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
            constexpr const char* kSlots = "slot-zero CG spills while both supplied update slots "
                                           "survive";
            const auto built = run_build(input);
            ASSERT_OK(built) << kSlots;
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << kSlots;
            ASSERT_OK(image->parse()) << kSlots;
            EXPECT_EQ(image->header.patch_slots.get(), 2u) << kSlots;
            EXPECT_FALSE(image->system_update_0.cg_spill_blocks.empty()) << kSlots;
            ASSERT_TRUE(image->system_update_0.cf.has_value()) << kSlots;
            ASSERT_TRUE(image->system_update_0.cg.has_value()) << kSlots;
            ASSERT_TRUE(image->system_update_1.cf.has_value()) << kSlots;
            ASSERT_TRUE(image->system_update_1.cg.has_value()) << kSlots;

            ASSERT_OK_AND_ASSIGN(const auto slot_zero,
                                 test::opened_cg(image->system_update_0.cf->serialize(),
                                                 image->system_update_0.cg->serialize()));
            ASSERT_OK_AND_ASSIGN(const auto supplied_zero, test::opened_cg(cf0, cg0.serialize()));
            ASSERT_TRUE(slot_zero.has_value()) << kSlots;
            ASSERT_TRUE(supplied_zero.has_value()) << kSlots;
            EXPECT_BYTES_EQ(*supplied_zero, *slot_zero) << kSlots << " (slot 0 CG)";

            ASSERT_OK_AND_ASSIGN(const auto slot_one,
                                 test::opened_cg(image->system_update_1.cf->serialize(),
                                                 image->system_update_1.cg->serialize()));
            ASSERT_OK_AND_ASSIGN(const auto supplied_one, test::opened_cg(cf1, cg1));
            ASSERT_TRUE(slot_one.has_value()) << kSlots;
            ASSERT_TRUE(supplied_one.has_value()) << kSlots;
            EXPECT_BYTES_EQ(*supplied_one, *slot_one) << kSlots << " (slot 1 CG)";
        }

        TEST(StageNonces, FreshBuildSealsStagesUnderRandomNonces) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.bootloaders.ce = test::valid_ce();
            const auto first = run_build(input);
            const auto second = run_build(input);
            constexpr const char* kFixture = "fresh nonce fixtures build and parse";
            ASSERT_OK(first) << kFixture;
            ASSERT_OK(second) << kFixture;
            auto one = parse_image(*first);
            auto two = parse_image(*second);
            ASSERT_TRUE(one.has_value()) << kFixture;
            ASSERT_TRUE(two.has_value()) << kFixture;
            ASSERT_TRUE(one->kernel_section.ce.has_value()) << kFixture;
            ASSERT_TRUE(two->kernel_section.ce.has_value()) << kFixture;

            const auto nonces = [](const FlashImage& image) {
                return std::array<Bytes, 3>{test::nonce_bytes(image.cb_section.cb_or_A.data),
                                            test::nonce_bytes(image.kernel_section.cd.header.key),
                                            test::nonce_bytes(image.kernel_section.ce->header.key)};
            };
            const auto first_nonces = nonces(*one);
            const auto second_nonces = nonces(*two);
            constexpr std::array<const char*, 3> kStages{"CB", "CD", "CE"};
            for (size_t index = 0; index < first_nonces.size(); ++index) {
                SCOPED_TRACE(kStages[index]);
                // Drawn nonces are compared, never printed.
                EXPECT_TRUE(first_nonces[index] != Bytes(0x10, 0))
                    << "fresh CB, CD and CE take non-zero nonces";
                EXPECT_TRUE(first_nonces[index] != second_nonces[index])
                    << "each fresh build draws new nonces";
            }
            EXPECT_TRUE(first_nonces[2] != Bytes(0x10, 0x55))
                << "a fresh CE does not keep its template's nonce";

            constexpr const char* kOpens = "stages sealed under fresh nonces decrypt to their "
                                           "payloads";
            ASSERT_OK(one->decrypt_all(input.metadata.cpu_key)) << kOpens;
            EXPECT_BYTES_EQ(Bytes(0x20, 0x42), one->kernel_section.cd.data) << kOpens;
            EXPECT_BYTES_EQ(Bytes(0x20, 0xCE), one->kernel_section.ce->data) << kOpens;
        }

        TEST(StageNonces, DonorNoncesSealStagesByPositionAndEverySlotAlike) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.bootloaders.ce = test::valid_ce();
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf0, test::decrypted_cf(3, {0x11, 0x12, 0x13}));
            input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf1, test::decrypted_cf(4, {0x11, 0x12, 0x13}));
            input.bootloaders.cg1 = test::valid_system_update(0x61).second;
            DonorNonces nonces{};
            nonces.stages = {test::filled_nonce(0xA1), test::filled_nonce(0xA2),
                             test::filled_nonce(0xA3), test::filled_nonce(0xA4)};
            nonces.cf = test::filled_nonce(0xB1);
            nonces.cg = test::filled_nonce(0xC1);
            input.metadata.donor_nonces = nonces;

            const auto built = run_build(input);
            constexpr const char* kFixture = "donor nonce fixture builds and parses";
            ASSERT_OK(built) << kFixture;
            auto image = parse_image(*built);
            ASSERT_TRUE(image.has_value()) << kFixture;
            ASSERT_TRUE(image->kernel_section.ce.has_value()) << kFixture;
            ASSERT_TRUE(image->system_update_0.cf.has_value()) << kFixture;
            ASSERT_TRUE(image->system_update_0.cg.has_value()) << kFixture;
            ASSERT_TRUE(image->system_update_1.cf.has_value()) << kFixture;
            ASSERT_TRUE(image->system_update_1.cg.has_value()) << kFixture;

            constexpr const char* kStages = "first CB, CD and CE take the donor nonces of their "
                                            "positions";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xA1), test::nonce_bytes(image->cb_section.cb_or_A.data))
                << kStages << " (CB)";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xA3),
                            test::nonce_bytes(image->kernel_section.cd.header.key))
                << kStages << " (CD)";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xA4),
                            test::nonce_bytes(image->kernel_section.ce->header.key))
                << kStages << " (CE)";

            constexpr const char* kSlots = "every update slot takes the donor CF and CG nonces";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xB1),
                            test::nonce_bytes(image->system_update_0.cf->header.fixpoint_nonce))
                << kSlots << " (CF0)";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xB1),
                            test::nonce_bytes(image->system_update_1.cf->header.fixpoint_nonce))
                << kSlots << " (CF1)";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xC1),
                            test::nonce_bytes(image->system_update_0.cg->header.key))
                << kSlots << " (CG0)";
            EXPECT_BYTES_EQ(Bytes(0x10, 0xC1),
                            test::nonce_bytes(image->system_update_1.cg->header.key))
                << kSlots << " (CG1)";

            constexpr const char* kOpens = "stages sealed under donor nonces decrypt to their "
                                           "payloads";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key)) << kOpens;
            EXPECT_BYTES_EQ(Bytes(0x20, 0x42), image->kernel_section.cd.data) << kOpens;
            EXPECT_BYTES_EQ(Bytes(0x20, 0xCE), image->kernel_section.ce->data) << kOpens;
        }

        TEST(StageNonces, ExtractionTakesCfMetadataAndNoncesFromTheMaxLdvSlot) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            const auto& cpu_key = source.metadata.cpu_key;
            source.bootloaders.ce = test::valid_ce();
            ASSERT_OK_AND_ASSIGN(source.bootloaders.cf0, test::decrypted_cf(3, {0x11, 0x12, 0x13}));
            source.bootloaders.cg0 = test::valid_system_update(0x51).second;
            ASSERT_OK_AND_ASSIGN(source.bootloaders.cf1, test::decrypted_cf(7, {0x11, 0x12, 0x13}));
            source.bootloaders.cg1 = test::valid_system_update(0x61).second;
            source.metadata.pairing_data = {0x21, 0x22, 0x23};
            const auto built = run_build(source);

            // Slot 1 states its own pairing, as after an update installed under other pairing.
            constexpr const char* kFixture = "max-LDV donor fixture builds and decrypts";
            ASSERT_OK(built) << kFixture;
            auto staged = parse_image(*built);
            ASSERT_TRUE(staged.has_value()) << kFixture;
            ASSERT_OK(staged->decrypt_all(cpu_key)) << kFixture;
            ASSERT_TRUE(staged->system_update_1.cf.has_value()) << kFixture;
            ASSERT_TRUE(staged->system_update_1.cf->perbox.has_value()) << kFixture;
            const std::array<uint8_t, 3> slot_one_pairing{0x31, 0x32, 0x33};
            std::copy(slot_one_pairing.begin(), slot_one_pairing.end(),
                      staged->system_update_1.cf->perbox->pairing_data);
            ASSERT_OK(staged->encrypt_all(cpu_key)) << "max-LDV donor fixture re-encrypts";

            constexpr const char* kExtracts = "max-LDV donor fixture extracts";
            const auto written = staged->write();
            ASSERT_OK(written) << kExtracts;
            const Bytes& donor = *written;
            const auto donor_image = parse_image(donor);
            const auto extracted = extract_all(donor, cpu_key);
            const auto metadata = extract_metadata(donor, cpu_key);
            ASSERT_TRUE(donor_image.has_value()) << kExtracts;
            ASSERT_OK(extracted) << kExtracts;
            ASSERT_OK(metadata) << kExtracts;
            ASSERT_TRUE(extracted->metadata.donor_nonces.has_value()) << kExtracts;
            ASSERT_TRUE(metadata->donor_nonces.has_value()) << kExtracts;
            ASSERT_TRUE(donor_image->kernel_section.ce.has_value()) << kExtracts;
            ASSERT_TRUE(donor_image->system_update_1.cf.has_value()) << kExtracts;
            ASSERT_TRUE(donor_image->system_update_1.cg.has_value()) << kExtracts;
            const auto& nonces = *extracted->metadata.donor_nonces;

            constexpr const char* kCfMetadata = "CF LDV and pairing come from the max-LDV donor "
                                                "slot";
            EXPECT_EQ(extracted->metadata.cf_ldv, 7) << kCfMetadata << " (extract_all)";
            EXPECT_EQ(extracted->metadata.cf_pairing_data, slot_one_pairing)
                << kCfMetadata << " (extract_all)";
            EXPECT_EQ(metadata->cf_ldv, 7) << kCfMetadata << " (extract_metadata)";
            EXPECT_EQ(metadata->cf_pairing_data, slot_one_pairing)
                << kCfMetadata << " (extract_metadata)";

            constexpr const char* kSlotNonces = "donor CF and CG nonces come from the max-LDV slot";
            EXPECT_TRUE(
                holds_nonce_of(nonces.cf, donor_image->system_update_1.cf->header.fixpoint_nonce))
                << kSlotNonces << " (CF)";
            EXPECT_TRUE(holds_nonce_of(nonces.cg, donor_image->system_update_1.cg->header.key))
                << kSlotNonces << " (CG)";

            constexpr const char* kStageOrder = "donor stage nonces are read by chain position";
            EXPECT_TRUE(holds_nonce_of(nonces.stages[0], donor_image->cb_section.cb_or_A.data))
                << kStageOrder << " (CB_A)";
            EXPECT_FALSE(nonces.stages[1].has_value()) << kStageOrder << " (no second CB)";
            EXPECT_TRUE(holds_nonce_of(nonces.stages[2], donor_image->kernel_section.cd.header.key))
                << kStageOrder << " (CD)";
            EXPECT_TRUE(
                holds_nonce_of(nonces.stages[3], donor_image->kernel_section.ce->header.key))
                << kStageOrder << " (CE)";

            auto rebuild = *extracted;
            rebuild.bootloaders = source.bootloaders;
            const auto rebuilt = run_build(rebuild);
            constexpr const char* kReuse = "a rebuild over the donor reuses its CB and max-LDV CF "
                                           "and CG nonces";
            ASSERT_OK(rebuilt) << kReuse;
            auto image = parse_image(*rebuilt);
            ASSERT_TRUE(image.has_value()) << kReuse;
            ASSERT_OK(image->decrypt_all(cpu_key)) << kReuse;
            ASSERT_TRUE(image->system_update_0.cf.has_value()) << kReuse;
            ASSERT_TRUE(image->system_update_0.cg.has_value()) << kReuse;
            ASSERT_TRUE(image->system_update_1.cf.has_value()) << kReuse;
            ASSERT_TRUE(image->system_update_1.cg.has_value()) << kReuse;
            const auto donor_cf_nonce =
                test::nonce_bytes(donor_image->system_update_1.cf->header.fixpoint_nonce);
            const auto donor_cg_nonce =
                test::nonce_bytes(donor_image->system_update_1.cg->header.key);
            EXPECT_BYTES_EQ(test::nonce_bytes(donor_image->cb_section.cb_or_A.data),
                            test::nonce_bytes(image->cb_section.cb_or_A.data))
                << kReuse << " (CB)";
            EXPECT_BYTES_EQ(donor_cf_nonce,
                            test::nonce_bytes(image->system_update_0.cf->header.fixpoint_nonce))
                << kReuse << " (CF0)";
            EXPECT_BYTES_EQ(donor_cf_nonce,
                            test::nonce_bytes(image->system_update_1.cf->header.fixpoint_nonce))
                << kReuse << " (CF1)";
            EXPECT_BYTES_EQ(donor_cg_nonce,
                            test::nonce_bytes(image->system_update_0.cg->header.key))
                << kReuse << " (CG0)";
            EXPECT_BYTES_EQ(donor_cg_nonce,
                            test::nonce_bytes(image->system_update_1.cg->header.key))
                << kReuse << " (CG1)";

            constexpr const char* kRebuiltCf = "the rebuilt CF states the max-LDV slot's LDV and "
                                               "pairing";
            ASSERT_TRUE(image->system_update_0.cf->perbox.has_value()) << kRebuiltCf;
            EXPECT_EQ(image->system_update_0.cf->perbox->lockdown_value, 7) << kRebuiltCf;
            EXPECT_BYTES_EQ(slot_one_pairing, image->system_update_0.cf->perbox->pairing_data)
                << kRebuiltCf;
        }

        TEST(ClearBootloaderChain, ClearsHeaderOnlyCbAndCdRecords) {
            const auto source = run_build(test::fresh_input(ImageType::SmallBlock));
            constexpr const char* kSource = "source donor for header-only chain parses";
            ASSERT_OK(source) << kSource;
            auto donor = FlashImage::read(*source);
            ASSERT_TRUE(donor.has_value()) << kSource;
            ASSERT_OK(donor->parse()) << kSource;

            BootloaderCb cb{};
            cb.header.header.magic = NANDBootloaderMagic::CB;
            cb.header.header.version = 1;
            cb.header.header.size = sizeof(nand::generic_header);
            BootloaderCd cd{};
            cd.header.header.magic = NANDBootloaderMagic::CD;
            cd.header.header.version = 1;
            cd.header.header.size = sizeof(nand::cd_header);
            const auto cb_bytes = cb.serialize();
            const auto cd_bytes = cd.serialize();

            constexpr const char* kHeaderOnly = "raw donor exposes valid parsed header-only CB and "
                                                "CD records";
            ASSERT_TRUE(donor->flash_driver.write_offset(0x8000, Bytes(0x1000, 0))) << kHeaderOnly;
            ASSERT_TRUE(donor->flash_driver.write_offset(0x8000, cb_bytes)) << kHeaderOnly;
            ASSERT_TRUE(donor->flash_driver.write_offset(0x8000 + cb_bytes.size(), cd_bytes))
                << kHeaderOnly;
            const auto header_only_bytes = donor->flash_driver.serialize();
            auto header_only = FlashImage::read(header_only_bytes);
            ASSERT_TRUE(header_only.has_value()) << kHeaderOnly;
            ASSERT_OK(header_only->parse()) << kHeaderOnly;
            ASSERT_TRUE(header_only->cb_section.cb_or_A.data.empty()) << kHeaderOnly;
            ASSERT_EQ(header_only->cb_section.cb_or_A.header.header.magic.get(),
                      std::to_underlying(NANDBootloaderMagic::CB))
                << kHeaderOnly;
            ASSERT_TRUE(header_only->kernel_section.cd.data.empty()) << kHeaderOnly;
            ASSERT_EQ(header_only->kernel_section.cd.header.header.magic.get(),
                      std::to_underlying(NANDBootloaderMagic::CD))
                << kHeaderOnly;

            constexpr const char* kCleared = "clearing a donor includes the full header-only CB "
                                             "and CD chain";
            ASSERT_OK(header_only->clear_bootloader_chain()) << kCleared;
            const auto cleared_bytes = std::as_const(header_only->flash_driver)
                                           .read_offset(0x8000, cb_bytes.size() + cd_bytes.size());
            EXPECT_BYTES_EQ(Bytes(cb_bytes.size() + cd_bytes.size(), 0), cleared_bytes) << kCleared;

            auto invalid_replacement = test::fresh_input(ImageType::SmallBlock);
            invalid_replacement.bootloaders.cd = cd_bytes;
            EXPECT_ERROR(run_build(invalid_replacement), BuildErrorCode::InvalidBootloader)
                << "a replacement header-only required CD remains structurally invalid";
        }

    } // namespace
} // namespace gxbuild3::orchestration
