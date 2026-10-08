// run_build's mobile blobs and settings blocks (src/BuildRunner.cpp, src/nand/FlashImage.cpp):
// an eMMC anchor lays mobiles 0x31-0x34 and drops the rest, a NAND donor keeps its geometry and
// takes high mobiles, an overlay replaces exactly the slots it names (no stale donor tail, never
// more than one block), mobile allocation skips a bad donor block, stays out of the SMC tail and
// off the fixed payloads; RunBuildSettings: the settings, statistics and manufacturing blocks
// follow the console into another layout. One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Stages.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::orchestration {
    namespace {

        using nand::Driver;
        using nand::FlashImage;
        using test::Bytes;

        // An eMMC anchor names four blobs, types 0x31-0x34. Those are laid; 0x35-0x39 are left
        // out with a warning and the build goes on. Builds `input` and names the first slot that
        // breaks that rule.
        ::testing::AssertionResult emmc_keeps_anchor_mobiles_only(const Input& input,
                                                                  std::string_view what) {
            const auto built = run_build(input);
            if (!built) {
                return ::testing::AssertionFailure()
                       << what << ": eMMC build with mobile data succeeds ("
                       << built.error().message << ")";
            }
            const auto parsed = parse_image(*built);
            if (!parsed || !parsed->mobile_data) {
                return ::testing::AssertionFailure()
                       << what << ": eMMC build with mobile data succeeds";
            }
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                const auto* given = input.mobiles.slot(block_type);
                const auto* laid = parsed->mobile_data->get_slot(block_type);
                const bool expected = block_type <= 0x34 && given && *given;
                if (!(expected ? *laid == *given : !laid->has_value())) {
                    return ::testing::AssertionFailure()
                           << what << ": eMMC lays mobiles 0x31-0x34 and drops the rest (type 0x"
                           << std::hex << static_cast<unsigned>(block_type)
                           << (expected ? " is not laid as given)" : " is laid)");
                }
            }
            return ::testing::AssertionSuccess();
        }

        TEST(RunBuildMobile, EmmcLaysFourAnchorMobilesAndDropsTheRest) {
            auto input = test::fresh_input(ImageType::Emmc);
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                *input.mobiles.slot(block_type) = Bytes(0x800, block_type);
            }
            *input.mobiles.slot(0x32) = Bytes(0x200, 0x32);
            EXPECT_TRUE(emmc_keeps_anchor_mobiles_only(input, "fresh eMMC"));
        }

        TEST(RunBuildMobile, EmmcDonorLaysFourAnchorMobilesAndDropsTheRest) {
            const auto donor = run_build(test::fresh_input(ImageType::Emmc));
            ASSERT_OK(donor) << "eMMC donor fixture builds";
            // The donor's eMMC geometry wins over the requested small block.
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
                *input.mobiles.slot(block_type) = Bytes{block_type};
            }
            EXPECT_TRUE(emmc_keeps_anchor_mobiles_only(input, "eMMC donor"));
        }

        TEST(RunBuildMobile, NandDonorAcceptsHighMobileWhenRequestedTypeIsEmmc) {
            auto input = test::fresh_input(ImageType::Emmc);
            ASSERT_OK_AND_ASSIGN(input.metadata.nand_image, test::make_donor(input, {}));
            *input.mobiles.slot(0x33) = Bytes{0x33, 0xCC};

            const auto built = run_build(input);
            ASSERT_OK(built) << "NAND donor accepts high mobile input despite requested eMMC";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value()) << "NAND donor retains its effective geometry";
            EXPECT_EQ(parsed->flash_driver.driver_mode(), Driver::DriverMode::Small)
                << "NAND donor retains its effective geometry";
            ASSERT_TRUE(parsed->mobile_data.has_value())
                << "NAND donor persists the high mobile replacement";
            EXPECT_EQ(parsed->mobile_data->x33, *input.mobiles.slot(0x33))
                << "NAND donor persists the high mobile replacement";
        }

        TEST(RunBuildMobile, DonorOverlaysReplaceExplicitValuesAndPreserveMobileSlots) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(input.metadata.nand_image,
                                 test::make_donor(input, {{0x31, Bytes{1}}, {0x32, Bytes{2}}}));
            input.metadata.smc = test::make_smc(0xA1);
            input.metadata.keyvault = test::canonical_keyvault(input.metadata.cpu_key,
                                                               Bytes(nand::Keyvault::kSize, 0xB2));
            *input.mobiles.slot(0x32) = Bytes{9};

            const auto built = run_build(input);
            ASSERT_OK(built) << "donor overlay build succeeds";
            auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value()) << "built donor image parses";
            ASSERT_TRUE(parsed->mobile_data.has_value()) << "built donor image has mobile data";
            EXPECT_EQ(parsed->mobile_data->x31, Bytes{1}) << "unmodified donor mobile survives";
            EXPECT_EQ(parsed->mobile_data->x32, Bytes{9}) << "user mobile replaces donor mobile";

            ASSERT_OK(parsed->decrypt_all(input.metadata.cpu_key))
                << "built donor components decrypt";
            ASSERT_TRUE(parsed->smc.has_value()) << "user SMC replaces donor SMC";
            EXPECT_BYTES_EQ(*input.metadata.smc, parsed->smc->data)
                << "user SMC replaces donor SMC";
            ASSERT_TRUE(parsed->keyvault.has_value()) << "user keyvault replaces donor keyvault";
            EXPECT_BYTES_EQ(*input.metadata.keyvault, parsed->keyvault->serialize())
                << "user keyvault replaces donor keyvault";
        }

        TEST(RunBuildMobile, OverlayReplacesLongerDonorMobileWithoutStaleTail) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(input.metadata.nand_image,
                                 test::make_donor(input, {{0x32, Bytes(0x800, 2)}}));
            *input.mobiles.slot(0x32) = Bytes(0x200, 9);

            const auto built = run_build(input);
            ASSERT_OK(built) << "long mobile overlay build succeeds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->mobile_data.has_value() &&
                        parsed->mobile_data->x32.has_value())
                << "long mobile overlay is present";
            EXPECT_EQ(parsed->mobile_data->x32->size(), input.mobiles.slot(0x32)->value().size())
                << "shorter replacement mobile retains its requested size";
            EXPECT_BYTES_EQ(input.mobiles.slot(0x32)->value(), *parsed->mobile_data->x32)
                << "shorter replacement mobile does not retain the donor tail";
        }

        // One copy of a blob fills at most its block on small block; nothing longer can be laid.
        TEST(RunBuildMobile, OverlayLongerThanOneBlockIsRefused) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(input.metadata.nand_image,
                                 test::make_donor(input, {{0x32, Bytes(0x800, 2)}}));
            *input.mobiles.slot(0x32) = Bytes(0x4001, 9);

            EXPECT_ERROR_HAS(run_build(input), BuildErrorCode::SerializationFailure,
                             "Mobile data type 0x32 is 0x4001 bytes")
                << "a mobile overlay longer than a block is refused; an over-long mobile reports "
                   "SerializationFailure; the writer's reason reaches the BuildError message";
        }

        TEST(RunBuildMobile, SerializedOverlaySkipsABadDonorBlock) {
            const auto initial = run_build(test::fresh_input(ImageType::SmallBlock));
            ASSERT_OK(initial) << "bad-block donor image opens";
            auto donor = FlashImage::read(*initial);
            ASSERT_TRUE(donor.has_value()) << "bad-block donor image opens";

            constexpr size_t first_mobile_block = 4;
            donor->flash_driver.mark_bad_block(first_mobile_block);
            const auto donor_bytes = donor->flash_driver.serialize();

            auto overlay = test::fresh_input(ImageType::SmallBlock);
            overlay.metadata.nand_image = donor_bytes;
            *overlay.mobiles.slot(0x31) = Bytes(0x4000, 0x31);
            const auto built = run_build(overlay);
            ASSERT_OK(built) << "bad-block mobile overlay builds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->mobile_data.has_value() &&
                        parsed->mobile_data->x31.has_value())
                << "serialized mobile overlay skips the bad donor block";
            EXPECT_BYTES_EQ(overlay.mobiles.slot(0x31)->value(), *parsed->mobile_data->x31)
                << "serialized mobile overlay skips the bad donor block";
            EXPECT_TRUE(parsed->flash_driver.is_bad_block(first_mobile_block))
                << "serialized bad donor marker remains set";
            EXPECT_NE(parsed->flash_driver.interpret_block(first_mobile_block).block_type, 0x31)
                << "bad donor block is not assigned mobile metadata";
        }

        TEST(RunBuildMobile, AllocationRejectsSmcTailOverlap) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            const size_t limit = image.flash_driver.data_block_limit();
            nand::FlashFileSystem filesystem{};
            filesystem.set_driver(&image.flash_driver);
            ASSERT_OK(filesystem.format(image.flash_driver.block_count(),
                                        nand::FlashFileSystem::kDeferRoot))
                << "a FlashFS holding every data block formats";
            ASSERT_OK(filesystem.reserve_blocks(0, limit))
                << "a FlashFS holding every data block formats";
            image.filesystem = std::move(filesystem);
            image.mobile_data = nand::MobileData{};
            image.mobile_data->x31 = Bytes(0x800, 0x31);

            ASSERT_FALSE(image.write().has_value())
                << "mobile allocation cannot enter the SMC tail";
            for (size_t block = limit; block < image.flash_driver.block_count(); ++block) {
                ASSERT_NE(image.flash_driver.interpret_block(block).block_type, 0x31)
                    << "no tail block is given the mobile (block 0x" << std::hex << block << ")";
            }
        }

        TEST(RunBuildMobile, SerializedMobileDoesNotOverlapFixedPayloads) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x1000, 0x71);
            payloads.fuses = Bytes(0x60, 0x72);
            payloads.xell = test::valid_xell();
            input.payloads = std::move(payloads);

            // The unreserved range begins at block 4. Nine one-block blobs are laid from there,
            // past the payload blocks from the rebooter at 0x90000 through XeLL at 0x95060.
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                *input.mobiles.slot(block_type) = Bytes(0x4000, block_type);
            }
            const auto built = run_build(input);
            ASSERT_OK(built) << "mobile and fixed payload image builds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->mobile_data.has_value())
                << "serialized mobile bytes are not overwritten by fixed payloads";
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                const auto* laid = parsed->mobile_data->get_slot(block_type);
                ASSERT_TRUE(laid->has_value())
                    << "serialized mobile bytes are not overwritten by fixed payloads (type 0x"
                    << std::hex << static_cast<unsigned>(block_type) << ")";
                EXPECT_BYTES_EQ(input.mobiles.slot(block_type)->value(), **laid)
                    << "serialized mobile bytes are not overwritten by fixed payloads (type 0x"
                    << std::hex << static_cast<unsigned>(block_type) << ")";
            }
            ASSERT_TRUE(parsed->payloads.rebooter.has_value())
                << "serialized rebooter bytes survive mobile allocation";
            EXPECT_BYTES_EQ(*input.payloads->rebooter, *parsed->payloads.rebooter)
                << "serialized rebooter bytes survive mobile allocation";
            ASSERT_TRUE(parsed->payloads.fuses.has_value())
                << "serialized fuse bytes survive mobile allocation";
            EXPECT_BYTES_EQ(*input.payloads->fuses, *parsed->payloads.fuses)
                << "serialized fuse bytes survive mobile allocation";
            ASSERT_TRUE(parsed->payloads.xell.has_value())
                << "serialized XeLL bytes survive mobile allocation";
            EXPECT_BYTES_EQ(*input.payloads->xell, parsed->payloads.xell->data)
                << "serialized XeLL bytes survive mobile allocation";
        }

        TEST(RunBuildMobile, EmmcSlotsRoundTripAndAnEmptyInputRemovesDonorData) {
            const Bytes donor_mobile_31(0x4000, 0x31);
            const Bytes donor_mobile_32(0x4000, 0x32);
            auto donor_input = test::fresh_input(ImageType::Emmc);
            *donor_input.mobiles.slot(0x31) = donor_mobile_31;
            *donor_input.mobiles.slot(0x32) = donor_mobile_32;
            const auto donor_bytes = run_build(donor_input);
            ASSERT_OK(donor_bytes) << "serialized eMMC mobiles parse";
            const auto parsed_donor = parse_image(*donor_bytes);
            ASSERT_TRUE(parsed_donor.has_value() && parsed_donor->mobile_data.has_value())
                << "serialized eMMC mobiles parse";
            ASSERT_FALSE(parsed_donor->filesystem.has_value())
                << "eMMC donor without FlashFS does not invent a filesystem at block zero";
            ASSERT_TRUE(parsed_donor->mobile_data->x31.has_value())
                << "eMMC 0x31 roundtrips exactly";
            EXPECT_BYTES_EQ(donor_mobile_31, *parsed_donor->mobile_data->x31)
                << "eMMC 0x31 roundtrips exactly";
            ASSERT_TRUE(parsed_donor->mobile_data->x32.has_value())
                << "eMMC 0x32 roundtrips exactly";
            EXPECT_BYTES_EQ(donor_mobile_32, *parsed_donor->mobile_data->x32)
                << "eMMC 0x32 roundtrips exactly";

            auto removal = test::fresh_input(ImageType::Emmc);
            removal.metadata.nand_image = *donor_bytes;
            *removal.mobiles.slot(0x31) = Bytes{};
            const auto rebuilt = run_build(removal);
            ASSERT_OK(rebuilt) << "eMMC empty mobile overlay builds";
            const auto parsed_rebuilt = parse_image(*rebuilt);
            ASSERT_TRUE(parsed_rebuilt.has_value()) << "eMMC empty mobile overlay parses";
            EXPECT_TRUE(!parsed_rebuilt->mobile_data.has_value() ||
                        !parsed_rebuilt->mobile_data->x31.has_value())
                << "eMMC present-empty 0x31 removes donor data";
            ASSERT_TRUE(parsed_rebuilt->mobile_data.has_value() &&
                        parsed_rebuilt->mobile_data->x32.has_value())
                << "eMMC absent 0x32 preserves donor data";
            EXPECT_BYTES_EQ(donor_mobile_32, *parsed_rebuilt->mobile_data->x32)
                << "eMMC absent 0x32 preserves donor data";
        }

        TEST(RunBuildMobile, EmmcTakesEachAnchorMobileAloneAndDropsEachOtherType) {
            for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
                SCOPED_TRACE(::testing::Message()
                             << "mobile 0x" << std::hex << static_cast<unsigned>(block_type));
                auto input = test::fresh_input(ImageType::Emmc);
                *input.mobiles.slot(0x31) = Bytes{0x31};
                *input.mobiles.slot(block_type) = Bytes{block_type};
                EXPECT_TRUE(emmc_keeps_anchor_mobiles_only(input, "single eMMC mobile"));
            }
        }

        TEST(RunBuildMobile, SerializedOverlaysPreserveAbsentSlotsForNandLayouts) {
            const std::array<std::pair<ImageType, std::string_view>, 3> layouts{{
                {ImageType::SmallBlock, "SmallBlock"},
                {ImageType::NewSmallBlock, "NewSmallBlock"},
                {ImageType::BigBlock, "BigBlock"},
            }};
            for (const auto& [layout, name] : layouts) {
                SCOPED_TRACE(name);
                auto donor_input = test::fresh_input(layout);
                *donor_input.mobiles.slot(0x31) = Bytes{0x31};
                *donor_input.mobiles.slot(0x39) = Bytes{0x39};
                const auto donor_bytes = run_build(donor_input);
                ASSERT_OK(donor_bytes) << "serialized NAND mobile donor builds";

                auto overlay = test::fresh_input(layout);
                overlay.metadata.nand_image = *donor_bytes;
                *overlay.mobiles.slot(0x39) = Bytes{0xA9, 0x39};
                const auto rebuilt = run_build(overlay);
                ASSERT_OK(rebuilt) << "serialized NAND mobile overlay parses";
                const auto parsed = parse_image(*rebuilt);
                ASSERT_TRUE(parsed.has_value() && parsed->mobile_data.has_value())
                    << "serialized NAND mobile overlay parses";
                EXPECT_EQ(parsed->mobile_data->x31, Bytes({0x31}))
                    << "absent NAND mobile slot preserves donor data";
                EXPECT_EQ(parsed->mobile_data->x39, Bytes({0xA9, 0x39}))
                    << "high NAND mobile slot accepts user replacement";
            }
        }

        // A settings block as a console holds it: 0x400 bytes whose head is the one's complement
        // of the byte sum over [0x10, 0x10C), little-endian.
        Bytes sound_smc_config() {
            Bytes block(0x400);
            for (size_t i = 2; i < block.size(); ++i) {
                block[i] = static_cast<uint8_t>(i * 5 + 1);
            }
            uint32_t sum = 0;
            for (size_t i = 0x10; i < 0x10C; ++i) {
                sum += block[i];
            }
            const uint16_t head = static_cast<uint16_t>(~sum);
            block[0] = static_cast<uint8_t>(head);
            block[1] = static_cast<uint8_t>(head >> 8);
            return block;
        }

        // A donor of one layout rebuilt as another keeps its settings, statistics and
        // manufacturing blocks, each at the offsets of the layout built.
        TEST(RunBuildSettings, BlocksFollowTheConsoleIntoAnotherLayout) {
            auto donor_input = test::fresh_input(ImageType::NewSmallBlock);
            donor_input.metadata.smc_config = sound_smc_config();
            donor_input.metadata.statistics = Bytes(0x1000, 0x5A);
            Bytes manufacturing(0x1000, 0xFF);
            std::fill_n(manufacturing.begin(), 0x40, uint8_t{0x4D});
            donor_input.metadata.manufacturing = manufacturing;
            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "settings donor builds";

            const struct {
                std::string_view name;
                ImageType type;
                size_t settings;
                size_t step;
            } targets[] = {
                {"SmallBlock", ImageType::SmallBlock, 0xF7C000, 0x4000},
                {"BigBlock", ImageType::BigBlock, 0x3BE0000, 0x20000},
                {"Emmc", ImageType::Emmc, 0x2FFC000, 0x4000},
            };
            for (const auto& target : targets) {
                SCOPED_TRACE(target.name);
                auto extracted = extract_all(*donor, donor_input.metadata.cpu_key);
                ASSERT_OK(extracted) << "extraction takes the donor's settings blocks";
                ASSERT_TRUE(extracted->metadata.smc_config.has_value() &&
                            extracted->metadata.statistics.has_value() &&
                            extracted->metadata.manufacturing.has_value())
                    << "extraction takes the donor's settings blocks";
                EXPECT_BYTES_EQ(*donor_input.metadata.smc_config, *extracted->metadata.smc_config)
                    << "extraction takes the donor's settings blocks";
                EXPECT_BYTES_EQ(*donor_input.metadata.statistics, *extracted->metadata.statistics)
                    << "extraction takes the donor's settings blocks";
                EXPECT_BYTES_EQ(manufacturing, *extracted->metadata.manufacturing)
                    << "extraction takes the donor's settings blocks";
                extracted->metadata.nand_image.reset();
                extracted->image_type = target.type;
                const auto built = run_build(*extracted);
                ASSERT_OK(built) << "cross-layout build with settings blocks parses";
                const auto parsed = parse_image(*built);
                ASSERT_TRUE(parsed.has_value()) << "cross-layout build with settings blocks parses";
                const auto& driver = std::as_const(parsed->flash_driver);
                Bytes settings(0x1000, 0xFF);
                std::copy(donor_input.metadata.smc_config->begin(),
                          donor_input.metadata.smc_config->end(), settings.begin());
                EXPECT_BYTES_EQ(settings, driver.read_clean(target.settings, 0x1000))
                    << "the settings block lands at the target layout's offset";
                EXPECT_BYTES_EQ(*donor_input.metadata.statistics,
                                driver.read_clean(target.settings - target.step, 0x1000))
                    << "the statistics block lands one erase block below it";
                EXPECT_BYTES_EQ(manufacturing,
                                driver.read_clean(target.settings - 2 * target.step, 0x1000))
                    << "the manufacturing block lands two erase blocks below it";
            }
        }

    } // namespace
} // namespace gxbuild3::orchestration
