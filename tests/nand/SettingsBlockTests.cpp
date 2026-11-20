// The settings blocks FlashImage reads and lays (src/nand/FlashImage*.cpp): the SMC config block
// where each shape keeps it, refused when its checksum fails, written without touching its
// neighbours, and the statistics and manufacturing blocks one and two erase blocks below it;
// and the bound on the SMC payload written beside them.

#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/NandShapes.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/XConfig.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/builders/Inputs.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        // A settings block as a console holds it: 0x400 bytes whose head is the one's complement
        // of the byte sum over [0x10, 0x10C), little-endian.
        Bytes sound_smc_config_block() {
            Bytes block(0x400);
            for (size_t i = 2; i < block.size(); ++i) {
                block[i] = static_cast<uint8_t>(i * 7 + 3);
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

        struct ConfigShape {
            const char* name;
            Driver::ImageSize size;
            Driver::DriverMode mode;
            size_t offset;
        };
        GX_PRINT_ROW_AS_NAME(ConfigShape)

        // Where the settings block sits on each shape, read off real dumps (16 MB and big block)
        // and the eMMC layout.
        constexpr ConfigShape kConfigShapes[] = {
            {"Small", Driver::Smallblock, Driver::DriverMode::Small, 0xF7C000},
            {"Big", Driver::Bigordevkit, Driver::DriverMode::Big, 0x3BE0000},
            {"Emmc", Driver::Emmcblock, Driver::DriverMode::Emmc, 0x2FFC000},
        };

        class SmcConfig : public ::testing::TestWithParam<ConfigShape> {};

        TEST_P(SmcConfig, FlashImageReadsCrossPageConfig) {
            const auto& shape = GetParam();
            const auto block = sound_smc_config_block();
            Driver source(shape.size, shape.mode);
            EXPECT_TRUE(source.write_offset(shape.offset, block)) << "the settings block is laid";

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value()) << "FlashImage must accept a valid-sized NAND image";
            EXPECT_OK(image->parse()) << "FlashImage must parse the NAND image";
            ASSERT_TRUE(image->smc_config.has_value())
                << "FlashImage must read the SMC config block where the shape keeps it";
            EXPECT_BYTES_EQ(block, image->smc_config->serialize())
                << "FlashImage must read the SMC config block where the shape keeps it";
        }

        TEST_P(SmcConfig, SmcConfigWriteLeavesNeighbouringBlocks) {
            const auto& shape = GetParam();
            const auto block = sound_smc_config_block();
            ASSERT_OK_AND_ASSIGN(auto parsed_cfg, SmcConfigBlock::parse(block));
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            // A dump written back keeps the bytes it does not model, as here the neighbours.
            image.preserve_layout = true;
            const size_t step = image.flash_driver.block_size_clean();
            // The statistics and manufacturing blocks lie one and two erase blocks below.
            const Bytes statistics(0x1000, 0xA5);
            const Bytes manufacturing(0x1000, 0x5A);
            EXPECT_TRUE(image.flash_driver.write_offset(shape.offset - step, statistics))
                << "the neighbouring blocks are laid";
            EXPECT_TRUE(image.flash_driver.write_offset(shape.offset - 2 * step, manufacturing))
                << "the neighbouring blocks are laid";
            image.smc_config = std::move(parsed_cfg);

            EXPECT_OK(image.write_to_driver()) << "an image with a settings block writes";
            const auto& driver = std::as_const(image.flash_driver);
            // A raw NAND read lands in a scratch buffer the next read replaces, so each
            // result is copied out before the next one is taken.
            const auto copy_of = [&driver](size_t offset) {
                const auto span = driver.read_offset(offset, 0x1000);
                return Bytes(span.begin(), span.end());
            };
            const auto settings = copy_of(shape.offset);
            Bytes expected(0x1000, 0xFF);
            std::copy(block.begin(), block.end(), expected.begin());
            EXPECT_BYTES_EQ(expected, settings)
                << "the settings block is laid in 0x1000 with 0xFF after it";
            const auto stats = copy_of(shape.offset - step);
            const auto manu = copy_of(shape.offset - 2 * step);
            EXPECT_BYTES_EQ(statistics, stats)
                << "writing the settings block must not touch the statistics block";
            EXPECT_BYTES_EQ(manufacturing, manu)
                << "writing the settings block must not touch the manufacturing block";
        }

        INSTANTIATE_TEST_SUITE_P(Shape, SmcConfig, ::testing::ValuesIn(kConfigShapes),
                                 test::RowName{});

        TEST(SmcConfigChecksum, SmcConfigWithBadChecksumIsNotCarried) {
            Driver source(Driver::Smallblock, Driver::DriverMode::Small);
            auto block = sound_smc_config_block();
            block[0x50] ^= 0xFF;
            ASSERT_TRUE(source.write_offset(0xF7C000, block)) << "the settings block is laid";

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value())
                << "a settings block whose checksum fails must not be carried";
            ASSERT_OK(image->parse())
                << "a settings block whose checksum fails must not be carried";
            EXPECT_FALSE(image->smc_config.has_value())
                << "a settings block whose checksum fails must not be carried";
        }

        class SettingsBlock : public ::testing::TestWithParam<ConfigShape> {};

        TEST_P(SettingsBlock, SettingsBlocksAreLaidAtTheHeadOfErasedBlocks) {
            const auto& shape = GetParam();
            const auto block = sound_smc_config_block();
            Bytes statistics(0x1000);
            for (size_t i = 0; i < statistics.size(); ++i) {
                statistics[i] = static_cast<uint8_t>(i * 13 + 1);
            }
            const Bytes no_manufacturing(0x1000, 0xFF);
            ASSERT_OK_AND_ASSIGN(auto parsed_cfg, SmcConfigBlock::parse(block));
            ASSERT_OK_AND_ASSIGN(auto parsed_stats, StatisticsBlock::parse(statistics));
            ASSERT_OK_AND_ASSIGN(auto parsed_manu, ManufacturingBlock::parse(no_manufacturing));
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            image.smc_config = std::move(parsed_cfg);
            image.statistics = std::move(parsed_stats);
            image.manufacturing = std::move(parsed_manu);
            const auto bytes = image.write();
            ASSERT_OK(bytes) << "an image with settings blocks writes";

            const auto& driver = std::as_const(image.flash_driver);
            const size_t step = driver.block_size_clean();
            Bytes settings(0x1000, 0xFF);
            std::copy(block.begin(), block.end(), settings.begin());
            EXPECT_BYTES_EQ(settings, driver.read_clean(shape.offset, 0x1000))
                << "the settings block heads an otherwise erased block";
            EXPECT_TRUE(all_erased(driver.read_clean(shape.offset + 0x1000, step - 0x1000)))
                << "the settings block heads an otherwise erased block";
            EXPECT_BYTES_EQ(statistics, driver.read_clean(shape.offset - step, 0x1000))
                << "the statistics block heads an otherwise erased block";
            EXPECT_TRUE(all_erased(driver.read_clean(shape.offset - step + 0x1000, step - 0x1000)))
                << "the statistics block heads an otherwise erased block";
            EXPECT_TRUE(all_erased(driver.read_clean(shape.offset - 2 * step, step)))
                << "a console without manufacturing data keeps that block erased";
            if (shape.mode != Driver::DriverMode::Emmc) {
                const size_t stats_page = (shape.offset - step) / 512;
                const auto stats_meta = driver.interpret_page(stats_page + 7);
                EXPECT_EQ(stats_meta.block_type, 0)
                    << "the statistics pages carry a type-0 spare naming their block";
                EXPECT_EQ(stats_meta.sequence, 0u)
                    << "the statistics pages carry a type-0 spare naming their block";
                EXPECT_EQ(size_t{stats_meta.logical_block_id}, (shape.offset - step) / step)
                    << "the statistics pages carry a type-0 spare naming their block";
                EXPECT_TRUE(page_is_erased(driver, stats_page + 8))
                    << "pages past the 0x1000 and an erased block carry no spare";
                EXPECT_TRUE(page_is_erased(driver, (shape.offset - 2 * step) / 512))
                    << "pages past the 0x1000 and an erased block carry no spare";
            }

            auto parsed = FlashImage::read(*bytes);
            ASSERT_TRUE(parsed.has_value())
                << "the settings blocks read back where the shape keeps them";
            ASSERT_OK(parsed->parse())
                << "the settings blocks read back where the shape keeps them";
            ASSERT_TRUE(parsed->smc_config.has_value());
            ASSERT_TRUE(parsed->statistics.has_value());
            ASSERT_TRUE(parsed->manufacturing.has_value());
            EXPECT_BYTES_EQ(block, parsed->smc_config->serialize())
                << "the settings blocks read back where the shape keeps them";
            EXPECT_BYTES_EQ(statistics, parsed->statistics->serialize())
                << "the settings blocks read back where the shape keeps them";
            EXPECT_BYTES_EQ(no_manufacturing, parsed->manufacturing->serialize())
                << "the settings blocks read back where the shape keeps them";
        }

        INSTANTIATE_TEST_SUITE_P(Shape, SettingsBlock, ::testing::ValuesIn(kConfigShapes),
                                 test::RowName{});

        TEST(SmcSize, FlashImageRejectsOversizedSmc) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            Smc oversized_smc{};
            oversized_smc.data.resize(0x4001, 0xA5);
            image.smc = std::move(oversized_smc);

            EXPECT_ERROR(image.write_to_driver(), ErrorCode::OutOfRange)
                << "FlashImage must reject an SMC that cannot fit before writing it";
        }

        // Builds a populated 0x400-byte smc_config, 0x1000-byte statistics, and 0x1000-byte
        // manufacturing block for SettingsBlockReserialize tests.
        struct PopulatedConsoleBlocks {
            Bytes smc_config;
            Bytes statistics;
            Bytes manufacturing;
        };

        PopulatedConsoleBlocks make_populated_console_blocks() {
            PopulatedConsoleBlocks out{};
            out.smc_config.assign(0x400, 0xFF);
            // Version = 3 (BE), FirstPowerOnDate = 0x11..0x15
            std::fill_n(out.smc_config.begin() + 0x04, 4, uint8_t{0});
            out.smc_config[0x07] = 3;
            out.smc_config[0x08] = 0x11;
            out.smc_config[0x11] = 0x80 | 65; // cpu_fan = 65% overridden
            out.smc_config[0x12] = 0x80 | 70; // gpu_fan = 70% overridden
            out.smc_config[0x29] = 75;        // cpu target
            out.smc_config[0x2A] = 72;        // gpu target
            out.smc_config[0x2B] = 74;        // edram target
            out.smc_config[0x2C] = 95;        // cpu overload
            out.smc_config[0x2D] = 92;        // gpu overload
            out.smc_config[0x2E] = 94;        // edram overload
            // Gap bytes [0x10E, 0x200) carry an identifiable non-0xFF pattern inside raw_data.
            out.smc_config[0x150] = 0xA7;
            // Secured region (+0x200)
            std::fill_n(out.smc_config.begin() + 0x204, 4, uint8_t{0});
            out.smc_config[0x207] = 1; // version = 1 (BE)
            const std::array<uint8_t, 6> mac{0x00, 0x22, 0x48, 0xAA, 0xBB, 0xCC};
            std::copy(mac.begin(), mac.end(), out.smc_config.begin() + 0x220);
            // AVRegion = 0x100 (BE) at 0x228
            std::fill_n(out.smc_config.begin() + 0x228, 4, uint8_t{0});
            out.smc_config[0x22A] = 0x01;
            out.smc_config[0x22B] = 0x00;
            // GameRegion = 0x00FF (BE) at 0x22C
            out.smc_config[0x22C] = 0x00;
            out.smc_config[0x22D] = 0xFF;
            // DVDRegion = 1 (BE) at 0x234
            std::fill_n(out.smc_config.begin() + 0x234, 4, uint8_t{0});
            out.smc_config[0x237] = 0x01;
            // ResetKey = "XXUD" at 0x238
            std::memcpy(out.smc_config.data() + 0x238, "XXUD", 4);
            const uint16_t sum = SmcConfigBlock::compute_checksum(out.smc_config);
            out.smc_config[0] = static_cast<uint8_t>(sum);
            out.smc_config[1] = static_cast<uint8_t>(sum >> 8);

            out.statistics.assign(0x1000, 0xFF);
            std::fill_n(out.statistics.begin(), 0x600, uint8_t{0});
            out.statistics[0x07] = 3; // version = 3 (BE)
            out.statistics[0x13] = 9; // xuid_count = 9 (BE)
            // last_report_time = 0x01CC1898E53A2370 (BE) at 0x5F8
            const std::array<uint8_t, 8> report_time{0x01, 0xCC, 0x18, 0x98,
                                                     0xE5, 0x3A, 0x23, 0x70};
            std::copy(report_time.begin(), report_time.end(), out.statistics.begin() + 0x5F8);

            out.manufacturing.assign(0x1000, 0xFF);
            out.manufacturing[0] = 0x4D;
            out.manufacturing[1] = 0x46;
            out.manufacturing[2] = 0x47;
            return out;
        }

        TEST(SettingsBlockReserialize, ParseDecodesSplitFieldsWithReserializeFalse) {
            const auto blocks = make_populated_console_blocks();
            Driver source(Driver::Smallblock, Driver::DriverMode::Small);
            ASSERT_TRUE(source.write_offset(0xF7C000, blocks.smc_config));
            ASSERT_TRUE(source.write_offset(0xF78000, blocks.statistics));
            ASSERT_TRUE(source.write_offset(0xF74000, blocks.manufacturing));

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value());
            ASSERT_OK(image->parse());

            ASSERT_TRUE(image->smc_config.has_value());
            EXPECT_FALSE(image->smc_config->reserialize);
            EXPECT_EQ(image->smc_config->static_settings.version.get(), 3u);
            EXPECT_EQ(image->smc_config->static_settings.smc.cpu_fan, 0x80 | 65);
            EXPECT_EQ(image->smc_config->static_settings.smc.gpu_fan, 0x80 | 70);
            EXPECT_EQ(image->smc_config->static_settings.smc.setpoint.cpu, 75);
            EXPECT_EQ(image->smc_config->static_settings.smc.overload.gpu, 92);
            EXPECT_EQ(image->smc_config->secured_settings.version.get(), 1u);
            EXPECT_EQ(image->smc_config->secured_settings.mac_address[5], 0xCC);
            EXPECT_EQ(image->smc_config->secured_settings.av_region.get(), 0x100u);
            EXPECT_EQ(image->smc_config->secured_settings.game_region.get(), 0x00FFu);
            EXPECT_EQ(image->smc_config->secured_settings.dvd_region.get(), 1u);
            EXPECT_EQ(std::string_view(image->smc_config->secured_settings.reset_key, 4), "XXUD");

            ASSERT_TRUE(image->statistics.has_value());
            EXPECT_FALSE(image->statistics->reserialize);
            EXPECT_FALSE(image->statistics->erased());
            EXPECT_EQ(image->statistics->data.version.get(), 3u);
            EXPECT_EQ(image->statistics->data.xuid_count.get(), 9u);
            EXPECT_EQ(image->statistics->data.last_report_time.get(), 0x01CC1898E53A2370ULL);

            ASSERT_TRUE(image->manufacturing.has_value());
            EXPECT_FALSE(image->manufacturing->reserialize);
            EXPECT_FALSE(image->manufacturing->erased());
            EXPECT_EQ(image->manufacturing->data.bytes[0], 0x4D);

            ASSERT_OK_AND_ASSIGN(const auto all_erased_manu,
                                 ManufacturingBlock::parse(Bytes(0x1000, 0xFF)));
            EXPECT_TRUE(all_erased_manu.erased());
            ASSERT_OK_AND_ASSIGN(const auto all_erased_stats,
                                 StatisticsBlock::parse(Bytes(0x1000, 0xFF)));
            EXPECT_TRUE(all_erased_stats.erased());
        }

        TEST(SettingsBlockReserialize, EditsAreIgnoredUnlessReserializeIsSet) {
            const auto blocks = make_populated_console_blocks();
            Driver source(Driver::Smallblock, Driver::DriverMode::Small);
            ASSERT_TRUE(source.write_offset(0xF7C000, blocks.smc_config));
            ASSERT_TRUE(source.write_offset(0xF78000, blocks.statistics));
            ASSERT_TRUE(source.write_offset(0xF74000, blocks.manufacturing));

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value());
            ASSERT_OK(image->parse());
            ASSERT_TRUE(image->smc_config && image->statistics && image->manufacturing);

            image->smc_config->static_settings.smc.setpoint.cpu = 60;
            image->smc_config->secured_settings.dvd_region = 2u;
            image->statistics->data.xuid_count = 42u;
            image->manufacturing->data.bytes[0] = 0x99;

            ASSERT_OK(image->write());
            const auto& driver = std::as_const(image->flash_driver);
            EXPECT_BYTES_EQ(blocks.smc_config, driver.read_clean(0xF7C000, 0x400));
            EXPECT_BYTES_EQ(blocks.statistics, driver.read_clean(0xF78000, 0x1000));
            EXPECT_BYTES_EQ(blocks.manufacturing, driver.read_clean(0xF74000, 0x1000));
        }

        TEST(SettingsBlockReserialize, ReserializeFlagRebuildsBlocksAndRecomputesChecksum) {
            const auto blocks = make_populated_console_blocks();
            Driver source(Driver::Smallblock, Driver::DriverMode::Small);
            ASSERT_TRUE(source.write_offset(0xF7C000, blocks.smc_config));
            ASSERT_TRUE(source.write_offset(0xF78000, blocks.statistics));
            ASSERT_TRUE(source.write_offset(0xF74000, blocks.manufacturing));

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value());
            ASSERT_OK(image->parse());
            ASSERT_TRUE(image->smc_config && image->statistics && image->manufacturing);

            image->smc_config->static_settings.smc.setpoint.cpu = 60;
            image->smc_config->static_settings.smc.cpu_fan = 0x80 | 85;
            image->smc_config->secured_settings.av_region = 0x300u;
            image->smc_config->secured_settings.game_region = 0x02FEu;
            image->smc_config->secured_settings.dvd_region = 2u;
            image->smc_config->reserialize = true;

            image->statistics->data.xuid_count = 42u;
            image->statistics->data.last_report_time = 0x1122334455667788ULL;
            image->statistics->reserialize = true;

            image->manufacturing->data.bytes[0] = 0x99;
            image->manufacturing->reserialize = true;

            ASSERT_OK_AND_ASSIGN(const auto written, image->write());
            const auto cfg_on_disk =
                std::as_const(image->flash_driver).read_clean(0xF7C000, 0x400);
            EXPECT_TRUE(SmcConfigBlock::checksum_valid(cfg_on_disk));
            EXPECT_NE(cfg_on_disk[0], blocks.smc_config[0]);
            EXPECT_EQ(cfg_on_disk[0x150], 0xA7);

            auto reparsed = FlashImage::read(written);
            ASSERT_TRUE(reparsed.has_value());
            ASSERT_OK(reparsed->parse());
            ASSERT_TRUE(reparsed->smc_config && reparsed->statistics && reparsed->manufacturing);
            EXPECT_EQ(reparsed->smc_config->static_settings.smc.setpoint.cpu, 60);
            EXPECT_EQ(reparsed->smc_config->static_settings.smc.cpu_fan, 0x80 | 85);
            EXPECT_EQ(reparsed->smc_config->secured_settings.av_region.get(), 0x300u);
            EXPECT_EQ(reparsed->smc_config->secured_settings.game_region.get(), 0x02FEu);
            EXPECT_EQ(reparsed->smc_config->secured_settings.dvd_region.get(), 2u);
            EXPECT_EQ(reparsed->statistics->data.xuid_count.get(), 42u);
            EXPECT_EQ(reparsed->statistics->data.last_report_time.get(), 0x1122334455667788ULL);
            EXPECT_EQ(reparsed->manufacturing->data.bytes[0], 0x99);
        }

        TEST(SettingsBlockReserialize, FreshBlocksWithEmptyRawDataSerializeWhenFlagged) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::Smallblock, Driver::DriverMode::Small);

            SmcConfigBlock cfg{};
            cfg.static_settings.version = 3u;
            cfg.static_settings.smc.setpoint.cpu = 68;
            cfg.secured_settings.av_region = 0x100u;
            cfg.secured_settings.dvd_region = 1u;
            cfg.reserialize = true;
            image.smc_config = std::move(cfg);

            StatisticsBlock stats{};
            stats.data.version = 3u;
            stats.data.xuid_count = 7u;
            stats.reserialize = true;
            image.statistics = std::move(stats);

            ManufacturingBlock manu{};
            std::fill(std::begin(manu.data.bytes), std::end(manu.data.bytes), uint8_t{0xFF});
            manu.data.bytes[0] = 0x55;
            manu.reserialize = true;
            image.manufacturing = std::move(manu);

            ASSERT_OK_AND_ASSIGN(const auto written, image.write());
            const auto& driver = std::as_const(image.flash_driver);
            const auto cfg_on_disk = driver.read_clean(0xF7C000, 0x400);
            EXPECT_TRUE(SmcConfigBlock::checksum_valid(cfg_on_disk));
            EXPECT_TRUE(all_erased(std::span<const uint8_t>(cfg_on_disk).subspan(0x10E, 0xF2)));
            const auto stats_on_disk = driver.read_clean(0xF78000, 0x1000);
            EXPECT_TRUE(all_erased(std::span<const uint8_t>(stats_on_disk).subspan(0x600)));

            auto reparsed = FlashImage::read(written);
            ASSERT_TRUE(reparsed.has_value());
            ASSERT_OK(reparsed->parse());
            ASSERT_TRUE(reparsed->smc_config && reparsed->statistics && reparsed->manufacturing);
            EXPECT_EQ(reparsed->smc_config->static_settings.smc.setpoint.cpu, 68);
            EXPECT_EQ(reparsed->smc_config->secured_settings.av_region.get(), 0x100u);
            EXPECT_EQ(reparsed->statistics->data.xuid_count.get(), 7u);
            EXPECT_EQ(reparsed->manufacturing->data.bytes[0], 0x55);
        }

        TEST(SettingsBlockReserialize, FlashImageKeyvaultReserializeFlagControlsRebuild) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(const auto donor_bytes, test::make_donor(source, {}));

            auto image = FlashImage::read(donor_bytes);
            ASSERT_TRUE(image.has_value());
            ASSERT_OK(image->parse());
            ASSERT_OK(image->decrypt_all(source.metadata.cpu_key));
            ASSERT_TRUE(image->keyvault.has_value());
            EXPECT_FALSE(image->keyvault->reserialize);
            const uint16_t original_region = image->keyvault->data.w16GameRegion.get();

            // Edit without setting reserialize -> encrypt_all + write keeps original region.
            image->keyvault->data.w16GameRegion = static_cast<uint16_t>(original_region ^ 0x0101u);
            ASSERT_OK(image->encrypt_all(source.metadata.cpu_key, BuildType::Retail));
            ASSERT_OK_AND_ASSIGN(const auto untouched_bytes, image->write());

            auto check_untouched = FlashImage::read(untouched_bytes);
            ASSERT_TRUE(check_untouched.has_value());
            ASSERT_OK(check_untouched->parse());
            ASSERT_OK(check_untouched->decrypt_all(source.metadata.cpu_key));
            ASSERT_TRUE(check_untouched->keyvault.has_value());
            EXPECT_EQ(check_untouched->keyvault->data.w16GameRegion.get(), original_region);

            // Edit with reserialize = true -> encrypt_all + write persists changes and clears flag.
            check_untouched->keyvault->data.w16GameRegion = uint16_t{0x02FEu};
            check_untouched->keyvault->data.b1ADvdKey[0] ^= 0x5Au;
            const uint8_t expected_dvd0 = check_untouched->keyvault->data.b1ADvdKey[0];
            check_untouched->keyvault->reserialize = true;
            ASSERT_OK(check_untouched->encrypt_all(source.metadata.cpu_key, BuildType::Retail));
            EXPECT_FALSE(check_untouched->keyvault->reserialize);
            ASSERT_OK_AND_ASSIGN(const auto rebuilt_bytes, check_untouched->write());

            auto check_rebuilt = FlashImage::read(rebuilt_bytes);
            ASSERT_TRUE(check_rebuilt.has_value());
            ASSERT_OK(check_rebuilt->parse());
            ASSERT_OK(check_rebuilt->decrypt_all(source.metadata.cpu_key));
            ASSERT_TRUE(check_rebuilt->keyvault.has_value());
            EXPECT_FALSE(check_rebuilt->keyvault->reserialize);
            EXPECT_EQ(check_rebuilt->keyvault->data.w16GameRegion.get(), 0x02FEu);
            EXPECT_EQ(check_rebuilt->keyvault->data.b1ADvdKey[0], expected_dvd0);
        }

    } // namespace
} // namespace gxbuild3::nand
