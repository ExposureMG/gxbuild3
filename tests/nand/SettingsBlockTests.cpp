// The settings blocks FlashImage reads and lays (src/nand/FlashImage*.cpp): the SMC config block
// where each shape keeps it, refused when its checksum fails, written without touching its
// neighbours, and the statistics and manufacturing blocks one and two erase blocks below it;
// and the bound on the SMC payload written beside them.

#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/NandShapes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
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
            EXPECT_BYTES_EQ(block, image->smc_config.value_or(Bytes{}))
                << "FlashImage must read the SMC config block where the shape keeps it";
        }

        TEST_P(SmcConfig, SmcConfigWriteLeavesNeighbouringBlocks) {
            const auto& shape = GetParam();
            const auto block = sound_smc_config_block();
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
            image.smc_config = block;

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
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            image.smc_config = block;
            image.statistics = statistics;
            image.manufacturing = no_manufacturing;
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
            EXPECT_BYTES_EQ(block, parsed->smc_config.value_or(Bytes{}))
                << "the settings blocks read back where the shape keeps them";
            EXPECT_BYTES_EQ(statistics, parsed->statistics.value_or(Bytes{}))
                << "the settings blocks read back where the shape keeps them";
            EXPECT_BYTES_EQ(no_manufacturing, parsed->manufacturing.value_or(Bytes{}))
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

    } // namespace
} // namespace gxbuild3::nand
