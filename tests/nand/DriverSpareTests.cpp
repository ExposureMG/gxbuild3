// The NAND driver (src/nand/FlashDriver.hpp): the spare bytes of each page (the good- and
// bad-block marks, the big-block sequence, the block type under its ECC bits), the size of an
// eMMC image and the refusal of an offset write past the clean capacity.

#include "nand/FlashDriver.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

namespace gxbuild3::nand {
    namespace {

        TEST(DriverSpare, FreshBlocksAreNotBad) {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            EXPECT_FALSE(driver.is_bad_block(100))
                << "fresh unused blocks must have a good-block marker";
        }

        // Spare byte 3 holds the sequence's middle byte, 4 its high byte and 5 its low byte.
        TEST(DriverSpare, BigBlockSequenceIsStoredMiddleHighLowInSpareBytes3To5) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            BlockMetadata metadata{};
            metadata.logical_block_id = 2;
            metadata.sequence = 0x123456;
            driver.write_block_metadata(2, metadata);

            const auto spare = driver.read_page_spare(2 * driver.pages_per_block());
            ASSERT_EQ(spare.size(), 16u) << "Big Block spare data must be readable";
            EXPECT_EQ(spare[3], 0x34) << "Big Block sequence must use spare bytes 3, 4, and 5";
            EXPECT_EQ(spare[4], 0x12) << "Big Block sequence must use spare bytes 3, 4, and 5";
            EXPECT_EQ(spare[5], 0x56) << "Big Block sequence must use spare bytes 3, 4, and 5";
            EXPECT_EQ(spare[6], 0)
                << "Big Block sequence high byte must be zero for a 24-bit value";
        }

        TEST(DriverSpare, BlockTypeMasksEccBits) {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            BlockMetadata metadata{};
            metadata.logical_block_id = 0;
            metadata.block_type = 0x30;
            driver.write_block_metadata(0, metadata);

            for (size_t page = 0; page < 2; ++page) {
                auto spare = driver.read_page_spare(page);
                std::array<uint8_t, 16> updated{};
                std::copy(spare.begin(), spare.end(), updated.begin());
                updated[0xC] = 0xF0;
                driver.write_page_spare(page, updated);
            }

            EXPECT_EQ(driver.interpret_block(0).block_type, 0x30)
                << "ECC bits must not be returned as part of the block type";
        }

        TEST(DriverSpare, EmmcImageIs48Megabytes) {
            Driver emmc(Driver::Emmcblock, Driver::DriverMode::Emmc);
            EXPECT_EQ(emmc.block_count(), 0xC00u) << "an eMMC image has 0xC00 blocks";
            EXPECT_EQ(emmc.serialize().size(), size_t{0xC00} * 0x4000)
                << "an eMMC image is 48 MB long";
        }

        TEST(DriverSpare, WritesRejectOutOfRangeData) {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            const size_t image_size = driver.block_count() * driver.block_size_clean();
            const std::array<uint8_t, 2> bytes{0xAA, 0xBB};
            const auto before = driver.read_clean(image_size - 1, 1);
            const bool written = driver.write_offset(image_size - 1, bytes);
            const auto after = driver.read_clean(image_size - 1, 1);
            EXPECT_FALSE(written)
                << "Driver must reject offset writes that exceed clean NAND capacity";
            ASSERT_EQ(before.size(), 1u)
                << "Driver must reject offset writes that exceed clean NAND capacity";
            ASSERT_EQ(after.size(), 1u)
                << "Driver must reject offset writes that exceed clean NAND capacity";
            EXPECT_EQ(before[0], after[0])
                << "Driver must reject offset writes that exceed clean NAND capacity";
        }

        // The bad-block mark sits at spare byte 0 on big block and 5 on small block; a block is
        // bad when its first or middle page carries it.
        struct MarkShape {
            const char* name;
            Driver::ImageSize size;
            Driver::DriverMode mode;
        };
        GX_PRINT_ROW_AS_NAME(MarkShape)

        constexpr MarkShape kMarkShapes[] = {
            {"Small", Driver::Smallblock, Driver::DriverMode::Small},
            {"Big", Driver::Bigordevkit, Driver::DriverMode::Big},
        };

        class BadBlockMark : public ::testing::TestWithParam<MarkShape> {};

        TEST_P(BadBlockMark, IsReadOnTheFirstAndMiddlePages) {
            const auto& shape = GetParam();
            Driver driver(shape.size, shape.mode);
            const size_t mark = shape.mode == Driver::DriverMode::Big ? 0 : 5;
            const size_t pages = driver.pages_per_block();

            // A big block's filesystem pages after the first hold zero at the mark byte.
            driver.read_page_spare(3 * pages + 1)[mark] = 0;
            EXPECT_FALSE(driver.is_bad_block(3)) << "a mark on the second page is not a bad block";

            driver.read_page_spare(4 * pages + pages / 2)[mark] = 0;
            EXPECT_TRUE(driver.is_bad_block(4)) << "a mark on the middle page is a bad block";

            driver.mark_bad_block(5);
            EXPECT_EQ(driver.read_page_spare(5 * pages)[mark], 0)
                << "marking a block bad marks its first and middle pages";
            EXPECT_EQ(driver.read_page_spare(5 * pages + pages / 2)[mark], 0)
                << "marking a block bad marks its first and middle pages";
            EXPECT_EQ(driver.read_page_spare(5 * pages + 1)[mark], 0xFF)
                << "marking a block bad marks its first and middle pages";
            EXPECT_TRUE(driver.is_bad_block(5)) << "a block marked bad reads back bad";
            EXPECT_TRUE(driver.interpret_block(5).is_bad) << "a block marked bad reads back bad";
        }

        INSTANTIATE_TEST_SUITE_P(Shape, BadBlockMark, ::testing::ValuesIn(kMarkShapes),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::nand
