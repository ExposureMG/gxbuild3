// The mobile data blobs (MobileB = type 0x31, MobileC = 0x32, src/nand/objects/MobileData.hpp)
// as FlashImage reads and lays them: the latest copy is taken on small and big block, a written
// blob is laid where and as xeBuild lays it, a rewrite erases every older copy, and a blob longer
// than one copy is refused, at a limit that follows the layout.
//
// The fixture class MobileData (the Shape/MobileData table) hides nand::MobileData inside this
// file's anonymous namespace, so the blob set is always spelled nand::MobileData here.

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/NandShapes.hpp"
#include "nand/objects/MobileData.hpp"
#include "support/Expect.hpp"
#include "support/builders/FlashImageCells.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <utility>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        // Lays one blob copy as a console does: its bytes in consecutive pages and, on those pages
        // only, a spare naming its type, version, length and the free count left behind it.
        void stamp_mobile_copy(Driver& driver, size_t block, size_t first_page, uint8_t type,
                               uint32_t sequence, uint8_t free_count, size_t tagged_pages,
                               const Bytes& bytes) {
            const size_t page = block * driver.pages_per_block() + first_page;
            EXPECT_TRUE(driver.write_offset(page * 512, bytes)) << "a mobile copy is laid";
            BlockMetadata meta{};
            meta.logical_block_id = static_cast<uint16_t>(block);
            meta.sequence = sequence;
            meta.block_type = type;
            meta.page_count = free_count;
            meta.fs_size = static_cast<uint16_t>(bytes.size());
            driver.write_page_metadata(page, tagged_pages, meta);
        }

        struct MobilePageSurvey {
            size_t tagged_pages = 0;
            size_t first_page = 0;
            BlockMetadata meta{};
        };

        // Where a type's pages are and what their spare says; assumes a single copy.
        MobilePageSurvey survey_mobile(const Driver& driver, uint8_t type) {
            MobilePageSurvey survey{};
            const size_t pages = driver.block_count() * driver.pages_per_block();
            for (size_t page = 0; page < pages; ++page) {
                const auto meta = driver.interpret_page(page);
                if (meta.block_type != type) {
                    continue;
                }
                if (survey.tagged_pages++ == 0) {
                    survey.first_page = page;
                    survey.meta = meta;
                }
            }
            return survey;
        }

        // The small-block modes, where each blob type keeps blocks of its own.
        struct LatestShape {
            const char* name;
            Driver::DriverMode mode;
        };
        GX_PRINT_ROW_AS_NAME(LatestShape)

        constexpr LatestShape kLatestShapes[] = {
            {"Small", Driver::DriverMode::Small},
            {"NewSmall", Driver::DriverMode::NewSmall},
        };

        class MobileData : public ::testing::TestWithParam<LatestShape> {};

        TEST_P(MobileData, FlashImageTakesTheLatestMobileCopy) {
            Driver source(Driver::ImageSize::Smallblock, GetParam().mode);
            // An older block of MobileB, then its live block holding three copies appended
            // one after another, each with four fewer pages free.
            source.erase_block(0x80);
            stamp_mobile_copy(source, 0x80, 0, 0x31, 5, 28, 4, Bytes(0x800, 0x99));
            source.erase_block(0x90);
            for (uint8_t copy = 0; copy < 3; ++copy) {
                stamp_mobile_copy(source, 0x90, copy * 4, 0x31, 6,
                                  static_cast<uint8_t>(28 - copy * 4), 4,
                                  Bytes(0x800, static_cast<uint8_t>(0x11 + copy)));
            }
            // MobileC: one-page copies.
            source.erase_block(0xA0);
            stamp_mobile_copy(source, 0xA0, 0, 0x32, 1, 31, 1, Bytes(0x200, 0x21));
            stamp_mobile_copy(source, 0xA0, 1, 0x32, 1, 30, 1, Bytes(0x200, 0x22));

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value()) << "FlashImage must parse small-block mobile copies";
            ASSERT_OK(image->parse()) << "FlashImage must parse small-block mobile copies";
            ASSERT_TRUE(image->mobile_data.has_value())
                << "FlashImage must parse small-block mobile copies";
            EXPECT_BYTES_EQ(Bytes(0x800, 0x13), image->mobile_data->x31.value_or(Bytes{}))
                << "the newest version's last copy of MobileB is taken";
            EXPECT_BYTES_EQ(Bytes(0x200, 0x22), image->mobile_data->x32.value_or(Bytes{}))
                << "the last one-page copy of MobileC is taken";
        }

        INSTANTIATE_TEST_SUITE_P(Shape, MobileData, ::testing::ValuesIn(kLatestShapes),
                                 test::RowName{});

        // Big block: every type shares one erase block, each copy in its own 0x800 slot. A
        // console tags the whole slot, so a 0x200-byte copy is followed by three tagged
        // pages of 0xFF.
        TEST(MobileDataBigBlock, FlashImageTakesTheLatestMobileCopy) {
            Driver big(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            big.erase_block(0x1C4);
            const Bytes slot_32(0x200, 0x32);
            stamp_mobile_copy(big, 0x1C4, 0, 0x32, 7, 60, 4, slot_32);
            stamp_mobile_copy(big, 0x1C4, 4, 0x31, 7, 60, 4, Bytes(0x800, 0x41));
            stamp_mobile_copy(big, 0x1C4, 8, 0x31, 7, 59, 4, Bytes(0x800, 0x42));
            auto image = FlashImage::read(big.serialize());
            ASSERT_TRUE(image.has_value()) << "FlashImage must parse big-block mobile copies";
            ASSERT_OK(image->parse()) << "FlashImage must parse big-block mobile copies";
            ASSERT_TRUE(image->mobile_data.has_value())
                << "FlashImage must parse big-block mobile copies";
            EXPECT_BYTES_EQ(Bytes(0x800, 0x42), image->mobile_data->x31.value_or(Bytes{}))
                << "the latest big-block MobileB slot is taken";
            EXPECT_BYTES_EQ(slot_32, image->mobile_data->x32.value_or(Bytes{}))
                << "a short big-block copy is read from its slot's first page";
        }

        struct LayoutShape {
            const char* name;
            Driver::ImageSize size;
            Driver::DriverMode mode;
            uint8_t b_free;
            uint8_t c_free;
            size_t c_after_b; // pages from MobileB's first page to MobileC's
        };
        GX_PRINT_ROW_AS_NAME(LayoutShape)

        // Small block: a block each, free pages counted. Big block: one erase block, 0x800
        // slots counted, 63 then 62 down the block.
        constexpr LayoutShape kLayoutShapes[] = {
            {"Small", Driver::ImageSize::Smallblock, Driver::DriverMode::Small, 28, 31, 32},
            {"NewSmall", Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall, 28, 31, 32},
            {"Big", Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big, 63, 62, 4},
        };

        class MobileDataLayout : public ::testing::TestWithParam<LayoutShape> {};

        TEST_P(MobileDataLayout, MobileCopiesAreLaidAsXeBuildLaysThem) {
            const auto& shape = GetParam();
            const Bytes mobile_b(0x800, 0x31);
            const Bytes mobile_c(0x200, 0x32);
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            nand::MobileData mobile;
            mobile.x31 = mobile_b;
            mobile.x32 = mobile_c;
            image.mobile_data = mobile;
            const auto bytes = image.write();
            ASSERT_OK(bytes) << "an image with mobile data writes";

            const auto& driver = std::as_const(image.flash_driver);
            const auto b = survey_mobile(driver, 0x31);
            const auto c = survey_mobile(driver, 0x32);
            EXPECT_EQ(b.tagged_pages, 4u) << "only the pages holding a blob carry its type";
            EXPECT_EQ(c.tagged_pages, 1u) << "only the pages holding a blob carry its type";
            EXPECT_EQ(b.first_page % driver.pages_per_block(), 0u)
                << "blobs are laid in type order where xeBuild lays them";
            EXPECT_EQ(c.first_page, b.first_page + shape.c_after_b)
                << "blobs are laid in type order where xeBuild lays them";
            EXPECT_EQ(b.meta.sequence, 1u) << "every blob is written as version 1";
            EXPECT_EQ(c.meta.sequence, 1u) << "every blob is written as version 1";
            EXPECT_EQ(b.meta.page_count, shape.b_free)
                << "the spare states what is left free behind each blob";
            EXPECT_EQ(c.meta.page_count, shape.c_free)
                << "the spare states what is left free behind each blob";
            EXPECT_EQ(b.meta.fs_size, 0x800) << "the spare states each blob's length";
            EXPECT_EQ(c.meta.fs_size, 0x200) << "the spare states each blob's length";
            // On big block MobileC's slot follows MobileB's directly.
            EXPECT_TRUE(b.first_page + 4 == c.first_page ||
                        page_is_erased(driver, b.first_page + 4))
                << "the pages after a blob stay erased";
            EXPECT_TRUE(page_is_erased(driver, c.first_page + 1))
                << "the pages after a blob stay erased";

            auto parsed = FlashImage::read(*bytes);
            ASSERT_TRUE(parsed.has_value()) << "laid blobs read back byte for byte";
            ASSERT_OK(parsed->parse()) << "laid blobs read back byte for byte";
            ASSERT_TRUE(parsed->mobile_data.has_value()) << "laid blobs read back byte for byte";
            EXPECT_BYTES_EQ(mobile_b, parsed->mobile_data->x31.value_or(Bytes{}))
                << "laid blobs read back byte for byte";
            EXPECT_BYTES_EQ(mobile_c, parsed->mobile_data->x32.value_or(Bytes{}))
                << "laid blobs read back byte for byte";
        }

        INSTANTIATE_TEST_SUITE_P(Shape, MobileDataLayout, ::testing::ValuesIn(kLayoutShapes),
                                 test::RowName{});

        TEST(MobileDataWrite, RewriteErasesEveryOlderMobileCopy) {
            Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall);
            // A donor copy whose version outranks the version 1 the writer gives the new one.
            source.erase_block(0x200);
            stamp_mobile_copy(source, 0x200, 0, 0x31, 900, 28, 4, Bytes(0x800, 0xEE));
            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value()) << "a donor with a mobile copy parses";
            ASSERT_OK(image->parse()) << "a donor with a mobile copy parses";
            ASSERT_TRUE(image->mobile_data.has_value()) << "a donor with a mobile copy parses";

            image->mobile_data->x31 = Bytes(0x800, 0x5A);
            const auto bytes = image->write();
            ASSERT_OK(bytes) << "the replacement blob is the one read back";
            auto parsed = FlashImage::read(*bytes);
            ASSERT_TRUE(parsed.has_value()) << "the replacement blob is the one read back";
            ASSERT_OK(parsed->parse()) << "the replacement blob is the one read back";
            ASSERT_TRUE(parsed->mobile_data.has_value())
                << "the replacement blob is the one read back";
            EXPECT_BYTES_EQ(Bytes(0x800, 0x5A), parsed->mobile_data->x31.value_or(Bytes{}))
                << "the replacement blob is the one read back";
            EXPECT_TRUE(page_is_erased(parsed->flash_driver, 0x200 * 32))
                << "the donor's mobile block is erased";
        }

        TEST(MobileDataWrite, MobileLongerThanOneCopyIsRefused) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            nand::MobileData mobile;
            mobile.x31 = Bytes(0x4001, 0x31);
            image.mobile_data = mobile;
            EXPECT_FALSE(image.write().has_value())
                << "a small-block blob longer than its block cannot be written";
        }

        // How long one copy may be follows the layout: small block holds a copy in one 0x4000
        // block, big block and eMMC cap it at the 16-bit length a copy records (0xFFFF), however
        // large their blocks are (lay_mobile_data in src/nand/FlashImageWrite.cpp; the
        // mobile_over_limit.* lines of flashimage_failures.txt).
        struct CopyLimitShape {
            const char* name;
            Driver::DriverMode mode;
            size_t over;
            const char* message;
        };
        GX_PRINT_ROW_AS_NAME(CopyLimitShape)

        constexpr CopyLimitShape kCopyLimitShapes[] = {
            {"Small", Driver::DriverMode::Small, 0x4001,
             "Mobile data type 0x31 is 0x4001 bytes; one copy holds at most 0x4000"},
            {"Big", Driver::DriverMode::Big, 0x10000,
             "Mobile data type 0x31 is 0x10000 bytes; one copy holds at most 0xFFFF"},
            {"Emmc", Driver::DriverMode::Emmc, 0x10000,
             "Mobile data type 0x31 is 0x10000 bytes; one copy holds at most 0xFFFF"},
        };

        class MobileDataCopyLimit : public ::testing::TestWithParam<CopyLimitShape> {};

        TEST_P(MobileDataCopyLimit, CopyLimitFollowsLayout) {
            const auto& shape = GetParam();
            // The failure table's bare Retail image of this shape.
            auto image = test::flashimage_cells::bare(shape.mode, BuildType::Retail);
            image->mobile_data = nand::MobileData{};
            image->mobile_data->x31 = Bytes(shape.over, 0x31);
            EXPECT_ERROR_MSG(image->write(), ErrorCode::OutOfRange, shape.message);
        }

        INSTANTIATE_TEST_SUITE_P(Shape, MobileDataCopyLimit, ::testing::ValuesIn(kCopyLimitShapes),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::nand
