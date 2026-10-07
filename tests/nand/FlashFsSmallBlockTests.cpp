// The small-block FlashFS (src/nand/objects/FlashFileSystem.hpp on Driver::DriverMode::Small and
// NewSmall): the spare metadata save() writes matches real 16 MB dumps on both modes, serialize()
// leaves the erased low pages unprogrammed, a deferred root is placed last from the free pool,
// and inserted CG tails lay every file back to back behind them.
//
// FlashFsSmallBlock is the Mode/ table over both small-block modes; its plain companions are in
// FlashFsSmallBlockLayout (gtest forbids TEST and TEST_P in one suite).

#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        struct SmallBlockMode {
            const char* name;
            Driver::DriverMode mode;
        };
        GX_PRINT_ROW_AS_NAME(SmallBlockMode)

        constexpr SmallBlockMode kSmallBlockModes[] = {
            {"Small", Driver::DriverMode::Small},
            {"NewSmall", Driver::DriverMode::NewSmall},
        };

        class FlashFsSmallBlock : public ::testing::TestWithParam<SmallBlockMode> {};

        // Small/new-small images stamp the root 0x30 with the FS version and leave file data
        // blocks as plain type 0x00, sequence 0, no size or page count, as real 16 MB dumps
        // and xeBuild do. The file's last cluster is zero-padded, so every page of it carries
        // that spare, and the FsUnused nibble and bytes 0xA-0xB are zero.
        TEST_P(FlashFsSmallBlock, MetadataMatchesDumps) {
            const Driver::DriverMode mode = GetParam().mode;
            Driver driver(Driver::ImageSize::Smallblock, mode);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), 300, 7)) << "small-block filesystem formats";
            const Bytes payload(1024, 0x42);
            ASSERT_OK(fs.add_file("boot.bin", payload)) << "small-block file allocates";
            const auto entry = fs.stat("boot.bin");
            ASSERT_TRUE(entry.has_value()) << "boot.bin entry exists";

            // Stale erased bytes and spare under the file's cluster.
            const size_t first_page = static_cast<size_t>(entry->block_number) * 32;
            ASSERT_TRUE(driver.write_offset(static_cast<size_t>(entry->block_number) * 0x4000,
                                            Bytes(0x4000, 0xFF)))
                << "stale cluster fill writes";
            for (size_t page = first_page; page < first_page + 32; ++page) {
                driver.write_page_spare(page, Bytes(16, 0xFF));
            }
            ASSERT_OK(fs.save()) << "small-block filesystem saves";

            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            const auto root = driver.interpret_cluster(300 * clusters_per_block);
            const auto data = driver.interpret_block(entry->block_number / clusters_per_block);
            const size_t nibble_byte = mode == Driver::DriverMode::Small ? 1 : 2;
            bool spare_clean = true;
            bool padded = true;
            for (size_t page = first_page; page < first_page + 32; ++page) {
                const auto spare = driver.read_page_spare(page);
                spare_clean = spare_clean && (spare[nibble_byte] & 0xF0) == 0 && spare[0xA] == 0 &&
                              spare[0xB] == 0 && spare[5] == 0xFF;
                if (page >= first_page + 2) {
                    const auto bytes = driver.read_page(page);
                    padded = padded && std::all_of(bytes.begin(), bytes.end(),
                                                   [](uint8_t b) { return b == 0; });
                }
            }

            EXPECT_EQ(root.block_type, FlashFsMetadata::kRootTypeSmall)
                << "small-block root stays 0x30";
            EXPECT_EQ(root.sequence, 7u) << "small-block root keeps the FS version";
            EXPECT_EQ(data.block_type, 0x00) << "small-block data is type 0x00";
            EXPECT_EQ(data.sequence, 0u) << "small-block data sequence is 0";
            EXPECT_EQ(data.fs_size, 0) << "small-block data carries no size or page count";
            EXPECT_EQ(data.page_count, 0) << "small-block data carries no size or page count";
            EXPECT_EQ(size_t{data.logical_block_id}, entry->block_number / clusters_per_block)
                << "small-block data carries its block ID";
            EXPECT_TRUE(spare_clean) << "small-block data spare has zero FsUnused fields";
            EXPECT_TRUE(padded) << "the file's last cluster is zero-padded";
        }

        INSTANTIATE_TEST_SUITE_P(Mode, FlashFsSmallBlock, ::testing::ValuesIn(kSmallBlockModes),
                                 test::RowName{});

        // serialize() stamps type-0 metadata on the blocks below 0x50 that are not the root, a
        // mobile or FlashFS file data. Pages holding erased data there get an erased spare,
        // whatever spare they held before; FlashFS file blocks keep the spare save() wrote.
        TEST(FlashFsSmallBlockLayout, SerializeLeavesErasedLowPagesUnprogrammed) {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall);
            const size_t block = 0x24;
            const size_t file_block = 0x25;
            const size_t ppb = driver.pages_per_block();
            ASSERT_TRUE(driver.write_offset(block * 0x4000, Bytes(0x8000, 0xFF)))
                << "erased low blocks write";
            ASSERT_TRUE(driver.write_offset(block * 0x4000, Bytes(0x200, 0x5A)))
                << "first low page writes";
            BlockMetadata file_meta{};
            file_meta.logical_block_id = static_cast<uint16_t>(file_block);
            driver.write_block_metadata(file_block, file_meta);
            NandLayout layout;
            layout.fs_data_blocks.push_back(static_cast<uint16_t>(file_block));
            driver.set_layout(layout);

            const auto& raw = driver.serialize();
            const auto page_raw = [&](size_t page) {
                return std::span<const uint8_t>(raw.data() + page * 528, 528);
            };
            const auto written = page_raw(block * ppb);
            bool erased = true;
            for (size_t page = block * ppb + 1; page < (block + 1) * ppb; ++page) {
                const auto bytes = page_raw(page);
                erased = erased && std::all_of(bytes.begin(), bytes.end(),
                                               [](uint8_t b) { return b == 0xFF; });
            }
            bool file_stamped = true;
            for (size_t page = file_block * ppb; page < (file_block + 1) * ppb; ++page) {
                const auto bytes = page_raw(page);
                file_stamped = file_stamped && bytes[0x201] == file_block && bytes[0x205] == 0xFF;
            }
            EXPECT_EQ(size_t{written[0x201]}, block)
                << "a programmed low page carries its block ID and type 0";
            EXPECT_EQ(written[0x202] & 0xF0, 0)
                << "a programmed low page carries its block ID and type 0";
            EXPECT_EQ(written[0x20C] & 0x3F, 0)
                << "a programmed low page carries its block ID and type 0";
            EXPECT_TRUE(erased) << "erased low pages carry erased data and spare";
            EXPECT_TRUE(file_stamped) << "erased pages of a FlashFS file block keep their stamp";
        }

        // A deferred format (kDeferRoot) must not commit a root block, so serialize can
        // allocate the root once, last, from the same free pool the files and mobile data
        // draw from. Regression: format() used to pre-consume the final data block for the
        // root, so a full image had no free block left for placement and the build failed.
        TEST(FlashFsSmallBlockLayout, DeferredRootIsPlacedLastFromFreePool) {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot))
                << "deferred-root filesystem formats";
            ASSERT_FALSE(fs.has_root()) << "kDeferRoot must leave the root unplaced after format";
            ASSERT_FALSE(fs.save().has_value())
                << "save must be rejected before a root block is placed";
            ASSERT_TRUE(fs.is_block_free(0x3E0))
                << "deferred format must not consume the default root block 0x3E0";

            // Consume every data block below the limit except the final one, mirroring a
            // build whose files and mobile data leave a single free block for the root.
            const size_t limit = driver.data_block_limit();
            constexpr size_t reserved_boundary = 0x50;
            ASSERT_OK(fs.reserve_blocks(reserved_boundary, limit - 1 - reserved_boundary))
                << "data region below the final block reserves";
            ASSERT_TRUE(fs.is_block_free(limit - 1))
                << "exactly one free data block remains below the limit";

            ASSERT_OK(fs.set_root_block(static_cast<uint16_t>(limit - 1)))
                << "set_root_block places the sole remaining free data block";
            EXPECT_TRUE(fs.has_root()) << "has_root() reports placement after set_root_block";
            EXPECT_EQ(size_t{fs.root_block()}, limit - 1)
                << "root_block() reports the deferred placement";
            EXPECT_FALSE(fs.is_block_free(limit - 1)) << "the placed root block is no longer free";
            EXPECT_OK(fs.save()) << "save succeeds once the deferred root is placed";
        }

        // A CG tail inserted first is laid on the first free blocks and every file after it is
        // laid again behind it, in directory order, with the filesystem's stamp.
        TEST(FlashFsSmallBlockLayout, InsertFileLaysFilesBackToBack) {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot, 1, 0x24))
                << "small-block filesystem formats from block 0x24";
            fs.set_timestamp(0x5D444AC2);
            ASSERT_OK(fs.add_file("a.bin", Bytes(0x4001, 0xA1))) << "files allocate";
            ASSERT_OK(fs.add_file("b.bin", Bytes(0x10, 0xB2), 0x11223344)) << "files allocate";
            ASSERT_OK(fs.insert_file(0, "sysupdate.xexp1", Bytes(0x8000, 0x51)))
                << "CG tails insert";
            ASSERT_OK(fs.insert_file(1, "sysupdate.xexp2", Bytes(0x10, 0x52))) << "CG tails insert";
            const auto& entries = fs.entries();
            const std::vector<std::pair<std::string, uint16_t>> expected{{"sysupdate.xexp1", 0x24},
                                                                         {"sysupdate.xexp2", 0x26},
                                                                         {"a.bin", 0x27},
                                                                         {"b.bin", 0x29}};
            ASSERT_EQ(entries.size(), expected.size())
                << "tails come first and the files follow back to back";
            for (size_t i = 0; i < expected.size(); ++i) {
                ASSERT_EQ(std::string(entries[i].filename), expected[i].first)
                    << "tails come first and the files follow back to back (entry " << i << ")";
                ASSERT_EQ(entries[i].block_number, expected[i].second)
                    << "tails come first and the files follow back to back (entry " << i << ")";
            }
            const auto a_chain = fs.get_chain(entries[2].block_number);
            ASSERT_EQ(a_chain, (std::vector<uint16_t>{0x27, 0x28}))
                << "a moved file keeps its chain";
            const auto a_bytes = fs.get_file("a.bin");
            ASSERT_TRUE(a_bytes.has_value()) << "a moved file keeps its bytes";
            ASSERT_BYTES_EQ(Bytes(0x4001, 0xA1), *a_bytes) << "a moved file keeps its bytes";
            ASSERT_EQ(entries[0].timestamp, 0x5D444AC2u) << "entries take the filesystem's stamp";
            ASSERT_EQ(entries[2].timestamp, 0x5D444AC2u) << "entries take the filesystem's stamp";
            ASSERT_EQ(entries[3].timestamp, 0x11223344u) << "a given stamp is kept when moved";
            ASSERT_OK(fs.insert_file(0, "sysupdate.xexp1", Bytes(0x10, 0x53)))
                << "a CG tail is replaced in place";
            ASSERT_EQ(fs.entries().size(), 4u)
                << "replacing the first tail lays the rest again behind it";
            EXPECT_EQ(std::string(fs.entries()[0].filename), "sysupdate.xexp1")
                << "replacing the first tail lays the rest again behind it";
            EXPECT_EQ(fs.entries()[0].block_number, 0x24)
                << "replacing the first tail lays the rest again behind it";
            EXPECT_EQ(fs.entries()[1].block_number, 0x25)
                << "replacing the first tail lays the rest again behind it";
            EXPECT_EQ(fs.entries()[2].block_number, 0x26)
                << "replacing the first tail lays the rest again behind it";
        }

    } // namespace
} // namespace gxbuild3::nand
