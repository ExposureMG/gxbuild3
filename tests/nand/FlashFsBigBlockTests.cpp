// The big-block FlashFS (src/nand/objects/FlashFileSystem.hpp on Driver::DriverMode::Big): file
// chains on 16 KiB cluster addresses, the writer's cluster allocation, the retail/xeBuild spare
// profile that save() and serialize() stamp, a 148-cluster file through save -> serialize -> load,
// what the table states for withheld and root clusters, and the spare of a one-cluster file's
// padding.

#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Expect.hpp"
#include "support/builders/FlashFsRoots.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <span>
#include <utility>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;
        using test::flashfs::map_offset;
        using test::flashfs::put16;
        using test::flashfs::put32;

        uint16_t stated_map_value(const Bytes& root, size_t index) {
            const size_t at = map_offset(index);
            return static_cast<uint16_t>((root[at] << 8) | root[at + 1]);
        }

        TEST(FlashFsBigBlock, LoadsTheIndependentBigBlockLayout) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            Bytes root(0x4000, 0);
            // The on-disk map has 4096 16 KiB clusters, despite only 512 erase blocks.
            for (size_t cluster = 0; cluster < 4096; ++cluster) {
                put16(root, map_offset(cluster), BlockMapStatus::Free);
            }
            put16(root, map_offset(988), 999);
            put16(root, map_offset(999), BlockMapStatus::EndOfChain);
            std::memcpy(root.data() + 512, "secdata.bin", 12);
            put16(root, 512 + 22, 988);
            put32(root, 512 + 24, 0x4003);
            Bytes expected(0x4003, 0x31);
            expected[0x4000] = 0x42;
            expected[0x4001] = 0x53;
            expected[0x4002] = 0x64;
            ASSERT_TRUE(driver.write_block(380, root)) << "independent fixture writes succeed";
            ASSERT_TRUE(
                driver.write_offset((0xAE0 + 988) * 0x4000, std::span(expected).first(0x4000)))
                << "independent fixture writes succeed";
            ASSERT_TRUE(
                driver.write_offset((0xAE0 + 999) * 0x4000, std::span(expected).subspan(0x4000)))
                << "independent fixture writes succeed";
            FlashFileSystem fs;
            ASSERT_OK(fs.load(driver, 380)) << "independent big-block root loads";
            const auto file = fs.get_file("secdata.bin");
            ASSERT_TRUE(file.has_value())
                << "big-block file chains use 16 KiB cluster addresses and lengths";
            ASSERT_BYTES_EQ(expected, *file)
                << "big-block file chains use 16 KiB cluster addresses and lengths";
            put16(root, map_offset(988), BlockMapStatus::EndOfChain);
            ASSERT_TRUE(driver.write_block(380, root)) << "the truncated root writes";
            FlashFileSystem truncated;
            EXPECT_FALSE(truncated.load(driver, 380).has_value())
                << "a truncated chain must not be cached as a successfully read file";
        }

        TEST(FlashFsBigBlock, WriterUsesClusters) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), 380)) << "big-block filesystem formats";
            const Bytes first(0x4003, 0x31);
            const Bytes second(1024, 0x42);
            ASSERT_OK(fs.add_file("first.bin", first)) << "big-block files allocate";
            ASSERT_OK(fs.add_file("second.bin", second)) << "big-block files allocate";
            const auto first_entry = fs.stat("first.bin");
            const auto second_entry = fs.stat("second.bin");
            ASSERT_TRUE(first_entry.has_value()) << "first.bin entry exists";
            ASSERT_TRUE(second_entry.has_value()) << "second.bin entry exists";
            ASSERT_FALSE(fs.is_block_free(first_entry->block_number / 8))
                << "physical allocation sees every occupied subcluster";
            ASSERT_FALSE(fs.set_root_block(first_entry->block_number / 8).has_value())
                << "root cannot overwrite an occupied physical block";
            ASSERT_OK(fs.reserve_blocks(200, 1)) << "physical block reservation succeeds";
            ASSERT_TRUE(
                std::all_of(fs.blockmap().begin() + 200 * 8, fs.blockmap().begin() + 201 * 8,
                            [](uint16_t value) { return value == BlockMapStatus::Reserved; }))
                << "physical reservation covers all eight clusters";
            ASSERT_OK(fs.set_root_block(350))
                << "root relocation reserves and releases whole erase blocks";
            ASSERT_TRUE(fs.is_block_free(380))
                << "root relocation reserves and releases whole erase blocks";
            ASSERT_FALSE(fs.is_block_free(350))
                << "root relocation reserves and releases whole erase blocks";
            ASSERT_EQ(fs.get_chain(first_entry->block_number).size(), 2u)
                << "a 16 KiB plus three byte file requires two clusters";
            ASSERT_OK(fs.save()) << "big-block files save";
            const auto first_address = static_cast<size_t>(first_entry->block_number) * 0x4000;
            const auto second_address = static_cast<size_t>(second_entry->block_number) * 0x4000;
            EXPECT_BYTES_EQ(first, driver.read_clean(first_address, first.size()))
                << "writer uses on-disk 16 KiB addresses";
            EXPECT_BYTES_EQ(second, driver.read_clean(second_address, second.size()))
                << "writing a neighboring cluster preserves earlier file data";
        }

        // Big-block images must carry the retail/xeBuild spare profile the stock kernel
        // mounts: root type 0x2C, data type 0x2A with sequence 0, and the constant
        // fs_size 0x2006 / page_count 0x04 stamp on both. A small-block 0x30 root makes
        // the filesystem invisible on big-block hardware (error 1033 / "xam.xex missing").
        TEST(FlashFsBigBlock, StampsRetailFsMetadata) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), 350, 0x125))
                << "big-block filesystem formats";
            const Bytes payload(0x4003, 0x31);
            ASSERT_OK(fs.add_file("xam.xex", payload)) << "big-block file allocates";
            ASSERT_OK(fs.save()) << "big-block filesystem saves";

            const auto entry = fs.stat("xam.xex");
            ASSERT_TRUE(entry.has_value()) << "xam.xex entry exists";

            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            const auto root = driver.interpret_cluster(350 * clusters_per_block);
            const auto data = driver.interpret_block(entry->block_number / clusters_per_block);

            EXPECT_EQ(root.block_type, FlashFsMetadata::kRootTypeBig)
                << "big-block root is stamped 0x2C";
            EXPECT_EQ(root.sequence, 0x125u) << "big-block root keeps the FS version";
            EXPECT_EQ(root.fs_size, FlashFsMetadata::kBigFsSize)
                << "big-block root fs_size matches the 0x2006 reference";
            EXPECT_EQ(root.page_count, FlashFsMetadata::kBigPageCount)
                << "big-block root page_count matches the 0x04 reference";
            EXPECT_EQ(data.block_type, FlashFsMetadata::kDataTypeBig)
                << "big-block data is stamped 0x2A";
            EXPECT_EQ(data.sequence, 0u) << "big-block data sequence is 0";
            EXPECT_EQ(data.fs_size, FlashFsMetadata::kBigFsSize)
                << "big-block data fs_size matches the 0x2006 reference";
            EXPECT_EQ(data.page_count, FlashFsMetadata::kBigPageCount)
                << "big-block data page_count matches the 0x04 reference";
        }

        // serialize() re-stamps the root from NandLayout and overrides whatever save() wrote,
        // so the big-block root profile must be applied there too.
        TEST(FlashFsBigBlock, SerializeRestampsRoot) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            NandLayout layout;
            layout.fs_root_block = 350;
            layout.fs_version = 0x125;
            driver.set_layout(layout);
            driver.serialize();

            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            const auto root = driver.interpret_cluster(350 * clusters_per_block);
            EXPECT_EQ(root.block_type, FlashFsMetadata::kRootTypeBig)
                << "serialize re-stamps the big-block root as 0x2C";
            EXPECT_EQ(root.sequence, 0x125u) << "serialize keeps the FS version on the root";
            EXPECT_EQ(root.fs_size, FlashFsMetadata::kBigFsSize)
                << "serialize overrides the root fs_size to 0x2006 on big-block";
            EXPECT_EQ(root.page_count, FlashFsMetadata::kBigPageCount)
                << "serialize stamps the root page_count 0x04 on big-block";
        }

        // Method 4: a large, multi-cluster file must survive the full write path
        // (save -> serialize ECC/metadata re-stamp -> fresh load) byte-for-byte. This mirrors
        // xam.xex (0x250000 == 148 clusters) plus a partial-tail neighbour, so it exercises
        // interleaved chains, a non-multiple final cluster, and the ECC recompute. A scatter,
        // chain-order, or short-write defect shows up here without any hardware.
        TEST(FlashFsBigBlock, LargeFileRoundtripsThroughSerialize) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            const uint16_t root_block = 350;
            ASSERT_OK(fs.format(driver.block_count(), root_block, 0x125))
                << "big-block filesystem formats for round-trip";

            const size_t xam_size = 0x250000;
            Bytes xam(xam_size);
            for (size_t i = 0; i < xam_size; ++i)
                xam[i] = static_cast<uint8_t>((i * 31 + (i >> 12)) & 0xFF);
            const size_t other_size = 0x12345;
            Bytes other(other_size);
            for (size_t i = 0; i < other_size; ++i)
                other[i] = static_cast<uint8_t>((i * 173 + (i >> 9)) & 0xFF);
            ASSERT_OK(fs.add_file("xam.xex", xam)) << "xam-sized file allocates";
            ASSERT_OK(fs.add_file("other.bin", other)) << "partial-tail file allocates";

            NandLayout layout;
            layout.fs_root_block = root_block;
            layout.fs_version = fs.version();
            driver.set_layout(layout);

            ASSERT_OK(fs.save()) << "large files save";
            Bytes serialized = driver.serialize();

            Driver reload(std::move(serialized));
            ASSERT_EQ(reload.driver_mode(), Driver::DriverMode::Big)
                << "serialized big-block image re-detects as big-block";
            FlashFileSystem reloaded;
            ASSERT_OK(reloaded.load(reload, root_block)) << "big-block filesystem reloads";

            const auto got_xam = reloaded.get_file("xam.xex");
            const auto got_other = reloaded.get_file("other.bin");
            EXPECT_TRUE(got_xam.has_value())
                << "148-cluster xam.xex survives save -> serialize -> load byte-for-byte";
            EXPECT_BYTES_EQ(xam, got_xam.value_or(Bytes{}))
                << "148-cluster xam.xex survives save -> serialize -> load byte-for-byte";
            EXPECT_TRUE(got_other.has_value())
                << "partial-tail neighbour survives the same round-trip";
            EXPECT_BYTES_EQ(other, got_other.value_or(Bytes{}))
                << "partial-tail neighbour survives the same round-trip";
        }

        // The table states what xeBuild 1.21 states: the root's own cluster 0x1FFD and the rest
        // of its erase block free, withheld clusters as they were withheld (settings blobs free,
        // the remap pool and stepped-over clusters 0), none of them allocatable.
        TEST(FlashFsBigBlock, TableStatesWithheldAndRootClusters) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot)) << "formats";
            // Big block: the table counts clusters from 0xAE0, 8 to an erase block.
            constexpr size_t base = 0xAE0;
            ASSERT_OK(fs.add_file("one.bin", Bytes(0x200, 1))) << "a file allocates";
            ASSERT_OK(fs.withhold_clusters(base + 1, 7, BlockMapStatus::Unnamed))
                << "stepped-over clusters withhold";
            ASSERT_OK(fs.withhold_blocks((base + 8) / 8, 1, BlockMapStatus::Free))
                << "a blob's erase block withholds";
            ASSERT_OK(fs.withhold_blocks(0x1DC, 4, BlockMapStatus::Unnamed))
                << "the tail withholds";
            ASSERT_OK(fs.set_root_block((base + 16) / 8)) << "the root takes the next erase block";
            ASSERT_FALSE(fs.is_block_free((base + 8) / 8)) << "withheld blocks are not free";
            ASSERT_FALSE(fs.is_block_free(0x1DC)) << "withheld blocks are not free";
            ASSERT_FALSE(fs.withhold_clusters(base, 1, BlockMapStatus::Free).has_value())
                << "a file cluster cannot be withheld";
            const auto table = fs.serialize_root_block();
            ASSERT_OK(table) << "the table serializes";
            ASSERT_EQ(table->size(), kCleanBlockSize) << "the table serializes";
            EXPECT_EQ(stated_map_value(*table, 0), BlockMapStatus::EndOfChain)
                << "the file ends its chain";
            EXPECT_EQ(stated_map_value(*table, 1), BlockMapStatus::Unnamed)
                << "stepped-over clusters are never named";
            EXPECT_EQ(stated_map_value(*table, 7), BlockMapStatus::Unnamed)
                << "stepped-over clusters are never named";
            EXPECT_EQ(stated_map_value(*table, 8), BlockMapStatus::Free)
                << "a blob's clusters are stated free";
            EXPECT_EQ(stated_map_value(*table, 15), BlockMapStatus::Free)
                << "a blob's clusters are stated free";
            EXPECT_EQ(stated_map_value(*table, 16), BlockMapStatus::Table)
                << "the root states itself";
            EXPECT_EQ(stated_map_value(*table, 17), BlockMapStatus::Free)
                << "the rest of the root's erase block is stated free";
            EXPECT_EQ(stated_map_value(*table, 23), BlockMapStatus::Free)
                << "the rest of the root's erase block is stated free";
            EXPECT_EQ(stated_map_value(*table, 0x400), BlockMapStatus::Unnamed)
                << "the tail is never named";
        }

        // A big-block file of one cluster states its spare on the pages its bytes reach and
        // leaves the padding's fields erased; a longer file states it on every page. The spare
        // carries the system area given to the filesystem.
        TEST(FlashFsBigBlock, SingleClusterPaddingKeepsErasedFields) {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            fs.set_big_system_blocks(0x10);
            ASSERT_OK(fs.format(driver.block_count(), 350)) << "formats";
            ASSERT_OK(fs.add_file("short.bin", Bytes(0x2800, 0x5A))) << "files allocate";
            ASSERT_OK(fs.add_file("long.bin", Bytes(0x4400, 0x6B))) << "files allocate";
            ASSERT_OK(fs.save()) << "saves";
            const auto short_entry = fs.stat("short.bin");
            const auto long_entry = fs.stat("long.bin");
            ASSERT_TRUE(short_entry.has_value()) << "short.bin entry exists";
            ASSERT_TRUE(long_entry.has_value()) << "long.bin entry exists";
            const auto long_chain = fs.get_chain(long_entry->block_number);
            ASSERT_FALSE(long_chain.empty()) << "long.bin has a chain";
            const size_t first_page = static_cast<size_t>(short_entry->block_number) * 32;
            bool data_pages = true;
            bool padding_pages = true;
            for (size_t page = first_page; page < first_page + 32; ++page) {
                const auto spare = driver.read_page_spare(page);
                if (page < first_page + 0x14) {
                    data_pages = data_pages && spare[7] == 0x10 && spare[8] == 0x20 &&
                                 spare[9] == 0x04 && (spare[0xC] & 0x3F) == 0x2A;
                } else {
                    padding_pages =
                        padding_pages && std::all_of(spare.begin(), spare.begin() + 12,
                                                     [](uint8_t b) { return b == 0xFF; });
                }
            }
            bool long_pages = long_chain.size() == 2;
            for (size_t page = long_chain.back() * 32u;
                 long_pages && page < static_cast<size_t>(long_chain.back()) * 32 + 32; ++page) {
                long_pages = (driver.read_page_spare(page)[0xC] & 0x3F) == 0x2A;
            }
            EXPECT_EQ(fs.big_fs_size(), 0x2010) << "the stamp states a 0x10-block system area";
            EXPECT_TRUE(data_pages) << "a one-cluster file's data pages carry its spare";
            EXPECT_TRUE(padding_pages) << "its padding pages keep erased fields";
            EXPECT_TRUE(long_pages)
                << "a longer file's last cluster carries its spare on every page";
        }

    } // namespace
} // namespace gxbuild3::nand
