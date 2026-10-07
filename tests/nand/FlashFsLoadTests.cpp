// FlashFileSystem::load (src/nand/objects/FlashFileSystem.hpp) is transactional: a root that
// fails to load leaves the filesystem, its root, table, directory, file data and driver, as the
// last successful load left it.

#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Expect.hpp"
#include "support/builders/FlashFsRoots.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <span>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;
        using test::flashfs::map_offset;
        using test::flashfs::put16;
        using test::flashfs::put32;

        TEST(FlashFsLoad, FailedLoadLeavesFilesystemUnchanged) {
            const auto write_root = [](Driver& driver, uint16_t root_block, uint16_t first_link) {
                Bytes root(0x4000, 0);
                for (size_t cluster = 0; cluster < 4096; ++cluster) {
                    put16(root, map_offset(cluster), BlockMapStatus::Free);
                }
                put16(root, map_offset(988), first_link);
                put16(root, map_offset(999), BlockMapStatus::EndOfChain);
                std::memcpy(root.data() + 512, "secdata.bin", 12);
                put16(root, 512 + 22, 988);
                put32(root, 512 + 24, 0x4003);
                const Bytes data(0x4003, 0x31);
                return driver.write_block(root_block, root) &&
                       driver.write_offset((0xAE0 + 988) * 0x4000, std::span(data).first(0x4000)) &&
                       driver.write_offset((0xAE0 + 999) * 0x4000, std::span(data).subspan(0x4000));
            };
            Driver good(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            Driver bad(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            // The bad root's file chain ends after one cluster, short of the file's length.
            ASSERT_TRUE(write_root(good, 380, 999)) << "transactional-load fixtures write";
            ASSERT_TRUE(write_root(bad, 381, BlockMapStatus::EndOfChain))
                << "transactional-load fixtures write";
            FlashFileSystem fs;
            ASSERT_OK(fs.load(good, 380)) << "the good root loads";
            const auto blockmap = fs.blockmap();
            const auto entries = fs.entries().size();
            const auto file = fs.get_file("secdata.bin");
            const auto version = fs.version();

            const auto failed = fs.load(bad, 381);
            EXPECT_ERROR(failed, ErrorCode::Truncated)
                << "a root whose file chain is short fails as Truncated";
            EXPECT_EQ(fs.root_block(), 380) << "a failed load keeps the loaded root";
            EXPECT_EQ(fs.version(), version) << "a failed load keeps the loaded root";
            EXPECT_TRUE(fs.has_root()) << "a failed load keeps the loaded root";
            EXPECT_EQ(fs.blockmap(), blockmap) << "a failed load keeps the table and directory";
            EXPECT_EQ(fs.entries().size(), entries)
                << "a failed load keeps the table and directory";
            const auto file_after = fs.get_file("secdata.bin");
            EXPECT_TRUE(file.has_value()) << "a failed load keeps the file data";
            EXPECT_TRUE(file_after.has_value()) << "a failed load keeps the file data";
            EXPECT_BYTES_EQ(file.value_or(Bytes{}), file_after.value_or(Bytes{}))
                << "a failed load keeps the file data";
            EXPECT_FALSE(fs.load(good, 380, 8).has_value())
                << "a root cluster past its erase block fails";
            EXPECT_EQ(fs.root_block(), 380) << "an out-of-range root cluster changes nothing";
            EXPECT_EQ(fs.blockmap(), blockmap) << "an out-of-range root cluster changes nothing";
        }

    } // namespace
} // namespace gxbuild3::nand
