// FlashFileSystem::load (src/nand/objects/FlashFileSystem.hpp) over on-disk roots a console
// never writes but a corrupt dump may hold: a name that fills all 22 bytes with no terminator,
// and a file length far past what its chain holds.

#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/FlashFsRoots.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;
        using test::flashfs_pattern;
        using test::flashfs::put_entry;
        using test::flashfs::slot_offset;
        using test::flashfs::small_root;

        // An on-disk name may fill all 22 bytes with no terminator. It is read as exactly those
        // 22 characters wherever an entry's name is taken: load, list_files, stat, get_file and
        // save agree on it, and re-serializing writes the same 22 bytes back.
        TEST(FlashFsCorruptInput, UnterminatedNameRoundTrips) {
            constexpr std::string_view kLongName = "abcdefghijklmnopqrstuv";
            static_assert(kLongName.size() == kMaxFilenameLength);
            constexpr uint16_t kRootBlock = 0x3E0;
            const Bytes long_data = flashfs_pattern(kCleanBlockSize, 0x22);
            const Bytes short_data = flashfs_pattern(kCleanBlockSize, 0x05);

            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            Bytes root = small_root();
            put_entry(root, 0, kLongName, 0x60, 0x10);
            put_entry(root, 1, "b.bin", 0x61, 0x20);
            ASSERT_TRUE(driver.write_offset(0x60 * kCleanBlockSize, long_data))
                << "unterminated-name fixture writes";
            ASSERT_TRUE(driver.write_offset(0x61 * kCleanBlockSize, short_data))
                << "unterminated-name fixture writes";
            ASSERT_TRUE(driver.write_offset(kRootBlock * kCleanBlockSize, root))
                << "unterminated-name fixture writes";

            const auto expect_files = [&](const FlashFileSystem& fs, const char* when) {
                SCOPED_TRACE(when);
                const std::vector<std::string> expected{std::string(kLongName), "b.bin"};
                EXPECT_EQ(fs.list_files(), expected)
                    << "list_files gives the 22-char name " << when;
                const auto entry = fs.stat(kLongName);
                EXPECT_TRUE(entry.has_value()) << "stat finds the 22-char name " << when;
                EXPECT_EQ(entry.value_or(FlashFileSystemEntry{}).block_number, 0x60)
                    << "stat finds the 22-char name " << when;
                EXPECT_EQ(entry.value_or(FlashFileSystemEntry{}).length, 0x10u)
                    << "stat finds the 22-char name " << when;
                EXPECT_TRUE(fs.stat("ABCDEFGHIJKLMNOPQRSTUV").has_value())
                    << "the 22-char name matches case-blind " << when;
                EXPECT_TRUE(fs.exists(kLongName)) << "the 22-char name matches case-blind " << when;
                const auto bytes = fs.get_file(kLongName);
                EXPECT_TRUE(bytes.has_value()) << "get_file reads the 22-char name's file " << when;
                EXPECT_BYTES_EQ(std::span(long_data).first(0x10), bytes.value_or(Bytes{}))
                    << "get_file reads the 22-char name's file " << when;
            };

            FlashFileSystem fs;
            EXPECT_OK(fs.load(driver, kRootBlock)) << "a 22-char on-disk name loads";
            expect_files(fs, "after load");

            const auto reserialized = fs.serialize_root_block();
            ASSERT_OK(reserialized)
                << "re-serializing writes the 22 name bytes and the block after them";
            ASSERT_EQ(reserialized->size(), kCleanBlockSize)
                << "re-serializing writes the 22 name bytes and the block after them";
            const auto* name_bytes =
                reinterpret_cast<const char*>(reserialized->data() + slot_offset(0));
            EXPECT_EQ(std::string_view(name_bytes, kMaxFilenameLength), kLongName)
                << "re-serializing writes the 22 name bytes and the block after them";
            EXPECT_EQ((*reserialized)[slot_offset(0) + 22], 0x00)
                << "re-serializing writes the 22 name bytes and the block after them";
            EXPECT_EQ((*reserialized)[slot_offset(0) + 23], 0x60)
                << "re-serializing writes the 22 name bytes and the block after them";

            // save() lays the file again from its data, found under the 22-char name.
            ASSERT_TRUE(driver.write_offset(0x60 * kCleanBlockSize, Bytes(kCleanBlockSize, 0)))
                << "unterminated-name cluster wipe";
            EXPECT_OK(fs.save()) << "a filesystem holding a 22-char name saves";
            FlashFileSystem reloaded;
            EXPECT_OK(reloaded.load(driver, kRootBlock)) << "the saved 22-char name loads again";
            expect_files(reloaded, "after save and reload");
        }

        // A corrupt length far past what the file's chain holds reads the chain and fails as
        // Truncated; the read reserves no more than the chain's clusters, so it cannot exhaust
        // memory first. A failed load leaves the filesystem as it was.
        TEST(FlashFsCorruptInput, CorruptLengthFailsTruncated) {
            constexpr uint16_t kRootBlock = 0x3E0;
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            Bytes root = small_root();
            put_entry(root, 0, "a.bin", 0x60, 0x10);
            put_entry(root, 1, "huge.bin", 0x61, 0xFFFFFFF0);
            ASSERT_TRUE(
                driver.write_offset(0x60 * kCleanBlockSize, flashfs_pattern(kCleanBlockSize, 1)))
                << "corrupt-length fixture writes";
            ASSERT_TRUE(
                driver.write_offset(0x61 * kCleanBlockSize, flashfs_pattern(kCleanBlockSize, 2)))
                << "corrupt-length fixture writes";
            ASSERT_TRUE(driver.write_offset(kRootBlock * kCleanBlockSize, root))
                << "corrupt-length fixture writes";

            FlashFileSystem fs;
            Result<> result;
            EXPECT_NO_THROW(result = fs.load(driver, kRootBlock)) << "a corrupt length throws";
            EXPECT_ERROR_MSG(result, ErrorCode::Truncated,
                             "FlashFS file 'huge.bin' is truncated: expected 4294967280 bytes, "
                             "read 16384")
                << "an entry with length 0xFFFFFFF0 fails as Truncated";
            EXPECT_TRUE(fs.entries().empty()) << "the failed load leaves the filesystem empty";
            EXPECT_TRUE(fs.list_files().empty()) << "the failed load leaves the filesystem empty";
        }

    } // namespace
} // namespace gxbuild3::nand
