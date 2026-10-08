// FlashFileSystem::load (src/nand/objects/FlashFileSystem.hpp) is transactional: a root that
// fails to load leaves the filesystem, its root, table, directory, file data and driver, as the
// last successful load left it.
//
// Pin/FlashFsLoadPin names the nine [load <pin>] lines of tests/golden/flashfs_roots.txt, one row
// each, over the same hand-built roots: which directory slots load() skips or drops, how the
// directory compacts, and which roots fail as Malformed or Truncated. FlashFsEmmc pins the [emmc]
// reload line: an eMMC image has no spare, so a reloaded filesystem reports version 0. The golden
// stays authoritative; these cases give its facts names.

#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Expect.hpp"
#include "support/builders/FlashFsRoots.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;
        using test::flashfs::map_offset;
        using test::flashfs::put16;
        using test::flashfs::put32;
        using test::flashfs::put_entry;
        using test::flashfs::slot_name;
        using test::flashfs::slot_offset;
        using test::flashfs::small_root;

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

        // ---- Pin/FlashFsLoadPin: the [load <pin>] golden lines, one row each --------------------

        // A driver, the clusters that get 0x77 file data, and the root written at root_block
        // (none: the root block is read as the image leaves it).
        struct LoadFixture {
            Driver driver;
            std::vector<size_t> data_clusters;
            std::optional<Bytes> root;
            uint16_t root_block;
        };

        // The golden's small_driver: a 16 MB small-block image with file data at 0x60..0x63 and
        // the root at 0x3E0.
        LoadFixture small_fixture(Bytes root) {
            return {Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small),
                    {0x60, 0x61, 0x62, 0x63},
                    std::move(root),
                    0x3E0};
        }

        LoadFixture skip_ffff() {
            Bytes root = small_root();
            put_entry(root, 0, "a.bin", 0x60, 0x10);
            put_entry(root, 1, "skipped.bin", 0xFFFF, 0x10);
            put_entry(root, 2, "c.bin", 0x62, 0x10);
            return small_fixture(std::move(root));
        }

        LoadFixture drop_compact() {
            Bytes root = small_root();
            put_entry(root, 0, "a.bin", 0x60, 0x10);
            put_entry(root, 1,
                      "\x05"
                      "deleted.bin",
                      0x61, 0x10);
            put_entry(root, 2,
                      "\xFF"
                      "erased.bin",
                      0x62, 0x10);
            put_entry(root, 3, "zero.bin", 0x0, 0x10);
            put_entry(root, 4, "", 0x62, 0x10);
            put_entry(root, 16, "d.bin", 0x63, 0x10);
            return small_fixture(std::move(root));
        }

        LoadFixture big_relative_zero() {
            Bytes root(kCleanBlockSize, 0);
            for (size_t cluster = 0; cluster < 0x520; ++cluster) {
                put16(root, map_offset(cluster), BlockMapStatus::Free);
            }
            put16(root, map_offset(0), BlockMapStatus::EndOfChain);
            put_entry(root, 0, "zero.bin", 0x0, 0x10);
            return {Driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big),
                    {0xAE0},
                    std::move(root),
                    380};
        }

        LoadFixture link_past_map() {
            Bytes root = small_root();
            put16(root, map_offset(0x60), 0x400);
            return small_fixture(std::move(root));
        }

        LoadFixture flagged_link_past_map() {
            Bytes root = small_root();
            put16(root, map_offset(0x60), 0x8000 | 0x61);
            put16(root, map_offset(0x61), 0x8000 | 0x400);
            return small_fixture(std::move(root));
        }

        LoadFixture file_past_map() {
            Bytes root = small_root();
            put_entry(root, 0, "a.bin", 0x60, 0x10);
            put_entry(root, 1, "far.bin", 0x400, 0x10);
            return small_fixture(std::move(root));
        }

        LoadFixture dropped_past_map() {
            Bytes root = small_root();
            put_entry(root, 0,
                      "\x05"
                      "far.bin",
                      0x400, 0x10);
            return small_fixture(std::move(root));
        }

        // No root is written: the root block is the first one past the image.
        LoadFixture short_root() {
            LoadFixture fixture = small_fixture({});
            fixture.root.reset();
            fixture.root_block = static_cast<uint16_t>(fixture.driver.block_count());
            return fixture;
        }

        // A 0x6000-byte image is taken as eMMC; its root cluster 1 runs off the end. The read is
        // all or nothing, so the error reports 0x0 bytes read, not the 0x2000 the image holds.
        LoadFixture short_emmc_root() {
            return {Driver(Bytes(0x6000, 0)), {}, std::nullopt, 1};
        }

        struct LoadPin {
            const char* name;
            LoadFixture (*fixture)();
            Driver::DriverMode mode;
            // nullopt: the load succeeds and lists `entries`.
            std::optional<ErrorCode> error;
            // The error's describe() when it fails.
            const char* message;
            // The loaded directory as the golden line lists it: <name>@0x<block>,...
            const char* entries;
            // The names serialize_root_block() writes into slots 0 and 1, every later slot
            // zero; nullptr when the row does not re-serialize.
            const char* reserialized;
        };
        GX_PRINT_ROW_AS_NAME(LoadPin)

        constexpr LoadPin kLoadPins[] = {
            // [load skip_ffff] ok entries=a.bin@0x60,c.bin@0x62
            {"SkipFfffSlot", skip_ffff, Driver::DriverMode::Small, std::nullopt, "",
             "a.bin@0x60,c.bin@0x62", nullptr},
            // [load drop_compact] ok entries=a.bin@0x60,d.bin@0x63
            // [load drop_compact] reserialized slots: 0=a.bin 1=d.bin rest_zero=yes
            {"DropCompactsTheDirectory", drop_compact, Driver::DriverMode::Small, std::nullopt, "",
             "a.bin@0x60,d.bin@0x63", "a.bin,d.bin"},
            // [load big_relative_zero] ok entries=zero.bin@0xAE0
            {"BigRelativeClusterZeroIsKept", big_relative_zero, Driver::DriverMode::Big,
             std::nullopt, "", "zero.bin@0xAE0", nullptr},
            // [load link_past_map] err=malformed
            {"LinkPastMapIsMalformed", link_past_map, Driver::DriverMode::Small,
             ErrorCode::Malformed, "FlashFS cluster 0x60 links past the map to 0x400", "", nullptr},
            // [load flagged_link_past_map] err=malformed
            {"FlaggedLinkIsCheckedOnLow15Bits", flagged_link_past_map, Driver::DriverMode::Small,
             ErrorCode::Malformed, "FlashFS cluster 0x61 links past the map to 0x400", "", nullptr},
            // [load file_past_map] err=malformed
            {"FilePastMapIsMalformed", file_past_map, Driver::DriverMode::Small,
             ErrorCode::Malformed, "FlashFS file 'far.bin' starts past the map at 0x400", "",
             nullptr},
            // [load dropped_past_map] ok entries=
            {"DroppedEntryPastMapIsOk", dropped_past_map, Driver::DriverMode::Small, std::nullopt,
             "", "", nullptr},
            // [load short_root] err=truncated
            {"ShortRootIsTruncated", short_root, Driver::DriverMode::Small, ErrorCode::Truncated,
             "FlashFS root cluster 0x400 reads 0x0 bytes", "", nullptr},
            // [load short_emmc_root] mode=Emmc err=truncated
            {"ShortEmmcRootIsTruncated", short_emmc_root, Driver::DriverMode::Emmc,
             ErrorCode::Truncated, "FlashFS root cluster 0x1 reads 0x0 bytes", "", nullptr},
        };

        std::string listed_entries(const FlashFileSystem& fs) {
            std::string text;
            for (const auto& entry : fs.entries()) {
                text += std::format("{}{}@0x{:X}", text.empty() ? "" : ",",
                                    std::string_view{entry.filename}, entry.block_number);
            }
            return text;
        }

        class FlashFsLoadPin : public ::testing::TestWithParam<LoadPin> {};

        TEST_P(FlashFsLoadPin, LoadsAsPinned) {
            const LoadPin& pin = GetParam();
            LoadFixture fixture = pin.fixture();
            ASSERT_EQ(fixture.driver.driver_mode(), pin.mode) << "the fixture's driver mode";
            const Bytes data(kCleanBlockSize, 0x77);
            for (const size_t cluster : fixture.data_clusters) {
                ASSERT_TRUE(fixture.driver.write_offset(cluster * kCleanBlockSize, data))
                    << "file fixture write at cluster 0x" << std::hex << cluster;
            }
            if (fixture.root) {
                const size_t ratio = fixture.driver.block_size_clean() / kCleanBlockSize;
                ASSERT_TRUE(fixture.driver.write_offset(
                    size_t{fixture.root_block} * ratio * kCleanBlockSize, *fixture.root))
                    << "root fixture write";
            }

            FlashFileSystem fs;
            const auto result = fs.load(fixture.driver, fixture.root_block);
            if (pin.error) {
                EXPECT_ERROR_MSG(result, *pin.error, pin.message);
                return;
            }
            ASSERT_OK(result);
            EXPECT_EQ(listed_entries(fs), pin.entries) << "the loaded directory, in order";
            if (pin.reserialized == nullptr) {
                return;
            }
            ASSERT_OK_AND_ASSIGN(const Bytes root, fs.serialize_root_block());
            ASSERT_EQ(root.size(), kCleanBlockSize) << "the root re-serializes whole";
            EXPECT_EQ(slot_name(root, 0) + "," + slot_name(root, 1), pin.reserialized)
                << "the kept entries take the first directory slots";
            for (size_t slot = 2; slot < 2 * kEntriesPerPage; ++slot) {
                const auto at = root.begin() + static_cast<std::ptrdiff_t>(slot_offset(slot));
                EXPECT_TRUE(std::all_of(at, at + 32, [](uint8_t b) { return b == 0; }))
                    << "directory slot " << slot << " is zero after compaction";
            }
        }

        INSTANTIATE_TEST_SUITE_P(Pin, FlashFsLoadPin, ::testing::ValuesIn(kLoadPins),
                                 test::RowName{});

        // ---- FlashFsEmmc: the [emmc] reload line ----------------------------------------------

        // An eMMC image carries no spare, so the version save() stamps into the root's metadata
        // is not written anywhere: the filesystem formatted as version 3 reloads as version 0,
        // with its files and root intact.
        TEST(FlashFsEmmc, ReloadReportsVersionZeroAsToday) {
            Driver driver(Driver::ImageSize::Emmcblock, Driver::DriverMode::Emmc);
            FlashFileSystem fs;
            fs.set_driver(&driver);
            ASSERT_OK(fs.format(driver.block_count(), 0x5C, 3)) << "the eMMC filesystem formats";
            const Bytes payload(0x4001, 0xA1);
            ASSERT_OK(fs.add_file("a.bin", payload)) << "a.bin allocates";
            ASSERT_OK(fs.save()) << "the eMMC filesystem saves";
            ASSERT_EQ(fs.version(), 3u) << "the saved filesystem is version 3";
            ASSERT_OK_AND_ASSIGN(const Bytes root, fs.serialize_root_block());

            Driver reload{Bytes(driver.serialize())};
            ASSERT_EQ(reload.driver_mode(), Driver::DriverMode::Emmc)
                << "the serialized image reloads as eMMC";
            FlashFileSystem loaded;
            ASSERT_OK(loaded.load(reload, 0x5C)) << "the serialized image loads";
            EXPECT_EQ(loaded.version(), 0u) << "an eMMC reload reports version 0";
            EXPECT_EQ(loaded.entries().size(), 1u) << "the directory reloads";
            const auto file = loaded.get_file("a.bin");
            ASSERT_TRUE(file.has_value()) << "a.bin reloads";
            EXPECT_BYTES_EQ(payload, *file) << "a.bin reloads";
            ASSERT_OK_AND_ASSIGN(const Bytes reroot, loaded.serialize_root_block());
            EXPECT_BYTES_EQ(root, reroot) << "the root codec round-trips";
        }

    } // namespace
} // namespace gxbuild3::nand
