#include "GoldenSnapshot.hpp"
#include "excrypt.h"
#include "nand/objects/FlashFileSystem.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <format>
#include <iostream>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace gxbuild3::nand;
using Bytes = std::vector<uint8_t>;

namespace gxbuild3::nand {

    // The goldens below need a chain link carrying the 0x8000 bit, which only load() produces
    // through the public API.
    struct FlashFileSystemTestAccess {
        static std::vector<uint16_t>& blockmap(FlashFileSystem& fs) { return fs.m_blockmap; }
    };

} // namespace gxbuild3::nand

namespace {
    bool check(bool condition, const char* message) {
        if (!condition)
            std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    bool check(const gxbuild3::Result<>& result, const char* message) {
        if (!result)
            std::cerr << "FAIL: " << message << ": " << result.error().describe() << '\n';
        return result.has_value();
    }

    void put16(Bytes& bytes, size_t offset, uint16_t value) {
        bytes[offset] = static_cast<uint8_t>(value >> 8);
        bytes[offset + 1] = static_cast<uint8_t>(value);
    }

    void put32(Bytes& bytes, size_t offset, uint32_t value) {
        put16(bytes, offset, static_cast<uint16_t>(value >> 16));
        put16(bytes, offset + 2, static_cast<uint16_t>(value));
    }

    size_t map_offset(size_t cluster) {
        return (cluster / 256) * 1024 + (cluster % 256) * 2;
    }

    bool test_load_independent_big_block_layout() {
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
        if (!driver.write_block(380, root) ||
            !driver.write_offset((0xAE0 + 988) * 0x4000, std::span(expected).first(0x4000)) ||
            !driver.write_offset((0xAE0 + 999) * 0x4000, std::span(expected).subspan(0x4000))) {
            return check(false, "independent fixture writes succeed");
        }
        FlashFileSystem fs;
        if (!check(fs.load(driver, 380), "independent big-block root loads") ||
            !check(fs.get_file("secdata.bin") == expected,
                   "big-block file chains use 16 KiB cluster addresses and lengths"))
            return false;
        put16(root, map_offset(988), BlockMapStatus::EndOfChain);
        if (!driver.write_block(380, root))
            return false;
        FlashFileSystem truncated;
        return check(!truncated.load(driver, 380),
                     "a truncated chain must not be cached as a successfully read file");
    }

    // load() is transactional: a root that fails to load leaves the filesystem, its root,
    // table, directory, file data and driver, as the last successful load left it.
    bool test_failed_load_leaves_filesystem_unchanged() {
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
        if (!check(write_root(good, 380, 999) && write_root(bad, 381, BlockMapStatus::EndOfChain),
                   "transactional-load fixtures write"))
            return false;
        FlashFileSystem fs;
        if (!check(fs.load(good, 380), "the good root loads"))
            return false;
        const auto blockmap = fs.blockmap();
        const auto entries = fs.entries().size();
        const auto file = fs.get_file("secdata.bin");
        const auto version = fs.version();

        const auto failed = fs.load(bad, 381);
        return check(!failed && failed.error().code == gxbuild3::ErrorCode::Truncated,
                     "a root whose file chain is short fails as Truncated") &&
               check(fs.root_block() == 380 && fs.version() == version && fs.has_root(),
                     "a failed load keeps the loaded root") &&
               check(fs.blockmap() == blockmap && fs.entries().size() == entries,
                     "a failed load keeps the table and directory") &&
               check(file && fs.get_file("secdata.bin") == file,
                     "a failed load keeps the file data") &&
               check(!fs.load(good, 380, 8), "a root cluster past its erase block fails") &&
               check(fs.root_block() == 380 && fs.blockmap() == blockmap,
                     "an out-of-range root cluster changes nothing");
    }

    bool test_big_block_writer_uses_clusters() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), 380), "big-block filesystem formats"))
            return false;
        const Bytes first(0x4003, 0x31);
        const Bytes second(1024, 0x42);
        if (!fs.add_file("first.bin", first) || !fs.add_file("second.bin", second))
            return check(false, "big-block files allocate");
        const auto first_entry = fs.stat("first.bin");
        const auto second_entry = fs.stat("second.bin");
        if (!check(!fs.is_block_free(first_entry->block_number / 8),
                   "physical allocation sees every occupied subcluster") ||
            !check(!fs.set_root_block(first_entry->block_number / 8),
                   "root cannot overwrite an occupied physical block") ||
            !check(fs.reserve_blocks(200, 1), "physical block reservation succeeds") ||
            !check(std::all_of(fs.blockmap().begin() + 200 * 8, fs.blockmap().begin() + 201 * 8,
                               [](uint16_t value) { return value == BlockMapStatus::Reserved; }),
                   "physical reservation covers all eight clusters") ||
            !check(fs.set_root_block(350) && fs.is_block_free(380) && !fs.is_block_free(350),
                   "root relocation reserves and releases whole erase blocks"))
            return false;
        if (!check(fs.get_chain(first_entry->block_number).size() == 2,
                   "a 16 KiB plus three byte file requires two clusters") ||
            !check(fs.save(), "big-block files save"))
            return false;
        const auto first_address = static_cast<size_t>(first_entry->block_number) * 0x4000;
        const auto second_address = static_cast<size_t>(second_entry->block_number) * 0x4000;
        return check(driver.read_clean(first_address, first.size()) == first,
                     "writer uses on-disk 16 KiB addresses") &&
               check(driver.read_clean(second_address, second.size()) == second,
                     "writing a neighboring cluster preserves earlier file data");
    }

    // Big-block images must carry the retail/xeBuild spare profile the stock kernel
    // mounts: root type 0x2C, data type 0x2A with sequence 0, and the constant
    // fs_size 0x2006 / page_count 0x04 stamp on both. A small-block 0x30 root makes
    // the filesystem invisible on big-block hardware (error 1033 / "xam.xex missing").
    bool test_big_block_stamps_retail_fs_metadata() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), 350, 0x125), "big-block filesystem formats"))
            return false;
        const Bytes payload(0x4003, 0x31);
        if (!check(fs.add_file("xam.xex", payload), "big-block file allocates") ||
            !check(fs.save(), "big-block filesystem saves"))
            return false;

        const auto entry = fs.stat("xam.xex");
        if (!check(entry.has_value(), "xam.xex entry exists"))
            return false;

        const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
        const auto root = driver.interpret_cluster(350 * clusters_per_block);
        const auto data = driver.interpret_block(entry->block_number / clusters_per_block);

        return check(root.block_type == FlashFsMetadata::kRootTypeBig,
                     "big-block root is stamped 0x2C") &&
               check(root.sequence == 0x125, "big-block root keeps the FS version") &&
               check(root.fs_size == FlashFsMetadata::kBigFsSize,
                     "big-block root fs_size matches the 0x2006 reference") &&
               check(root.page_count == FlashFsMetadata::kBigPageCount,
                     "big-block root page_count matches the 0x04 reference") &&
               check(data.block_type == FlashFsMetadata::kDataTypeBig,
                     "big-block data is stamped 0x2A") &&
               check(data.sequence == 0, "big-block data sequence is 0") &&
               check(data.fs_size == FlashFsMetadata::kBigFsSize,
                     "big-block data fs_size matches the 0x2006 reference") &&
               check(data.page_count == FlashFsMetadata::kBigPageCount,
                     "big-block data page_count matches the 0x04 reference");
    }

    // serialize() re-stamps the root from NandLayout and overrides whatever save() wrote,
    // so the big-block root profile must be applied there too.
    bool test_big_block_serialize_restamps_root() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        NandLayout layout;
        layout.fs_root_block = 350;
        layout.fs_version = 0x125;
        driver.set_layout(layout);
        driver.serialize();

        const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
        const auto root = driver.interpret_cluster(350 * clusters_per_block);
        return check(root.block_type == FlashFsMetadata::kRootTypeBig,
                     "serialize re-stamps the big-block root as 0x2C") &&
               check(root.sequence == 0x125, "serialize keeps the FS version on the root") &&
               check(root.fs_size == FlashFsMetadata::kBigFsSize,
                     "serialize overrides the root fs_size to 0x2006 on big-block") &&
               check(root.page_count == FlashFsMetadata::kBigPageCount,
                     "serialize stamps the root page_count 0x04 on big-block");
    }

    // Small/new-small images stamp the root 0x30 with the FS version and leave file data
    // blocks as plain type 0x00, sequence 0, no size or page count, as real 16 MB dumps
    // and xeBuild do. The file's last cluster is zero-padded, so every page of it carries
    // that spare, and the FsUnused nibble and bytes 0xA-0xB are zero.
    bool small_block_fs_metadata_matches_dumps(Driver::DriverMode mode) {
        Driver driver(Driver::ImageSize::Smallblock, mode);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), 300, 7), "small-block filesystem formats"))
            return false;
        const Bytes payload(1024, 0x42);
        if (!check(fs.add_file("boot.bin", payload), "small-block file allocates"))
            return false;
        const auto entry = fs.stat("boot.bin");
        if (!check(entry.has_value(), "boot.bin entry exists"))
            return false;

        // Stale erased bytes and spare under the file's cluster.
        const size_t first_page = static_cast<size_t>(entry->block_number) * 32;
        if (!check(driver.write_offset(static_cast<size_t>(entry->block_number) * 0x4000,
                                       Bytes(0x4000, 0xFF)),
                   "stale cluster fill writes"))
            return false;
        for (size_t page = first_page; page < first_page + 32; ++page) {
            driver.write_page_spare(page, Bytes(16, 0xFF));
        }
        if (!check(fs.save(), "small-block filesystem saves"))
            return false;

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
                padded = padded &&
                         std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0; });
            }
        }

        return check(root.block_type == FlashFsMetadata::kRootTypeSmall,
                     "small-block root stays 0x30") &&
               check(root.sequence == 7, "small-block root keeps the FS version") &&
               check(data.block_type == 0x00, "small-block data is type 0x00") &&
               check(data.sequence == 0, "small-block data sequence is 0") &&
               check(data.fs_size == 0 && data.page_count == 0,
                     "small-block data carries no size or page count") &&
               check(data.logical_block_id == entry->block_number / clusters_per_block,
                     "small-block data carries its block ID") &&
               check(spare_clean, "small-block data spare has zero FsUnused fields") &&
               check(padded, "the file's last cluster is zero-padded");
    }

    bool test_small_block_fs_metadata_matches_dumps() {
        return small_block_fs_metadata_matches_dumps(Driver::DriverMode::Small) &&
               small_block_fs_metadata_matches_dumps(Driver::DriverMode::NewSmall);
    }

    // serialize() stamps type-0 metadata on the blocks below 0x50 that are not the root, a
    // mobile or FlashFS file data. Pages holding erased data there get an erased spare,
    // whatever spare they held before; FlashFS file blocks keep the spare save() wrote.
    bool test_serialize_leaves_erased_low_pages_unprogrammed() {
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall);
        const size_t block = 0x24;
        const size_t file_block = 0x25;
        const size_t ppb = driver.pages_per_block();
        if (!check(driver.write_offset(block * 0x4000, Bytes(0x8000, 0xFF)),
                   "erased low blocks write") ||
            !check(driver.write_offset(block * 0x4000, Bytes(0x200, 0x5A)),
                   "first low page writes"))
            return false;
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
            erased = erased &&
                     std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0xFF; });
        }
        bool file_stamped = true;
        for (size_t page = file_block * ppb; page < (file_block + 1) * ppb; ++page) {
            const auto bytes = page_raw(page);
            file_stamped = file_stamped && bytes[0x201] == file_block && bytes[0x205] == 0xFF;
        }
        return check(written[0x201] == block && (written[0x202] & 0xF0) == 0 &&
                         (written[0x20C] & 0x3F) == 0,
                     "a programmed low page carries its block ID and type 0") &&
               check(erased, "erased low pages carry erased data and spare") &&
               check(file_stamped, "erased pages of a FlashFS file block keep their stamp");
    }

    // Method 4: a large, multi-cluster file must survive the full write path
    // (save -> serialize ECC/metadata re-stamp -> fresh load) byte-for-byte. This mirrors
    // xam.xex (0x250000 == 148 clusters) plus a partial-tail neighbour, so it exercises
    // interleaved chains, a non-multiple final cluster, and the ECC recompute. A scatter,
    // chain-order, or short-write defect shows up here without any hardware.
    bool test_big_block_large_file_roundtrips_through_serialize() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        const uint16_t root_block = 350;
        if (!check(fs.format(driver.block_count(), root_block, 0x125),
                   "big-block filesystem formats for round-trip"))
            return false;

        const size_t xam_size = 0x250000;
        Bytes xam(xam_size);
        for (size_t i = 0; i < xam_size; ++i)
            xam[i] = static_cast<uint8_t>((i * 31 + (i >> 12)) & 0xFF);
        const size_t other_size = 0x12345;
        Bytes other(other_size);
        for (size_t i = 0; i < other_size; ++i)
            other[i] = static_cast<uint8_t>((i * 173 + (i >> 9)) & 0xFF);
        if (!check(fs.add_file("xam.xex", xam), "xam-sized file allocates") ||
            !check(fs.add_file("other.bin", other), "partial-tail file allocates"))
            return false;

        NandLayout layout;
        layout.fs_root_block = root_block;
        layout.fs_version = fs.version();
        driver.set_layout(layout);

        if (!check(fs.save(), "large files save"))
            return false;
        Bytes serialized = driver.serialize();

        Driver reload(std::move(serialized));
        if (!check(reload.driver_mode() == Driver::DriverMode::Big,
                   "serialized big-block image re-detects as big-block"))
            return false;
        FlashFileSystem reloaded;
        if (!check(reloaded.load(reload, root_block), "big-block filesystem reloads"))
            return false;

        const auto got_xam = reloaded.get_file("xam.xex");
        const auto got_other = reloaded.get_file("other.bin");
        return check(got_xam.has_value() && *got_xam == xam,
                     "148-cluster xam.xex survives save -> serialize -> load byte-for-byte") &&
               check(got_other.has_value() && *got_other == other,
                     "partial-tail neighbour survives the same round-trip");
    }

    // A deferred format (kDeferRoot) must not commit a root block, so serialize can
    // allocate the root once, last, from the same free pool the files and mobile data
    // draw from. Regression: format() used to pre-consume the final data block for the
    // root, so a full image had no free block left for placement and the build failed.
    bool test_deferred_root_is_placed_last_from_free_pool() {
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot),
                   "deferred-root filesystem formats"))
            return false;
        if (!check(!fs.has_root(), "kDeferRoot must leave the root unplaced after format"))
            return false;
        if (!check(!fs.save(), "save must be rejected before a root block is placed"))
            return false;
        if (!check(fs.is_block_free(0x3E0),
                   "deferred format must not consume the default root block 0x3E0"))
            return false;

        // Consume every data block below the limit except the final one, mirroring a
        // build whose files and mobile data leave a single free block for the root.
        const size_t limit = driver.data_block_limit();
        constexpr size_t reserved_boundary = 0x50;
        if (!check(fs.reserve_blocks(reserved_boundary, limit - 1 - reserved_boundary),
                   "data region below the final block reserves"))
            return false;
        if (!check(fs.is_block_free(limit - 1),
                   "exactly one free data block remains below the limit"))
            return false;

        if (!check(fs.set_root_block(static_cast<uint16_t>(limit - 1)),
                   "set_root_block places the sole remaining free data block"))
            return false;
        return check(fs.has_root(), "has_root() reports placement after set_root_block") &&
               check(fs.root_block() == limit - 1, "root_block() reports the deferred placement") &&
               check(!fs.is_block_free(limit - 1), "the placed root block is no longer free") &&
               check(fs.save(), "save succeeds once the deferred root is placed");
    }

    uint16_t stated_map_value(const Bytes& root, size_t index) {
        const size_t at = map_offset(index);
        return static_cast<uint16_t>((root[at] << 8) | root[at + 1]);
    }

    // A CG tail inserted first is laid on the first free blocks and every file after it is
    // laid again behind it, in directory order, with the filesystem's stamp.
    bool test_insert_file_lays_files_back_to_back() {
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot, 1, 0x24),
                   "small-block filesystem formats from block 0x24"))
            return false;
        fs.set_timestamp(0x5D444AC2);
        if (!check(fs.add_file("a.bin", Bytes(0x4001, 0xA1)) &&
                       fs.add_file("b.bin", Bytes(0x10, 0xB2), 0x11223344),
                   "files allocate"))
            return false;
        if (!check(fs.insert_file(0, "sysupdate.xexp1", Bytes(0x8000, 0x51)) &&
                       fs.insert_file(1, "sysupdate.xexp2", Bytes(0x10, 0x52)),
                   "CG tails insert"))
            return false;
        const auto& entries = fs.entries();
        const std::vector<std::pair<std::string, uint16_t>> expected{
            {"sysupdate.xexp1", 0x24}, {"sysupdate.xexp2", 0x26}, {"a.bin", 0x27}, {"b.bin", 0x29}};
        bool laid = entries.size() == expected.size();
        for (size_t i = 0; laid && i < expected.size(); ++i) {
            laid = std::string(entries[i].filename) == expected[i].first &&
                   entries[i].block_number == expected[i].second;
        }
        const auto a_chain = fs.get_chain(entries[2].block_number);
        if (!check(laid, "tails come first and the files follow back to back") ||
            !check(a_chain == std::vector<uint16_t>{0x27, 0x28}, "a moved file keeps its chain") ||
            !check(fs.get_file("a.bin") == Bytes(0x4001, 0xA1), "a moved file keeps its bytes") ||
            !check(entries[0].timestamp == 0x5D444AC2 && entries[2].timestamp == 0x5D444AC2,
                   "entries take the filesystem's stamp") ||
            !check(entries[3].timestamp == 0x11223344, "a given stamp is kept when moved"))
            return false;
        if (!check(fs.insert_file(0, "sysupdate.xexp1", Bytes(0x10, 0x53)),
                   "a CG tail is replaced in place"))
            return false;
        return check(fs.entries().size() == 4 &&
                         std::string(fs.entries()[0].filename) == "sysupdate.xexp1" &&
                         fs.entries()[0].block_number == 0x24 &&
                         fs.entries()[1].block_number == 0x25 &&
                         fs.entries()[2].block_number == 0x26,
                     "replacing the first tail lays the rest again behind it");
    }

    // The table states what xeBuild 1.21 states: the root's own cluster 0x1FFD and the rest
    // of its erase block free, withheld clusters as they were withheld (settings blobs free,
    // the remap pool and stepped-over clusters 0), none of them allocatable.
    bool test_table_states_withheld_and_root_clusters() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot), "formats"))
            return false;
        // Big block: the table counts clusters from 0xAE0, 8 to an erase block.
        constexpr size_t base = 0xAE0;
        if (!check(fs.add_file("one.bin", Bytes(0x200, 1)), "a file allocates") ||
            !check(fs.withhold_clusters(base + 1, 7, BlockMapStatus::Unnamed),
                   "stepped-over clusters withhold") ||
            !check(fs.withhold_blocks((base + 8) / 8, 1, BlockMapStatus::Free),
                   "a blob's erase block withholds") ||
            !check(fs.withhold_blocks(0x1DC, 4, BlockMapStatus::Unnamed), "the tail withholds") ||
            !check(fs.set_root_block((base + 16) / 8), "the root takes the next erase block"))
            return false;
        if (!check(!fs.is_block_free((base + 8) / 8) && !fs.is_block_free(0x1DC),
                   "withheld blocks are not free") ||
            !check(!fs.withhold_clusters(base, 1, BlockMapStatus::Free),
                   "a file cluster cannot be withheld"))
            return false;
        const auto table = fs.serialize_root_block();
        if (!check(table && table->size() == kCleanBlockSize, "the table serializes"))
            return false;
        return check(stated_map_value(*table, 0) == BlockMapStatus::EndOfChain,
                     "the file ends its chain") &&
               check(stated_map_value(*table, 1) == BlockMapStatus::Unnamed &&
                         stated_map_value(*table, 7) == BlockMapStatus::Unnamed,
                     "stepped-over clusters are never named") &&
               check(stated_map_value(*table, 8) == BlockMapStatus::Free &&
                         stated_map_value(*table, 15) == BlockMapStatus::Free,
                     "a blob's clusters are stated free") &&
               check(stated_map_value(*table, 16) == BlockMapStatus::Table,
                     "the root states itself") &&
               check(stated_map_value(*table, 17) == BlockMapStatus::Free &&
                         stated_map_value(*table, 23) == BlockMapStatus::Free,
                     "the rest of the root's erase block is stated free") &&
               check(stated_map_value(*table, 0x400) == BlockMapStatus::Unnamed,
                     "the tail is never named");
    }

    // A big-block file of one cluster states its spare on the pages its bytes reach and leaves
    // the padding's fields erased; a longer file states it on every page. The spare carries the
    // system area given to the filesystem.
    bool test_big_block_single_cluster_padding_keeps_erased_fields() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        fs.set_big_system_blocks(0x10);
        if (!check(fs.format(driver.block_count(), 350), "formats") ||
            !check(fs.add_file("short.bin", Bytes(0x2800, 0x5A)) &&
                       fs.add_file("long.bin", Bytes(0x4400, 0x6B)),
                   "files allocate") ||
            !check(fs.save(), "saves"))
            return false;
        const auto short_entry = fs.stat("short.bin");
        const auto long_chain = fs.get_chain(fs.stat("long.bin")->block_number);
        const size_t first_page = static_cast<size_t>(short_entry->block_number) * 32;
        bool data_pages = true;
        bool padding_pages = true;
        for (size_t page = first_page; page < first_page + 32; ++page) {
            const auto spare = driver.read_page_spare(page);
            if (page < first_page + 0x14) {
                data_pages = data_pages && spare[7] == 0x10 && spare[8] == 0x20 &&
                             spare[9] == 0x04 && (spare[0xC] & 0x3F) == 0x2A;
            } else {
                padding_pages = padding_pages && std::all_of(spare.begin(), spare.begin() + 12,
                                                             [](uint8_t b) { return b == 0xFF; });
            }
        }
        bool long_pages = long_chain.size() == 2;
        for (size_t page = long_chain.back() * 32u;
             long_pages && page < static_cast<size_t>(long_chain.back()) * 32 + 32; ++page) {
            long_pages = (driver.read_page_spare(page)[0xC] & 0x3F) == 0x2A;
        }
        return check(fs.big_fs_size() == 0x2010, "the stamp states a 0x10-block system area") &&
               check(data_pages, "a one-cluster file's data pages carry its spare") &&
               check(padding_pages, "its padding pages keep erased fields") &&
               check(long_pages, "a longer file's last cluster carries its spare on every page");
    }

    // ---- Root-codec and driver.serialize goldens (tests/golden/flashfs_roots.txt) ----------

    std::string sha1(std::span<const uint8_t> bytes) {
        std::array<uint8_t, 20> digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        std::string out;
        for (const uint8_t b : digest) {
            out += std::format("{:02x}", b);
        }
        return out;
    }

    const char* mode_name(Driver::DriverMode mode) {
        switch (mode) {
            case Driver::DriverMode::Small:
                return "Small";
            case Driver::DriverMode::NewSmall:
                return "NewSmall";
            case Driver::DriverMode::Big:
                return "Big";
            case Driver::DriverMode::Emmc:
                return "Emmc";
        }
        return "?";
    }

    std::string outcome(const gxbuild3::Result<>& result) {
        return result ? std::string{"ok"}
                      : std::format("err={}", gxbuild3::to_string(result.error().code));
    }

    Bytes pattern(size_t size, uint32_t seed) {
        Bytes bytes(size);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = static_cast<uint8_t>((i * seed + (i >> 9) + seed) & 0xFF);
        }
        return bytes;
    }

    struct RootCase {
        const char* name;
        Driver::ImageSize size;
        Driver::DriverMode mode;
        bool larger;
        std::optional<uint8_t> system_blocks;
        uint32_t version;
    };

    struct RootFile {
        const char* name;
        Bytes data;
        std::optional<uint32_t> timestamp;
    };

    // Builds a filesystem with several files, clusters withheld and stated Unnamed and Free, a
    // chain link carrying the 0x8000 bit and a deferred root, then snapshots the root codec
    // (serialize_root_block), the image after save() and driver.serialize(), and a load of that
    // image back. Pins today's output, quirks included.
    bool root_case_golden(const RootCase& c, std::string& text) {
        bool ok = true;
        const auto fail = [&](const std::string& what) {
            return check(false, std::format("[{}] {}", c.name, what).c_str());
        };
        Driver driver(c.size, c.mode);
        const size_t ratio = driver.block_size_clean() / kCleanBlockSize;
        const bool big = c.mode == Driver::DriverMode::Big;
        const size_t base = big ? (c.larger ? 0x2E0 : 0xAE0) : 0;
        FlashFileSystem fs;
        fs.set_driver(&driver);
        fs.set_larger_filesystem(c.larger);
        if (c.system_blocks) {
            fs.set_big_system_blocks(*c.system_blocks);
        }
        if (!check(fs.format(driver.block_count(), FlashFileSystem::kDeferRoot, c.version, 0x50),
                   std::format("[{}] formats with a deferred root", c.name).c_str()))
            return false;
        fs.set_timestamp(0x5D444AC2);
        if (fs.has_root())
            return fail("the deferred format leaves no root");

        const std::vector<RootFile> files{
            {"a.bin", pattern(0x4001, 3), std::nullopt},
            {"b.bin", pattern(0x10, 5), 0x11223344},
            {"c.bin", pattern(0x9000, 7), std::nullopt},
            {"empty.bin", Bytes{}, std::nullopt},
            {"abcdefghijklmnopq.bin", pattern(0x200, 11), 0x01020304},
        };
        if (!fs.add_file(files[0].name, files[0].data, files[0].timestamp))
            return fail("a.bin allocates");
        // Clusters the next files step over: three stated Unnamed right after a.bin, then the
        // whole next erase block stated Free.
        const size_t after_a = fs.get_chain(fs.stat("a.bin")->block_number).back() + 1u;
        const size_t free_block = (after_a + 3 + ratio - 1) / ratio;
        if (!fs.withhold_clusters(after_a, 3, BlockMapStatus::Unnamed) ||
            !fs.withhold_blocks(free_block, 1, BlockMapStatus::Free) ||
            !fs.withhold_blocks(driver.data_block_limit(), 2, BlockMapStatus::Unnamed))
            return fail("clusters withhold");
        for (size_t i = 1; i < files.size(); ++i) {
            if (!fs.add_file(files[i].name, files[i].data, files[i].timestamp))
                return fail(std::format("{} allocates", files[i].name));
        }
        // c.bin's first link carries the 0x8000 bit.
        const auto c_start = fs.stat("c.bin")->block_number;
        gxbuild3::nand::FlashFileSystemTestAccess::blockmap(fs)[c_start] |= 0x8000;

        // The deferred root takes the first free erase block past the files.
        std::optional<uint16_t> root_block;
        for (size_t block = 0; block < driver.block_count(); ++block) {
            if (fs.is_block_free(block)) {
                root_block = static_cast<uint16_t>(block);
                break;
            }
        }
        if (!root_block || !fs.set_root_block(*root_block))
            return fail("the deferred root is placed");

        NandLayout layout;
        layout.fs_root_block = *root_block;
        layout.fs_version = fs.version();
        if (big) {
            layout.big_fs_size = fs.big_fs_size();
        }
        std::set<uint16_t> data_blocks;
        for (const auto cluster : fs.get_all_file_blocks()) {
            data_blocks.insert(static_cast<uint16_t>(cluster / ratio));
        }
        layout.fs_data_blocks.assign(data_blocks.begin(), data_blocks.end());
        driver.set_layout(layout);

        const auto root = fs.serialize_root_block();
        if (!check(root.has_value() && root->size() == kCleanBlockSize,
                   std::format("[{}] the root serializes", c.name).c_str()))
            return false;
        ok = check(fs.save(), std::format("[{}] saves", c.name).c_str()) && ok;
        const auto root_after_save = fs.serialize_root_block();
        ok = check(root_after_save && *root_after_save == *root,
                   std::format("[{}] save() leaves the root codec unchanged", c.name).c_str()) &&
             ok;
        const Bytes image = driver.serialize();

        text += std::format("[{}] mode={} base=0x{:X} ratio={} blocks=0x{:X} clusters=0x{:X} "
                            "root_block=0x{:X} version=0x{:X} big_fs_size=0x{:X}\n",
                            c.name, mode_name(c.mode), base, ratio, driver.block_count(),
                            fs.blockmap().size(), *root_block, fs.version(), fs.big_fs_size());
        for (const auto& entry : fs.entries()) {
            std::string chain;
            for (const auto cluster : fs.get_chain(entry.block_number)) {
                chain += std::format("{}{:X}", chain.empty() ? "" : ",", cluster);
            }
            text += std::format("[{}] entry {} block=0x{:X} length=0x{:X} ts=0x{:08X} chain={}\n",
                                c.name, std::string_view{entry.filename}, entry.block_number,
                                entry.length, entry.timestamp, chain);
        }
        text +=
            std::format("[{}] link 0x{:X} -> 0x{:04X}\n", c.name, c_start, fs.blockmap()[c_start]);
        text += std::format("[{}] root size=0x{:X} sha1={}\n", c.name, root->size(), sha1(*root));
        text += std::format("[{}] image size=0x{:X} sha1={}\n", c.name, image.size(), sha1(image));

        // load() of the serialized image reproduces the root and every file.
        Driver reload{Bytes(image)};
        FlashFileSystem loaded;
        loaded.set_larger_filesystem(c.larger);
        const auto load = loaded.load(reload, *root_block);
        std::optional<Bytes> reroot;
        bool files_equal = load.has_value();
        if (load) {
            if (const auto again = loaded.serialize_root_block()) {
                reroot = *again;
            }
            for (const auto& file : files) {
                files_equal = files_equal && loaded.get_file(file.name) == file.data;
            }
        }
        const bool identity = reroot && *reroot == *root;
        text += std::format("[{}] reload mode={} load={} version=0x{:X} entries={} files_equal={} "
                            "root_identity={}\n",
                            c.name, mode_name(reload.driver_mode()), outcome(load),
                            loaded.version(), loaded.entries().size(), files_equal ? "yes" : "no",
                            identity ? "yes" : "no");
        ok = check(load, std::format("[{}] the serialized image loads", c.name).c_str()) && ok;
        ok = check(identity, std::format("[{}] load() then serialize_root_block() reproduces the "
                                         "root",
                                         c.name)
                                 .c_str()) &&
             ok;
        ok = check(files_equal, std::format("[{}] every file reloads", c.name).c_str()) && ok;
        return ok;
    }

    // ---- Pins of today's load() skip, drop and error behaviour ---------------------------

    size_t slot_offset(size_t slot) {
        return (1 + 2 * (slot / kEntriesPerPage)) * 512 + (slot % kEntriesPerPage) * 32;
    }

    void put_entry(Bytes& root, size_t slot, std::string_view name, uint16_t relative_block,
                   uint32_t length) {
        const size_t at = slot_offset(slot);
        std::fill(root.begin() + static_cast<std::ptrdiff_t>(at),
                  root.begin() + static_cast<std::ptrdiff_t>(at + kMaxFilenameLength), 0);
        std::memcpy(root.data() + at, name.data(), std::min(name.size(), kMaxFilenameLength));
        put16(root, at + 22, relative_block);
        put32(root, at + 24, length);
        put32(root, at + 28, 0x5D444AC2);
    }

    // A small-block root at block 0x3E0 with every cluster Free and four one-cluster files at
    // 0x60..0x63.
    Bytes small_root() {
        Bytes root(kCleanBlockSize, 0);
        for (size_t cluster = 0; cluster < 0x400; ++cluster) {
            put16(root, map_offset(cluster), BlockMapStatus::Free);
        }
        put16(root, map_offset(0x3E0), BlockMapStatus::Table);
        for (uint16_t cluster = 0x60; cluster < 0x64; ++cluster) {
            put16(root, map_offset(cluster), BlockMapStatus::EndOfChain);
        }
        return root;
    }

    std::string load_pin(const char* name, Driver& driver, const Bytes& root, uint16_t root_block,
                         FlashFileSystem& fs, gxbuild3::Result<>& result) {
        const size_t ratio = driver.block_size_clean() / kCleanBlockSize;
        if (!driver.write_offset(static_cast<size_t>(root_block) * ratio * kCleanBlockSize, root))
            return std::format("[load {}] fixture write failed\n", name);
        result = fs.load(driver, root_block);
        std::string text = std::format("[load {}] {}", name, outcome(result));
        if (result) {
            text += " entries=";
            for (size_t i = 0; i < fs.entries().size(); ++i) {
                text += std::format("{}{}@0x{:X}", i ? "," : "",
                                    std::string_view{fs.entries()[i].filename},
                                    fs.entries()[i].block_number);
            }
        }
        return text + '\n';
    }

    std::string slot_name(const Bytes& root, size_t slot) {
        const char* at = reinterpret_cast<const char*>(root.data() + slot_offset(slot));
        return std::string(at, strnlen(at, kMaxFilenameLength));
    }

    bool test_load_pins(std::string& text) {
        bool ok = true;
        const Bytes data(kCleanBlockSize, 0x77);
        const auto small_driver = [&] {
            Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            for (size_t cluster = 0x60; cluster < 0x64; ++cluster) {
                if (!driver.write_offset(cluster * kCleanBlockSize, data))
                    std::cerr << "FAIL: file fixture write\n";
            }
            return driver;
        };

        // A slot whose block reads 0xFFFF is skipped whatever its name, and later slots load.
        {
            Driver driver = small_driver();
            Bytes root = small_root();
            put_entry(root, 0, "a.bin", 0x60, 0x10);
            put_entry(root, 1, "skipped.bin", 0xFFFF, 0x10);
            put_entry(root, 2, "c.bin", 0x62, 0x10);
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            text += load_pin("skip_ffff", driver, root, 0x3E0, fs, result);
            ok = check(result && fs.entries().size() == 2 && fs.exists("a.bin") &&
                           fs.exists("c.bin") && !fs.exists("skipped.bin"),
                       "a 0xFFFF slot is skipped and the slots after it load") &&
                 ok;
        }

        // A 0x05-first (deleted) entry and a 0xFF-first name are dropped, as are a nameless
        // slot and, on small block, a file at cluster 0. The directory compacts: an entry on
        // the second directory page takes the first free index, and re-serializing writes it
        // there.
        {
            Driver driver = small_driver();
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
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            text += load_pin("drop_compact", driver, root, 0x3E0, fs, result);
            const auto reserialized = result ? fs.serialize_root_block()
                                             : gxbuild3::Result<std::vector<uint8_t>>{Bytes{}};
            bool compacted = reserialized && reserialized->size() == kCleanBlockSize;
            if (compacted) {
                compacted = slot_name(*reserialized, 0) == "a.bin" &&
                            slot_name(*reserialized, 1) == "d.bin";
                for (size_t slot = 2; compacted && slot < 32; ++slot) {
                    const auto at =
                        reserialized->begin() + static_cast<std::ptrdiff_t>(slot_offset(slot));
                    compacted = std::all_of(at, at + 32, [](uint8_t b) { return b == 0; });
                }
            }
            text += std::format("[load drop_compact] reserialized slots: 0={} 1={} rest_zero={}\n",
                                compacted ? slot_name(*reserialized, 0) : "?",
                                compacted ? slot_name(*reserialized, 1) : "?",
                                compacted ? "yes" : "no");
            ok = check(result && fs.entries().size() == 2 && fs.entries()[0].matches("a.bin") &&
                           fs.entries()[1].matches("d.bin"),
                       "deleted, erased, nameless and cluster-0 entries drop; d.bin compacts") &&
                 ok;
            ok = check(compacted, "re-serializing writes the compacted directory") && ok;
        }

        // On big block the same relative cluster 0 is the filesystem base, and is kept.
        {
            Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
            Bytes root(kCleanBlockSize, 0);
            for (size_t cluster = 0; cluster < 0x520; ++cluster) {
                put16(root, map_offset(cluster), BlockMapStatus::Free);
            }
            put16(root, map_offset(0), BlockMapStatus::EndOfChain);
            put_entry(root, 0, "zero.bin", 0x0, 0x10);
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            if (!driver.write_offset(0xAE0 * kCleanBlockSize, data))
                ok = check(false, "big-block file fixture writes");
            text += load_pin("big_relative_zero", driver, root, 380, fs, result);
            ok = check(result && fs.entries().size() == 1 && fs.entries()[0].block_number == 0xAE0,
                       "a big-block file at relative cluster 0 is kept at the base") &&
                 ok;
        }

        // A map link past the map is Malformed.
        {
            Driver driver = small_driver();
            Bytes root = small_root();
            put16(root, map_offset(0x60), 0x400);
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            text += load_pin("link_past_map", driver, root, 0x3E0, fs, result);
            ok = check(!result && result.error().code == gxbuild3::ErrorCode::Malformed &&
                           result.error().message.find("links past the map") != std::string::npos,
                       "a map link past the map fails as Malformed") &&
                 ok;
        }

        // A link with the 0x8000 bit is checked on its low 15 bits.
        {
            Driver driver = small_driver();
            Bytes root = small_root();
            put16(root, map_offset(0x60), 0x8000 | 0x61);
            put16(root, map_offset(0x61), 0x8000 | 0x400);
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            text += load_pin("flagged_link_past_map", driver, root, 0x3E0, fs, result);
            ok = check(!result && result.error().code == gxbuild3::ErrorCode::Malformed,
                       "a flagged map link past the map fails as Malformed") &&
                 ok;
        }

        // A file starting past the map is Malformed.
        {
            Driver driver = small_driver();
            Bytes root = small_root();
            put_entry(root, 0, "a.bin", 0x60, 0x10);
            put_entry(root, 1, "far.bin", 0x400, 0x10);
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            text += load_pin("file_past_map", driver, root, 0x3E0, fs, result);
            ok = check(!result && result.error().code == gxbuild3::ErrorCode::Malformed &&
                           result.error().message.find("starts past the map") != std::string::npos,
                       "a file starting past the map fails as Malformed") &&
                 ok;
        }

        // A dropped entry is not checked against the map.
        {
            Driver driver = small_driver();
            Bytes root = small_root();
            put_entry(root, 0,
                      "\x05"
                      "far.bin",
                      0x400, 0x10);
            FlashFileSystem fs;
            gxbuild3::Result<> result;
            text += load_pin("dropped_past_map", driver, root, 0x3E0, fs, result);
            ok = check(result && fs.entries().empty(),
                       "a deleted entry past the map is dropped, not Malformed") &&
                 ok;
        }

        // A root that cannot be read whole is Truncated.
        {
            Driver driver = small_driver();
            FlashFileSystem fs;
            const auto block = static_cast<uint16_t>(driver.block_count());
            const auto result = fs.load(driver, block);
            text += std::format("[load short_root] {}\n", outcome(result));
            ok = check(!result && result.error().code == gxbuild3::ErrorCode::Truncated,
                       "a short root read fails as Truncated") &&
                 ok;
        }
        {
            Driver driver(Bytes(0x6000, 0));
            FlashFileSystem fs;
            const auto result = fs.load(driver, 1);
            text += std::format("[load short_emmc_root] mode={} {}\n",
                                mode_name(driver.driver_mode()), outcome(result));
            ok = check(!result && result.error().code == gxbuild3::ErrorCode::Truncated,
                       "a root cluster running off the image fails as Truncated") &&
                 ok;
        }
        return ok;
    }

    // An on-disk name may fill all 22 bytes with no terminator. It is read as exactly those 22
    // characters wherever an entry's name is taken: load, list_files, stat, get_file and save
    // agree on it, and re-serializing writes the same 22 bytes back.
    bool test_unterminated_name_round_trips() {
        bool ok = true;
        constexpr std::string_view kLongName = "abcdefghijklmnopqrstuv";
        static_assert(kLongName.size() == kMaxFilenameLength);
        constexpr uint16_t kRootBlock = 0x3E0;
        const Bytes long_data = pattern(kCleanBlockSize, 0x22);
        const Bytes short_data = pattern(kCleanBlockSize, 0x05);

        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        Bytes root = small_root();
        put_entry(root, 0, kLongName, 0x60, 0x10);
        put_entry(root, 1, "b.bin", 0x61, 0x20);
        if (!driver.write_offset(0x60 * kCleanBlockSize, long_data) ||
            !driver.write_offset(0x61 * kCleanBlockSize, short_data) ||
            !driver.write_offset(kRootBlock * kCleanBlockSize, root)) {
            return check(false, "unterminated-name fixture writes");
        }

        const auto expect_files = [&](const FlashFileSystem& fs, const char* when) {
            bool good = true;
            const std::vector<std::string> expected{std::string(kLongName), "b.bin"};
            good = check(fs.list_files() == expected,
                         std::format("list_files gives the 22-char name {}", when).c_str()) &&
                   good;
            const auto entry = fs.stat(kLongName);
            good = check(entry && entry->block_number == 0x60 && entry->length == 0x10,
                         std::format("stat finds the 22-char name {}", when).c_str()) &&
                   good;
            good = check(fs.stat("ABCDEFGHIJKLMNOPQRSTUV").has_value() && fs.exists(kLongName),
                         std::format("the 22-char name matches case-blind {}", when).c_str()) &&
                   good;
            const auto bytes = fs.get_file(kLongName);
            good = check(bytes && std::ranges::equal(*bytes, std::span(long_data).first(0x10)),
                         std::format("get_file reads the 22-char name's file {}", when).c_str()) &&
                   good;
            return good;
        };

        FlashFileSystem fs;
        ok = check(fs.load(driver, kRootBlock), "a 22-char on-disk name loads") && ok;
        ok = expect_files(fs, "after load") && ok;

        const auto reserialized = fs.serialize_root_block();
        ok = check(reserialized && reserialized->size() == kCleanBlockSize &&
                       std::ranges::equal(
                           std::span(*reserialized).subspan(slot_offset(0), kMaxFilenameLength),
                           kLongName) &&
                       (*reserialized)[slot_offset(0) + 22] == 0x00 &&
                       (*reserialized)[slot_offset(0) + 23] == 0x60,
                   "re-serializing writes the 22 name bytes and the block after them") &&
             ok;

        // save() lays the file again from its data, found under the 22-char name.
        if (!driver.write_offset(0x60 * kCleanBlockSize, Bytes(kCleanBlockSize, 0))) {
            return check(false, "unterminated-name cluster wipe");
        }
        ok = check(fs.save(), "a filesystem holding a 22-char name saves") && ok;
        FlashFileSystem reloaded;
        ok = check(reloaded.load(driver, kRootBlock), "the saved 22-char name loads again") && ok;
        ok = expect_files(reloaded, "after save and reload") && ok;
        return ok;
    }

    // A corrupt length far past what the file's chain holds reads the chain and fails as
    // Truncated; the read reserves no more than the chain's clusters, so it cannot exhaust
    // memory first. A failed load leaves the filesystem as it was.
    bool test_corrupt_length_fails_truncated() {
        bool ok = true;
        constexpr uint16_t kRootBlock = 0x3E0;
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        Bytes root = small_root();
        put_entry(root, 0, "a.bin", 0x60, 0x10);
        put_entry(root, 1, "huge.bin", 0x61, 0xFFFFFFF0);
        if (!driver.write_offset(0x60 * kCleanBlockSize, pattern(kCleanBlockSize, 1)) ||
            !driver.write_offset(0x61 * kCleanBlockSize, pattern(kCleanBlockSize, 2)) ||
            !driver.write_offset(kRootBlock * kCleanBlockSize, root)) {
            return check(false, "corrupt-length fixture writes");
        }

        FlashFileSystem fs;
        gxbuild3::Result<> result;
        try {
            result = fs.load(driver, kRootBlock);
        } catch (const std::exception& e) {
            return check(false, std::format("a corrupt length throws {}", e.what()).c_str());
        }
        ok = check(!result && result.error().code == gxbuild3::ErrorCode::Truncated &&
                       result.error().message ==
                           "FlashFS file 'huge.bin' is truncated: expected 4294967280 bytes, "
                           "read 16384",
                   "an entry with length 0xFFFFFFF0 fails as Truncated") &&
             ok;
        ok = check(fs.entries().empty() && fs.list_files().empty(),
                   "the failed load leaves the filesystem empty") &&
             ok;
        return ok;
    }

    bool test_flashfs_root_goldens(const gxbuild3::test::GoldenOptions& options) {
        const std::vector<RootCase> cases{
            {"small", Driver::ImageSize::Smallblock, Driver::DriverMode::Small, false, std::nullopt,
             7},
            {"newsmall", Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall, false,
             std::nullopt, 9},
            {"big", Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big, false, uint8_t{6},
             0x125},
            {"big_larger", Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big, true,
             std::nullopt, 0x126},
            {"emmc", Driver::ImageSize::Emmcblock, Driver::DriverMode::Emmc, false, std::nullopt,
             3},
        };
        std::string text = "# FlashFileSystem root codec, save()+driver.serialize() and load "
                           "pins (FlashFileSystemTests.cpp)\n";
        bool ok = true;
        for (const auto& c : cases) {
            ok = root_case_golden(c, text) && ok;
        }
        ok = test_load_pins(text) && ok;
        std::cout << "flashfs root goldens: " << cases.size() << " layouts\n";
        return gxbuild3::test::check_golden(options, "flashfs_roots", text) && ok;
    }
} // namespace

int main(int argc, char** argv) {
    const auto options = gxbuild3::test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }
    bool passed = test_load_independent_big_block_layout();
    passed = test_failed_load_leaves_filesystem_unchanged() && passed;
    passed = test_big_block_writer_uses_clusters() && passed;
    passed = test_big_block_stamps_retail_fs_metadata() && passed;
    passed = test_big_block_serialize_restamps_root() && passed;
    passed = test_small_block_fs_metadata_matches_dumps() && passed;
    passed = test_serialize_leaves_erased_low_pages_unprogrammed() && passed;
    passed = test_big_block_large_file_roundtrips_through_serialize() && passed;
    passed = test_deferred_root_is_placed_last_from_free_pool() && passed;
    passed = test_insert_file_lays_files_back_to_back() && passed;
    passed = test_table_states_withheld_and_root_clusters() && passed;
    passed = test_big_block_single_cluster_padding_keeps_erased_fields() && passed;
    passed = test_unterminated_name_round_trips() && passed;
    passed = test_corrupt_length_fails_truncated() && passed;
    passed = test_flashfs_root_goldens(*options) && passed;
    return passed ? 0 : 1;
}
