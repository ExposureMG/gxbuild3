// FlashFS root snapshot (tests/golden/flashfs_roots.txt). Runs on a clean clone: every input is
// synthetic. Lines, in order:
//   # header     the literal header naming FlashFileSystemTests.cpp, kept byte-identical.
//   [<layout>]   for small, newsmall, big, big_larger and emmc: a filesystem with several files,
//                clusters withheld and stated Unnamed and Free, a chain link carrying the 0x8000
//                bit and a deferred root; the layout line, every entry with its chain, the
//                flagged link, the SHA-1 of the root codec (serialize_root_block) and of the image
//                after save() and driver.serialize(), and a reload of that image.
//   [load <pin>] today's load() skip, drop and error behaviour over hand-built roots.
// The renderer and its format strings are the old FlashFileSystemTests.cpp ones, verbatim; its
// check() calls no longer write to stderr but append their messages to Rendered::problems, which
// FlashFsRootGolden.MatchesGolden reports one failure each. No build time is pinned: the stamps
// are fixed in the render (set_timestamp 0x5D444AC2 and the entry stamps).
// `gxbuild3_golden_tests --update flashfs_roots` rewrites tests/golden/flashfs_roots.txt (CTest
// never passes it) and refuses while the render reports a problem.

#include "FlashFsRootRender.hpp"

#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Bytes.hpp"
#include "support/FlashFsAccess.hpp"
#include "support/builders/FlashFsRoots.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots::flashfs_roots {
    namespace {

        using nand::BlockMapStatus;
        using nand::Driver;
        using nand::FlashFileSystem;
        using nand::kCleanBlockSize;
        using nand::NandLayout;
        using test::flashfs_pattern;
        using test::flashfs::load_pin;
        using test::flashfs::map_offset;
        using test::flashfs::outcome;
        using test::flashfs::put16;
        using test::flashfs::put_entry;
        using test::flashfs::slot_name;
        using test::flashfs::slot_offset;
        using test::flashfs::small_root;
        using Bytes = std::vector<uint8_t>;

        // The old check() helpers: a failed condition or Result appends its message (and the
        // Result's describe()) to the problems instead of printing "FAIL: ..." on stderr.
        class Problems {
          public:
            explicit Problems(std::vector<std::string>& list) : m_list(list) {}

            bool check(bool condition, const char* message) {
                if (!condition)
                    m_list.emplace_back(message);
                return condition;
            }

            bool check(const Result<>& result, const char* message) {
                if (!result)
                    m_list.push_back(std::format("{}: {}", message, result.error().describe()));
                return result.has_value();
            }

          private:
            std::vector<std::string>& m_list;
        };

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

        // ---- Root-codec and driver.serialize goldens ------------------------------------------

        // Builds a filesystem with several files, clusters withheld and stated Unnamed and Free,
        // a chain link carrying the 0x8000 bit and a deferred root, then snapshots the root codec
        // (serialize_root_block), the image after save() and driver.serialize(), and a load of
        // that image back. Pins today's output, quirks included.
        bool root_case_golden(const RootCase& c, std::string& text, Problems& problems) {
            bool ok = true;
            const auto fail = [&](const std::string& what) {
                return problems.check(false, std::format("[{}] {}", c.name, what).c_str());
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
            if (!problems.check(
                    fs.format(driver.block_count(), FlashFileSystem::kDeferRoot, c.version, 0x50),
                    std::format("[{}] formats with a deferred root", c.name).c_str()))
                return false;
            fs.set_timestamp(0x5D444AC2);
            if (fs.has_root())
                return fail("the deferred format leaves no root");

            const std::vector<RootFile> files{
                {"a.bin", flashfs_pattern(0x4001, 3), std::nullopt},
                {"b.bin", flashfs_pattern(0x10, 5), 0x11223344},
                {"c.bin", flashfs_pattern(0x9000, 7), std::nullopt},
                {"empty.bin", Bytes{}, std::nullopt},
                {"abcdefghijklmnopq.bin", flashfs_pattern(0x200, 11), 0x01020304},
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
            nand::FlashFileSystemTestAccess::blockmap(fs)[c_start] |= 0x8000;

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
            if (!problems.check(root.has_value() && root->size() == kCleanBlockSize,
                                std::format("[{}] the root serializes", c.name).c_str()))
                return false;
            ok = problems.check(fs.save(), std::format("[{}] saves", c.name).c_str()) && ok;
            const auto root_after_save = fs.serialize_root_block();
            ok = problems.check(
                     root_after_save && *root_after_save == *root,
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
                text +=
                    std::format("[{}] entry {} block=0x{:X} length=0x{:X} ts=0x{:08X} chain={}\n",
                                c.name, std::string_view{entry.filename}, entry.block_number,
                                entry.length, entry.timestamp, chain);
            }
            text += std::format("[{}] link 0x{:X} -> 0x{:04X}\n", c.name, c_start,
                                fs.blockmap()[c_start]);
            text += std::format("[{}] root size=0x{:X} sha1={}\n", c.name, root->size(),
                                test::sha1_hex(*root));
            text += std::format("[{}] image size=0x{:X} sha1={}\n", c.name, image.size(),
                                test::sha1_hex(image));

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
            text += std::format(
                "[{}] reload mode={} load={} version=0x{:X} entries={} files_equal={} "
                "root_identity={}\n",
                c.name, mode_name(reload.driver_mode()), outcome(load), loaded.version(),
                loaded.entries().size(), files_equal ? "yes" : "no", identity ? "yes" : "no");
            ok = problems.check(load,
                                std::format("[{}] the serialized image loads", c.name).c_str()) &&
                 ok;
            ok = problems.check(identity,
                                std::format("[{}] load() then serialize_root_block() reproduces "
                                            "the "
                                            "root",
                                            c.name)
                                    .c_str()) &&
                 ok;
            ok = problems.check(files_equal,
                                std::format("[{}] every file reloads", c.name).c_str()) &&
                 ok;
            return ok;
        }

        // ---- Pins of today's load() skip, drop and error behaviour ----------------------------

        bool load_pins(std::string& text, Problems& problems) {
            bool ok = true;
            const Bytes data(kCleanBlockSize, 0x77);
            // The old fixture write only printed "FAIL: file fixture write"; it is now a problem.
            const auto small_driver = [&] {
                Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
                for (size_t cluster = 0x60; cluster < 0x64; ++cluster) {
                    if (!driver.write_offset(cluster * kCleanBlockSize, data))
                        problems.check(false, "file fixture write");
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
                Result<> result;
                text += load_pin("skip_ffff", driver, root, 0x3E0, fs, result);
                ok = problems.check(result && fs.entries().size() == 2 && fs.exists("a.bin") &&
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
                Result<> result;
                text += load_pin("drop_compact", driver, root, 0x3E0, fs, result);
                const auto reserialized =
                    result ? fs.serialize_root_block() : Result<std::vector<uint8_t>>{Bytes{}};
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
                text += std::format(
                    "[load drop_compact] reserialized slots: 0={} 1={} rest_zero={}\n",
                    compacted ? slot_name(*reserialized, 0) : "?",
                    compacted ? slot_name(*reserialized, 1) : "?", compacted ? "yes" : "no");
                ok = problems.check(
                         result && fs.entries().size() == 2 && fs.entries()[0].matches("a.bin") &&
                             fs.entries()[1].matches("d.bin"),
                         "deleted, erased, nameless and cluster-0 entries drop; d.bin compacts") &&
                     ok;
                ok = problems.check(compacted, "re-serializing writes the compacted directory") &&
                     ok;
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
                Result<> result;
                if (!driver.write_offset(0xAE0 * kCleanBlockSize, data))
                    ok = problems.check(false, "big-block file fixture writes");
                text += load_pin("big_relative_zero", driver, root, 380, fs, result);
                ok = problems.check(result && fs.entries().size() == 1 &&
                                        fs.entries()[0].block_number == 0xAE0,
                                    "a big-block file at relative cluster 0 is kept at the base") &&
                     ok;
            }

            // A map link past the map is Malformed.
            {
                Driver driver = small_driver();
                Bytes root = small_root();
                put16(root, map_offset(0x60), 0x400);
                FlashFileSystem fs;
                Result<> result;
                text += load_pin("link_past_map", driver, root, 0x3E0, fs, result);
                ok = problems.check(!result && result.error().code == ErrorCode::Malformed &&
                                        result.error().message.find("links past the map") !=
                                            std::string::npos,
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
                Result<> result;
                text += load_pin("flagged_link_past_map", driver, root, 0x3E0, fs, result);
                ok = problems.check(!result && result.error().code == ErrorCode::Malformed,
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
                Result<> result;
                text += load_pin("file_past_map", driver, root, 0x3E0, fs, result);
                ok = problems.check(!result && result.error().code == ErrorCode::Malformed &&
                                        result.error().message.find("starts past the map") !=
                                            std::string::npos,
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
                Result<> result;
                text += load_pin("dropped_past_map", driver, root, 0x3E0, fs, result);
                ok = problems.check(result && fs.entries().empty(),
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
                ok = problems.check(!result && result.error().code == ErrorCode::Truncated,
                                    "a short root read fails as Truncated") &&
                     ok;
            }
            {
                Driver driver(Bytes(0x6000, 0));
                FlashFileSystem fs;
                const auto result = fs.load(driver, 1);
                text += std::format("[load short_emmc_root] mode={} {}\n",
                                    mode_name(driver.driver_mode()), outcome(result));
                ok = problems.check(!result && result.error().code == ErrorCode::Truncated,
                                    "a root cluster running off the image fails as Truncated") &&
                     ok;
            }
            return ok;
        }

    } // namespace

    Rendered render() {
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
        Rendered rendered;
        rendered.text = "# FlashFileSystem root codec, save()+driver.serialize() and load "
                        "pins (FlashFileSystemTests.cpp)\n";
        Problems problems{rendered.problems};
        for (const auto& c : cases) {
            (void) root_case_golden(c, rendered.text, problems);
        }
        (void) load_pins(rendered.text, problems);
        rendered.layouts = cases.size();
        return rendered;
    }

    Result<std::string> render_file() {
        Rendered rendered = render();
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the flashfs_roots render reports {} problem(s), "
                        "first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::flashfs_roots
