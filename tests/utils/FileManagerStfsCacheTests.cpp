// src/utils/FileManager.hpp: the process-wide STFS caches and in-memory packages. Repeat lookups
// are served from the package, directory and derived-bootloader caches, clear_stfs_cache()
// empties them and a package rewritten on disk is read again, but only when its mtime or size
// changed: a same-size rewrite under the old mtime is served from the cache (AsToday).
// ScanOptions::in_memory_stfs packages answer without any root (empty source_path, root_index
// counting the packages), outrank the disk roots and honour nosu and nosusecurity.
//
// The in-memory cases touch no file, but use the fixture too (gtest cannot mix TEST and TEST_F
// in one suite) for its clear_stfs_cache() in SetUp and TearDown.

#include "FileManagerTest.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "utils/FileManager.hpp"

#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <system_error>
#include <vector>

namespace gxbuild3::utils {
    namespace {

        namespace fs = std::filesystem;
        using test::Bytes;

        class FileManagerStfsCache : public FileManagerTest {};

        TEST_F(FileManagerStfsCache, RepeatLookupsAreCachedAndClearingOrRewritingReadsAgain) {
            const Bytes xboxupd = make_xboxupd();
            const Bytes cf = xboxupd_cf(xboxupd);
            const Bytes cg = xboxupd_cg(xboxupd);
            write_stfs("mydata/su_test", {{"$flash_dash.xex", {0x10}}, {"xboxupd.bin", xboxupd}});
            const std::vector<fs::path> roots{root() / "mydata"};

            // First lookups populate cache
            ASSERT_OK_AND_ASSIGN(const auto file1, find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(file1.has_value()) << "first lookup retrieves file and caches package";
            EXPECT_EQ(file1->data, Bytes{0x10}) << "first lookup retrieves file and caches package";

            ASSERT_OK_AND_ASSIGN(const auto cf1, find_file_data_detailed("cf_1.bin", roots, {},
                                                                         AssetKind::Bootloader));
            ASSERT_TRUE(cf1.has_value())
                << "first bootloader lookup derives CF and caches split parts";
            EXPECT_EQ(cf1->data, cf) << "first bootloader lookup derives CF and caches split parts";

            ASSERT_OK_AND_ASSIGN(const auto cg1, find_file_data_detailed("cg_1.bin", roots, {},
                                                                         AssetKind::Bootloader));
            ASSERT_TRUE(cg1.has_value()) << "second bootloader lookup reuses cached split parts";
            EXPECT_EQ(cg1->data, cg) << "second bootloader lookup reuses cached split parts";

            // Subsequent lookups hit cache
            ASSERT_OK_AND_ASSIGN(const auto file2, find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(file2.has_value()) << "cached lookup returns identical data";
            EXPECT_EQ(file2->data, Bytes{0x10}) << "cached lookup returns identical data";

            // Clear cache and verify re-reading works
            clear_stfs_cache();
            ASSERT_OK_AND_ASSIGN(const auto after_clear,
                                 find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(after_clear.has_value())
                << "lookup after clear_stfs_cache repopulates cache successfully";
            EXPECT_EQ(after_clear->data, Bytes{0x10})
                << "lookup after clear_stfs_cache repopulates cache successfully";

            // Overwrite file on disk and verify disk cache auto-invalidates
            write_stfs("mydata/su_test", {{"$flash_dash.xex", {0x99}}});
            ASSERT_OK_AND_ASSIGN(const auto after_modify,
                                 find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(after_modify.has_value())
                << "modifying STFS package on disk invalidates cache and returns fresh data";
            EXPECT_EQ(after_modify->data, Bytes{0x99})
                << "modifying STFS package on disk invalidates cache and returns fresh data";
        }

        // get_or_load_disk_package keys a disk package on its canonical path, last_write_time
        // and file_size only, never on its bytes: a rewrite that keeps both is served from the
        // cached package. Setting the old mtime back makes this deterministic, unlike the
        // rewrite above, which relies on a size change. Moving the mtime alone reloads.
        TEST_F(FileManagerStfsCache, SameSizeSameMtimeRewriteIsServedFromCacheAsToday) {
            write_stfs("mydata/su_test", {{"$flash_dash.xex", {0x10}}});
            const fs::path package = root() / "mydata/su_test";
            const std::vector<fs::path> roots{root() / "mydata"};

            ASSERT_OK_AND_ASSIGN(const auto first, find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(first.has_value());
            EXPECT_EQ(first->data, Bytes{0x10}) << "first lookup loads and caches the package";
            EXPECT_EQ(first->source_path, package);

            std::error_code ec;
            const auto old_mtime = fs::last_write_time(package, ec);
            ASSERT_FALSE(ec) << ec.message();
            const auto old_size = fs::file_size(package, ec);
            ASSERT_FALSE(ec) << ec.message();

            write_stfs("mydata/su_test", {{"$flash_dash.xex", {0x20}}});
            fs::last_write_time(package, old_mtime, ec);
            ASSERT_FALSE(ec) << ec.message();
            ASSERT_EQ(fs::file_size(package), old_size) << "the rewrite keeps the size";
            ASSERT_EQ(fs::last_write_time(package), old_mtime) << "the old mtime is restored";
            ASSERT_OK_AND_ASSIGN(const Bytes on_disk, test::read_file(package));
            ASSERT_EQ(on_disk, make_simple_package({{"$flash_dash.xex", {0x20}}}))
                << "the new bytes are on disk";

            ASSERT_OK_AND_ASSIGN(const auto stale, find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(stale.has_value());
            EXPECT_EQ(stale->data, Bytes{0x10})
                << "same path, size and mtime: the cached package answers with the old bytes";

            fs::last_write_time(package, old_mtime + std::chrono::seconds(2), ec);
            ASSERT_FALSE(ec) << ec.message();
            ASSERT_OK_AND_ASSIGN(const auto fresh, find_file_data_detailed("dash.xex", roots));
            ASSERT_TRUE(fresh.has_value());
            EXPECT_EQ(fresh->data, Bytes{0x20})
                << "a changed mtime alone (same size) invalidates the cached package";
        }

        TEST_F(FileManagerStfsCache, InMemoryPackageAnswersWithoutAnyRoot) {
            ScanOptions options;
            options.in_memory_stfs.push_back(
                {"embedded_su", make_simple_package({{"$flash_dash.xex", {0x42}}})});

            // Search with empty roots (no paths at all!)
            const std::vector<fs::path> empty_roots{};
            const auto detailed = find_file_data_detailed("dash.xex", empty_roots, options);
            ASSERT_OK(detailed) << "in-memory STFS asset found with empty roots";
            ASSERT_TRUE(detailed->has_value()) << "in-memory STFS asset found with empty roots";
            EXPECT_EQ((*detailed)->requested_name, "dash.xex") << "preserves requested name";
            EXPECT_TRUE((*detailed)->source_path.empty())
                << "source_path must be empty for in-memory STFS";
            EXPECT_EQ((*detailed)->data, Bytes{0x42})
                << "correct bytes returned from in-memory STFS";
            EXPECT_EQ((*detailed)->root_index, 0u)
                << "root_index indicates in-memory package index";
            EXPECT_EQ((*detailed)->source, AssetSource::Stfs)
                << "source identifies as AssetSource::Stfs";
        }

        TEST_F(FileManagerStfsCache, InMemoryPackageDerivesBootloadersFromItsXboxupd) {
            const Bytes xboxupd = make_xboxupd();
            ScanOptions options;
            options.in_memory_stfs.push_back(
                {"embedded_update", make_simple_package({{"xboxupd.bin", xboxupd}})});
            const std::vector<fs::path> empty_roots{};

            const auto cf =
                find_file_data_detailed("cf_1.bin", empty_roots, options, AssetKind::Bootloader);
            ASSERT_OK(cf) << "in-memory STFS derives CF from xboxupd";
            ASSERT_TRUE(cf->has_value()) << "in-memory STFS derives CF from xboxupd";
            EXPECT_EQ((*cf)->data, xboxupd_cf(xboxupd)) << "in-memory STFS derives CF from xboxupd";
            EXPECT_TRUE((*cf)->source_path.empty()) << "derived CF source_path is empty";
            EXPECT_EQ((*cf)->source, AssetSource::Xboxupd) << "derived CF source is Xboxupd";

            const auto cg =
                find_file_data_detailed("cg_1.bin", empty_roots, options, AssetKind::Bootloader);
            ASSERT_OK(cg) << "in-memory STFS derives CG from xboxupd";
            ASSERT_TRUE(cg->has_value()) << "in-memory STFS derives CG from xboxupd";
            EXPECT_EQ((*cg)->data, xboxupd_cg(xboxupd)) << "in-memory STFS derives CG from xboxupd";
            EXPECT_TRUE((*cg)->source_path.empty()) << "derived CG source_path is empty";
        }

        TEST_F(FileManagerStfsCache, InMemoryPackageOutranksTheRootsAndHonoursNosuAndNosusecurity) {
            ScanOptions options;
            options.in_memory_stfs.push_back(
                {"embedded_su", make_simple_package({{"$flash_dash.xex", {0x99}},
                                                     {"$flash_secdata.bin", {0x77}}})});
            write("first/dash.xex", Bytes{0x11});
            write("first/secdata.bin", Bytes{0x22});
            const std::vector<fs::path> roots{root() / "first"};

            // In-memory package beats disk loose file
            const auto detailed = find_file_data_detailed("dash.xex", roots, options);
            ASSERT_OK(detailed) << "in-memory STFS package has priority over disk roots";
            ASSERT_TRUE(detailed->has_value())
                << "in-memory STFS package has priority over disk roots";
            EXPECT_EQ((*detailed)->data, Bytes{0x99})
                << "in-memory STFS package has priority over disk roots";
            EXPECT_TRUE((*detailed)->source_path.empty())
                << "in-memory STFS package has priority over disk roots";

            // nosu skips in-memory STFS
            auto nosu_options = options;
            nosu_options.nosu = true;
            const auto nosu = find_file_data_detailed("dash.xex", roots, nosu_options);
            ASSERT_OK(nosu) << "nosu skips in-memory STFS package and falls back to disk";
            ASSERT_TRUE(nosu->has_value())
                << "nosu skips in-memory STFS package and falls back to disk";
            EXPECT_EQ((*nosu)->data, Bytes{0x11})
                << "nosu skips in-memory STFS package and falls back to disk";
            EXPECT_EQ((*nosu)->source_path, root() / "first/dash.xex")
                << "nosu skips in-memory STFS package and falls back to disk";

            // nosusecurity skips security files from in-memory STFS
            auto nosusecurity_options = options;
            nosusecurity_options.nosusecurity = true;
            const auto secdata =
                find_file_data_detailed("secdata.bin", roots, nosusecurity_options);
            ASSERT_OK(secdata) << "nosusecurity excludes security files from in-memory STFS";
            ASSERT_TRUE(secdata->has_value())
                << "nosusecurity excludes security files from in-memory STFS";
            EXPECT_EQ((*secdata)->data, Bytes{0x22})
                << "nosusecurity excludes security files from in-memory STFS";
            EXPECT_EQ((*secdata)->source_path, root() / "first/secdata.bin")
                << "nosusecurity excludes security files from in-memory STFS";

            // read_ini_files with in-memory STFS
            write("version/_test.ini", "[testbl]\nnone\n[flashfs]\ndash.xex\n");
            const auto ini = read_ini_files("version", "test", "test", {}, options);
            ASSERT_OK(ini) << "read_ini_files resolves payload from in-memory STFS";
            EXPECT_EQ(payload(*ini, "dash.xex"), Bytes{0x99})
                << "read_ini_files resolves payload from in-memory STFS";
        }

    } // namespace
} // namespace gxbuild3::utils
