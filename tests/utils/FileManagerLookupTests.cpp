// src/utils/FileManager.hpp: find_file_data_detailed for regular assets. Roots are searched in
// order and within a root a loose file beats an STFS entry; the result names its provenance
// (source kind, root index, package or file path, requested name). A missing asset is an empty
// optional; a source that cannot be inspected fails the strict lookup with its provenance while
// the INI lookup skips it; nosu and nosusecurity filter what the packages answer.

#include "FileManagerTest.hpp"
#include "support/Expect.hpp"
#include "utils/FileManager.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <vector>

namespace gxbuild3::utils {
    namespace {

        namespace fs = std::filesystem;
        using test::Bytes;

        class FileManagerLookup : public FileManagerTest {};

        TEST_F(FileManagerLookup, EarlierRootWinsWhateverTheCaseAndLooseWinsWithinARoot) {
            write_stfs("first/su_test", {{"$flash_dash.xex", {1}}});
            write("second/dash.xex", Bytes{2});
            ASSERT_OK_AND_ASSIGN(
                const auto upper,
                find_file_data_detailed("DASH.XEX", {root() / "first", root() / "second"}));
            ASSERT_TRUE(upper.has_value())
                << "earlier STFS wins over later loose file, whatever the requested case";
            EXPECT_EQ(upper->source_path, root() / "first/su_test")
                << "earlier STFS wins over later loose file, whatever the requested case";

            ASSERT_OK_AND_ASSIGN(
                const auto reversed,
                find_file_data_detailed("dash.xex", {root() / "second", root() / "first"}));
            ASSERT_TRUE(reversed.has_value()) << "reversing roots changes winner";
            EXPECT_EQ(reversed->source_path, root() / "second/dash.xex")
                << "reversing roots changes winner";

            write("first/dash.xex", Bytes{3});
            ASSERT_OK_AND_ASSIGN(const auto tied,
                                 find_file_data_detailed("dash.xex", {root() / "first"}));
            ASSERT_TRUE(tied.has_value()) << "loose wins within a root";
            EXPECT_EQ(tied->source_path, root() / "first/dash.xex") << "loose wins within a root";
        }

        TEST_F(FileManagerLookup, EarlierStfsBytesWinAndProvenanceNamesThePackage) {
            write_stfs("first/su_test", {{"$flash_dash.xex", {1}}});
            write("second/dash.xex", Bytes{2});
            ASSERT_OK_AND_ASSIGN(
                const auto resolved,
                find_file_data_detailed("dash.xex", {root() / "first", root() / "second"}));
            ASSERT_TRUE(resolved.has_value()) << "earlier STFS bytes win";
            EXPECT_EQ(resolved->data, Bytes{1}) << "earlier STFS bytes win";
            EXPECT_EQ(resolved->source, AssetSource::Stfs) << "provenance identifies STFS";
            EXPECT_EQ(resolved->root_index, 0u) << "provenance identifies winning root";
            EXPECT_EQ(resolved->requested_name, "dash.xex")
                << "provenance preserves requested STFS name";
            EXPECT_EQ(resolved->source_path, root() / "first/su_test")
                << "provenance identifies STFS package path";

            ASSERT_OK_AND_ASSIGN(
                const auto nosu,
                find_file_data_detailed("dash.xex", {root() / "first"}, {.nosu = true}));
            EXPECT_FALSE(nosu.has_value()) << "nosu makes STFS-only byte lookup unavailable";
        }

        TEST_F(FileManagerLookup, MissingAssetIsOptionalAndLooseBytesWinWithinARoot) {
            ASSERT_OK_AND_ASSIGN(const auto missing,
                                 find_file_data_detailed("optional.bin", {root() / "first"}));
            EXPECT_FALSE(missing.has_value()) << "missing byte lookup is optional";

            write_stfs("first/su_test", {{"$flash_dash.xex", {1}}});
            write("first/dash.xex", Bytes{2});
            ASSERT_OK_AND_ASSIGN(const auto resolved,
                                 find_file_data_detailed("dash.xex", {root() / "first"}));
            ASSERT_TRUE(resolved.has_value()) << "loose bytes win within a root";
            EXPECT_EQ(resolved->data, Bytes{2}) << "loose bytes win within a root";
            EXPECT_EQ(resolved->source, AssetSource::Loose) << "provenance identifies loose files";
            EXPECT_EQ(resolved->requested_name, "dash.xex")
                << "provenance preserves requested loose name";
            EXPECT_EQ(resolved->source_path, root() / "first/dash.xex")
                << "provenance identifies loose file path";
        }

        TEST_F(FileManagerLookup, DetailedDistinguishesMissingAndInspectionFailure) {
            const auto missing = find_file_data_detailed("optional.bin", {root() / "first"});
            ASSERT_OK(missing) << "detailed lookup represents a missing asset as nullopt";
            EXPECT_FALSE(missing->has_value())
                << "detailed lookup represents a missing asset as nullopt";

            fs::create_directories(root() / "first/cpukey.txt");
            const auto invalid =
                find_file_data_detailed("cpukey.txt", {root() / "first", root() / "second"});
            EXPECT_ERROR(invalid, ErrorCode::Unsupported)
                << "an existing non-file candidate is an inspection failure";
            ASSERT_FALSE(invalid.has_value())
                << "lookup failure retains exact candidate and root provenance";
            EXPECT_EQ(invalid.error().source_path, root() / "first/cpukey.txt")
                << "lookup failure retains exact candidate and root provenance";
            EXPECT_EQ(invalid.error().root_path, root() / "first")
                << "lookup failure retains exact candidate and root provenance";
            EXPECT_EQ(invalid.error().root_index, 0u)
                << "lookup failure retains exact candidate and root provenance";
        }

        TEST_F(FileManagerLookup, DetailedPreservesRootPriority) {
            write_stfs("first/su_test", {{"$flash_dash.xex", {1}}});
            write("second/dash.xex", Bytes{2});
            const auto resolved =
                find_file_data_detailed("dash.xex", {root() / "first", root() / "second"});
            ASSERT_OK(resolved) << "detailed lookup keeps earlier-root STFS above later-root loose "
                                   "data";
            ASSERT_TRUE(resolved->has_value())
                << "detailed lookup keeps earlier-root STFS above later-root loose data";
            EXPECT_EQ((*resolved)->data, Bytes{1})
                << "detailed lookup keeps earlier-root STFS above later-root loose data";
            EXPECT_EQ((*resolved)->source, AssetSource::Stfs)
                << "detailed lookup keeps earlier-root STFS above later-root loose data";
            EXPECT_EQ((*resolved)->root_index, 0u)
                << "detailed lookup keeps earlier-root STFS above later-root loose data";
        }

        TEST_F(FileManagerLookup, DetailedStfsFailureIsTerminalButIniLookupFallsBack) {
            write("first/su_corrupt", Bytes{0x00, 0x01, 0x02});
            write("second/dash.xex", Bytes{0x22});
            const std::vector<fs::path> roots{root() / "first", root() / "second"};

            const auto detailed = find_file_data_detailed("dash.xex", roots);
            EXPECT_ERROR(detailed, ErrorCode::Malformed)
                << "detailed lookup reports the first corrupt STFS package with exact provenance";
            ASSERT_FALSE(detailed.has_value());
            EXPECT_EQ(detailed.error().source_path, root() / "first/su_corrupt")
                << "detailed lookup reports the first corrupt STFS package with exact provenance";
            EXPECT_EQ(detailed.error().root_path, root() / "first")
                << "detailed lookup reports the first corrupt STFS package with exact provenance";
            EXPECT_EQ(detailed.error().root_index, 0u)
                << "detailed lookup reports the first corrupt STFS package with exact provenance";
            EXPECT_EQ(detailed.error().source, AssetSource::Stfs)
                << "detailed lookup reports the first corrupt STFS package with exact provenance";

            const auto ini = read_ini_files(root() / "version/_test.ini", "test", roots);
            ASSERT_OK(ini)
                << "an INI lookup skips a corrupt STFS package and uses the later loose asset";
            EXPECT_EQ(payload(*ini, "dash.xex"), Bytes{0x22})
                << "an INI lookup skips a corrupt STFS package and uses the later loose asset";
        }

        TEST_F(FileManagerLookup, DetailedXboxupdFailureIsTerminalButIniLookupFallsBack) {
            write_stfs("first/su_test", {{"xboxupd.bin", {0x00, 0x01}}});
            write("second/cf_1.bin", Bytes{0x22});
            const std::vector<fs::path> roots{root() / "first", root() / "second"};

            const auto detailed =
                find_file_data_detailed("cf_1.bin", roots, {}, AssetKind::Bootloader);
            EXPECT_ERROR(detailed, ErrorCode::Truncated)
                << "detailed bootloader lookup reports failed xboxupd derivation with provenance";
            ASSERT_FALSE(detailed.has_value());
            EXPECT_EQ(detailed.error().source_path, root() / "first/su_test")
                << "detailed bootloader lookup reports failed xboxupd derivation with provenance";
            EXPECT_EQ(detailed.error().root_path, root() / "first")
                << "detailed bootloader lookup reports failed xboxupd derivation with provenance";
            EXPECT_EQ(detailed.error().root_index, 0u)
                << "detailed bootloader lookup reports failed xboxupd derivation with provenance";
            EXPECT_EQ(detailed.error().source, AssetSource::Xboxupd)
                << "detailed bootloader lookup reports failed xboxupd derivation with provenance";

            write("version/_test.ini", "[testbl]\ncf_1.bin\n");
            const auto ini = read_ini_files(root() / "version/_test.ini", "test", roots);
            ASSERT_OK(ini) << "an INI bootloader lookup skips failed xboxupd derivation and uses "
                              "later loose data";
            EXPECT_EQ(ini->bootloaders.cf0, Bytes{0x22})
                << "an INI bootloader lookup skips failed xboxupd derivation and uses later loose "
                   "data";
        }

        TEST_F(FileManagerLookup, RegularLookupDoesNotExtractUnrelatedXboxupd) {
            write_stfs("first/su_test",
                       {{"$flash_dash.xex", {0x11}}, {"xboxupd.bin", {0x00, 0x01}}}, "xboxupd.bin");
            const auto detailed = find_file_data_detailed("dash.xex", {root() / "first"});
            ASSERT_OK(detailed)
                << "regular lookup extracts only its requested STFS entry, not unrelated xboxupd "
                   "data";
            ASSERT_TRUE(detailed->has_value())
                << "regular lookup extracts only its requested STFS entry, not unrelated xboxupd "
                   "data";
            EXPECT_EQ((*detailed)->data, Bytes{0x11})
                << "regular lookup extracts only its requested STFS entry, not unrelated xboxupd "
                   "data";
            EXPECT_EQ((*detailed)->source, AssetSource::Stfs)
                << "regular lookup extracts only its requested STFS entry, not unrelated xboxupd "
                   "data";
        }

        TEST_F(FileManagerLookup, SameBasenamePathsKeepTheirOwnRootsAndPriority) {
            write("first/old/asset.bin", Bytes{1});
            write("second/new/asset.bin", Bytes{2});
            const std::vector<fs::path> roots{root() / "first", root() / "second"};
            ASSERT_OK_AND_ASSIGN(const auto old_alias,
                                 find_file_data_detailed("old/asset.bin", roots));
            ASSERT_OK_AND_ASSIGN(const auto new_alias,
                                 find_file_data_detailed("new/asset.bin", roots));
            ASSERT_TRUE(old_alias.has_value())
                << "same-basename lookup paths keep their own roots and priority";
            ASSERT_TRUE(new_alias.has_value())
                << "same-basename lookup paths keep their own roots and priority";
            EXPECT_EQ(old_alias->source_path, root() / "first/old/asset.bin")
                << "same-basename lookup paths keep their own roots and priority";
            EXPECT_EQ(new_alias->source_path, root() / "second/new/asset.bin")
                << "same-basename lookup paths keep their own roots and priority";
            EXPECT_LT(old_alias->root_index, new_alias->root_index)
                << "same-basename lookup paths keep their own roots and priority";
        }

        TEST_F(FileManagerLookup, NosuMakesStfsUnavailableAndKeepsTheLooseFallback) {
            write_stfs("mydata/su_test", {{"$flash_dash.xex", {1}}});
            ASSERT_OK_AND_ASSIGN(
                const auto stfs_only,
                find_file_data_detailed("dash.xex", {root() / "mydata"}, {.nosu = true}));
            EXPECT_FALSE(stfs_only.has_value()) << "nosu must make STFS-only entries unavailable";

            const auto result = read_ini_files("version", "test", "test", {}, {.nosu = true});
            ASSERT_OK(result) << "nosu must skip STFS payloads in INI lookup";
            EXPECT_TRUE(result->flashfs_sec.empty())
                << "nosu must skip STFS payloads in INI lookup";

            write("version/dash.xex", Bytes{2});
            ASSERT_OK_AND_ASSIGN(const auto loose,
                                 find_file_data_detailed("dash.xex",
                                                         {root() / "mydata", root() / "version"},
                                                         {.nosu = true}));
            ASSERT_TRUE(loose.has_value()) << "nosu retains loose fallback";
            EXPECT_EQ(loose->source_path, root() / "version/dash.xex")
                << "nosu retains loose fallback";
        }

        TEST_F(FileManagerLookup, NosusecurityFiltersOnlySecurityFilesFromStfs) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[security]\nsecdata.bin\n[flashfs]\ndash.xex\nSECDATA.BIN\n");
            write_stfs("mydata/su_test", {{"$flash_dash.xex", {1}}, {"$flash_secdata.bin", {2}}});
            const auto result =
                read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
            ASSERT_OK(result)
                << "nosusecurity blocks STFS security even when also listed in flashfs";
            EXPECT_EQ(result->flashfs_sec.size(), 1u)
                << "nosusecurity blocks STFS security even when also listed in flashfs";
            EXPECT_EQ(payload(*result, "dash.xex"), Bytes{1})
                << "nosusecurity blocks STFS security even when also listed in flashfs";

            write("version/secdata.bin", Bytes{3});
            const auto loose =
                read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
            // [flashfs] is read before [security], so the file keeps its [flashfs] spelling.
            ASSERT_OK(loose) << "nosusecurity retains loose security";
            EXPECT_EQ(payload(*loose, "SECDATA.BIN"), Bytes{3})
                << "nosusecurity retains loose security";

            const std::vector<fs::path> roots{root() / "mydata", root() / "version"};
            ASSERT_OK_AND_ASSIGN(
                const auto secdata,
                find_file_data_detailed("secdata.bin", roots, {.nosusecurity = true}));
            ASSERT_OK_AND_ASSIGN(const auto dash, find_file_data_detailed("dash.xex", roots,
                                                                          {.nosusecurity = true}));
            ASSERT_TRUE(secdata.has_value()) << "the lookup filters only security from STFS";
            ASSERT_TRUE(dash.has_value()) << "the lookup filters only security from STFS";
            EXPECT_EQ(secdata->source_path, root() / "version/secdata.bin")
                << "the lookup filters only security from STFS";
            EXPECT_EQ(dash->source_path, root() / "mydata/su_test")
                << "the lookup filters only security from STFS";
        }

        TEST_F(FileManagerLookup, NosusecuritySkipsExtractingSecurityContent) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[security]\ncustom.bin\n[flashfs]\ndash.xex\n");
            write_stfs("mydata/su_test", {{"$flash_custom.bin", {2}}, {"$flash_dash.xex", {1}}},
                       "$flash_custom.bin");
            const auto result =
                read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
            ASSERT_OK(result) << "skipped security content must not be extracted, even if its "
                                 "block chain is corrupt";
            EXPECT_EQ(payload(*result, "dash.xex"), Bytes{1})
                << "skipped security content must not be extracted, even if its block chain is "
                   "corrupt";
        }

    } // namespace
} // namespace gxbuild3::utils
