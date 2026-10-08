// src/utils/FileManager.hpp: how read_ini_files scans its roots and names the FlashFS payloads.
// Explicit roots replace the defaults and their order decides; missing, regular-file, invalid
// and repeated roots do not stop the fallback; a loose alias outranks STFS in one root; the
// payloads list [flashfs] before [security] in INI order, keep the INI's casing and take the
// patch-slot suffix (1, or 2 on a JTAG image) on .xexp/.xttp names.

#include "Args.hpp"
#include "FileManagerTest.hpp"
#include "support/Expect.hpp"
#include "utils/FileManager.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace gxbuild3::utils {
    namespace {

        namespace fs = std::filesystem;
        using test::Bytes;

        class FileManagerScan : public FileManagerTest {};

        // The FlashFS lists the [flashfs] files and then the [security] files, each in INI order,
        // whatever order the INI gives the sections in (xeBuild 1.21).
        TEST_F(FileManagerScan, FlashFsFilesPrecedeSecurityFiles) {
            write("version/_test.ini", "[testbl]\nnone\n[security]\ncrl.bin\nsecdata.bin\n"
                                       "[flashfs]\nxam.xex\naac.xexp,12345678\n");
            for (const auto* name : {"crl.bin", "secdata.bin", "xam.xex", "aac.xexp"}) {
                write(fs::path{"version"} / name, Bytes{1});
            }
            const auto result = read_ini_files("version", "test", "test", {});
            std::vector<std::string> names;
            if (result) {
                for (const auto& file : result->flashfs_sec) {
                    names.push_back(file.first);
                }
            }
            EXPECT_EQ(names,
                      (std::vector<std::string>{"xam.xex", "aac.xexp1", "crl.bin", "secdata.bin"}))
                << "[flashfs] files come first, then [security] files, each in INI order";
        }

        TEST_F(FileManagerScan, ExplicitRootOrderDecidesAndLooseWinsTiesWithinARoot) {
            write_stfs("first/su_test", {{"$flash_dash.xex", {1}}});
            write("second/dash.xex", Bytes{2});
            const auto ini = root() / "version/_test.ini";
            const auto first = read_ini_files(ini, "test", {root() / "first", root() / "second"});
            ASSERT_OK(first) << "explicit first root has priority";
            EXPECT_EQ(payload(*first, "dash.xex"), Bytes{1}) << "explicit first root has priority";

            const auto second = read_ini_files(ini, "test", {root() / "second", root() / "first"});
            ASSERT_OK(second) << "explicit root order controls the winner";
            EXPECT_EQ(payload(*second, "dash.xex"), Bytes{2})
                << "explicit root order controls the winner";

            write("first/dash.xex", Bytes{3});
            const auto tied = read_ini_files(ini, "test", {root() / "first", root() / "second"});
            ASSERT_OK(tied) << "loose wins over STFS in the same root";
            EXPECT_EQ(payload(*tied, "dash.xex"), Bytes{3})
                << "loose wins over STFS in the same root";

            const auto empty = read_ini_files(ini, "test", std::vector<fs::path>{});
            ASSERT_OK(empty) << "explicit empty roots must not inject default roots";
            EXPECT_TRUE(empty->flashfs_sec.empty())
                << "explicit empty roots must not inject default roots";
        }

        TEST_F(FileManagerScan, MissingAndInvalidSourcesDoNotPreventFallback) {
            write("first/su_broken", "not an STFS package");
            write_stfs("second/su_test", {{"$flash_dash.xex", {2}}});
            const std::vector<fs::path> roots{root() / "absent", root() / "first/su_broken",
                                              root() / "first", root() / "second",
                                              root() / "second"};
            const auto result = read_ini_files(root() / "version/_test.ini", "test", roots);
            ASSERT_OK(result) << "missing roots, regular-file roots, invalid packages, and "
                                 "repeated roots do not prevent fallback";
            EXPECT_EQ(result->flashfs_sec.size(), 1u)
                << "missing roots, regular-file roots, invalid packages, and repeated roots do not "
                   "prevent fallback";
            EXPECT_EQ(payload(*result, "dash.xex"), Bytes{2})
                << "missing roots, regular-file roots, invalid packages, and repeated roots do not "
                   "prevent fallback";

            EXPECT_FALSE(read_ini_files(root() / "missing.ini", "test", roots).has_value())
                << "missing INI remains an error";
            EXPECT_FALSE(read_ini_files(root() / "version/_test.ini", "absent", roots).has_value())
                << "missing section remains an error";
            ASSERT_OK_AND_ASSIGN(
                const auto absent,
                find_file_data_detailed("missing.bin", {root() / "absent", root() / "second"}));
            EXPECT_FALSE(absent.has_value()) << "a missing asset is reported absent";
            EXPECT_FALSE(find_file_data_detailed("missing.bin", roots).has_value())
                << "the strict lookup fails at an invalid package instead of reporting absence";
        }

        TEST_F(FileManagerScan, LaterListedLooseAliasReplacesStfsOfTheSameRoot) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[flashfs]\nstfs/asset.bin\nloose/ASSET.BIN\n");
            write_stfs("mydata/su_test", {{"$flash_asset.bin", {1}}});
            write("mydata/loose/ASSET.BIN", Bytes{2});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result)
                << "a later-listed loose alias replaces STFS of the same root using source rank";
            EXPECT_EQ(result->flashfs_sec.size(), 1u)
                << "a later-listed loose alias replaces STFS of the same root using source rank";
            EXPECT_EQ(payload(*result, "asset.bin"), Bytes{2})
                << "a later-listed loose alias replaces STFS of the same root using source rank";
        }

        TEST_F(FileManagerScan, FlashFsPreservesFilenameCase) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[flashfs]\nSegoeXbox-Light.xtt\nMixedCase.BIN\n");
            write("mydata/SegoeXbox-Light.xtt", Bytes{7});
            write("mydata/MixedCase.BIN", Bytes{8});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "both mixed-case payloads must be present";
            EXPECT_EQ(result->flashfs_sec.size(), 2u) << "both mixed-case payloads must be present";
            EXPECT_EQ(payload(*result, "SegoeXbox-Light.xtt"), Bytes{7})
                << "FlashFS entry name must preserve the INI-declared mixed casing";
            EXPECT_EQ(payload(*result, "MixedCase.BIN"), Bytes{8})
                << "FlashFS entry name must preserve uppercase extension casing";
        }

        TEST_F(FileManagerScan, FlashFsAppendsPatchSlotSuffix) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[flashfs]\naac.xexp\nxenonclatin.xttp\nxenonclatin.xtt\n"
                  "nomni.xexp1\n");
            write("mydata/aac.xexp", Bytes{1});
            write("mydata/xenonclatin.xttp", Bytes{2});
            write("mydata/xenonclatin.xtt", Bytes{4});
            write("mydata/nomni.xexp1", Bytes{5});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "each distinct payload must be present exactly once";
            EXPECT_EQ(result->flashfs_sec.size(), 4u)
                << "each distinct payload must be present exactly once";
            EXPECT_EQ(payload(*result, "aac.xexp1"), Bytes{1})
                << "unsuffixed .xexp payload must be stored with the slot-1 suffix";
            EXPECT_EQ(payload(*result, "xenonclatin.xttp1"), Bytes{2})
                << "unsuffixed .xttp payload must be stored with the slot-1 suffix";
            EXPECT_EQ(payload(*result, "xenonclatin.xtt"), Bytes{4})
                << ".xtt fonts must not be suffixed";
            EXPECT_EQ(payload(*result, "nomni.xexp1"), Bytes{5})
                << "already-suffixed .xexp1 payload must not be double-suffixed";
        }

        TEST_F(FileManagerScan, FlashFsJtagTakesTheTwoSlotSuffix) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[flashfs]\naac.xexp\nxenonclatin.xttp\nxenonclatin.xtt\n"
                  "nomni.xexp1\n");
            write("mydata/aac.xexp", Bytes{1});
            write("mydata/xenonclatin.xttp", Bytes{2});
            write("mydata/xenonclatin.xtt", Bytes{4});
            write("mydata/nomni.xexp1", Bytes{5});
            const auto result = read_ini_files("version", "test", "test", {}, {}, BuildType::Jtag);
            ASSERT_OK(result) << "each distinct JTAG payload must be present exactly once";
            EXPECT_EQ(result->flashfs_sec.size(), 4u)
                << "each distinct JTAG payload must be present exactly once";
            EXPECT_EQ(payload(*result, "aac.xexp2"), Bytes{1})
                << "a JTAG image stores an unsuffixed .xexp payload with the two-slot suffix";
            EXPECT_EQ(payload(*result, "xenonclatin.xttp2"), Bytes{2})
                << "a JTAG image stores an unsuffixed .xttp payload with the two-slot suffix";
            EXPECT_EQ(payload(*result, "xenonclatin.xtt"), Bytes{4})
                << ".xtt fonts must not be suffixed on a JTAG image";
            EXPECT_EQ(payload(*result, "nomni.xexp1"), Bytes{5})
                << "an already-suffixed payload keeps its suffix on a JTAG image";
        }

    } // namespace
} // namespace gxbuild3::utils
