// src/utils/FileManager.hpp: read_ini_files over the default roots (./mydata, ./version,
// ./common). Earlier roots win and later STFS packages fill gaps; aliases collapse by basename
// across sections; names fall back to any case; ..\ entries name files beside the release and
// are skipped when missing, as are missing [rawpatch] files. An entry that escapes its root
// (FileManagerUnconfinedPath, FileManagerSymlink) never falls through to an STFS entry.

#include "FileManagerTest.hpp"
#include "support/Expect.hpp"
#include "utils/FileManager.hpp"

#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <system_error>

namespace gxbuild3::utils {
    namespace {

        namespace fs = std::filesystem;
        using test::Bytes;

        class FileManagerIni : public FileManagerTest {};

        TEST_F(FileManagerIni, EarlierStfsWinsOverALaterLoosePayload) {
            write_stfs("mydata/su_test", {{"$flash_dash.xex", {1}}});
            write("version/dash.xex", Bytes{2});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "INI must resolve";
            EXPECT_EQ(payload(*result, "dash.xex"), Bytes{1})
                << "earlier STFS wins over later loose payload";
        }

        TEST_F(FileManagerIni, MissingEntriesFallBackToALaterStfs) {
            write_stfs("mydata/su_test", {{"unrelated.bin", {1}}});
            write_stfs("version/su_test", {{"$flash_dash.xex", {2}}});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "INI must resolve";
            EXPECT_EQ(payload(*result, "dash.xex"), Bytes{2})
                << "missing entries fall back to a later STFS";
        }

        TEST_F(FileManagerIni, DeduplicatesAndScoresAliasesAcrossSections) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[security]\nold\\asset.bin\n[flashfs]\nnew/ASSET.BIN\n");
            write("version/old/asset.bin", Bytes{2});
            write("mydata/new/ASSET.BIN", Bytes{1});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "payload aliases collapse across sections";
            ASSERT_EQ(result->flashfs_sec.size(), 1u) << "payload aliases collapse across sections";
            EXPECT_EQ(result->flashfs_sec[0].second, Bytes{1})
                << "higher priority alias replaces earlier entry";
        }

        TEST_F(FileManagerIni, LookupFallsBackToAnyCase) {
            write("version/_test.ini", "[testbl]\nsc_17489.bin\n[flashfs]\nSegoe.XTT\nexact.bin\n");
            write("mydata/SC_17489.bin", Bytes{0x53, 0x43});
            write("mydata/segoe.xtt", Bytes{0x07});
            write("mydata/EXACT.bin", Bytes{0x01});
            write("mydata/exact.bin", Bytes{0x02});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "a bootloader named in another case is found";
            EXPECT_EQ(result->bootloaders.sc, (Bytes{0x53, 0x43}))
                << "a bootloader named in another case is found";
            EXPECT_EQ(payload(*result, "Segoe.XTT"), Bytes{0x07})
                << "a payload named in another case is found and keeps the INI's casing";
            EXPECT_EQ(payload(*result, "exact.bin"), Bytes{0x02})
                << "an exact-case file wins over one that only matches without case";

            const auto detailed = find_file_data_detailed("sc_17489.bin", {root() / "mydata"});
            ASSERT_OK(detailed) << "the detailed lookup falls back to any case as well";
            ASSERT_TRUE(detailed->has_value())
                << "the detailed lookup falls back to any case as well";
            EXPECT_EQ((**detailed).data, (Bytes{0x53, 0x43}))
                << "the detailed lookup falls back to any case as well";
            ASSERT_OK_AND_ASSIGN(const auto upper,
                                 find_file_data_detailed("SC_17489.BIN", {root() / "mydata"}));
            EXPECT_TRUE(upper.has_value())
                << "an upper-case request falls back to any case as well";
        }

        TEST_F(FileManagerIni, PayloadOutsideTheReleaseAndRawpatchFilesAreSkippedWhenMissing) {
            write("version/_test.ini",
                  "[testbl]\nnone\n[flashfs]\n..\\data\\xell.bin,;\n..\\launch.xex,0\n"
                  "rrbkgnd.bmp ,6850A07F\nrglXam.rglp\n[rawpatch]\nvfuses_khv.bin,0xE4000\n"
                  "reason.bin,0x4E\n");
            write("mydata/data/xell.bin", Bytes{0x7F, 'E'});
            write("mydata/rrbkgnd.bmp", Bytes{0x42});
            write("mydata/rglXam.rglp", Bytes{0x43});
            write("mydata/reason.bin", Bytes{0x12});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "a missing file from outside the release and a missing "
                                 "[rawpatch] file are skipped";
            EXPECT_EQ(payload(*result, "xell.bin"), (Bytes{0x7F, 'E'}))
                << "..\\data\\xell.bin is found under data/ in a root and stored by its basename";
            EXPECT_TRUE(std::ranges::none_of(result->flashfs_sec, [](const auto& file) {
                return file.first == "launch.xex";
            })) << "a missing file from outside the release is left out";
            EXPECT_EQ(payload(*result, "rrbkgnd.bmp1"), Bytes{0x42})
                << "a name ending in p with a checksum takes the slot suffix, as xeBuild writes it";
            EXPECT_EQ(payload(*result, "rglXam.rglp"), Bytes{0x43})
                << "a name ending in p without a checksum is stored as it is";
            ASSERT_EQ(result->raw_patches.size(), 1u)
                << "a [rawpatch] file is read with its offset; a missing one is skipped";
            EXPECT_EQ(result->raw_patches[0].name, "reason.bin")
                << "a [rawpatch] file is read with its offset; a missing one is skipped";
            EXPECT_EQ(result->raw_patches[0].offset, 0x4Eu)
                << "a [rawpatch] file is read with its offset; a missing one is skipped";
            EXPECT_EQ(result->raw_patches[0].data, Bytes{0x12})
                << "a [rawpatch] file is read with its offset; a missing one is skipped";

            write("version/_test.ini", "[testbl]\nnone\n[rawpatch]\nreason.bin,0xZZ\n");
            EXPECT_FALSE(read_ini_files("version", "test", "test").has_value())
                << "a [rawpatch] offset that does not parse rejects the INI";
        }

        // ---- Entries that escape their root ------------------------------------------------

        // An INI path that is not confined to a source root. Each row lists it as a bootloader
        // (the INI is rejected) and as a payload: a leading "../" names a file beside the release,
        // looked for as a loose file in the roots only and skipped when missing there; every other
        // unsafe payload path rejects the INI.
        struct UnconfinedPathRow {
            const char* name;
            const char* path;
            bool payload_is_outside_the_release;
        };
        GX_PRINT_ROW_AS_NAME(UnconfinedPathRow)

        class FileManagerUnconfinedPath : public FileManagerTest,
                                          public ::testing::WithParamInterface<UnconfinedPathRow> {
        };

        TEST_P(FileManagerUnconfinedPath, IsRejectedAndNeverFallsThroughToStfs) {
            const std::string path = GetParam().path;
            write("version/_test.ini", "[testbl]\n" + path + "\n");
            write("outside/cb_1.bin", Bytes{0x01});
            write_stfs("mydata/su_test", {{"cb_1.bin", {0x02}}});
            EXPECT_FALSE(read_ini_files("version", "test", "test").has_value())
                << "unconfined INI bootloader path cannot escape or fall through to STFS";
            EXPECT_ERROR(find_file_data_detailed(path, {root() / "mydata"}),
                         ErrorCode::InvalidArgument)
                << "detailed lookup rejects an unsafe name before STFS fallback";

            write("version/_test.ini", "[testbl]\nnone\n[flashfs]\n" + path + "\n");
            const auto payloads = read_ini_files("version", "test", "test");
            if (GetParam().payload_is_outside_the_release) {
                // A leading ".." names a file beside the release, looked for as a loose file
                // in the roots only: the file outside them and the STFS entry are not read.
                ASSERT_OK(payloads) << "a payload from outside the release is skipped, never read "
                                       "from outside the roots or from STFS";
                EXPECT_TRUE(payloads->flashfs_sec.empty())
                    << "a payload from outside the release is skipped, never read from outside the "
                       "roots or from STFS";
            } else {
                EXPECT_FALSE(payloads.has_value()) << "unsafe payload paths reject the INI instead "
                                                      "of becoming optional missing data";
            }
        }

        INSTANTIATE_TEST_SUITE_P(
            Row, FileManagerUnconfinedPath,
            ::testing::Values(UnconfinedPathRow{"DotDotOutside", "../outside/cb_1.bin", true},
                              UnconfinedPathRow{"NestedDotDot", "nested/../cb_1.bin", false},
                              UnconfinedPathRow{"AbsoluteRoot", "/outside/cb_1.bin", false},
                              UnconfinedPathRow{"DriveAbsolute", "C:\\outside\\cb_1.bin", false},
                              UnconfinedPathRow{"DriveRelative", "C:cb_1.bin", false},
                              UnconfinedPathRow{"UncShare", "\\\\server\\share\\cb_1.bin", false}),
            test::RowName{});

        // Not bundled: it skips where directory symlinks cannot be made.
        class FileManagerSymlink : public FileManagerTest {};

        TEST_F(FileManagerSymlink, EscapeIsRejectedAndSafeNestedPathsResolve) {
            write("version/_test.ini", "[testbl]\nnested/cb_1.bin\n");
            write("mydata/nested/cb_1.bin", Bytes{0x11});
            const auto nested = read_ini_files("version", "test", "test");
            ASSERT_OK(nested) << "safe nested INI path resolves within a source root";
            EXPECT_EQ(nested->bootloaders.cb_or_a, Bytes{0x11})
                << "safe nested INI path resolves within a source root";

            write("version/_test.ini", "[testbl]\nlinked/cb_1.bin\n");
            write("outside/cb_1.bin", Bytes{0x22});
            std::error_code ec;
            fs::create_directory_symlink(root() / "outside", root() / "mydata/linked", ec);
            if (ec) {
                GTEST_SKIP() << "directory symlink unavailable: " << ec.message();
            }
            write_stfs("mydata/su_test", {{"cb_1.bin", {0x33}}});
            EXPECT_FALSE(read_ini_files("version", "test", "test").has_value())
                << "symlink escape cannot fall through to a same-basename STFS entry";
        }

    } // namespace
} // namespace gxbuild3::utils
