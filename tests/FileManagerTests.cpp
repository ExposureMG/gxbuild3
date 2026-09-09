#include "utils/FileManager.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
    namespace fs = std::filesystem;
    using Bytes = std::vector<uint8_t>;

    void require(bool condition, std::string_view message) {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    void write_file(const fs::path& path, const Bytes& data) {
        fs::create_directories(path.parent_path());
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        require(out.good(), "fixture file must be writable");
    }

    void write_text(const fs::path& path, std::string_view text) {
        write_file(path, Bytes(text.begin(), text.end()));
    }

    void be32(Bytes& bytes, size_t offset, uint32_t value) {
        for (size_t i = 0; i < 4; ++i)
            bytes.at(offset + i) = static_cast<uint8_t>(value >> (24 - 8 * i));
    }

    // One file-table block and one data block per file. No external firmware required.
    Bytes make_stfs_bytes(const std::vector<std::pair<std::string, Bytes>>& files,
                          std::string_view corrupt_file = {}) {
        require(files.size() < 64, "fixture fits in one file table");
        Bytes package(0xC000 + files.size() * 0x1000, 0);
        std::copy_n("PIRS", 4, package.begin());
        be32(package, 0x340, 0xA000);
        package[0x379] = 0x24;
        package[0x37C] = 1; // file table block count (little endian)
        for (size_t block = 0; block <= files.size(); ++block) {
            const size_t hash = 0xA000 + block * 0x18;
            package[hash + 0x14] = 0x80;
            package[hash + 0x15] = package[hash + 0x16] = package[hash + 0x17] = 0xFF;
        }
        for (size_t i = 0; i < files.size(); ++i) {
            const auto& [name, data] = files[i];
            require(name.size() <= 40 && data.size() <= 0x1000, "fixture entry fits");
            const size_t entry = 0xB000 + i * 0x40;
            std::copy(name.begin(), name.end(), package.begin() + entry);
            package[entry + 0x28] = static_cast<uint8_t>(name.size());
            package[entry + 0x29] = package[entry + 0x2C] = 1;
            package[entry + 0x2F] = static_cast<uint8_t>(i + 1);
            package[entry + 0x32] = package[entry + 0x33] = 0xFF;
            be32(package, entry + 0x34, static_cast<uint32_t>(data.size()));
            std::copy(data.begin(), data.end(), package.begin() + 0xC000 + i * 0x1000);
            if (name == corrupt_file)
                package[0xA000 + (i + 1) * 0x18 + 0x14] = 0; // invalid block chain
        }
        return package;
    }

    void write_stfs(const fs::path& path, const std::vector<std::pair<std::string, Bytes>>& files,
                    std::string_view corrupt_file = {}) {
        write_file(path, make_stfs_bytes(files, corrupt_file));
    }

    struct Fixture {
        fs::path original = fs::current_path();
        fs::path root;

        Fixture() {
            static unsigned counter = 0;
            root = original /
                   ("filemanager-test-" +
                    std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                    "-" + std::to_string(counter++));
            require(fs::create_directory(root), "fixture directory must be new");
            fs::current_path(root);
            write_text(root / "version/_test.ini", "[testbl]\nnone\n[flashfs]\ndash.xex\n");
        }

        ~Fixture() {
            std::error_code ec;
            fs::current_path(original, ec);
            if (root.parent_path() == original &&
                root.filename().string().starts_with("filemanager-test-"))
                fs::remove_all(root, ec);
        }
    };

    const Bytes& payload(const FileManager::IniFilesResult& result, std::string_view name) {
        const auto it = std::find_if(result.flashfs_sec.begin(), result.flashfs_sec.end(),
                                     [&](const auto& entry) { return entry.first == name; });
        require(it != result.flashfs_sec.end(), "expected payload must be present");
        return it->second;
    }

    void test_findfiles_priority() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "second/dash.xex", {2});
        auto result =
            FileManager::FindFiles({"dash.xex", "DASH.XEX"}, {f.root / "first", f.root / "second"});
        require(result.size() == 1 && result.at("dash.xex") == f.root / "first/su_test",
                "earlier STFS wins over later loose file and duplicates collapse");
        result = FileManager::FindFiles({"dash.xex"}, {f.root / "second", f.root / "first"});
        require(result.at("dash.xex") == f.root / "second/dash.xex",
                "reversing roots changes winner");
        write_file(f.root / "first/dash.xex", {3});
        result = FileManager::FindFiles({"dash.xex"}, {f.root / "first"});
        require(result.at("dash.xex") == f.root / "first/dash.xex", "loose wins within a root");
    }

    void test_find_file_data_priority_and_kind() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "second/dash.xex", {2});
        const auto resolved =
            FileManager::FindFileData("dash.xex", {f.root / "first", f.root / "second"});
        require(resolved && resolved->data == Bytes{1}, "earlier STFS bytes win");
        require(resolved->source == FileManager::AssetSource::Stfs, "provenance identifies STFS");
        require(resolved->root_index == 0, "provenance identifies winning root");
        require(resolved->requested_name == "dash.xex", "provenance preserves requested STFS name");
        require(resolved->source_path == f.root / "first/su_test",
                "provenance identifies STFS package path");
        require(!FileManager::FindFileData("dash.xex", {f.root / "first"}, {.nosu = true}),
                "nosu makes STFS-only byte lookup unavailable");
    }

    void test_find_file_data_optional_and_loose_priority() {
        Fixture f;
        require(!FileManager::FindFileData("optional.bin", {f.root / "first"}),
                "missing byte lookup is optional");
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "first/dash.xex", {2});
        const auto resolved = FileManager::FindFileData("dash.xex", {f.root / "first"});
        require(resolved && resolved->data == Bytes{2}, "loose bytes win within a root");
        require(resolved->source == FileManager::AssetSource::Loose,
                "provenance identifies loose files");
        require(resolved->requested_name == "dash.xex",
                "provenance preserves requested loose name");
        require(resolved->source_path == f.root / "first/dash.xex",
                "provenance identifies loose file path");
    }

    void test_find_file_data_detailed_distinguishes_missing_and_inspection_failure() {
        Fixture f;
        const auto missing = FileManager::FindFileDataDetailed("optional.bin", {f.root / "first"});
        require(missing && !*missing, "detailed lookup represents a missing asset as nullopt");

        fs::create_directories(f.root / "first/cpukey.txt");
        const auto invalid =
            FileManager::FindFileDataDetailed("cpukey.txt", {f.root / "first", f.root / "second"});
        require(!invalid &&
                    invalid.error().code == FileManager::FileLookupErrorCode::InspectionFailed,
                "an existing non-file candidate is an inspection failure");
        require(invalid.error().source_path == f.root / "first/cpukey.txt" &&
                    invalid.error().root_path == f.root / "first" &&
                    invalid.error().root_index == 0,
                "lookup failure retains exact candidate and root provenance");
    }

    void test_find_file_data_detailed_preserves_root_priority() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "second/dash.xex", {2});
        const auto resolved =
            FileManager::FindFileDataDetailed("dash.xex", {f.root / "first", f.root / "second"});
        require(resolved && *resolved && (*resolved)->data == Bytes{1} &&
                    (*resolved)->source == FileManager::AssetSource::Stfs &&
                    (*resolved)->root_index == 0,
                "detailed lookup keeps earlier-root STFS above later-root loose data");
    }

    void test_detailed_stfs_failure_is_terminal_but_legacy_lookup_falls_back() {
        Fixture f;
        write_file(f.root / "first/su_corrupt", {0x00, 0x01, 0x02});
        write_file(f.root / "second/dash.xex", {0x22});
        const std::vector<fs::path> roots{f.root / "first", f.root / "second"};

        const auto detailed = FileManager::FindFileDataDetailed("dash.xex", roots);
        require(!detailed &&
                    detailed.error().code == FileManager::FileLookupErrorCode::InspectionFailed &&
                    detailed.error().source_path == f.root / "first/su_corrupt" &&
                    detailed.error().root_path == f.root / "first" &&
                    detailed.error().root_index == 0 &&
                    detailed.error().source == FileManager::AssetSource::Stfs,
                "detailed lookup reports the first corrupt STFS package with exact provenance");

        const auto legacy = FileManager::FindFileData("dash.xex", roots);
        require(legacy && legacy->data == Bytes{0x22} && legacy->root_index == 1 &&
                    legacy->source == FileManager::AssetSource::Loose,
                "legacy lookup skips a corrupt STFS package and uses the later loose asset");
    }

    void test_detailed_xboxupd_failure_is_terminal_but_legacy_lookup_falls_back() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"xboxupd.bin", {0x00, 0x01}}});
        write_file(f.root / "second/cf_1.bin", {0x22});
        const std::vector<fs::path> roots{f.root / "first", f.root / "second"};

        const auto detailed = FileManager::FindFileDataDetailed("cf_1.bin", roots, {},
                                                                FileManager::AssetKind::Bootloader);
        require(!detailed &&
                    detailed.error().code == FileManager::FileLookupErrorCode::InspectionFailed &&
                    detailed.error().source_path == f.root / "first/su_test" &&
                    detailed.error().root_path == f.root / "first" &&
                    detailed.error().root_index == 0 &&
                    detailed.error().source == FileManager::AssetSource::Xboxupd,
                "detailed bootloader lookup reports failed xboxupd derivation with provenance");

        const auto legacy =
            FileManager::FindFileData("cf_1.bin", roots, {}, FileManager::AssetKind::Bootloader);
        require(
            legacy && legacy->data == Bytes{0x22} && legacy->root_index == 1 &&
                legacy->source == FileManager::AssetSource::Loose,
            "legacy bootloader lookup skips failed xboxupd derivation and uses later loose data");
    }

    void test_regular_lookup_does_not_extract_unrelated_xboxupd() {
        Fixture f;
        write_stfs(f.root / "first/su_test",
                   {{"$flash_dash.xex", {0x11}}, {"xboxupd.bin", {0x00, 0x01}}}, "xboxupd.bin");
        const auto detailed = FileManager::FindFileDataDetailed("dash.xex", {f.root / "first"});
        require(
            detailed && *detailed && (*detailed)->data == Bytes{0x11} &&
                (*detailed)->source == FileManager::AssetSource::Stfs,
            "regular lookup extracts only its requested STFS entry, not unrelated xboxupd data");
    }

    void test_find_file_data_derives_bootloaders_only_on_request() {
        Fixture f;
        Bytes xboxupd(0x40, 0);
        xboxupd[0] = xboxupd[0x20] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x21] = 0x47;
        be32(xboxupd, 0x0C, 0x20);
        be32(xboxupd, 0x1C, 0x20);
        write_stfs(f.root / "first/su_test", {{"xboxupd.bin", xboxupd}});
        require(!FileManager::FindFileData("cf_1.bin", {f.root / "first"}),
                "regular lookup does not derive bootloaders");
        const auto resolved = FileManager::FindFileData("cf_1.bin", {f.root / "first"}, {},
                                                        FileManager::AssetKind::Bootloader);
        require(resolved && resolved->data == Bytes(xboxupd.begin(), xboxupd.begin() + 0x20),
                "bootloader lookup derives CF from xboxupd");
        require(resolved->source == FileManager::AssetSource::Xboxupd,
                "provenance identifies xboxupd derivation");
        require(resolved->requested_name == "cf_1.bin",
                "provenance preserves requested derived bootloader name");
        require(resolved->source_path == f.root / "first/su_test",
                "provenance identifies xboxupd package path");
    }

    void test_ini_path_priority() {
        Fixture f;
        write_stfs(f.root / "mydata/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "version/dash.xex", {2});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result.has_value(), "INI must resolve");
        require(payload(*result, "dash.xex") == Bytes{1},
                "earlier STFS wins over later loose payload");
    }

    void test_ini_later_stfs_fallback() {
        Fixture f;
        write_stfs(f.root / "mydata/su_test", {{"unrelated.bin", {1}}});
        write_stfs(f.root / "version/su_test", {{"$flash_dash.xex", {2}}});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result.has_value(), "INI must resolve");
        require(payload(*result, "dash.xex") == Bytes{2},
                "missing entries fall back to a later STFS");
    }

    void test_ini_deduplicates_and_scores_aliases() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[security]\nold\\asset.bin\n[flashfs]\nnew/ASSET.BIN\n");
        write_file(f.root / "version/old/asset.bin", {2});
        write_file(f.root / "mydata/new/ASSET.BIN", {1});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result && result->flashfs_sec.size() == 1,
                "payload aliases collapse across sections");
        require(result->flashfs_sec[0].second == Bytes{1},
                "higher priority alias replaces earlier entry");
    }

    void test_ini_preserves_bootloader_chains() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\ncf_1.bin\ncf_2.bin\ncg_1.bin\ncg_2.bin\n");
        write_file(f.root / "mydata/cf_1.bin", {1});
        write_file(f.root / "mydata/cf_2.bin", {2});
        write_file(f.root / "mydata/cg_1.bin", {3});
        write_file(f.root / "mydata/cg_2.bin", {4});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result && result->bootloaders.cf0 == Bytes{1} &&
                    result->bootloaders.cf1 == Bytes{2} && result->bootloaders.cg0 == Bytes{3} &&
                    result->bootloaders.cg1 == Bytes{4},
                "deduplication must preserve both CF/CG chains");
    }

    void test_findfiles_alias_priority() {
        Fixture f;
        write_file(f.root / "first/old/asset.bin", {1});
        write_file(f.root / "second/new/asset.bin", {2});
        const auto result = FileManager::FindFiles({"old/asset.bin", "new/asset.bin"},
                                                   {f.root / "first", f.root / "second"});
        require(result.size() == 1 && result.at("asset.bin") == f.root / "first/old/asset.bin",
                "duplicate basenames must not discard higher priority lookup paths");
    }

    void test_nosu() {
        Fixture f;
        write_stfs(f.root / "mydata/su_test", {{"$flash_dash.xex", {1}}});
        bool missing = false;
        try {
            FileManager::FindFiles({"dash.xex"}, {f.root / "mydata"}, {.nosu = true});
        } catch (const std::runtime_error&) {
            missing = true;
        }
        require(missing, "nosu must make STFS-only FindFiles entries unavailable");
        const auto result =
            FileManager::ReadIniFiles("version", "test", "test", {}, {.nosu = true});
        require(result && result->flashfs_sec.empty(),
                "nosu must skip STFS payloads in INI lookup");
        write_file(f.root / "version/dash.xex", {2});
        const auto loose = FileManager::FindFiles(
            {"dash.xex"}, {f.root / "mydata", f.root / "version"}, {.nosu = true});
        require(loose.at("dash.xex") == f.root / "version/dash.xex", "nosu retains loose fallback");
    }

    void test_nosusecurity() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[security]\nsecdata.bin\n[flashfs]\ndash.xex\nSECDATA.BIN\n");
        write_stfs(f.root / "mydata/su_test",
                   {{"$flash_dash.xex", {1}}, {"$flash_secdata.bin", {2}}});
        const auto result =
            FileManager::ReadIniFiles("version", "test", "test", {}, {.nosusecurity = true});
        require(result && result->flashfs_sec.size() == 1 &&
                    payload(*result, "dash.xex") == Bytes{1},
                "nosusecurity blocks STFS security even when also listed in flashfs");
        write_file(f.root / "version/secdata.bin", {3});
        const auto loose =
            FileManager::ReadIniFiles("version", "test", "test", {}, {.nosusecurity = true});
        require(loose && payload(*loose, "secdata.bin") == Bytes{3},
                "nosusecurity retains loose security");
        const auto paths =
            FileManager::FindFiles({"secdata.bin", "dash.xex"},
                                   {f.root / "mydata", f.root / "version"}, {.nosusecurity = true});
        require(paths.at("secdata.bin") == f.root / "version/secdata.bin" &&
                    paths.at("dash.xex") == f.root / "mydata/su_test",
                "FindFiles filters only security from STFS");
    }

    void test_nosusecurity_skips_extraction() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[security]\ncustom.bin\n[flashfs]\ndash.xex\n");
        write_stfs(f.root / "mydata/su_test",
                   {{"$flash_custom.bin", {2}}, {"$flash_dash.xex", {1}}}, "$flash_custom.bin");
        const auto result =
            FileManager::ReadIniFiles("version", "test", "test", {}, {.nosusecurity = true});
        require(
            result && payload(*result, "dash.xex") == Bytes{1},
            "skipped security content must not be extracted, even if its block chain is corrupt");
    }

    void test_explicit_roots_and_same_root_ties() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "second/dash.xex", {2});
        const auto ini = f.root / "version/_test.ini";
        const auto first =
            FileManager::ReadIniFiles(ini, "test", {f.root / "first", f.root / "second"});
        require(first && payload(*first, "dash.xex") == Bytes{1},
                "explicit first root has priority");
        const auto second =
            FileManager::ReadIniFiles(ini, "test", {f.root / "second", f.root / "first"});
        require(second && payload(*second, "dash.xex") == Bytes{2},
                "explicit root order controls the winner");
        write_file(f.root / "first/dash.xex", {3});
        const auto tied =
            FileManager::ReadIniFiles(ini, "test", {f.root / "first", f.root / "second"});
        require(tied && payload(*tied, "dash.xex") == Bytes{3},
                "loose wins over STFS in the same root");
        const auto empty = FileManager::ReadIniFiles(ini, "test", std::vector<fs::path>{});
        require(empty && empty->flashfs_sec.empty(),
                "explicit empty roots must not inject default roots");
    }

    void test_split_bootloader_priority() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\ncf_1.bin\ncg_1.bin\ncf_2.bin\ncg_2.bin\n");
        Bytes xboxupd(0x40, 0);
        xboxupd[0] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x20] = 0x43;
        xboxupd[0x21] = 0x47;
        be32(xboxupd, 0x0C, 0x20);
        be32(xboxupd, 0x1C, 0x20);
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());
        write_stfs(f.root / "mydata/su_test", {{"xboxupd.bin", xboxupd}});
        write_file(f.root / "version/cf_1.bin", {9});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result && result->bootloaders.cf0 == cf && result->bootloaders.cf1 == cf &&
                    result->bootloaders.cg0 == cg && result->bootloaders.cg1 == cg,
                "earlier STFS-derived bootloaders beat later loose files and populate both chains");
        const auto secured =
            FileManager::ReadIniFiles("version", "test", "test", {}, {.nosusecurity = true});
        require(secured && secured->bootloaders.cf0 == cf && secured->bootloaders.cg0 == cg,
                "nosusecurity must retain xboxupd bootloader splitting");
        require(!FileManager::ReadIniFiles("version", "test", "test", {}, {.nosu = true}),
                "nosu must disable derived bootloaders and preserve required-file failure");
        write_stfs(f.root / "mydata/su_test", {{"xboxupd.bin", xboxupd}, {"cf_1.bin", {4}}});
        const auto direct = FileManager::ReadIniFiles("version", "test", "test");
        require(direct && direct->bootloaders.cf0 == Bytes{4},
                "direct STFS entry wins over derived CF");
        write_file(f.root / "mydata/cf_1.bin", {5});
        const auto loose = FileManager::ReadIniFiles("version", "test", "test");
        require(loose && loose->bootloaders.cf0 == Bytes{5}, "loose bootloader wins within a root");
        const auto aliases = FileManager::FindFiles(
            {"cf", "6bl", "cf_split", "cg", "7bl", "cg_split"}, {f.root / "mydata"});
        require(aliases.size() == 6 && aliases.at("cf_split") == f.root / "mydata/su_test" &&
                    aliases.at("7bl") == f.root / "mydata/su_test",
                "FindFiles retains split bootloader aliases");
    }

    void test_missing_and_invalid_sources() {
        Fixture f;
        write_text(f.root / "first/su_broken", "not an STFS package");
        write_stfs(f.root / "second/su_test", {{"$flash_dash.xex", {2}}});
        const std::vector<fs::path> roots{f.root / "absent", f.root / "first/su_broken",
                                          f.root / "first", f.root / "second", f.root / "second"};
        const auto result = FileManager::ReadIniFiles(f.root / "version/_test.ini", "test", roots);
        require(result && result->flashfs_sec.size() == 1 &&
                    payload(*result, "dash.xex") == Bytes{2},
                "missing roots, regular-file roots, invalid packages, and repeated roots do not "
                "prevent fallback");
        require(FileManager::FindFiles({}, roots).empty(),
                "empty requested files produce empty results");
        require(!FileManager::ReadIniFiles(f.root / "missing.ini", "test", roots),
                "missing INI remains an error");
        require(!FileManager::ReadIniFiles(f.root / "version/_test.ini", "absent", roots),
                "missing section remains an error");
        bool missing = false;
        try {
            FileManager::FindFiles({"missing.bin"}, roots);
        } catch (const std::runtime_error&) {
            missing = true;
        }
        require(missing, "missing FindFiles entries remain an error");
    }

    void test_duplicate_loose_wins_over_stfs() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[flashfs]\nstfs/asset.bin\nloose/ASSET.BIN\n");
        write_stfs(f.root / "mydata/su_test", {{"$flash_asset.bin", {1}}});
        write_file(f.root / "mydata/loose/ASSET.BIN", {2});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result && result->flashfs_sec.size() == 1 &&
                    payload(*result, "asset.bin") == Bytes{2},
                "a later-listed loose alias replaces STFS of the same root using source rank");
    }

    void test_nested_bootloader_chains() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nfirst/cb_1.bin\nsecond/cb_2.bin\nfirst/cf_1.bin\nsecond/cf_2.bin\n"
                   "first/cg_1.bin\nsecond/cg_2.bin\n");
        write_file(f.root / "mydata/first/cb_1.bin", {1});
        write_file(f.root / "mydata/second/cb_2.bin", {2});
        write_file(f.root / "mydata/first/cf_1.bin", {3});
        write_file(f.root / "mydata/second/cf_2.bin", {4});
        write_file(f.root / "mydata/first/cg_1.bin", {5});
        write_file(f.root / "mydata/second/cg_2.bin", {6});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result && result->bootloaders.cb_or_a == Bytes{1} &&
                    result->bootloaders.cb_b == Bytes{2} && result->bootloaders.cf0 == Bytes{3} &&
                    result->bootloaders.cf1 == Bytes{4} && result->bootloaders.cg0 == Bytes{5} &&
                    result->bootloaders.cg1 == Bytes{6},
                "chain numbering must follow bootloader basenames, not their parent directories");
    }

    void test_numeric_bootloader_aliases() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\n6bl.bin\n7bl.bin\n");
        Bytes xboxupd(0x40, 0);
        xboxupd[0] = xboxupd[0x20] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x21] = 0x47;
        be32(xboxupd, 0x0C, 0x20);
        be32(xboxupd, 0x1C, 0x20);
        write_stfs(f.root / "mydata/su_test", {{"xboxupd.bin", xboxupd}});
        const auto result = FileManager::ReadIniFiles("version", "test", "test");
        require(result &&
                    result->bootloaders.cf0 == Bytes(xboxupd.begin(), xboxupd.begin() + 0x20) &&
                    result->bootloaders.cg0 == Bytes(xboxupd.begin() + 0x20, xboxupd.end()),
                "numeric bootloader aliases with extensions must populate CF and CG slots");
        write_text(f.root / "version/_test.ini",
                   "[testbl]\ncf_1.bin\ncg_1.bin\n6bl.bin\n7bl.bin\n");
        write_file(f.root / "mydata/cf_1.bin", {1});
        write_file(f.root / "mydata/cg_1.bin", {2});
        const auto mixed = FileManager::ReadIniFiles("version", "test", "test");
        require(mixed && mixed->bootloaders.cf0 == Bytes{1} && mixed->bootloaders.cg0 == Bytes{2} &&
                    mixed->bootloaders.cf1 == Bytes(xboxupd.begin(), xboxupd.begin() + 0x20) &&
                    mixed->bootloaders.cg1 == Bytes(xboxupd.begin() + 0x20, xboxupd.end()),
                 "numeric aliases must share chain numbering with their CF/CG families");
    }

    void test_ini_recognizes_sc_and_3bl_bootloaders() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\nfirmware/sc_1.bin\n");
        write_file(f.root / "mydata/firmware/sc_1.bin", {0x53, 0x43, 0x01});
        const auto sc = FileManager::ReadIniFiles("version", "test", "test");
        require(sc && sc->bootloaders.sc == Bytes({0x53, 0x43, 0x01}),
                "SC-family INI entry populates the SC bootloader slot");

        write_text(f.root / "version/_test.ini", "[testbl]\n3bl.bin\n");
        write_file(f.root / "mydata/3bl.bin", {0x33, 0x42, 0x4C});
        const auto numeric = FileManager::ReadIniFiles("version", "test", "test");
        require(numeric && numeric->bootloaders.sc == Bytes({0x33, 0x42, 0x4C}),
                "3BL INI alias populates the SC bootloader slot");
    }

    void test_ini_rejects_unconfined_asset_paths() {
        const std::vector<std::string> invalid_paths{
            "../outside/cb_1.bin", "nested/../cb_1.bin", "/outside/cb_1.bin",
            "C:\\outside\\cb_1.bin", "C:cb_1.bin", "\\\\server\\share\\cb_1.bin"};
        for (const auto& path : invalid_paths) {
            Fixture f;
            write_text(f.root / "version/_test.ini", "[testbl]\n" + path + "\n");
            write_file(f.root / "outside/cb_1.bin", {0x01});
            write_stfs(f.root / "mydata/su_test", {{"cb_1.bin", {0x02}}});
            require(!FileManager::ReadIniFiles("version", "test", "test"),
                    "unconfined INI bootloader path cannot escape or fall through to STFS");
            require(!FileManager::FindFileData(path, {f.root / "mydata"}),
                    "legacy byte lookup also rejects an unsafe name before STFS fallback");
            const auto detailed = FileManager::FindFileDataDetailed(path, {f.root / "mydata"});
            require(!detailed && detailed.error().code ==
                                     FileManager::FileLookupErrorCode::InspectionFailed,
                    "detailed lookup reports an unsafe name as an inspection failure");
            write_text(f.root / "version/_test.ini", "[testbl]\nnone\n[flashfs]\n" + path + "\n");
            require(!FileManager::ReadIniFiles("version", "test", "test"),
                    "unsafe payload paths reject the INI instead of becoming optional missing data");
        }
    }

    void test_ini_rejects_symlink_escape_and_keeps_safe_nested_paths() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\nnested/cb_1.bin\n");
        write_file(f.root / "mydata/nested/cb_1.bin", {0x11});
        const auto nested = FileManager::ReadIniFiles("version", "test", "test");
        require(nested && nested->bootloaders.cb_or_a == Bytes({0x11}),
                "safe nested INI path resolves within a source root");

        write_text(f.root / "version/_test.ini", "[testbl]\nlinked/cb_1.bin\n");
        write_file(f.root / "outside/cb_1.bin", {0x22});
        std::error_code ec;
        fs::create_directory_symlink(f.root / "outside", f.root / "mydata/linked", ec);
        if (ec) {
            std::cout << "SKIP: directory symlink unavailable: " << ec.message() << '\n';
            return;
        }
        write_stfs(f.root / "mydata/su_test", {{"cb_1.bin", {0x33}}});
        require(!FileManager::ReadIniFiles("version", "test", "test"),
                "symlink escape cannot fall through to a same-basename STFS entry");
    }

    void test_stfs_caching_and_cache_clearing() {
        Fixture f;
        Bytes xboxupd(0x40, 0);
        xboxupd[0] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x20] = 0x43;
        xboxupd[0x21] = 0x47;
        be32(xboxupd, 0x0C, 0x20);
        be32(xboxupd, 0x1C, 0x20);
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());

        write_stfs(f.root / "mydata/su_test",
                   {{"$flash_dash.xex", {0x10}}, {"xboxupd.bin", xboxupd}});

        const std::vector<fs::path> roots{f.root / "mydata"};

        // First lookups populate cache
        const auto resolved_file1 = FileManager::FindFileDataDetailed("dash.xex", roots);
        require(resolved_file1 && *resolved_file1 && (*resolved_file1)->data == Bytes{0x10},
                "first lookup retrieves file and caches package");

        const auto resolved_cf1 = FileManager::FindFileDataDetailed(
            "cf_1.bin", roots, {}, FileManager::AssetKind::Bootloader);
        require(resolved_cf1 && *resolved_cf1 && (*resolved_cf1)->data == cf,
                "first bootloader lookup derives CF and caches split parts");

        const auto resolved_cg1 = FileManager::FindFileDataDetailed(
            "cg_1.bin", roots, {}, FileManager::AssetKind::Bootloader);
        require(resolved_cg1 && *resolved_cg1 && (*resolved_cg1)->data == cg,
                "second bootloader lookup reuses cached split parts");

        // Subsequent lookups hit cache
        const auto resolved_file2 = FileManager::FindFileDataDetailed("dash.xex", roots);
        require(resolved_file2 && *resolved_file2 && (*resolved_file2)->data == Bytes{0x10},
                "cached lookup returns identical data");

        // Clear cache and verify re-reading works
        FileManager::ClearStfsCache();
        const auto resolved_after_clear = FileManager::FindFileDataDetailed("dash.xex", roots);
        require(resolved_after_clear && *resolved_after_clear &&
                    (*resolved_after_clear)->data == Bytes{0x10},
                "lookup after ClearStfsCache repopulates cache successfully");

        // Overwrite file on disk and verify disk cache auto-invalidates
        write_stfs(f.root / "mydata/su_test", {{"$flash_dash.xex", {0x99}}});
        const auto resolved_after_modify = FileManager::FindFileDataDetailed("dash.xex", roots);
        require(resolved_after_modify && *resolved_after_modify &&
                    (*resolved_after_modify)->data == Bytes{0x99},
                "modifying STFS package on disk invalidates cache and returns fresh data");
    }

    void test_in_memory_stfs_without_path() {
        const Bytes pkg_data = make_stfs_bytes({{"$flash_dash.xex", {0x42}}});
        FileManager::ScanOptions options;
        options.in_memory_stfs.push_back({"embedded_su", pkg_data});

        // Search with empty roots (no paths at all!)
        const std::vector<fs::path> empty_roots{};
        const auto detailed = FileManager::FindFileDataDetailed("dash.xex", empty_roots, options);
        require(detailed.has_value() && *detailed, "in-memory STFS asset found with empty roots");
        require((*detailed)->requested_name == "dash.xex", "preserves requested name");
        require((*detailed)->source_path.empty(), "source_path must be empty for in-memory STFS");
        require((*detailed)->data == Bytes{0x42}, "correct bytes returned from in-memory STFS");
        require((*detailed)->root_index == 0, "root_index indicates in-memory package index");
        require((*detailed)->source == FileManager::AssetSource::Stfs,
                "source identifies as AssetSource::Stfs");

        // Legacy FindFileData also works with in-memory STFS
        const auto legacy = FileManager::FindFileData("dash.xex", empty_roots, options);
        require(legacy.has_value() && legacy->data == Bytes{0x42} && legacy->source_path.empty() &&
                    legacy->source == FileManager::AssetSource::Stfs,
                "legacy FindFileData accepts in-memory STFS without a path");
    }

    void test_in_memory_stfs_bootloader_derivation() {
        Bytes xboxupd(0x40, 0);
        xboxupd[0] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x20] = 0x43;
        xboxupd[0x21] = 0x47;
        be32(xboxupd, 0x0C, 0x20);
        be32(xboxupd, 0x1C, 0x20);
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());

        const Bytes pkg_data = make_stfs_bytes({{"xboxupd.bin", xboxupd}});
        FileManager::ScanOptions options;
        options.in_memory_stfs.push_back({"embedded_update", pkg_data});

        const std::vector<fs::path> empty_roots{};
        const auto cf_res = FileManager::FindFileDataDetailed(
            "cf_1.bin", empty_roots, options, FileManager::AssetKind::Bootloader);
        require(cf_res && *cf_res && (*cf_res)->data == cf,
                "in-memory STFS derives CF from xboxupd");
        require((*cf_res)->source_path.empty(), "derived CF source_path is empty");
        require((*cf_res)->source == FileManager::AssetSource::Xboxupd,
                "derived CF source is Xboxupd");

        const auto cg_res = FileManager::FindFileDataDetailed(
            "cg_1.bin", empty_roots, options, FileManager::AssetKind::Bootloader);
        require(cg_res && *cg_res && (*cg_res)->data == cg,
                "in-memory STFS derives CG from xboxupd");
        require((*cg_res)->source_path.empty(), "derived CG source_path is empty");
    }

    void test_in_memory_stfs_priority_and_flags() {
        Fixture f;
        const Bytes mem_data = make_stfs_bytes(
            {{"$flash_dash.xex", {0x99}}, {"$flash_secdata.bin", {0x77}}});
        FileManager::ScanOptions options;
        options.in_memory_stfs.push_back({"embedded_su", mem_data});

        write_file(f.root / "first/dash.xex", {0x11});
        write_file(f.root / "first/secdata.bin", {0x22});
        const std::vector<fs::path> roots{f.root / "first"};

        // In-memory package beats disk loose file
        const auto detailed = FileManager::FindFileDataDetailed("dash.xex", roots, options);
        require(detailed && *detailed && (*detailed)->data == Bytes{0x99} &&
                    (*detailed)->source_path.empty(),
                "in-memory STFS package has priority over disk roots");

        // nosu skips in-memory STFS
        auto nosu_options = options;
        nosu_options.nosu = true;
        const auto nosu_res = FileManager::FindFileDataDetailed("dash.xex", roots, nosu_options);
        require(nosu_res && *nosu_res && (*nosu_res)->data == Bytes{0x11} &&
                    (*nosu_res)->source_path == f.root / "first/dash.xex",
                "nosu skips in-memory STFS package and falls back to disk");

        // nosusecurity skips security files from in-memory STFS
        auto nosusec_options = options;
        nosusec_options.nosusecurity = true;
        const auto sec_res =
            FileManager::FindFileDataDetailed("secdata.bin", roots, nosusec_options);
        require(sec_res && *sec_res && (*sec_res)->data == Bytes{0x22} &&
                    (*sec_res)->source_path == f.root / "first/secdata.bin",
                "nosusecurity excludes security files from in-memory STFS");

        // ReadIniFiles with in-memory STFS
        write_text(f.root / "version/_test.ini", "[testbl]\nnone\n[flashfs]\ndash.xex\n");
        const auto ini_res = FileManager::ReadIniFiles("version", "test", "test", {}, options);
        require(ini_res && payload(*ini_res, "dash.xex") == Bytes{0x99},
                "ReadIniFiles resolves payload from in-memory STFS");
    }

} // namespace

int main() {
    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"FindFiles priority", test_findfiles_priority},
        {"FindFileData priority and kind", test_find_file_data_priority_and_kind},
        {"FindFileData optional and loose priority",
         test_find_file_data_optional_and_loose_priority},
        {"FindFileData detailed errors",
         test_find_file_data_detailed_distinguishes_missing_and_inspection_failure},
        {"FindFileData detailed priority", test_find_file_data_detailed_preserves_root_priority},
        {"FindFileData strict STFS error and tolerant fallback",
         test_detailed_stfs_failure_is_terminal_but_legacy_lookup_falls_back},
        {"FindFileData strict xboxupd error and tolerant fallback",
         test_detailed_xboxupd_failure_is_terminal_but_legacy_lookup_falls_back},
        {"FindFileData regular lookup skips unrelated xboxupd extraction",
         test_regular_lookup_does_not_extract_unrelated_xboxupd},
        {"FindFileData bootloader derivation",
         test_find_file_data_derives_bootloaders_only_on_request},
        {"INI path priority", test_ini_path_priority},
        {"INI later STFS fallback", test_ini_later_stfs_fallback},
        {"INI deduplication", test_ini_deduplicates_and_scores_aliases},
        {"INI bootloader chains", test_ini_preserves_bootloader_chains},
        {"FindFiles alias priority", test_findfiles_alias_priority},
        {"nosu", test_nosu},
        {"nosusecurity", test_nosusecurity},
        {"nosusecurity skips extraction", test_nosusecurity_skips_extraction},
        {"explicit roots and ties", test_explicit_roots_and_same_root_ties},
        {"split bootloader priority", test_split_bootloader_priority},
        {"missing and invalid sources", test_missing_and_invalid_sources},
        {"duplicate loose wins over STFS", test_duplicate_loose_wins_over_stfs},
        {"nested bootloader chains", test_nested_bootloader_chains},
        {"numeric bootloader aliases", test_numeric_bootloader_aliases},
        {"INI recognizes SC and 3BL", test_ini_recognizes_sc_and_3bl_bootloaders},
        {"INI rejects unconfined paths", test_ini_rejects_unconfined_asset_paths},
        {"INI rejects symlink escapes and keeps nested paths",
         test_ini_rejects_symlink_escape_and_keeps_safe_nested_paths},
        {"STFS caching and cache clearing", test_stfs_caching_and_cache_clearing},
        {"in-memory STFS without path", test_in_memory_stfs_without_path},
        {"in-memory STFS bootloader derivation", test_in_memory_stfs_bootloader_derivation},
        {"in-memory STFS priority and flags", test_in_memory_stfs_priority_and_flags},
    };
    int failed = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch (const std::exception& e) {
            std::cerr << "FAIL: " << name << ": " << e.what() << '\n';
            ++failed;
        }
    }
    return failed == 0 ? 0 : 1;
}
