#include "utils/FileManager.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace gxbuild3;

namespace {
    namespace fs = std::filesystem;
    namespace utils = gxbuild3::utils;
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
        package[0x37B] = 1; // block_separation: read-only layout
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

    // A synthetic xboxupd.bin: a 0x20-byte CF and a 0x20-byte CG, each stating `version`.
    Bytes make_xboxupd(uint16_t version = 1) {
        Bytes xboxupd(0x40, 0);
        xboxupd[0] = xboxupd[0x20] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x21] = 0x47;
        xboxupd[2] = xboxupd[0x22] = static_cast<uint8_t>(version >> 8);
        xboxupd[3] = xboxupd[0x23] = static_cast<uint8_t>(version);
        be32(xboxupd, 0x0C, 0x20);
        be32(xboxupd, 0x1C, 0x20);
        return xboxupd;
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

    const Bytes& payload(const utils::IniFilesResult& result, std::string_view name) {
        const auto it = std::find_if(result.flashfs_sec.begin(), result.flashfs_sec.end(),
                                     [&](const auto& entry) { return entry.first == name; });
        require(it != result.flashfs_sec.end(), "expected payload must be present");
        return it->second;
    }

    // The asset a lookup that must not fail found, if any.
    std::optional<utils::ResolvedFile> found(utils::FileLookupResult result) {
        if (!result)
            throw std::runtime_error("lookup failed: " + result.error().describe());
        return std::move(*result);
    }

    void test_lookup_priority() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "second/dash.xex", {2});
        auto result = found(
            utils::find_file_data_detailed("DASH.XEX", {f.root / "first", f.root / "second"}));
        require(result && result->source_path == f.root / "first/su_test",
                "earlier STFS wins over later loose file, whatever the requested case");
        result = found(
            utils::find_file_data_detailed("dash.xex", {f.root / "second", f.root / "first"}));
        require(result && result->source_path == f.root / "second/dash.xex",
                "reversing roots changes winner");
        write_file(f.root / "first/dash.xex", {3});
        result = found(utils::find_file_data_detailed("dash.xex", {f.root / "first"}));
        require(result && result->source_path == f.root / "first/dash.xex",
                "loose wins within a root");
    }

    void test_find_file_data_priority_and_kind() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "second/dash.xex", {2});
        const auto resolved = found(
            utils::find_file_data_detailed("dash.xex", {f.root / "first", f.root / "second"}));
        require(resolved && resolved->data == Bytes{1}, "earlier STFS bytes win");
        require(resolved->source == utils::AssetSource::Stfs, "provenance identifies STFS");
        require(resolved->root_index == 0, "provenance identifies winning root");
        require(resolved->requested_name == "dash.xex", "provenance preserves requested STFS name");
        require(resolved->source_path == f.root / "first/su_test",
                "provenance identifies STFS package path");
        require(
            !found(utils::find_file_data_detailed("dash.xex", {f.root / "first"}, {.nosu = true})),
            "nosu makes STFS-only byte lookup unavailable");
    }

    void test_find_file_data_optional_and_loose_priority() {
        Fixture f;
        require(!found(utils::find_file_data_detailed("optional.bin", {f.root / "first"})),
                "missing byte lookup is optional");
        write_stfs(f.root / "first/su_test", {{"$flash_dash.xex", {1}}});
        write_file(f.root / "first/dash.xex", {2});
        const auto resolved = found(utils::find_file_data_detailed("dash.xex", {f.root / "first"}));
        require(resolved && resolved->data == Bytes{2}, "loose bytes win within a root");
        require(resolved->source == utils::AssetSource::Loose, "provenance identifies loose files");
        require(resolved->requested_name == "dash.xex",
                "provenance preserves requested loose name");
        require(resolved->source_path == f.root / "first/dash.xex",
                "provenance identifies loose file path");
    }

    void test_find_file_data_detailed_distinguishes_missing_and_inspection_failure() {
        Fixture f;
        const auto missing = utils::find_file_data_detailed("optional.bin", {f.root / "first"});
        require(missing && !*missing, "detailed lookup represents a missing asset as nullopt");

        fs::create_directories(f.root / "first/cpukey.txt");
        const auto invalid =
            utils::find_file_data_detailed("cpukey.txt", {f.root / "first", f.root / "second"});
        require(!invalid && invalid.error().code == ErrorCode::Unsupported,
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
            utils::find_file_data_detailed("dash.xex", {f.root / "first", f.root / "second"});
        require(resolved && *resolved && (*resolved)->data == Bytes{1} &&
                    (*resolved)->source == utils::AssetSource::Stfs && (*resolved)->root_index == 0,
                "detailed lookup keeps earlier-root STFS above later-root loose data");
    }

    void test_detailed_stfs_failure_is_terminal_but_ini_lookup_falls_back() {
        Fixture f;
        write_file(f.root / "first/su_corrupt", {0x00, 0x01, 0x02});
        write_file(f.root / "second/dash.xex", {0x22});
        const std::vector<fs::path> roots{f.root / "first", f.root / "second"};

        const auto detailed = utils::find_file_data_detailed("dash.xex", roots);
        require(!detailed && detailed.error().code == ErrorCode::Malformed &&
                    detailed.error().source_path == f.root / "first/su_corrupt" &&
                    detailed.error().root_path == f.root / "first" &&
                    detailed.error().root_index == 0 &&
                    detailed.error().source == utils::AssetSource::Stfs,
                "detailed lookup reports the first corrupt STFS package with exact provenance");

        const auto ini = utils::read_ini_files(f.root / "version/_test.ini", "test", roots);
        require(ini && payload(*ini, "dash.xex") == Bytes{0x22},
                "an INI lookup skips a corrupt STFS package and uses the later loose asset");
    }

    void test_detailed_xboxupd_failure_is_terminal_but_ini_lookup_falls_back() {
        Fixture f;
        write_stfs(f.root / "first/su_test", {{"xboxupd.bin", {0x00, 0x01}}});
        write_file(f.root / "second/cf_1.bin", {0x22});
        const std::vector<fs::path> roots{f.root / "first", f.root / "second"};

        const auto detailed =
            utils::find_file_data_detailed("cf_1.bin", roots, {}, utils::AssetKind::Bootloader);
        require(!detailed && detailed.error().code == ErrorCode::Truncated &&
                    detailed.error().source_path == f.root / "first/su_test" &&
                    detailed.error().root_path == f.root / "first" &&
                    detailed.error().root_index == 0 &&
                    detailed.error().source == utils::AssetSource::Xboxupd,
                "detailed bootloader lookup reports failed xboxupd derivation with provenance");

        write_text(f.root / "version/_test.ini", "[testbl]\ncf_1.bin\n");
        const auto ini = utils::read_ini_files(f.root / "version/_test.ini", "test", roots);
        require(ini && ini->bootloaders.cf0 == Bytes{0x22},
                "an INI bootloader lookup skips failed xboxupd derivation and uses later loose "
                "data");
    }

    void test_regular_lookup_does_not_extract_unrelated_xboxupd() {
        Fixture f;
        write_stfs(f.root / "first/su_test",
                   {{"$flash_dash.xex", {0x11}}, {"xboxupd.bin", {0x00, 0x01}}}, "xboxupd.bin");
        const auto detailed = utils::find_file_data_detailed("dash.xex", {f.root / "first"});
        require(
            detailed && *detailed && (*detailed)->data == Bytes{0x11} &&
                (*detailed)->source == utils::AssetSource::Stfs,
            "regular lookup extracts only its requested STFS entry, not unrelated xboxupd data");
    }

    void test_find_file_data_derives_bootloaders_only_on_request() {
        Fixture f;
        const Bytes xboxupd = make_xboxupd();
        write_stfs(f.root / "first/su_test", {{"xboxupd.bin", xboxupd}});
        require(!found(utils::find_file_data_detailed("cf_1.bin", {f.root / "first"})),
                "regular lookup does not derive bootloaders");
        const auto resolved = found(utils::find_file_data_detailed(
            "cf_1.bin", {f.root / "first"}, {}, utils::AssetKind::Bootloader));
        require(resolved && resolved->data == Bytes(xboxupd.begin(), xboxupd.begin() + 0x20),
                "bootloader lookup derives CF from xboxupd");
        require(resolved->source == utils::AssetSource::Xboxupd,
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
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result.has_value(), "INI must resolve");
        require(payload(*result, "dash.xex") == Bytes{1},
                "earlier STFS wins over later loose payload");
    }

    void test_ini_later_stfs_fallback() {
        Fixture f;
        write_stfs(f.root / "mydata/su_test", {{"unrelated.bin", {1}}});
        write_stfs(f.root / "version/su_test", {{"$flash_dash.xex", {2}}});
        const auto result = utils::read_ini_files("version", "test", "test");
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
        const auto result = utils::read_ini_files("version", "test", "test");
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
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->bootloaders.cf0 == Bytes{1} &&
                    result->bootloaders.cf1 == Bytes{2} && result->bootloaders.cg0 == Bytes{3} &&
                    result->bootloaders.cg1 == Bytes{4},
                "deduplication must preserve both CF/CG chains");
    }

    void test_ini_jtag_separates_extra_bootloaders() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\n"
                                                 "cb_4558.bin,57dba8ff\n"
                                                 "cd_4558.bin,3286f409\n"
                                                 "ce_1888.bin,ff9b60df\n"
                                                 "cf_4532.bin,d28ef722\n"
                                                 "cg_4532.bin,2530f8ce\n"
                                                 "cb_4579.bin,a504b0f1\n"
                                                 "cd_8453.bin,25e0acd0\n"
                                                 "cf_17559.bin,0883e155\n"
                                                 "cg_17559.bin,10fbc84d\n");
        write_file(f.root / "mydata/cb_4558.bin", {0x01});
        write_file(f.root / "mydata/cd_4558.bin", {0x02});
        write_file(f.root / "mydata/ce_1888.bin", {0x03});
        write_file(f.root / "mydata/cf_4532.bin", {0x04});
        write_file(f.root / "mydata/cg_4532.bin", {0x05});
        write_file(f.root / "mydata/cb_4579.bin", {0x06});
        write_file(f.root / "mydata/cd_8453.bin", {0x07});
        write_file(f.root / "mydata/cf_17559.bin", {0x08});
        write_file(f.root / "mydata/cg_17559.bin", {0x09});

        const auto result =
            utils::read_ini_files("version", "test", "test", {}, {}, BuildType::Jtag);
        require(result.has_value(), "JTAG INI must resolve");
        const auto& bl = result->bootloaders;
        require(bl.cb_or_a == Bytes{0x01}, "first CB is the boot-chain CB");
        require(bl.cd == Bytes{0x02}, "first CD is the boot-chain CD");
        require(bl.ce == Bytes{0x03}, "CE is the boot-chain CE");
        require(bl.cf0 == Bytes{0x04} && bl.cg0 == Bytes{0x05}, "first CF/CG pair is patch slot 0");
        require(bl.cf1 == Bytes{0x08} && bl.cg1 == Bytes{0x09},
                "second CF/CG pair is patch slot 1");
        require(!bl.cb_b.has_value(), "JTAG second CB must not become CB_B");
        require(bl.extra_cb == Bytes{0x06}, "second CB is the JTAG extra bootloader");
        require(bl.extra_cd == Bytes{0x07}, "second CD is the JTAG extra bootloader");
    }

    void test_ini_non_jtag_leaves_extra_bootloaders_empty() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\n"
                                                 "cba_5772.bin,6cb45431\n"
                                                 "cbb_5772.bin,7a62ed25\n"
                                                 "cd_9452.bin,231d513c\n"
                                                 "ce_1888.bin,ff9b60df\n"
                                                 "cf_17559.bin,0883e155\n"
                                                 "cg_17559.bin,10fbc84d\n");
        write_file(f.root / "mydata/cba_5772.bin", {0xA1});
        write_file(f.root / "mydata/cbb_5772.bin", {0xA2});
        write_file(f.root / "mydata/cd_9452.bin", {0xA3});
        write_file(f.root / "mydata/ce_1888.bin", {0xA4});
        write_file(f.root / "mydata/cf_17559.bin", {0xA5});
        write_file(f.root / "mydata/cg_17559.bin", {0xA6});

        const auto result =
            utils::read_ini_files("version", "test", "test", {}, {}, BuildType::Glitch2);
        require(result.has_value(), "glitch2 INI must resolve");
        const auto& bl = result->bootloaders;
        require(bl.cb_or_a == Bytes{0xA1} && bl.cb_b == Bytes{0xA2}, "CBA/CBB map to cb_or_a/cb_b");
        require(bl.cd == Bytes{0xA3} && bl.ce == Bytes{0xA4}, "CD/CE map to the boot chain");
        require(bl.cf0 == Bytes{0xA5} && bl.cg0 == Bytes{0xA6}, "CF/CG map to patch slot 0");
        require(!bl.extra_cb.has_value() && !bl.extra_cd.has_value(),
                "non-JTAG builds never populate extra bootloaders");
    }

    void test_ini_non_jtag_second_cb_stays_cb_b() {
        Fixture f;
        // Synthetic: a non-JTAG INI with two plain cb_ files keeps the historical
        // mapping (second cb_ -> CB_B). This is the branch the JTAG gate protects.
        write_text(f.root / "version/_test.ini", "[testbl]\ncb_1.bin\ncd_1.bin\ncb_2.bin\n");
        write_file(f.root / "mydata/cb_1.bin", {0x11});
        write_file(f.root / "mydata/cd_1.bin", {0x22});
        write_file(f.root / "mydata/cb_2.bin", {0x33});

        const auto result =
            utils::read_ini_files("version", "test", "test", {}, {}, BuildType::Glitch2);
        require(result.has_value(), "glitch INI must resolve");
        const auto& bl = result->bootloaders;
        require(bl.cb_or_a == Bytes{0x11}, "first CB stays the boot-chain CB");
        require(bl.cb_b == Bytes{0x33}, "second CB stays CB_B for non-JTAG");
        require(!bl.extra_cb.has_value() && !bl.extra_cd.has_value(),
                "non-JTAG builds never populate extra bootloaders");
        require(bl.cd == Bytes{0x22}, "single CD is the boot-chain CD");
    }

    void test_lookup_alias_priority() {
        Fixture f;
        write_file(f.root / "first/old/asset.bin", {1});
        write_file(f.root / "second/new/asset.bin", {2});
        const std::vector<fs::path> roots{f.root / "first", f.root / "second"};
        const auto old_alias = found(utils::find_file_data_detailed("old/asset.bin", roots));
        const auto new_alias = found(utils::find_file_data_detailed("new/asset.bin", roots));
        require(old_alias && new_alias &&
                    old_alias->source_path == f.root / "first/old/asset.bin" &&
                    new_alias->source_path == f.root / "second/new/asset.bin" &&
                    old_alias->root_index < new_alias->root_index,
                "same-basename lookup paths keep their own roots and priority");
    }

    void test_nosu() {
        Fixture f;
        write_stfs(f.root / "mydata/su_test", {{"$flash_dash.xex", {1}}});
        require(
            !found(utils::find_file_data_detailed("dash.xex", {f.root / "mydata"}, {.nosu = true})),
            "nosu must make STFS-only entries unavailable");
        const auto result = utils::read_ini_files("version", "test", "test", {}, {.nosu = true});
        require(result && result->flashfs_sec.empty(),
                "nosu must skip STFS payloads in INI lookup");
        write_file(f.root / "version/dash.xex", {2});
        const auto loose = found(utils::find_file_data_detailed(
            "dash.xex", {f.root / "mydata", f.root / "version"}, {.nosu = true}));
        require(loose && loose->source_path == f.root / "version/dash.xex",
                "nosu retains loose fallback");
    }

    void test_nosusecurity() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[security]\nsecdata.bin\n[flashfs]\ndash.xex\nSECDATA.BIN\n");
        write_stfs(f.root / "mydata/su_test",
                   {{"$flash_dash.xex", {1}}, {"$flash_secdata.bin", {2}}});
        const auto result =
            utils::read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
        require(result && result->flashfs_sec.size() == 1 &&
                    payload(*result, "dash.xex") == Bytes{1},
                "nosusecurity blocks STFS security even when also listed in flashfs");
        write_file(f.root / "version/secdata.bin", {3});
        const auto loose =
            utils::read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
        // [flashfs] is read before [security], so the file keeps its [flashfs] spelling.
        require(loose && payload(*loose, "SECDATA.BIN") == Bytes{3},
                "nosusecurity retains loose security");
        const std::vector<fs::path> roots{f.root / "mydata", f.root / "version"};
        const auto secdata =
            found(utils::find_file_data_detailed("secdata.bin", roots, {.nosusecurity = true}));
        const auto dash =
            found(utils::find_file_data_detailed("dash.xex", roots, {.nosusecurity = true}));
        require(secdata && secdata->source_path == f.root / "version/secdata.bin" && dash &&
                    dash->source_path == f.root / "mydata/su_test",
                "the lookup filters only security from STFS");
    }

    // The FlashFS lists the [flashfs] files and then the [security] files, each in INI order,
    // whatever order the INI gives the sections in (xeBuild 1.21).
    void test_flashfs_files_precede_security_files() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[security]\ncrl.bin\nsecdata.bin\n"
                   "[flashfs]\nxam.xex\naac.xexp,12345678\n");
        for (const auto* name : {"crl.bin", "secdata.bin", "xam.xex", "aac.xexp"})
            write_file(f.root / "version" / name, {1});
        const auto result = utils::read_ini_files("version", "test", "test", {});
        std::vector<std::string> names;
        if (result)
            for (const auto& file : result->flashfs_sec)
                names.push_back(file.first);
        require(names == std::vector<std::string>{"xam.xex", "aac.xexp1", "crl.bin", "secdata.bin"},
                "[flashfs] files come first, then [security] files, each in INI order");
    }

    void test_nosusecurity_skips_extraction() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[security]\ncustom.bin\n[flashfs]\ndash.xex\n");
        write_stfs(f.root / "mydata/su_test",
                   {{"$flash_custom.bin", {2}}, {"$flash_dash.xex", {1}}}, "$flash_custom.bin");
        const auto result =
            utils::read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
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
            utils::read_ini_files(ini, "test", {f.root / "first", f.root / "second"});
        require(first && payload(*first, "dash.xex") == Bytes{1},
                "explicit first root has priority");
        const auto second =
            utils::read_ini_files(ini, "test", {f.root / "second", f.root / "first"});
        require(second && payload(*second, "dash.xex") == Bytes{2},
                "explicit root order controls the winner");
        write_file(f.root / "first/dash.xex", {3});
        const auto tied = utils::read_ini_files(ini, "test", {f.root / "first", f.root / "second"});
        require(tied && payload(*tied, "dash.xex") == Bytes{3},
                "loose wins over STFS in the same root");
        const auto empty = utils::read_ini_files(ini, "test", std::vector<fs::path>{});
        require(empty && empty->flashfs_sec.empty(),
                "explicit empty roots must not inject default roots");
    }

    void test_split_bootloader_priority() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\ncf_1.bin\ncg_1.bin\ncf.bin\ncg.bin\n");
        const Bytes xboxupd = make_xboxupd();
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());
        write_stfs(f.root / "mydata/su_test", {{"xboxupd.bin", xboxupd}});
        write_file(f.root / "version/cf_1.bin", {9});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->bootloaders.cf0 == cf && result->bootloaders.cf1 == cf &&
                    result->bootloaders.cg0 == cg && result->bootloaders.cg1 == cg,
                "earlier STFS-derived bootloaders beat later loose files and populate both chains");
        const auto secured =
            utils::read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
        require(secured && secured->bootloaders.cf0 == cf && secured->bootloaders.cg0 == cg,
                "nosusecurity must retain xboxupd bootloader splitting");
        require(!utils::read_ini_files("version", "test", "test", {}, {.nosu = true}),
                "nosu must disable derived bootloaders and preserve required-file failure");
        write_stfs(f.root / "mydata/su_test", {{"xboxupd.bin", xboxupd}, {"cf_1.bin", {4}}});
        const auto direct = utils::read_ini_files("version", "test", "test");
        require(direct && direct->bootloaders.cf0 == Bytes{4},
                "direct STFS entry wins over derived CF");
        write_file(f.root / "mydata/cf_1.bin", {5});
        const auto loose = utils::read_ini_files("version", "test", "test");
        require(loose && loose->bootloaders.cf0 == Bytes{5}, "loose bootloader wins within a root");
        for (const auto* alias : {"cf", "6bl", "cf_split", "cg", "7bl", "cg_split"}) {
            const auto part = found(utils::find_file_data_detailed(alias, {f.root / "mydata"}, {},
                                                                   utils::AssetKind::Bootloader));
            require(part && part->source_path == f.root / "mydata/su_test" &&
                        part->source == utils::AssetSource::Xboxupd,
                    "split bootloader aliases resolve to the package's xboxupd");
        }
    }

    void test_missing_and_invalid_sources() {
        Fixture f;
        write_text(f.root / "first/su_broken", "not an STFS package");
        write_stfs(f.root / "second/su_test", {{"$flash_dash.xex", {2}}});
        const std::vector<fs::path> roots{f.root / "absent", f.root / "first/su_broken",
                                          f.root / "first", f.root / "second", f.root / "second"};
        const auto result = utils::read_ini_files(f.root / "version/_test.ini", "test", roots);
        require(result && result->flashfs_sec.size() == 1 &&
                    payload(*result, "dash.xex") == Bytes{2},
                "missing roots, regular-file roots, invalid packages, and repeated roots do not "
                "prevent fallback");
        require(!utils::read_ini_files(f.root / "missing.ini", "test", roots),
                "missing INI remains an error");
        require(!utils::read_ini_files(f.root / "version/_test.ini", "absent", roots),
                "missing section remains an error");
        require(!found(utils::find_file_data_detailed("missing.bin",
                                                      {f.root / "absent", f.root / "second"})),
                "a missing asset is reported absent");
        require(!utils::find_file_data_detailed("missing.bin", roots),
                "the strict lookup fails at an invalid package instead of reporting absence");
    }

    void test_duplicate_loose_wins_over_stfs() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[flashfs]\nstfs/asset.bin\nloose/ASSET.BIN\n");
        write_stfs(f.root / "mydata/su_test", {{"$flash_asset.bin", {1}}});
        write_file(f.root / "mydata/loose/ASSET.BIN", {2});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->flashfs_sec.size() == 1 &&
                    payload(*result, "asset.bin") == Bytes{2},
                "a later-listed loose alias replaces STFS of the same root using source rank");
    }

    void test_flashfs_preserves_filename_case() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[flashfs]\nSegoeXbox-Light.xtt\nMixedCase.BIN\n");
        write_file(f.root / "mydata/SegoeXbox-Light.xtt", {7});
        write_file(f.root / "mydata/MixedCase.BIN", {8});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->flashfs_sec.size() == 2,
                "both mixed-case payloads must be present");
        require(payload(*result, "SegoeXbox-Light.xtt") == Bytes{7},
                "FlashFS entry name must preserve the INI-declared mixed casing");
        require(payload(*result, "MixedCase.BIN") == Bytes{8},
                "FlashFS entry name must preserve uppercase extension casing");
    }

    void test_flashfs_appends_patch_slot_suffix() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[flashfs]\naac.xexp\nxenonclatin.xttp\nxenonclatin.xtt\n"
                   "nomni.xexp1\n");
        write_file(f.root / "mydata/aac.xexp", {1});
        write_file(f.root / "mydata/xenonclatin.xttp", {2});
        write_file(f.root / "mydata/xenonclatin.xtt", {4});
        write_file(f.root / "mydata/nomni.xexp1", {5});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->flashfs_sec.size() == 4,
                "each distinct payload must be present exactly once");
        require(payload(*result, "aac.xexp1") == Bytes{1},
                "unsuffixed .xexp payload must be stored with the slot-1 suffix");
        require(payload(*result, "xenonclatin.xttp1") == Bytes{2},
                "unsuffixed .xttp payload must be stored with the slot-1 suffix");
        require(payload(*result, "xenonclatin.xtt") == Bytes{4}, ".xtt fonts must not be suffixed");
        require(payload(*result, "nomni.xexp1") == Bytes{5},
                "already-suffixed .xexp1 payload must not be double-suffixed");
    }

    void test_flashfs_jtag_patch_slot_suffix() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[flashfs]\naac.xexp\nxenonclatin.xttp\nxenonclatin.xtt\n"
                   "nomni.xexp1\n");
        write_file(f.root / "mydata/aac.xexp", {1});
        write_file(f.root / "mydata/xenonclatin.xttp", {2});
        write_file(f.root / "mydata/xenonclatin.xtt", {4});
        write_file(f.root / "mydata/nomni.xexp1", {5});
        const auto result =
            utils::read_ini_files("version", "test", "test", {}, {}, BuildType::Jtag);
        require(result && result->flashfs_sec.size() == 4,
                "each distinct JTAG payload must be present exactly once");
        require(payload(*result, "aac.xexp2") == Bytes{1},
                "a JTAG image stores an unsuffixed .xexp payload with the two-slot suffix");
        require(payload(*result, "xenonclatin.xttp2") == Bytes{2},
                "a JTAG image stores an unsuffixed .xttp payload with the two-slot suffix");
        require(payload(*result, "xenonclatin.xtt") == Bytes{4},
                ".xtt fonts must not be suffixed on a JTAG image");
        require(payload(*result, "nomni.xexp1") == Bytes{5},
                "an already-suffixed payload keeps its suffix on a JTAG image");
    }

    void test_versioned_bootloader_skips_other_release_xboxupd() {
        Fixture f;
        const Bytes xboxupd = make_xboxupd(17559);
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());
        write_stfs(f.root / "version/su_test", {{"xboxupd.bin", xboxupd}});
        write_file(f.root / "common/cf_4532.bin", {0x45});
        write_file(f.root / "common/cg_4532.bin", {0x46});
        const std::vector<fs::path> roots{f.root / "version", f.root / "common"};

        const auto legacy = found(
            utils::find_file_data_detailed("cf_4532.bin", roots, {}, utils::AssetKind::Bootloader));
        require(legacy && legacy->data == Bytes{0x45} && legacy->root_index == 1 &&
                    legacy->source == utils::AssetSource::Loose,
                "a CF naming another release is not answered from the package's xboxupd");
        const auto detailed =
            utils::find_file_data_detailed("cg_4532.bin", roots, {}, utils::AssetKind::Bootloader);
        require(detailed && *detailed && (*detailed)->data == Bytes{0x46} &&
                    (*detailed)->source == utils::AssetSource::Loose,
                "a CG naming another release is not answered from the package's xboxupd");
        const auto own =
            utils::find_file_data_detailed("cf_17559.bin", roots, {}, utils::AssetKind::Bootloader);
        require(own && *own && (*own)->data == cf && (*own)->source == utils::AssetSource::Xboxupd,
                "a CF naming the package's own release comes from its xboxupd");
        const auto absent =
            utils::find_file_data_detailed("cf_17489.bin", roots, {}, utils::AssetKind::Bootloader);
        require(absent && !*absent, "a release no source supplies is reported absent");

        require(legacy->source_path == f.root / "common/cf_4532.bin" &&
                    found(utils::find_file_data_detailed("cf_17559.bin", roots, {},
                                                         utils::AssetKind::Bootloader))
                            .value()
                            .source_path == f.root / "version/su_test",
                "the lookup resolves CF requests by release");

        utils::ScanOptions in_memory;
        in_memory.in_memory_stfs.push_back(
            {"versioned_update", make_stfs_bytes({{"xboxupd.bin", xboxupd}})});
        const auto memory = utils::find_file_data_detailed("cf_4532.bin", {f.root / "common"},
                                                           in_memory, utils::AssetKind::Bootloader);
        require(memory && *memory && (*memory)->data == Bytes{0x45} &&
                    (*memory)->source == utils::AssetSource::Loose,
                "an in-memory package does not answer a CF naming another release");

        write_text(f.root / "version/_test.ini",
                   "[testbl]\ncf_4532.bin\ncg_4532.bin\ncf_17559.bin\ncg_17559.bin\n");
        const auto jtag =
            utils::read_ini_files(f.root / "version/_test.ini", "test", roots, {}, BuildType::Jtag);
        require(jtag && jtag->bootloaders.cf0 == Bytes{0x45} &&
                    jtag->bootloaders.cg0 == Bytes{0x46} && jtag->bootloaders.cf1 == cf &&
                    jtag->bootloaders.cg1 == cg,
                "a JTAG list takes its 4532 pair from disk and its 17559 pair from the package");
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
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->bootloaders.cb_or_a == Bytes{1} &&
                    result->bootloaders.cb_b == Bytes{2} && result->bootloaders.cf0 == Bytes{3} &&
                    result->bootloaders.cf1 == Bytes{4} && result->bootloaders.cg0 == Bytes{5} &&
                    result->bootloaders.cg1 == Bytes{6},
                "chain numbering must follow bootloader basenames, not their parent directories");
    }

    void test_numeric_bootloader_aliases() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\n6bl.bin\n7bl.bin\n");
        const Bytes xboxupd = make_xboxupd();
        write_stfs(f.root / "mydata/su_test", {{"xboxupd.bin", xboxupd}});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result &&
                    result->bootloaders.cf0 == Bytes(xboxupd.begin(), xboxupd.begin() + 0x20) &&
                    result->bootloaders.cg0 == Bytes(xboxupd.begin() + 0x20, xboxupd.end()),
                "numeric bootloader aliases with extensions must populate CF and CG slots");
        write_text(f.root / "version/_test.ini",
                   "[testbl]\ncf_1.bin\ncg_1.bin\n6bl.bin\n7bl.bin\n");
        write_file(f.root / "mydata/cf_1.bin", {1});
        write_file(f.root / "mydata/cg_1.bin", {2});
        const auto mixed = utils::read_ini_files("version", "test", "test");
        require(mixed && mixed->bootloaders.cf0 == Bytes{1} && mixed->bootloaders.cg0 == Bytes{2} &&
                    mixed->bootloaders.cf1 == Bytes(xboxupd.begin(), xboxupd.begin() + 0x20) &&
                    mixed->bootloaders.cg1 == Bytes(xboxupd.begin() + 0x20, xboxupd.end()),
                "numeric aliases must share chain numbering with their CF/CG families");
    }

    void test_ini_recognizes_sc_and_3bl_bootloaders() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\nfirmware/sc_1.bin\n");
        write_file(f.root / "mydata/firmware/sc_1.bin", {0x53, 0x43, 0x01});
        const auto sc = utils::read_ini_files("version", "test", "test");
        require(sc && sc->bootloaders.sc == Bytes({0x53, 0x43, 0x01}),
                "SC-family INI entry populates the SC bootloader slot");

        write_text(f.root / "version/_test.ini", "[testbl]\n3bl.bin\n");
        write_file(f.root / "mydata/3bl.bin", {0x33, 0x42, 0x4C});
        const auto numeric = utils::read_ini_files("version", "test", "test");
        require(numeric && numeric->bootloaders.sc == Bytes({0x33, 0x42, 0x4C}),
                "3BL INI alias populates the SC bootloader slot");
    }

    void test_ini_rejects_unconfined_asset_paths() {
        const std::vector<std::string> invalid_paths{
            "../outside/cb_1.bin",   "nested/../cb_1.bin", "/outside/cb_1.bin",
            "C:\\outside\\cb_1.bin", "C:cb_1.bin",         "\\\\server\\share\\cb_1.bin"};
        for (const auto& path : invalid_paths) {
            Fixture f;
            write_text(f.root / "version/_test.ini", "[testbl]\n" + path + "\n");
            write_file(f.root / "outside/cb_1.bin", {0x01});
            write_stfs(f.root / "mydata/su_test", {{"cb_1.bin", {0x02}}});
            require(!utils::read_ini_files("version", "test", "test"),
                    "unconfined INI bootloader path cannot escape or fall through to STFS");
            const auto detailed = utils::find_file_data_detailed(path, {f.root / "mydata"});
            require(!detailed && detailed.error().code == ErrorCode::InvalidArgument,
                    "detailed lookup rejects an unsafe name before STFS fallback");
            write_text(f.root / "version/_test.ini", "[testbl]\nnone\n[flashfs]\n" + path + "\n");
            const auto payloads = utils::read_ini_files("version", "test", "test");
            if (path.starts_with("../")) {
                // A leading ".." names a file beside the release, looked for as a loose file
                // in the roots only: the file outside them and the STFS entry are not read.
                require(payloads && payloads->flashfs_sec.empty(),
                        "a payload from outside the release is skipped, never read from "
                        "outside the roots or from STFS");
            } else {
                require(!payloads, "unsafe payload paths reject the INI instead of becoming "
                                   "optional missing data");
            }
        }
    }

    void test_ini_devkit_chain_takes_cd_and_ce_positions() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nSB_1.bin\nSC_1.bin\nSD_1.bin\nSE_1.bin\nnone\n");
        write_file(f.root / "mydata/SB_1.bin", {0x53, 0x42});
        write_file(f.root / "mydata/SC_1.bin", {0x53, 0x43});
        write_file(f.root / "mydata/SD_1.bin", {0x53, 0x44});
        write_file(f.root / "mydata/SE_1.bin", {0x53, 0x45});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->bootloaders.cb_or_a == Bytes({0x53, 0x42}) &&
                    result->bootloaders.sc == Bytes({0x53, 0x43}) &&
                    result->bootloaders.cd == Bytes({0x53, 0x44}) &&
                    result->bootloaders.ce == Bytes({0x53, 0x45}),
                "SB, SC, SD and SE take the CB, SC, CD and CE positions");
    }

    void test_ini_lookup_falls_back_to_any_case() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nsc_17489.bin\n[flashfs]\nSegoe.XTT\nexact.bin\n");
        write_file(f.root / "mydata/SC_17489.bin", {0x53, 0x43});
        write_file(f.root / "mydata/segoe.xtt", {0x07});
        write_file(f.root / "mydata/EXACT.bin", {0x01});
        write_file(f.root / "mydata/exact.bin", {0x02});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result && result->bootloaders.sc == Bytes({0x53, 0x43}),
                "a bootloader named in another case is found");
        require(payload(*result, "Segoe.XTT") == Bytes{0x07},
                "a payload named in another case is found and keeps the INI's casing");
        require(payload(*result, "exact.bin") == Bytes{0x02},
                "an exact-case file wins over one that only matches without case");
        const auto detailed = utils::find_file_data_detailed("sc_17489.bin", {f.root / "mydata"});
        require(detailed && *detailed && (**detailed).data == Bytes({0x53, 0x43}),
                "the detailed lookup falls back to any case as well");
        require(
            found(utils::find_file_data_detailed("SC_17489.BIN", {f.root / "mydata"})).has_value(),
            "an upper-case request falls back to any case as well");
    }

    void test_ini_payload_outside_release_and_rawpatch() {
        Fixture f;
        write_text(f.root / "version/_test.ini",
                   "[testbl]\nnone\n[flashfs]\n..\\data\\xell.bin,;\n..\\launch.xex,0\n"
                   "rrbkgnd.bmp ,6850A07F\nrglXam.rglp\n[rawpatch]\nvfuses_khv.bin,0xE4000\n"
                   "reason.bin,0x4E\n");
        write_file(f.root / "mydata/data/xell.bin", {0x7F, 'E'});
        write_file(f.root / "mydata/rrbkgnd.bmp", {0x42});
        write_file(f.root / "mydata/rglXam.rglp", {0x43});
        write_file(f.root / "mydata/reason.bin", {0x12});
        const auto result = utils::read_ini_files("version", "test", "test");
        require(result.has_value(), "a missing file from outside the release and a missing "
                                    "[rawpatch] file are skipped");
        require(payload(*result, "xell.bin") == Bytes({0x7F, 'E'}),
                "..\\data\\xell.bin is found under data/ in a root and stored by its basename");
        require(std::none_of(result->flashfs_sec.begin(), result->flashfs_sec.end(),
                             [](const auto& file) { return file.first == "launch.xex"; }),
                "a missing file from outside the release is left out");
        require(payload(*result, "rrbkgnd.bmp1") == Bytes{0x42},
                "a name ending in p with a checksum takes the slot suffix, as xeBuild writes it");
        require(payload(*result, "rglXam.rglp") == Bytes{0x43},
                "a name ending in p without a checksum is stored as it is");
        require(result->raw_patches.size() == 1 && result->raw_patches[0].name == "reason.bin" &&
                    result->raw_patches[0].offset == 0x4E &&
                    result->raw_patches[0].data == Bytes{0x12},
                "a [rawpatch] file is read with its offset; a missing one is skipped");

        write_text(f.root / "version/_test.ini", "[testbl]\nnone\n[rawpatch]\nreason.bin,0xZZ\n");
        require(!utils::read_ini_files("version", "test", "test"),
                "a [rawpatch] offset that does not parse rejects the INI");
    }

    void test_ini_rejects_symlink_escape_and_keeps_safe_nested_paths() {
        Fixture f;
        write_text(f.root / "version/_test.ini", "[testbl]\nnested/cb_1.bin\n");
        write_file(f.root / "mydata/nested/cb_1.bin", {0x11});
        const auto nested = utils::read_ini_files("version", "test", "test");
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
        require(!utils::read_ini_files("version", "test", "test"),
                "symlink escape cannot fall through to a same-basename STFS entry");
    }

    void test_stfs_caching_and_cache_clearing() {
        Fixture f;
        const Bytes xboxupd = make_xboxupd();
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());

        write_stfs(f.root / "mydata/su_test",
                   {{"$flash_dash.xex", {0x10}}, {"xboxupd.bin", xboxupd}});

        const std::vector<fs::path> roots{f.root / "mydata"};

        // First lookups populate cache
        const auto resolved_file1 = utils::find_file_data_detailed("dash.xex", roots);
        require(resolved_file1 && *resolved_file1 && (*resolved_file1)->data == Bytes{0x10},
                "first lookup retrieves file and caches package");

        const auto resolved_cf1 =
            utils::find_file_data_detailed("cf_1.bin", roots, {}, utils::AssetKind::Bootloader);
        require(resolved_cf1 && *resolved_cf1 && (*resolved_cf1)->data == cf,
                "first bootloader lookup derives CF and caches split parts");

        const auto resolved_cg1 =
            utils::find_file_data_detailed("cg_1.bin", roots, {}, utils::AssetKind::Bootloader);
        require(resolved_cg1 && *resolved_cg1 && (*resolved_cg1)->data == cg,
                "second bootloader lookup reuses cached split parts");

        // Subsequent lookups hit cache
        const auto resolved_file2 = utils::find_file_data_detailed("dash.xex", roots);
        require(resolved_file2 && *resolved_file2 && (*resolved_file2)->data == Bytes{0x10},
                "cached lookup returns identical data");

        // Clear cache and verify re-reading works
        utils::clear_stfs_cache();
        const auto resolved_after_clear = utils::find_file_data_detailed("dash.xex", roots);
        require(resolved_after_clear && *resolved_after_clear &&
                    (*resolved_after_clear)->data == Bytes{0x10},
                "lookup after clear_stfs_cache repopulates cache successfully");

        // Overwrite file on disk and verify disk cache auto-invalidates
        write_stfs(f.root / "mydata/su_test", {{"$flash_dash.xex", {0x99}}});
        const auto resolved_after_modify = utils::find_file_data_detailed("dash.xex", roots);
        require(resolved_after_modify && *resolved_after_modify &&
                    (*resolved_after_modify)->data == Bytes{0x99},
                "modifying STFS package on disk invalidates cache and returns fresh data");
    }

    void test_in_memory_stfs_without_path() {
        const Bytes pkg_data = make_stfs_bytes({{"$flash_dash.xex", {0x42}}});
        utils::ScanOptions options;
        options.in_memory_stfs.push_back({"embedded_su", pkg_data});

        // Search with empty roots (no paths at all!)
        const std::vector<fs::path> empty_roots{};
        const auto detailed = utils::find_file_data_detailed("dash.xex", empty_roots, options);
        require(detailed.has_value() && *detailed, "in-memory STFS asset found with empty roots");
        require((*detailed)->requested_name == "dash.xex", "preserves requested name");
        require((*detailed)->source_path.empty(), "source_path must be empty for in-memory STFS");
        require((*detailed)->data == Bytes{0x42}, "correct bytes returned from in-memory STFS");
        require((*detailed)->root_index == 0, "root_index indicates in-memory package index");
        require((*detailed)->source == utils::AssetSource::Stfs,
                "source identifies as AssetSource::Stfs");
    }

    void test_in_memory_stfs_bootloader_derivation() {
        const Bytes xboxupd = make_xboxupd();
        const Bytes cf(xboxupd.begin(), xboxupd.begin() + 0x20);
        const Bytes cg(xboxupd.begin() + 0x20, xboxupd.end());

        const Bytes pkg_data = make_stfs_bytes({{"xboxupd.bin", xboxupd}});
        utils::ScanOptions options;
        options.in_memory_stfs.push_back({"embedded_update", pkg_data});

        const std::vector<fs::path> empty_roots{};
        const auto cf_res = utils::find_file_data_detailed("cf_1.bin", empty_roots, options,
                                                           utils::AssetKind::Bootloader);
        require(cf_res && *cf_res && (*cf_res)->data == cf,
                "in-memory STFS derives CF from xboxupd");
        require((*cf_res)->source_path.empty(), "derived CF source_path is empty");
        require((*cf_res)->source == utils::AssetSource::Xboxupd, "derived CF source is Xboxupd");

        const auto cg_res = utils::find_file_data_detailed("cg_1.bin", empty_roots, options,
                                                           utils::AssetKind::Bootloader);
        require(cg_res && *cg_res && (*cg_res)->data == cg,
                "in-memory STFS derives CG from xboxupd");
        require((*cg_res)->source_path.empty(), "derived CG source_path is empty");
    }

    void test_in_memory_stfs_priority_and_flags() {
        Fixture f;
        const Bytes mem_data =
            make_stfs_bytes({{"$flash_dash.xex", {0x99}}, {"$flash_secdata.bin", {0x77}}});
        utils::ScanOptions options;
        options.in_memory_stfs.push_back({"embedded_su", mem_data});

        write_file(f.root / "first/dash.xex", {0x11});
        write_file(f.root / "first/secdata.bin", {0x22});
        const std::vector<fs::path> roots{f.root / "first"};

        // In-memory package beats disk loose file
        const auto detailed = utils::find_file_data_detailed("dash.xex", roots, options);
        require(detailed && *detailed && (*detailed)->data == Bytes{0x99} &&
                    (*detailed)->source_path.empty(),
                "in-memory STFS package has priority over disk roots");

        // nosu skips in-memory STFS
        auto nosu_options = options;
        nosu_options.nosu = true;
        const auto nosu_res = utils::find_file_data_detailed("dash.xex", roots, nosu_options);
        require(nosu_res && *nosu_res && (*nosu_res)->data == Bytes{0x11} &&
                    (*nosu_res)->source_path == f.root / "first/dash.xex",
                "nosu skips in-memory STFS package and falls back to disk");

        // nosusecurity skips security files from in-memory STFS
        auto nosusec_options = options;
        nosusec_options.nosusecurity = true;
        const auto sec_res = utils::find_file_data_detailed("secdata.bin", roots, nosusec_options);
        require(sec_res && *sec_res && (*sec_res)->data == Bytes{0x22} &&
                    (*sec_res)->source_path == f.root / "first/secdata.bin",
                "nosusecurity excludes security files from in-memory STFS");

        // read_ini_files with in-memory STFS
        write_text(f.root / "version/_test.ini", "[testbl]\nnone\n[flashfs]\ndash.xex\n");
        const auto ini_res = utils::read_ini_files("version", "test", "test", {}, options);
        require(ini_res && payload(*ini_res, "dash.xex") == Bytes{0x99},
                "read_ini_files resolves payload from in-memory STFS");
    }

    // read_file, write_file and create_directory report failures as Errors that carry the
    // path, and write_file creates missing parents.
    void test_utils_io_results() {
        Fixture f;
        const auto missing = utils::read_file(f.root / "absent.bin");
        require(!missing && missing.error().code == ErrorCode::NotFound &&
                    missing.error().message.find("absent.bin") != std::string::npos,
                "reading a missing file fails with NotFound naming the path");

        const auto nested = f.root / "out/deeper/image.bin";
        const auto written = utils::write_file(nested, {0x01, 0x02, 0x03});
        require(written.has_value(), "write_file creates missing parents and writes");
        const auto read_back = utils::read_file(nested);
        require(read_back && *read_back == Bytes{0x01, 0x02, 0x03}, "written bytes read back");
        const auto truncated = utils::read_file(nested, 2);
        require(truncated && *truncated == Bytes{0x01, 0x02}, "max_length truncates the read");

        const auto blocker = f.root / "blocker";
        write_file(blocker, {0x00});
        const auto created = utils::create_directory(blocker / "child");
        require(!created && created.error().code == ErrorCode::IoError,
                "create_directory under a regular file fails with IoError");
        const auto blocked_write = utils::write_file(blocker / "child/file.bin", {0x00});
        require(!blocked_write && !blocked_write.error().context.empty(),
                "write_file reports a parent creation failure with context");
        require(utils::create_directory(f.root / "out").has_value(),
                "create_directory on an existing directory succeeds");
    }

} // namespace

int main() {
    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"lookup priority", test_lookup_priority},
        {"find_file_data priority and kind", test_find_file_data_priority_and_kind},
        {"find_file_data optional and loose priority",
         test_find_file_data_optional_and_loose_priority},
        {"find_file_data detailed errors",
         test_find_file_data_detailed_distinguishes_missing_and_inspection_failure},
        {"find_file_data detailed priority", test_find_file_data_detailed_preserves_root_priority},
        {"find_file_data strict STFS error and tolerant INI fallback",
         test_detailed_stfs_failure_is_terminal_but_ini_lookup_falls_back},
        {"find_file_data strict xboxupd error and tolerant INI fallback",
         test_detailed_xboxupd_failure_is_terminal_but_ini_lookup_falls_back},
        {"find_file_data regular lookup skips unrelated xboxupd extraction",
         test_regular_lookup_does_not_extract_unrelated_xboxupd},
        {"find_file_data bootloader derivation",
         test_find_file_data_derives_bootloaders_only_on_request},
        {"INI path priority", test_ini_path_priority},
        {"INI later STFS fallback", test_ini_later_stfs_fallback},
        {"INI deduplication", test_ini_deduplicates_and_scores_aliases},
        {"INI bootloader chains", test_ini_preserves_bootloader_chains},
        {"INI JTAG extra bootloaders", test_ini_jtag_separates_extra_bootloaders},
        {"INI non-JTAG leaves extra bootloaders empty",
         test_ini_non_jtag_leaves_extra_bootloaders_empty},
        {"INI non-JTAG second CB stays CB_B", test_ini_non_jtag_second_cb_stays_cb_b},
        {"lookup alias priority", test_lookup_alias_priority},
        {"nosu", test_nosu},
        {"nosusecurity", test_nosusecurity},
        {"flashfs files precede security files", test_flashfs_files_precede_security_files},
        {"nosusecurity skips extraction", test_nosusecurity_skips_extraction},
        {"explicit roots and ties", test_explicit_roots_and_same_root_ties},
        {"split bootloader priority", test_split_bootloader_priority},
        {"missing and invalid sources", test_missing_and_invalid_sources},
        {"duplicate loose wins over STFS", test_duplicate_loose_wins_over_stfs},
        {"FlashFS preserves filename case", test_flashfs_preserves_filename_case},
        {"FlashFS appends patch slot suffix", test_flashfs_appends_patch_slot_suffix},
        {"FlashFS JTAG patch slot suffix", test_flashfs_jtag_patch_slot_suffix},
        {"versioned bootloader skips another release's xboxupd",
         test_versioned_bootloader_skips_other_release_xboxupd},
        {"nested bootloader chains", test_nested_bootloader_chains},
        {"numeric bootloader aliases", test_numeric_bootloader_aliases},
        {"INI recognizes SC and 3BL", test_ini_recognizes_sc_and_3bl_bootloaders},
        {"INI rejects unconfined paths", test_ini_rejects_unconfined_asset_paths},
        {"INI devkit chain positions", test_ini_devkit_chain_takes_cd_and_ce_positions},
        {"INI lookup falls back to any case", test_ini_lookup_falls_back_to_any_case},
        {"INI payload outside the release and [rawpatch]",
         test_ini_payload_outside_release_and_rawpatch},
        {"INI rejects symlink escapes and keeps nested paths",
         test_ini_rejects_symlink_escape_and_keeps_safe_nested_paths},
        {"STFS caching and cache clearing", test_stfs_caching_and_cache_clearing},
        {"in-memory STFS without path", test_in_memory_stfs_without_path},
        {"in-memory STFS bootloader derivation", test_in_memory_stfs_bootloader_derivation},
        {"in-memory STFS priority and flags", test_in_memory_stfs_priority_and_flags},
        {"Utils I/O results", test_utils_io_results},
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
