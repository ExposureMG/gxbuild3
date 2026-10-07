// src/utils/FileManager.hpp: bootloaders. A bootloader lookup (AssetKind::Bootloader) may derive
// CF and CG from a package's xboxupd.bin, only for the package's own release; read_ini_files
// places the [<section>bl] entries into the boot chain (CB/CB_B, SC, CD, CE), the two CF/CG patch
// slots and, for JTAG only, the extra CB and CD, numbering chains by basename.

#include "Args.hpp"
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

        class FileManagerBootloader : public FileManagerTest {};

        TEST_F(FileManagerBootloader, DerivesBootloadersOnlyOnRequest) {
            const Bytes xboxupd = make_xboxupd();
            write_stfs("first/su_test", {{"xboxupd.bin", xboxupd}});
            ASSERT_OK_AND_ASSIGN(const auto regular,
                                 find_file_data_detailed("cf_1.bin", {root() / "first"}));
            EXPECT_FALSE(regular.has_value()) << "regular lookup does not derive bootloaders";

            ASSERT_OK_AND_ASSIGN(
                const auto resolved,
                find_file_data_detailed("cf_1.bin", {root() / "first"}, {}, AssetKind::Bootloader));
            ASSERT_TRUE(resolved.has_value()) << "bootloader lookup derives CF from xboxupd";
            EXPECT_EQ(resolved->data, xboxupd_cf(xboxupd))
                << "bootloader lookup derives CF from xboxupd";
            EXPECT_EQ(resolved->source, AssetSource::Xboxupd)
                << "provenance identifies xboxupd derivation";
            EXPECT_EQ(resolved->requested_name, "cf_1.bin")
                << "provenance preserves requested derived bootloader name";
            EXPECT_EQ(resolved->source_path, root() / "first/su_test")
                << "provenance identifies xboxupd package path";
        }

        TEST_F(FileManagerBootloader, IniPreservesBothCfCgChains) {
            write("version/_test.ini", "[testbl]\ncf_1.bin\ncf_2.bin\ncg_1.bin\ncg_2.bin\n");
            write("mydata/cf_1.bin", Bytes{1});
            write("mydata/cf_2.bin", Bytes{2});
            write("mydata/cg_1.bin", Bytes{3});
            write("mydata/cg_2.bin", Bytes{4});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "deduplication must preserve both CF/CG chains";
            const auto& bl = result->bootloaders;
            EXPECT_EQ(bl.cf0, Bytes{1}) << "deduplication must preserve both CF/CG chains";
            EXPECT_EQ(bl.cf1, Bytes{2}) << "deduplication must preserve both CF/CG chains";
            EXPECT_EQ(bl.cg0, Bytes{3}) << "deduplication must preserve both CF/CG chains";
            EXPECT_EQ(bl.cg1, Bytes{4}) << "deduplication must preserve both CF/CG chains";
        }

        TEST_F(FileManagerBootloader, IniJtagSeparatesExtraBootloaders) {
            write("version/_test.ini", "[testbl]\n"
                                       "cb_4558.bin,57dba8ff\n"
                                       "cd_4558.bin,3286f409\n"
                                       "ce_1888.bin,ff9b60df\n"
                                       "cf_4532.bin,d28ef722\n"
                                       "cg_4532.bin,2530f8ce\n"
                                       "cb_4579.bin,a504b0f1\n"
                                       "cd_8453.bin,25e0acd0\n"
                                       "cf_17559.bin,0883e155\n"
                                       "cg_17559.bin,10fbc84d\n");
            write("mydata/cb_4558.bin", Bytes{0x01});
            write("mydata/cd_4558.bin", Bytes{0x02});
            write("mydata/ce_1888.bin", Bytes{0x03});
            write("mydata/cf_4532.bin", Bytes{0x04});
            write("mydata/cg_4532.bin", Bytes{0x05});
            write("mydata/cb_4579.bin", Bytes{0x06});
            write("mydata/cd_8453.bin", Bytes{0x07});
            write("mydata/cf_17559.bin", Bytes{0x08});
            write("mydata/cg_17559.bin", Bytes{0x09});

            const auto result = read_ini_files("version", "test", "test", {}, {}, BuildType::Jtag);
            ASSERT_OK(result) << "JTAG INI must resolve";
            const auto& bl = result->bootloaders;
            EXPECT_EQ(bl.cb_or_a, Bytes{0x01}) << "first CB is the boot-chain CB";
            EXPECT_EQ(bl.cd, Bytes{0x02}) << "first CD is the boot-chain CD";
            EXPECT_EQ(bl.ce, Bytes{0x03}) << "CE is the boot-chain CE";
            EXPECT_EQ(bl.cf0, Bytes{0x04}) << "first CF/CG pair is patch slot 0";
            EXPECT_EQ(bl.cg0, Bytes{0x05}) << "first CF/CG pair is patch slot 0";
            EXPECT_EQ(bl.cf1, Bytes{0x08}) << "second CF/CG pair is patch slot 1";
            EXPECT_EQ(bl.cg1, Bytes{0x09}) << "second CF/CG pair is patch slot 1";
            EXPECT_FALSE(bl.cb_b.has_value()) << "JTAG second CB must not become CB_B";
            EXPECT_EQ(bl.extra_cb, Bytes{0x06}) << "second CB is the JTAG extra bootloader";
            EXPECT_EQ(bl.extra_cd, Bytes{0x07}) << "second CD is the JTAG extra bootloader";
        }

        TEST_F(FileManagerBootloader, IniNonJtagLeavesExtraBootloadersEmpty) {
            write("version/_test.ini", "[testbl]\n"
                                       "cba_5772.bin,6cb45431\n"
                                       "cbb_5772.bin,7a62ed25\n"
                                       "cd_9452.bin,231d513c\n"
                                       "ce_1888.bin,ff9b60df\n"
                                       "cf_17559.bin,0883e155\n"
                                       "cg_17559.bin,10fbc84d\n");
            write("mydata/cba_5772.bin", Bytes{0xA1});
            write("mydata/cbb_5772.bin", Bytes{0xA2});
            write("mydata/cd_9452.bin", Bytes{0xA3});
            write("mydata/ce_1888.bin", Bytes{0xA4});
            write("mydata/cf_17559.bin", Bytes{0xA5});
            write("mydata/cg_17559.bin", Bytes{0xA6});

            const auto result =
                read_ini_files("version", "test", "test", {}, {}, BuildType::Glitch2);
            ASSERT_OK(result) << "glitch2 INI must resolve";
            const auto& bl = result->bootloaders;
            EXPECT_EQ(bl.cb_or_a, Bytes{0xA1}) << "CBA/CBB map to cb_or_a/cb_b";
            EXPECT_EQ(bl.cb_b, Bytes{0xA2}) << "CBA/CBB map to cb_or_a/cb_b";
            EXPECT_EQ(bl.cd, Bytes{0xA3}) << "CD/CE map to the boot chain";
            EXPECT_EQ(bl.ce, Bytes{0xA4}) << "CD/CE map to the boot chain";
            EXPECT_EQ(bl.cf0, Bytes{0xA5}) << "CF/CG map to patch slot 0";
            EXPECT_EQ(bl.cg0, Bytes{0xA6}) << "CF/CG map to patch slot 0";
            EXPECT_FALSE(bl.extra_cb.has_value())
                << "non-JTAG builds never populate extra bootloaders";
            EXPECT_FALSE(bl.extra_cd.has_value())
                << "non-JTAG builds never populate extra bootloaders";
        }

        TEST_F(FileManagerBootloader, IniNonJtagSecondCbStaysCbB) {
            // Synthetic: a non-JTAG INI with two plain cb_ files keeps the historical
            // mapping (second cb_ -> CB_B). This is the branch the JTAG gate protects.
            write("version/_test.ini", "[testbl]\ncb_1.bin\ncd_1.bin\ncb_2.bin\n");
            write("mydata/cb_1.bin", Bytes{0x11});
            write("mydata/cd_1.bin", Bytes{0x22});
            write("mydata/cb_2.bin", Bytes{0x33});

            const auto result =
                read_ini_files("version", "test", "test", {}, {}, BuildType::Glitch2);
            ASSERT_OK(result) << "glitch INI must resolve";
            const auto& bl = result->bootloaders;
            EXPECT_EQ(bl.cb_or_a, Bytes{0x11}) << "first CB stays the boot-chain CB";
            EXPECT_EQ(bl.cb_b, Bytes{0x33}) << "second CB stays CB_B for non-JTAG";
            EXPECT_FALSE(bl.extra_cb.has_value())
                << "non-JTAG builds never populate extra bootloaders";
            EXPECT_FALSE(bl.extra_cd.has_value())
                << "non-JTAG builds never populate extra bootloaders";
            EXPECT_EQ(bl.cd, Bytes{0x22}) << "single CD is the boot-chain CD";
        }

        TEST_F(FileManagerBootloader, EarlierStfsDerivedPartsBeatLaterLooseFilesAndAliasesFollow) {
            write("version/_test.ini", "[testbl]\ncf_1.bin\ncg_1.bin\ncf.bin\ncg.bin\n");
            const Bytes xboxupd = make_xboxupd();
            const Bytes cf = xboxupd_cf(xboxupd);
            const Bytes cg = xboxupd_cg(xboxupd);
            write_stfs("mydata/su_test", {{"xboxupd.bin", xboxupd}});
            write("version/cf_1.bin", Bytes{9});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "earlier STFS-derived bootloaders beat later loose files and "
                                 "populate both chains";
            EXPECT_EQ(result->bootloaders.cf0, cf)
                << "earlier STFS-derived bootloaders beat later loose files and populate both "
                   "chains";
            EXPECT_EQ(result->bootloaders.cf1, cf)
                << "earlier STFS-derived bootloaders beat later loose files and populate both "
                   "chains";
            EXPECT_EQ(result->bootloaders.cg0, cg)
                << "earlier STFS-derived bootloaders beat later loose files and populate both "
                   "chains";
            EXPECT_EQ(result->bootloaders.cg1, cg)
                << "earlier STFS-derived bootloaders beat later loose files and populate both "
                   "chains";

            const auto secured =
                read_ini_files("version", "test", "test", {}, {.nosusecurity = true});
            ASSERT_OK(secured) << "nosusecurity must retain xboxupd bootloader splitting";
            EXPECT_EQ(secured->bootloaders.cf0, cf)
                << "nosusecurity must retain xboxupd bootloader splitting";
            EXPECT_EQ(secured->bootloaders.cg0, cg)
                << "nosusecurity must retain xboxupd bootloader splitting";
            EXPECT_FALSE(read_ini_files("version", "test", "test", {}, {.nosu = true}).has_value())
                << "nosu must disable derived bootloaders and preserve required-file failure";

            write_stfs("mydata/su_test", {{"xboxupd.bin", xboxupd}, {"cf_1.bin", {4}}});
            const auto direct = read_ini_files("version", "test", "test");
            ASSERT_OK(direct) << "direct STFS entry wins over derived CF";
            EXPECT_EQ(direct->bootloaders.cf0, Bytes{4})
                << "direct STFS entry wins over derived CF";

            write("mydata/cf_1.bin", Bytes{5});
            const auto loose = read_ini_files("version", "test", "test");
            ASSERT_OK(loose) << "loose bootloader wins within a root";
            EXPECT_EQ(loose->bootloaders.cf0, Bytes{5}) << "loose bootloader wins within a root";

            for (const auto* alias : {"cf", "6bl", "cf_split", "cg", "7bl", "cg_split"}) {
                SCOPED_TRACE(alias);
                ASSERT_OK_AND_ASSIGN(
                    const auto part,
                    find_file_data_detailed(alias, {root() / "mydata"}, {}, AssetKind::Bootloader));
                ASSERT_TRUE(part.has_value())
                    << "split bootloader aliases resolve to the package's xboxupd";
                EXPECT_EQ(part->source_path, root() / "mydata/su_test")
                    << "split bootloader aliases resolve to the package's xboxupd";
                EXPECT_EQ(part->source, AssetSource::Xboxupd)
                    << "split bootloader aliases resolve to the package's xboxupd";
            }
        }

        TEST_F(FileManagerBootloader, VersionedBootloaderSkipsOtherReleaseXboxupd) {
            const Bytes xboxupd = make_xboxupd(17559);
            const Bytes cf = xboxupd_cf(xboxupd);
            const Bytes cg = xboxupd_cg(xboxupd);
            write_stfs("version/su_test", {{"xboxupd.bin", xboxupd}});
            write("common/cf_4532.bin", Bytes{0x45});
            write("common/cg_4532.bin", Bytes{0x46});
            const std::vector<fs::path> roots{root() / "version", root() / "common"};

            ASSERT_OK_AND_ASSIGN(
                const auto legacy,
                find_file_data_detailed("cf_4532.bin", roots, {}, AssetKind::Bootloader));
            ASSERT_TRUE(legacy.has_value())
                << "a CF naming another release is not answered from the package's xboxupd";
            EXPECT_EQ(legacy->data, Bytes{0x45})
                << "a CF naming another release is not answered from the package's xboxupd";
            EXPECT_EQ(legacy->root_index, 1u)
                << "a CF naming another release is not answered from the package's xboxupd";
            EXPECT_EQ(legacy->source, AssetSource::Loose)
                << "a CF naming another release is not answered from the package's xboxupd";

            const auto detailed =
                find_file_data_detailed("cg_4532.bin", roots, {}, AssetKind::Bootloader);
            ASSERT_OK(detailed)
                << "a CG naming another release is not answered from the package's xboxupd";
            ASSERT_TRUE(detailed->has_value())
                << "a CG naming another release is not answered from the package's xboxupd";
            EXPECT_EQ((*detailed)->data, Bytes{0x46})
                << "a CG naming another release is not answered from the package's xboxupd";
            EXPECT_EQ((*detailed)->source, AssetSource::Loose)
                << "a CG naming another release is not answered from the package's xboxupd";

            const auto own =
                find_file_data_detailed("cf_17559.bin", roots, {}, AssetKind::Bootloader);
            ASSERT_OK(own) << "a CF naming the package's own release comes from its xboxupd";
            ASSERT_TRUE(own->has_value())
                << "a CF naming the package's own release comes from its xboxupd";
            EXPECT_EQ((*own)->data, cf)
                << "a CF naming the package's own release comes from its xboxupd";
            EXPECT_EQ((*own)->source, AssetSource::Xboxupd)
                << "a CF naming the package's own release comes from its xboxupd";

            const auto absent =
                find_file_data_detailed("cf_17489.bin", roots, {}, AssetKind::Bootloader);
            ASSERT_OK(absent) << "a release no source supplies is reported absent";
            EXPECT_FALSE(absent->has_value()) << "a release no source supplies is reported absent";

            EXPECT_EQ(legacy->source_path, root() / "common/cf_4532.bin")
                << "the lookup resolves CF requests by release";
            ASSERT_OK_AND_ASSIGN(
                const auto own_again,
                find_file_data_detailed("cf_17559.bin", roots, {}, AssetKind::Bootloader));
            ASSERT_TRUE(own_again.has_value()) << "the lookup resolves CF requests by release";
            EXPECT_EQ(own_again->source_path, root() / "version/su_test")
                << "the lookup resolves CF requests by release";

            ScanOptions in_memory;
            in_memory.in_memory_stfs.push_back(
                {"versioned_update", make_simple_package({{"xboxupd.bin", xboxupd}})});
            const auto memory = find_file_data_detailed("cf_4532.bin", {root() / "common"},
                                                        in_memory, AssetKind::Bootloader);
            ASSERT_OK(memory) << "an in-memory package does not answer a CF naming another release";
            ASSERT_TRUE(memory->has_value())
                << "an in-memory package does not answer a CF naming another release";
            EXPECT_EQ((*memory)->data, Bytes{0x45})
                << "an in-memory package does not answer a CF naming another release";
            EXPECT_EQ((*memory)->source, AssetSource::Loose)
                << "an in-memory package does not answer a CF naming another release";

            write("version/_test.ini",
                  "[testbl]\ncf_4532.bin\ncg_4532.bin\ncf_17559.bin\ncg_17559.bin\n");
            const auto jtag =
                read_ini_files(root() / "version/_test.ini", "test", roots, {}, BuildType::Jtag);
            ASSERT_OK(jtag)
                << "a JTAG list takes its 4532 pair from disk and its 17559 pair from the package";
            EXPECT_EQ(jtag->bootloaders.cf0, Bytes{0x45})
                << "a JTAG list takes its 4532 pair from disk and its 17559 pair from the package";
            EXPECT_EQ(jtag->bootloaders.cg0, Bytes{0x46})
                << "a JTAG list takes its 4532 pair from disk and its 17559 pair from the package";
            EXPECT_EQ(jtag->bootloaders.cf1, cf)
                << "a JTAG list takes its 4532 pair from disk and its 17559 pair from the package";
            EXPECT_EQ(jtag->bootloaders.cg1, cg)
                << "a JTAG list takes its 4532 pair from disk and its 17559 pair from the package";
        }

        TEST_F(FileManagerBootloader, ChainNumberingFollowsBasenamesNotParentDirectories) {
            write("version/_test.ini",
                  "[testbl]\nfirst/cb_1.bin\nsecond/cb_2.bin\nfirst/cf_1.bin\nsecond/cf_2.bin\n"
                  "first/cg_1.bin\nsecond/cg_2.bin\n");
            write("mydata/first/cb_1.bin", Bytes{1});
            write("mydata/second/cb_2.bin", Bytes{2});
            write("mydata/first/cf_1.bin", Bytes{3});
            write("mydata/second/cf_2.bin", Bytes{4});
            write("mydata/first/cg_1.bin", Bytes{5});
            write("mydata/second/cg_2.bin", Bytes{6});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result)
                << "chain numbering must follow bootloader basenames, not their parent directories";
            const auto& bl = result->bootloaders;
            EXPECT_EQ(bl.cb_or_a, Bytes{1})
                << "chain numbering must follow bootloader basenames, not their parent directories";
            EXPECT_EQ(bl.cb_b, Bytes{2})
                << "chain numbering must follow bootloader basenames, not their parent directories";
            EXPECT_EQ(bl.cf0, Bytes{3})
                << "chain numbering must follow bootloader basenames, not their parent directories";
            EXPECT_EQ(bl.cf1, Bytes{4})
                << "chain numbering must follow bootloader basenames, not their parent directories";
            EXPECT_EQ(bl.cg0, Bytes{5})
                << "chain numbering must follow bootloader basenames, not their parent directories";
            EXPECT_EQ(bl.cg1, Bytes{6})
                << "chain numbering must follow bootloader basenames, not their parent directories";
        }

        TEST_F(FileManagerBootloader, NumericAliasesPopulateAndShareTheCfCgChains) {
            write("version/_test.ini", "[testbl]\n6bl.bin\n7bl.bin\n");
            const Bytes xboxupd = make_xboxupd();
            write_stfs("mydata/su_test", {{"xboxupd.bin", xboxupd}});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result)
                << "numeric bootloader aliases with extensions must populate CF and CG slots";
            EXPECT_EQ(result->bootloaders.cf0, xboxupd_cf(xboxupd))
                << "numeric bootloader aliases with extensions must populate CF and CG slots";
            EXPECT_EQ(result->bootloaders.cg0, xboxupd_cg(xboxupd))
                << "numeric bootloader aliases with extensions must populate CF and CG slots";

            write("version/_test.ini", "[testbl]\ncf_1.bin\ncg_1.bin\n6bl.bin\n7bl.bin\n");
            write("mydata/cf_1.bin", Bytes{1});
            write("mydata/cg_1.bin", Bytes{2});
            const auto mixed = read_ini_files("version", "test", "test");
            ASSERT_OK(mixed) << "numeric aliases must share chain numbering with their CF/CG "
                                "families";
            EXPECT_EQ(mixed->bootloaders.cf0, Bytes{1})
                << "numeric aliases must share chain numbering with their CF/CG families";
            EXPECT_EQ(mixed->bootloaders.cg0, Bytes{2})
                << "numeric aliases must share chain numbering with their CF/CG families";
            EXPECT_EQ(mixed->bootloaders.cf1, xboxupd_cf(xboxupd))
                << "numeric aliases must share chain numbering with their CF/CG families";
            EXPECT_EQ(mixed->bootloaders.cg1, xboxupd_cg(xboxupd))
                << "numeric aliases must share chain numbering with their CF/CG families";
        }

        TEST_F(FileManagerBootloader, IniRecognizesScAnd3blBootloaders) {
            write("version/_test.ini", "[testbl]\nfirmware/sc_1.bin\n");
            write("mydata/firmware/sc_1.bin", Bytes{0x53, 0x43, 0x01});
            const auto sc = read_ini_files("version", "test", "test");
            ASSERT_OK(sc) << "SC-family INI entry populates the SC bootloader slot";
            EXPECT_EQ(sc->bootloaders.sc, (Bytes{0x53, 0x43, 0x01}))
                << "SC-family INI entry populates the SC bootloader slot";

            write("version/_test.ini", "[testbl]\n3bl.bin\n");
            write("mydata/3bl.bin", Bytes{0x33, 0x42, 0x4C});
            const auto numeric = read_ini_files("version", "test", "test");
            ASSERT_OK(numeric) << "3BL INI alias populates the SC bootloader slot";
            EXPECT_EQ(numeric->bootloaders.sc, (Bytes{0x33, 0x42, 0x4C}))
                << "3BL INI alias populates the SC bootloader slot";
        }

        TEST_F(FileManagerBootloader, IniDevkitChainTakesCdAndCePositions) {
            write("version/_test.ini", "[testbl]\nSB_1.bin\nSC_1.bin\nSD_1.bin\nSE_1.bin\nnone\n");
            write("mydata/SB_1.bin", Bytes{0x53, 0x42});
            write("mydata/SC_1.bin", Bytes{0x53, 0x43});
            write("mydata/SD_1.bin", Bytes{0x53, 0x44});
            write("mydata/SE_1.bin", Bytes{0x53, 0x45});
            const auto result = read_ini_files("version", "test", "test");
            ASSERT_OK(result) << "SB, SC, SD and SE take the CB, SC, CD and CE positions";
            const auto& bl = result->bootloaders;
            EXPECT_EQ(bl.cb_or_a, (Bytes{0x53, 0x42}))
                << "SB, SC, SD and SE take the CB, SC, CD and CE positions";
            EXPECT_EQ(bl.sc, (Bytes{0x53, 0x43}))
                << "SB, SC, SD and SE take the CB, SC, CD and CE positions";
            EXPECT_EQ(bl.cd, (Bytes{0x53, 0x44}))
                << "SB, SC, SD and SE take the CB, SC, CD and CE positions";
            EXPECT_EQ(bl.ce, (Bytes{0x53, 0x45}))
                << "SB, SC, SD and SE take the CB, SC, CD and CE positions";
        }

    } // namespace
} // namespace gxbuild3::utils
