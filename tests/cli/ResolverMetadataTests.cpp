// src/cli/BuildInputResolver.hpp: the metadata and the FlashFS files. Precedence, lowest to
// highest: options.ini, the donor, each -c item; user kv.bin, smc.bin and mobile files replace
// the donor's. Only the winning source of a value is parsed (a malformed losing value is never
// seen), a value must be a whole valid string, and a refused value names the source that won
// (options.ini by path, the CLI by an empty path). A CLI pairing override also replaces the
// donor CF pairing. The FlashFS holds the INI's [flashfs] files in INI order, then [security],
// then the console's other secured files, each from the roots or else the donor; an unsupplied
// security file reaches the build as it stands, and fcrt.bin follows the INI, not the
// keyvault's flag.
//
// CliMetadataProvenance: three refused -c metadata values in loose-donor mode, each one keeps
// the CLI's empty path instead of options.ini's (bundled as Row/CliMetadataProvenance).

#include "BuildRunner.hpp"
#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/builders/Stages.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::cli {
    namespace {

        using test::Bytes;

        class ResolverMetadata : public ResolverTest {};

        TEST_F(ResolverMetadata, PrecedenceAndUserFileOverrides) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto donor, test::donor_image(ImageType::SmallBlock, key));
            write("first/nanddump.bin", donor);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            write("working/options.ini", "cbldv=7\ncfldv=8\npairing_data=010203\nnofcrt=true\n");
            write("first/kv.bin", test::encrypted_keyvault(key, 0x44));
            write("first/smc.bin", test::make_smc(0x45));
            write("first/mobileA.bin", Bytes{0xA1});
            write("first/mobileI.bin", Bytes{0xA9});

            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.image_type.reset();
            const auto donor_layered = resolve(args);
            ASSERT_OK(donor_layered) << "donor precedence fixture resolves";
            const auto& layered = donor_layered->input.metadata;
            ASSERT_EQ(layered.cb_ldv, 0)
                << "donor metadata beats options.ini while absent donor values use defaults";
            ASSERT_EQ(layered.cf_ldv, std::optional<uint8_t>{8})
                << "donor metadata beats options.ini while absent donor values use defaults";
            ASSERT_EQ(layered.pairing_data, (std::array<uint8_t, 3>{0, 0, 0}))
                << "donor metadata beats options.ini while absent donor values use defaults";

            args.config = {"cbldv=4", "cfldv=5", "pairing_data=0a0b0c", "nofcrt=false"};
            const auto result = resolve(args);
            ASSERT_OK(result) << "donor plus user overlays resolves";
            const auto& metadata = result->input.metadata;
            ASSERT_TRUE(metadata.keyvault.has_value()) << "user KV and SMC replace donor values";
            EXPECT_BYTES_EQ(test::canonical_keyvault_filled(key, 0x44), *metadata.keyvault)
                << "user KV and SMC replace donor values";
            ASSERT_TRUE(metadata.smc.has_value()) << "user KV and SMC replace donor values";
            EXPECT_BYTES_EQ(test::make_smc(0x45), *metadata.smc)
                << "user KV and SMC replace donor values";
            const auto* slot_a = result->input.mobiles.slot(0x31);
            const auto* slot_i = result->input.mobiles.slot(0x39);
            ASSERT_TRUE(slot_a != nullptr && slot_a->has_value())
                << "mobileA through mobileI map to slots 0x31 through 0x39";
            ASSERT_TRUE(slot_i != nullptr && slot_i->has_value())
                << "mobileA through mobileI map to slots 0x31 through 0x39";
            EXPECT_BYTES_EQ(Bytes{0xA1}, **slot_a)
                << "mobileA through mobileI map to slots 0x31 through 0x39";
            EXPECT_BYTES_EQ(Bytes{0xA9}, **slot_i)
                << "mobileA through mobileI map to slots 0x31 through 0x39";
            EXPECT_EQ(metadata.cb_ldv, 4) << "CLI metadata overrides donor and options.ini";
            EXPECT_EQ(metadata.cf_ldv, std::optional<uint8_t>{5})
                << "CLI metadata overrides donor and options.ini";
            EXPECT_EQ(metadata.pairing_data, (std::array<uint8_t, 3>{0x0A, 0x0B, 0x0C}))
                << "CLI metadata overrides donor and options.ini";
            EXPECT_EQ(result->input.options.nofcrt, std::optional<bool>{false})
                << "an explicit false CLI value remains present and wins";
        }

        TEST_F(ResolverMetadata, FlashFsHoldsIniFilesAndDonorSecuredFilesOnly) {
            const auto key = test::valid_cpu_key();
            Input donor{};
            donor.image_type = ImageType::SmallBlock;
            donor.metadata.cpu_key = Bytes(key.begin(), key.end());
            donor.metadata.smc = test::make_smc(0x61);
            donor.metadata.keyvault = test::canonical_keyvault_filled(key, 0x62);
            donor.bootloaders = test::valid_bootloaders();
            donor.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
                {"Launch.ini", Bytes{0x10}},        {"launch.INI", Bytes{0x11}},
                {"SECDATA.BIN", Bytes(0x20, 0x20)}, {"extended.bin", Bytes(0x20, 0x22)},
                {"crl.bin", Bytes{0x23}},           {"fcrt.bin", Bytes{0x24}},
                {"listed.bin", Bytes{0x25}},        {"donor.bin", Bytes{0x30}},
                {"aac.xexp2", Bytes{0x31}},         {"aac.xexp1", Bytes{0x32}},
                {"sysupdate.xexp2", Bytes{0x33}}};
            const auto image = run_build(donor);
            ASSERT_OK(image) << "FlashFS donor fixture builds";
            // The donor's extended.bin was the wrong length, so its image carries a clean one.
            const auto donor_files = extract_all(*image, key);
            Bytes donor_extended;
            if (donor_files && donor_files->flashfs_sec) {
                for (const auto& [name, data] : *donor_files->flashfs_sec) {
                    if (name == "extended.bin") {
                        donor_extended = data;
                    }
                }
            }
            write("first/nanddump.bin", *image);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("first/launch.ini", Bytes{0x41});
            const auto plaintext_secdata = Bytes(0x20, 0x51);
            auto encrypted_secdata = plaintext_secdata;
            ASSERT_OK(nand::crypt_secfile(key, encrypted_secdata)) << "secure fixture encrypts";
            write("first/secdata.bin", encrypted_secdata);
            write("first/new.bin", Bytes{0x61});
            write("first/aac.xexp", Bytes{0x62});
            write("working/build.ini",
                  "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsecdata.bin\nextended.bin\n"
                  "[flashfs]\nlaunch.ini\nnew.bin\nlisted.bin\naac.xexp\n");

            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.image_type.reset();
            const auto result = resolve(args);
            ASSERT_OK(result) << "INI FlashFS and security entries resolve";
            ASSERT_TRUE(result->input.flashfs_sec.has_value())
                << "resolved input has FlashFS files";
            const auto& files = *result->input.flashfs_sec;
            const auto find = [&](std::string_view name) {
                return std::find_if(files.begin(), files.end(), [name](const auto& file) {
                    std::string lower = file.first;
                    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
                        return static_cast<char>(std::tolower(c));
                    });
                    return lower == name;
                });
            };
            const auto has = [&](std::string_view name, const Bytes& contents) {
                const auto file = find(name);
                return file != files.end() && file->second == contents;
            };
            // xeBuild 1.21 order: [flashfs] in INI order, then [security] in INI order, then the
            // console's secured files the INI does not name.
            const std::array<std::string_view, 8> order{"launch.ini", "new.bin",     "listed.bin",
                                                        "aac.xexp1",  "secdata.bin", "extended.bin",
                                                        "crl.bin",    "fcrt.bin"};
            bool ordered = files.size() == order.size();
            for (size_t i = 0; ordered && i < order.size(); ++i) {
                ordered = find(order[i]) == files.begin() + static_cast<std::ptrdiff_t>(i);
            }
            EXPECT_EQ(files.size(), 8U) << "the FlashFS holds exactly the expected files";
            EXPECT_TRUE(ordered) << "the FlashFS lists [flashfs], then [security], then the "
                                    "console's other secured files";
            EXPECT_TRUE(has("launch.ini", Bytes{0x41}))
                << "an INI file from the source roots replaces the donor basename";
            EXPECT_TRUE(has("secdata.bin", plaintext_secdata))
                << "a secure INI file from the source roots arrives as plaintext";
            EXPECT_EQ(donor_extended.size(), 0x4000U)
                << "an INI security file missing from the roots comes from the donor";
            EXPECT_TRUE(has("extended.bin", donor_extended))
                << "an INI security file missing from the roots comes from the donor";
            EXPECT_TRUE(has("crl.bin", Bytes{0x23}))
                << "donor secured files are carried without an INI entry";
            EXPECT_TRUE(has("fcrt.bin", Bytes{0x24}))
                << "donor secured files are carried without an INI entry";
            EXPECT_TRUE(has("listed.bin", Bytes{0x25}))
                << "an INI file missing from the roots comes from the donor";
            EXPECT_TRUE(has("new.bin", Bytes{0x61})) << "a new INI file is added";
            EXPECT_TRUE(has("aac.xexp1", Bytes{0x62}))
                << "an INI patch file is suffixed and replaces the donor copy";
            EXPECT_TRUE(find("donor.bin") == files.end())
                << "unlisted donor files, patch files and CG tails are dropped";
            EXPECT_TRUE(find("aac.xexp2") == files.end())
                << "unlisted donor files, patch files and CG tails are dropped";
            EXPECT_TRUE(find("sysupdate.xexp2") == files.end())
                << "unlisted donor files, patch files and CG tails are dropped";
        }

        // An extended.bin or secdata.bin the INI's [security] names reaches run_build even when
        // nothing supplies it (empty) or it is too short to hold a nonce (as supplied); run_build
        // makes up a clean one for each.
        TEST_F(ResolverMetadata, UnsuppliedSecurityFilesReachTheBuild) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args());
            write("working/build.ini",
                  "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nextended.bin\nsecdata.bin\n");
            write("first/extended.bin", Bytes(5, 0x45));
            const auto result = resolve(args);
            ASSERT_OK(result) << "a build whose security files are missing resolves";
            ASSERT_TRUE(result->input.flashfs_sec.has_value())
                << "resolved input has FlashFS files";
            const auto& files = *result->input.flashfs_sec;
            ASSERT_EQ(files.size(), 2U) << "a short extended.bin is carried as supplied";
            EXPECT_EQ(files[0].first, "extended.bin")
                << "a short extended.bin is carried as supplied";
            EXPECT_BYTES_EQ(Bytes(5, 0x45), files[0].second)
                << "a short extended.bin is carried as supplied";
            EXPECT_EQ(files[1].first, "secdata.bin") << "a missing secdata.bin is carried empty";
            EXPECT_TRUE(files[1].second.empty()) << "a missing secdata.bin is carried empty";
        }

        // fcrt.bin is in the FlashFS when the INI's [security] lists it and a source supplies
        // it, as xeBuild 1.21 puts it there. The keyvault's flag (none, 0x0020, 0x0200) and
        // nofcrt neither add it nor drop it; they only change what is said about a missing one.
        // One TEST over the 24 combinations, as the plan keeps it: each runs in a tree of its
        // own and a failure names its combination.
        TEST_F(ResolverMetadata, FcrtFollowsTheIniNotTheKeyvault) {
            const auto key = test::valid_cpu_key();
            int combination = 0;
            for (const uint16_t features : {0x0000, 0x0020, 0x0200}) {
                Bytes plain(nand::Keyvault::kSize, 0x00);
                plain[0x1C] = static_cast<uint8_t>(features >> 8);
                plain[0x1D] = static_cast<uint8_t>(features);
                for (const bool listed : {true, false}) {
                    for (const bool supplied : {true, false}) {
                        for (const bool nofcrt : {false, true}) {
                            SCOPED_TRACE(::testing::Message()
                                         << "features 0x" << std::hex << features << std::dec
                                         << ", listed " << listed << ", supplied " << supplied
                                         << ", nofcrt " << nofcrt);
                            ASSERT_OK_AND_ASSIGN(
                                const auto own,
                                test::ResolverTree::make(
                                    path("combination-" + std::to_string(combination++))));
                            ASSERT_OK_AND_ASSIGN(auto args, own.complete_loose_args());
                            ASSERT_OK_AND_ASSIGN(const auto sealed,
                                                 nand::keyvault_encrypt(key, plain));
                            ASSERT_OK(own.write_binary("first/kv.bin", sealed));
                            ASSERT_OK(own.write_text(
                                "working/build.ini",
                                std::string("[falconbl]\ncb_1.bin\ncd.bin\n[security]\n") +
                                    (listed ? "fcrt.bin\n" : ";fcrt.bin,\n")));
                            const Bytes fcrt(0x4000, 0x46);
                            if (supplied) {
                                ASSERT_OK(own.write_binary("first/fcrt.bin", fcrt));
                            }
                            if (nofcrt) {
                                args.config = {"nofcrt"};
                            }
                            const auto result = own.resolve(args);
                            EXPECT_OK(result) << "a build with or without fcrt.bin resolves";
                            if (!result) {
                                continue;
                            }
                            const auto& files = result->input.flashfs_sec;
                            const bool held =
                                files &&
                                std::any_of(files->begin(), files->end(), [&](const auto& f) {
                                    return f.first == "fcrt.bin" && f.second == fcrt;
                                });
                            const bool any = files && std::any_of(files->begin(), files->end(),
                                                                  [](const auto& f) {
                                                                      return f.first == "fcrt.bin";
                                                                  });
                            EXPECT_EQ(held, listed && supplied)
                                << "fcrt.bin is in the FlashFS exactly when the INI lists it "
                                   "and a source supplies it";
                            EXPECT_EQ(any, held)
                                << "fcrt.bin is in the FlashFS exactly when the INI lists it "
                                   "and a source supplies it";
                        }
                    }
                }
            }
        }

        TEST_F(ResolverMetadata, ValuesRequireFullValidStrings) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args());
            write("working/options.ini", "cbldv=7tail\ncfldv=3\npairing_data=010203\n");
            const auto bad_ldv = resolve(args);
            ASSERT_ERROR(bad_ldv, ResolutionErrorCode::InvalidInput)
                << "LDV parsing rejects trailing content";
            ASSERT_EQ(bad_ldv.error().item, "cbldv") << "LDV parsing rejects trailing content";

            write("working/options.ini", "cbldv=2\ncfldv=3\npairing_data=01020304\n");
            const auto bad_pairing = resolve(args);
            ASSERT_ERROR(bad_pairing, ResolutionErrorCode::InvalidInput)
                << "pairing data must contain exactly three bytes";
            EXPECT_EQ(bad_pairing.error().item, "pairing_data")
                << "pairing data must contain exactly three bytes";
        }

        // The donor half runs in the test's tree, the CLI half (a loose donor) in a second tree
        // of its own, as the old test used two fixtures.
        TEST_F(ResolverMetadata, OnlyTheWinningPrecedenceSourceIsParsed) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto donor_image,
                                 test::donor_image_with_metadata(ImageType::SmallBlock, key));
            write("first/nanddump.bin", donor_image);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            write("working/options.ini", "cbldv=bad\ncfldv=bad\npairing_data=bad\n");
            auto donor_args = minimum_args();
            donor_args.build_ini = "build.ini";
            donor_args.section = "falcon";
            donor_args.image_type.reset();
            const auto donor = resolve(donor_args);
            ASSERT_OK(donor) << "donor metadata overrides malformed options.ini metadata";
            ASSERT_EQ(donor->input.metadata.cb_ldv, 7)
                << "donor values are selected before parsing lower-precedence text";
            ASSERT_EQ(donor->input.metadata.cf_ldv, std::optional<uint8_t>{8})
                << "donor values are selected before parsing lower-precedence text";
            ASSERT_EQ(donor->input.metadata.pairing_data,
                      (std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3}))
                << "donor values are selected before parsing lower-precedence text";

            ASSERT_OK_AND_ASSIGN(const auto cli_tree, test::ResolverTree::make(path("cli")));
            ASSERT_OK_AND_ASSIGN(auto cli_args, cli_tree.complete_loose_args());
            ASSERT_OK(cli_tree.write_text("working/options.ini",
                                          "cbldv=bad\ncfldv=bad\npairing_data=bad\n"));
            cli_args.config = {"cbldv=9", "cfldv=10", "pairing_data=a1b2c3"};
            const auto cli = cli_tree.resolve(cli_args);
            ASSERT_OK(cli) << "CLI metadata overrides malformed options.ini metadata";
            EXPECT_EQ(cli->input.metadata.cb_ldv, 9)
                << "CLI metadata is parsed only after winning precedence is selected";
            EXPECT_EQ(cli->input.metadata.cf_ldv, std::optional<uint8_t>{10})
                << "CLI metadata is parsed only after winning precedence is selected";
            EXPECT_EQ(cli->input.metadata.pairing_data, (std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3}))
                << "CLI metadata is parsed only after winning precedence is selected";
        }

        TEST_F(ResolverMetadata, CliPairingOverrideReachesTheCfAndTheConsoleIsCarried) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto donor_image,
                                 test::donor_image_with_metadata(ImageType::SmallBlock, key));
            write("first/nanddump.bin", donor_image);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.console = ConsoleType::Falcon;
            args.image_type.reset();
            const auto donor = resolve(args);
            ASSERT_OK(donor) << "donor CF pairing fixture resolves";
            ASSERT_EQ(donor->input.metadata.cf_pairing_data,
                      (std::optional{std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3}}))
                << "the donor CF pairing reaches the input";
            ASSERT_EQ(donor->input.console, ConsoleType::Falcon)
                << "the selected console reaches the input";

            args.config = {"pairing_data=0a0b0c"};
            const auto overridden = resolve(args);
            ASSERT_OK(overridden) << "CLI pairing override resolves";
            EXPECT_EQ(overridden->input.metadata.pairing_data,
                      (std::array<uint8_t, 3>{0x0A, 0x0B, 0x0C}))
                << "a CLI pairing override also replaces the donor CF pairing";
            EXPECT_FALSE(overridden->input.metadata.cf_pairing_data.has_value())
                << "a CLI pairing override also replaces the donor CF pairing";
        }

        // The options.ini half runs in the test's tree, the CLI half in a second tree of its
        // own, as the old test used two fixtures.
        TEST_F(ResolverMetadata, WinnerErrorsReportTheWinningSource) {
            ASSERT_OK_AND_ASSIGN(const auto file_args, tree().complete_loose_args());
            write("working/options.ini", "cbldv=bad\ncfldv=3\npairing_data=010203\n");
            const auto file = resolve(file_args);
            ASSERT_ERROR(file, ResolutionErrorCode::InvalidInput)
                << "options.ini winning metadata error retains options.ini provenance";
            ASSERT_EQ(file.error().path, working_directory() / "options.ini")
                << "options.ini winning metadata error retains options.ini provenance";
            ASSERT_EQ(file.error().item, "cbldv")
                << "options.ini winning metadata error retains options.ini provenance";

            ASSERT_OK_AND_ASSIGN(const auto cli_tree, test::ResolverTree::make(path("cli")));
            ASSERT_OK_AND_ASSIGN(auto cli_args, cli_tree.complete_loose_args());
            cli_args.config = {"cbldv=bad"};
            const auto cli = cli_tree.resolve(cli_args);
            ASSERT_ERROR(cli, ResolutionErrorCode::InvalidInput)
                << "CLI winning metadata error retains CLI no-path provenance";
            EXPECT_TRUE(cli.error().path.empty())
                << "CLI winning metadata error retains CLI no-path provenance";
            EXPECT_EQ(cli.error().item, "cbldv")
                << "CLI winning metadata error retains CLI no-path provenance";
        }

        // ---- CliMetadataProvenance ----------------------------------------------------------

        // name is the row's gtest name; config the -c item and item the option it is refused
        // as.
        struct CliMetadataCase {
            const char* name;
            std::string_view config;
            std::string_view item;
        };
        GX_PRINT_ROW_AS_NAME(CliMetadataCase)

        constexpr std::array kCliMetadataCases{
            CliMetadataCase{"CbLdvTail", "cbldv=7tail", "cbldv"},
            CliMetadataCase{"CfLdvOverflow", "cfldv=0x100", "cfldv"},
            CliMetadataCase{"PairingTooLong", "pairing_data=01020304", "pairing_data"},
        };

        class CliMetadataProvenance : public ResolverTest,
                                      public ::testing::WithParamInterface<CliMetadataCase> {};

        TEST_P(CliMetadataProvenance, InvalidCliMetadataKeepsTheCliProvenanceInLooseDonorMode) {
            const auto& row = GetParam();
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args());
            args.config = {std::string{row.config}};
            const auto result = resolve(args);
            ASSERT_ERROR(result, ResolutionErrorCode::InvalidInput)
                << "invalid CLI metadata retains CLI rather than options.ini provenance";
            EXPECT_TRUE(result.error().path.empty())
                << "invalid CLI metadata retains CLI rather than options.ini provenance";
            EXPECT_EQ(result.error().item, row.item)
                << "invalid CLI metadata retains CLI rather than options.ini provenance";
        }

        INSTANTIATE_TEST_SUITE_P(Row, CliMetadataProvenance, ::testing::ValuesIn(kCliMetadataCases),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::cli
