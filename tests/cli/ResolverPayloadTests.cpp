// src/cli/BuildInputResolver.hpp: the INI payloads and the build type's fixed payloads. A named
// INI payload comes from the first root that holds it (a first-root file that cannot be read
// stops the search), else from the donor's FlashFS by lowercase basename, else it is an exact
// AssetNotFound. JTAG resolves its XeLL (xell-2f.bin), the embedded freeBOOT rebooter for the
// INI's kernel version, the SMC payload and generated fuses; glitch resolves only its XeLL
// (xell-gggggg.bin) and glitch2m adds fuses read from the CB_B; devgl finds the SB private key
// by CRC-32 in a root or its keys folder, leaves XeLL to the FlashFS and writes retail fuses.
// A glitch donor's ambiguous KHV bytes never become fixed payloads, the final Input is
// validated before it is returned, and a retail resolve from a hacked donor keeps the donor's
// payloads (today's behaviour, pinned).

#include "BuildRunner.hpp"
#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "nand/objects/Freeboot.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/XeRsaTestKey.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/builders/Stages.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace gxbuild3::cli {
    namespace {

        using test::Bytes;

        class ResolverPayload : public ResolverTest {};

        // Lines 0-6 for test::kFuseCbWord, as xerunner's test_build.py states them; lines 1-2
        // come from the CB, not from the falcon section, and 3-6 are the CPU key halves twice
        // each. Reports the sizes and the first differing offset, never the bytes.
        ::testing::AssertionResult fuse_lines_follow_the_cb_word(const Bytes& fuses) {
            const auto key = test::valid_cpu_key();
            Bytes expected{0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x0F, 0x0F, 0x0F,
                           0x0F, 0x0F, 0xF0, 0xF0, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            expected.insert(expected.end(), key.begin(), key.begin() + 8);
            expected.insert(expected.end(), key.begin(), key.begin() + 8);
            expected.insert(expected.end(), key.begin() + 8, key.end());
            expected.insert(expected.end(), key.begin() + 8, key.end());
            if (fuses.size() < expected.size()) {
                return ::testing::AssertionFailure()
                       << "the fuses hold " << fuses.size() << " bytes, fewer than the "
                       << expected.size() << " of lines 0-6";
            }
            const auto [want, got] = std::mismatch(expected.begin(), expected.end(), fuses.begin());
            if (want != expected.end()) {
                return ::testing::AssertionFailure() << std::format(
                           "fuse lines 0-6 first differ at offset 0x{:x}", want - expected.begin());
            }
            return ::testing::AssertionSuccess();
        }

        // Both absent, or both present and byte-identical (sizes and the first differing offset
        // on failure, never the bytes).
        ::testing::AssertionResult same_payload(const char* kept_expression,
                                                const char* source_expression,
                                                const std::optional<Bytes>& kept,
                                                const std::optional<Bytes>& source) {
            if (kept.has_value() != source.has_value()) {
                return ::testing::AssertionFailure()
                       << kept_expression << (kept ? " is present" : " is absent") << " but "
                       << source_expression << (source ? " is present" : " is absent");
            }
            if (!kept) {
                return ::testing::AssertionSuccess();
            }
            return test::detail::bytes_equal(source_expression, kept_expression, *source, *kept);
        }

        // A throwaway key whose file states the SB private key's CRC-32, so the resolver takes
        // it (tests/support/XeRsaTestKey.hpp); the real SB key is never read.
        Bytes sb_key_stand_in() {
            return test::xe_rsa::with_crc32(test::xe_rsa::shared_private_key(),
                                            utils::kSbPrivateKeyCrc32);
        }

        TEST_F(ResolverPayload, IniPayloadLookupFailureIsTerminal) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args());
            args.source_dirs = {path("first"), path("second")};
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsecdata.bin\n");
            std::error_code error;
            ASSERT_TRUE(std::filesystem::create_directory(path("first/secdata.bin"), error))
                << "a directory stands in the first root's secdata.bin: " << error.message();
            auto later = Bytes(0x20, 0x63);
            ASSERT_OK(nand::crypt_secfile(test::valid_cpu_key(), later))
                << "later secure fixture encrypts";
            write("second/secdata.bin", later);

            std::expected<BuildRequest, ResolutionError> result;
            ASSERT_NO_THROW(result = resolve(args))
                << "INI payload lookup failures must not escape the resolver";
            ASSERT_ERROR(result, ResolutionErrorCode::AssetNotFound)
                << "failed first-priority INI payload inspection is terminal";
            EXPECT_EQ(result.error().path, path("first/secdata.bin"))
                << "failed first-priority INI payload inspection is terminal";
            EXPECT_EQ(result.error().item, "secdata.bin")
                << "failed first-priority INI payload inspection is terminal";
        }

        TEST_F(ResolverPayload, IniPayloadIsRequiredUnlessTheDonorSuppliesTheSameBasename) {
            const auto key = test::valid_cpu_key();
            Input donor{};
            donor.image_type = ImageType::SmallBlock;
            donor.metadata.cpu_key = Bytes(key.begin(), key.end());
            donor.metadata.smc = test::make_smc(0x61);
            donor.metadata.keyvault = test::canonical_keyvault_filled(key, 0x62);
            donor.bootloaders = test::valid_bootloaders();
            donor.flashfs_sec =
                std::vector<std::pair<std::string, Bytes>>{{"DONOR-ONLY.BIN", Bytes{0x44}}};
            const auto donor_bytes = run_build(donor);
            ASSERT_OK(donor_bytes) << "required-payload donor fixture builds";
            write("first/nanddump.bin", *donor_bytes);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\ndonor-only.bin\n");

            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.image_type.reset();
            const auto fallback = resolve(args);
            ASSERT_OK(fallback) << "donor FlashFS satisfies a named INI payload";
            ASSERT_TRUE(fallback->input.flashfs_sec.has_value())
                << "donor fallback uses the lowercase basename and preserves its bytes";
            ASSERT_EQ(fallback->input.flashfs_sec->size(), 1U)
                << "donor fallback uses the lowercase basename and preserves its bytes";
            ASSERT_BYTES_EQ(Bytes{0x44}, fallback->input.flashfs_sec->front().second)
                << "donor fallback uses the lowercase basename and preserves its bytes";

            write("working/build.ini",
                  "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsub/missing-security.bin\n");
            const auto missing_security = resolve(args);
            ASSERT_ERROR(missing_security, ResolutionErrorCode::AssetNotFound)
                << "a missing named security payload is an exact error";
            ASSERT_EQ(missing_security.error().path, path("working/build.ini"))
                << "a missing named security payload is an exact error";
            ASSERT_EQ(missing_security.error().item, "sub/missing-security.bin")
                << "a missing named security payload is an exact error";

            write("working/build.ini",
                  "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\ndonor-only.bin\nsub/missing.bin\n");
            const auto missing = resolve(args);
            ASSERT_ERROR(missing, ResolutionErrorCode::AssetNotFound)
                << "a named INI payload absent from donor and roots is an exact error";
            EXPECT_EQ(missing.error().path, path("working/build.ini"))
                << "a named INI payload absent from donor and roots is an exact error";
            EXPECT_EQ(missing.error().item, "sub/missing.bin")
                << "a named INI payload absent from donor and roots is an exact error";
        }

        TEST_F(ResolverPayload, JtagResolvePopulatesPayloads) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Jtag));
            args.console = ConsoleType::Falcon;
            args.patch_extension = "test";
            write("first/bin/patches_falcon_test.bin", test::valid_glitch_patchset());
            write("first/xell-2f.bin", Bytes(0x40000, 0x5A));

            const auto result = resolve(args);
            ASSERT_OK(result) << "JTAG fixture carrying xell-2f.bin resolves";
            const auto& payloads = result->input.payloads;
            ASSERT_TRUE(payloads.has_value()) << "JTAG resolution populates input.payloads";
            ASSERT_TRUE(payloads->xell.has_value()) << "xell-2f.bin is loaded verbatim";
            EXPECT_EQ(payloads->xell->size(), 0x40000U) << "xell-2f.bin is loaded verbatim";
            ASSERT_TRUE(payloads->rebooter.has_value())
                << "the embedded freeBOOT rebooter is loaded at 0xd40 bytes";
            EXPECT_EQ(payloads->rebooter->size(), 0xd40U)
                << "the embedded freeBOOT rebooter is loaded at 0xd40 bytes";
            EXPECT_BYTES_EQ(nand::freeboot_rebooter_for("17559"), *payloads->rebooter)
                << "the rebooter states the INI's kernel version";
            ASSERT_TRUE(payloads->payload.has_value())
                << "the embedded SMC payload is loaded at 0x200 bytes";
            EXPECT_EQ(payloads->payload->size(), 0x200U)
                << "the embedded SMC payload is loaded at 0x200 bytes";
            EXPECT_BYTES_EQ(nand::freeboot_payload_for(0xd40), *payloads->payload)
                << "the payload loads exactly the rebooter";
            ASSERT_TRUE(payloads->fuses.has_value())
                << "generated virtual fuses fill the 0x60-byte region";
            EXPECT_EQ(payloads->fuses->size(), 0x60U)
                << "generated virtual fuses fill the 0x60-byte region";
            EXPECT_TRUE(fuse_lines_follow_the_cb_word(*payloads->fuses))
                << "JTAG second CB fuse lines 0-6 follow the CB word and CPU key";
        }

        TEST_F(ResolverPayload, JtagResolveFailsWithoutXell) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Jtag));
            args.console = ConsoleType::Falcon;
            args.patch_extension = "test";
            write("first/bin/patches_falcon_test.bin", test::valid_glitch_patchset());

            const auto result = resolve(args);
            ASSERT_FALSE(result.has_value()) << "JTAG without a XeLL is rejected";
            EXPECT_TRUE(result.error().message.contains("require a XeLL"))
                << "the missing-XeLL error names the requirement";
        }

        TEST_F(ResolverPayload, GlitchResolvePopulatesXellOnly) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2));
            args.patch_extension = "test";
            write("first/bin/patches_g2falcon_test.bin", test::valid_glitch_patchset());
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

            const auto result = resolve(args);
            ASSERT_OK(result) << "glitch2 carrying xell-gggggg.bin resolves";
            const auto& payloads = result->input.payloads;
            ASSERT_TRUE(payloads.has_value()) << "xell-gggggg.bin is loaded";
            ASSERT_TRUE(payloads->xell.has_value()) << "xell-gggggg.bin is loaded";
            EXPECT_EQ(payloads->xell->size(), 0x40000U) << "xell-gggggg.bin is loaded";
            EXPECT_FALSE(payloads->rebooter.has_value())
                << "glitch carries no JTAG rebooter/payload";
            EXPECT_FALSE(payloads->payload.has_value())
                << "glitch carries no JTAG rebooter/payload";
            EXPECT_FALSE(payloads->fuses.has_value())
                << "non-manufacturing glitch carries no fuses";
        }

        TEST_F(ResolverPayload, Glitch2mResolvePopulatesFuses) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2m));
            args.patch_extension = "test";
            write("first/bin/patches_g2mfalcon_test.bin", test::valid_glitch_patchset());
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

            const auto result = resolve(args);
            ASSERT_OK(result) << "glitch2m resolves";
            const auto& payloads = result->input.payloads;
            ASSERT_TRUE(payloads.has_value()) << "glitch2m loads XeLL and generated 0x60 fuses";
            EXPECT_TRUE(payloads->xell.has_value())
                << "glitch2m loads XeLL and generated 0x60 fuses";
            ASSERT_TRUE(payloads->fuses.has_value())
                << "glitch2m loads XeLL and generated 0x60 fuses";
            EXPECT_EQ(payloads->fuses->size(), 0x60U)
                << "glitch2m loads XeLL and generated 0x60 fuses";
            EXPECT_TRUE(fuse_lines_follow_the_cb_word(*payloads->fuses))
                << "glitch2m CB_B fuse lines 0-6 follow the CB word and CPU key";
        }

        TEST_F(ResolverPayload, Glitch2mWithoutCbBIsRefused) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2m));
            args.patch_extension = "test";
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            write("first/bin/patches_g2mfalcon_test.bin", test::valid_glitch_patchset());
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

            const auto result = resolve(args);
            ASSERT_FALSE(result.has_value())
                << "glitch2m fuses without a CB_B to read the word from are refused";
            EXPECT_EQ(result.error().item, "fuses")
                << "glitch2m fuses without a CB_B to read the word from are refused";
            EXPECT_TRUE(result.error().message.contains("CB_B"))
                << "glitch2m fuses without a CB_B to read the word from are refused";
        }

        TEST_F(ResolverPayload, DevglResolveFindsTheSbKeyAndBuildsRetailFuses) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Devgl));
            args.patch_extension = "test";
            write("first/bin/patches_g2mfalcon_test.bin", test::valid_glitch_patchset());
            const auto stand_in = sb_key_stand_in();
            // A root's own candidate of the wrong CRC-32 is passed over for its keys folder's.
            write("first/SB_priv.bin", Bytes(stand_in.size(), 0x11));
            write("first/keys/sb_PRV.bin", stand_in);

            const auto result = resolve(args);
            ASSERT_EQ(utils::crc32(stand_in), utils::kSbPrivateKeyCrc32)
                << "the stand-in key states the SB key's CRC-32";
            ASSERT_OK(result) << "devgl resolves with an SB key in a keys folder";
            const auto& input = result->input;
            ASSERT_TRUE(input.sb_private_key.has_value()) << "the keys folder's SB key is taken";
            EXPECT_BYTES_EQ(stand_in, *input.sb_private_key) << "the keys folder's SB key is taken";
            ASSERT_TRUE(input.patches.has_value() && input.patches->automatic.has_value())
                << "devgl reads the glitch2m patch file";
            EXPECT_EQ(input.patches->automatic->name, "patches_g2mfalcon_test.bin")
                << "devgl reads the glitch2m patch file";
            ASSERT_TRUE(input.payloads.has_value()) << "devgl leaves XeLL to the FlashFS";
            EXPECT_FALSE(input.payloads->xell.has_value()) << "devgl leaves XeLL to the FlashFS";

            // Line 1 names the retail type, line 2 holds no allow bits, lines 7.. count cfldv=3.
            const Bytes type_line{0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xF0};
            const Bytes allow_line(8, 0x00);
            const Bytes ldv_line{0xFF, 0xF0, 0, 0, 0, 0, 0, 0};
            const auto& fuses = input.payloads->fuses;
            ASSERT_TRUE(fuses.has_value())
                << "devgl fuses state the retail type, no allow bits and the CF LDV";
            ASSERT_EQ(fuses->size(), 0x60U)
                << "devgl fuses state the retail type, no allow bits and the CF LDV";
            const std::span<const uint8_t> lines{*fuses};
            EXPECT_BYTES_EQ(type_line, lines.subspan(0x08, 8))
                << "devgl fuses state the retail type, no allow bits and the CF LDV";
            EXPECT_BYTES_EQ(allow_line, lines.subspan(0x10, 8))
                << "devgl fuses state the retail type, no allow bits and the CF LDV";
            EXPECT_BYTES_EQ(ldv_line, lines.subspan(0x38, 8))
                << "devgl fuses state the retail type, no allow bits and the CF LDV";
        }

        TEST_F(ResolverPayload, DevglResolveWithoutTheSbKeyIsRefused) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Devgl));
            args.patch_extension = "test";
            write("first/bin/patches_g2mfalcon_test.bin", test::valid_glitch_patchset());
            const auto absent = resolve(args);
            write("first/keys/SB_priv.bin", test::xe_rsa::shared_private_key());
            const auto wrong = resolve(args);
            EXPECT_ERROR_HAS(absent, ResolutionErrorCode::SigningKeyNotFound, "No SB_priv.bin")
                << "devgl without an SB key is refused";
            EXPECT_ERROR_HAS(wrong, ResolutionErrorCode::SigningKeyNotFound, "No candidate")
                << "devgl with only a key of another CRC-32 is refused";
        }

        TEST_F(ResolverPayload, GlitchResolveFailsWithoutXell) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch2));
            args.patch_extension = "test";
            write("first/bin/patches_g2falcon_test.bin", test::valid_glitch_patchset());

            const auto result = resolve(args);
            ASSERT_FALSE(result.has_value()) << "glitch without a XeLL is rejected";
            EXPECT_TRUE(result.error().message.contains("require a XeLL"))
                << "the missing-XeLL error names the requirement";
        }

        TEST_F(ResolverPayload, GlitchKhvDonorDoesNotResolveAmbiguousFixedPayloads) {
            const auto key = test::valid_cpu_key();
            Input donor{};
            donor.image_type = ImageType::SmallBlock;
            donor.build_type = BuildType::Glitch;
            donor.metadata.cpu_key = Bytes(key.begin(), key.end());
            donor.metadata.smc = test::make_smc(0x63);
            donor.metadata.keyvault = test::canonical_keyvault_filled(key, 0x64);
            donor.bootloaders = test::valid_bootloaders();
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::valid_glitch_patchset(0xC4)};
            donor.patches = std::move(patches);
            const auto donor_bytes = run_build(donor);
            ASSERT_OK(donor_bytes) << "small-block Glitch KHV donor fixture builds";

            const auto extracted = extract_all(*donor_bytes, key);
            ASSERT_OK(extracted)
                << "extract_all does not invent fixed payloads from ambiguous Glitch KHV bytes";
            ASSERT_FALSE(extracted->payloads.has_value())
                << "extract_all does not invent fixed payloads from ambiguous Glitch KHV bytes";

            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args(BuildType::Glitch));
            args.image_type.reset();
            write("first/nanddump.bin", *donor_bytes);
            write("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
            write("first/bin/patches_fat.bin", test::valid_glitch_patchset(0xC4));
            const auto resolved = resolve(args);
            ASSERT_OK(resolved) << "small-block Glitch KHV donor resolves";
            const auto& payloads = resolved->input.payloads;
            EXPECT_TRUE(!payloads || !payloads->rebooter)
                << "resolver preserves the conservative ambiguous-KHV payload policy";
            EXPECT_TRUE(!payloads || !payloads->fuses)
                << "resolver preserves the conservative ambiguous-KHV payload policy";
        }

        TEST_F(ResolverPayload, FinalInputIsValidatedBeforeReturn) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args());
            write("first/smc.bin", Bytes{});
            EXPECT_ERROR_MSG(resolve(args), ResolutionErrorCode::InvalidInput, "SMC is required")
                << "validate_input failure becomes a structured InvalidInput error";
        }

        // Today's behaviour, deliberate until decided: resolve seeds its Input from the donor's
        // extract_all, and only the devgl and JTAG/glitch branches replace input.payloads, so a
        // retail resolve from a hacked donor keeps the donor's XeLL. Whether that is a bug is an
        // open question; this pin keeps a resolver split from changing it silently.
        TEST_F(ResolverPayload, RetailFromHackedDonorKeepsDonorPayloadsAsToday) {
            const auto key = test::valid_cpu_key();
            const auto donor =
                test::pinned_donor_image(test::glitch2_donor_input(key), "glitch2 donor");
            ASSERT_OK(donor) << "the glitch2 donor builds";
            const auto extracted = extract_all(*donor, key);
            ASSERT_OK(extracted) << "extract_all of the glitch2 donor carries its XeLL payload";
            ASSERT_TRUE(extracted->payloads.has_value())
                << "extract_all of the glitch2 donor carries its XeLL payload";
            ASSERT_TRUE(extracted->payloads->xell.has_value())
                << "extract_all of the glitch2 donor carries its XeLL payload";
            write("first/nanddump.bin", *donor);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.image_type.reset();
            const auto result = resolve(args);
            ASSERT_OK(result) << "a retail resolve from the glitch2 donor";

            const auto& kept = result->input.payloads;
            const auto& source = *extracted->payloads;
            EXPECT_EQ(result->input.build_type, BuildType::Retail)
                << "the resolve is a retail build";
            EXPECT_FALSE(result->input.patches.has_value())
                << "a retail resolve carries no patch file";
            ASSERT_TRUE(kept.has_value()) << "a retail resolve keeps the donor's payloads (today)";
            EXPECT_PRED_FORMAT2(same_payload, kept->xell, source.xell)
                << "the kept payloads are exactly the donor's extract_all payloads";
            EXPECT_PRED_FORMAT2(same_payload, kept->rebooter, source.rebooter)
                << "the kept payloads are exactly the donor's extract_all payloads";
            EXPECT_PRED_FORMAT2(same_payload, kept->fuses, source.fuses)
                << "the kept payloads are exactly the donor's extract_all payloads";
            EXPECT_PRED_FORMAT2(same_payload, kept->patches, source.patches)
                << "the kept payloads are exactly the donor's extract_all payloads";
            EXPECT_PRED_FORMAT2(same_payload, kept->payload, source.payload)
                << "the kept payloads are exactly the donor's extract_all payloads";
        }

    } // namespace
} // namespace gxbuild3::cli
