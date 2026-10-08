#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "TestResult.hpp"
#include "cli/BuildInputResolver.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/Freeboot.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/Patchset.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/XeRsaTestKey.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/builders/Stages.hpp"
#include "support/render/ExtractProjection.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::cli::BuildArgs;
    using gxbuild3::cli::BuildInputResolver;
    using gxbuild3::cli::ResolutionErrorCode;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    bool require_resolved(
        const std::expected<gxbuild3::cli::BuildRequest, gxbuild3::cli::ResolutionError>& result,
        std::string_view message) {
        if (!result) {
            std::cerr << "RESOLUTION ERROR: code=" << static_cast<int>(result.error().code)
                      << " path='" << result.error().path.string() << "' item='"
                      << result.error().item << "' message='" << result.error().message << "'\n";
        }
        return require(result.has_value(), message);
    }

    // The shared builders (tests/support/builders/), byte for byte what this file defined.
    using gxbuild3::test::canonical_keyvault_filled;
    using gxbuild3::test::glitch2_donor_input;
    using gxbuild3::test::kFuseCbWord;
    using gxbuild3::test::make_smc;
    using gxbuild3::test::valid_bootloaders;
    using gxbuild3::test::valid_glitch_patchset;

    // The resolver's test key as bytes: valid_cpu_key() (bits 0..52 ECC-encoded), pinned by
    // core.Keys.
    Bytes valid_cpu_key() {
        const auto key = gxbuild3::test::valid_cpu_key();
        return Bytes(key.begin(), key.end());
    }

    // The Result-returning builders, unwrapped as before: a failure aborts the binary with its
    // description. These go as their callers are ported.
    Input donor_input_with_metadata(ImageType type, std::span<const uint8_t> key) {
        return test::must(gxbuild3::test::donor_input_with_metadata(type, key));
    }

    // A donor image built twice under the pinned build time with every donor nonce pinned;
    // nullopt unless both builds succeed and are byte-identical.
    std::optional<Bytes> pinned_donor_image(Input input, std::string_view label) {
        auto donor = gxbuild3::test::pinned_donor_image(std::move(input), label);
        if (!donor) {
            std::cerr << "DONOR BUILD ERROR: " << donor.error().describe() << '\n';
            return std::nullopt;
        }
        return std::move(*donor);
    }

    // ResolverTree (tests/support/builders/ResolverTree.hpp) rooted at a fresh directory under
    // the temporary directory, removed again at scope end. A write that fails aborts the binary.
    struct ResolverFixture : gxbuild3::test::ResolverTree {
        ResolverFixture() : ResolverTree(test::must(ResolverTree::make(fresh_root()))) {}

        ~ResolverFixture() {
            std::error_code error;
            std::filesystem::remove_all(root(), error);
        }

        ResolverFixture(const ResolverFixture&) = delete;
        ResolverFixture& operator=(const ResolverFixture&) = delete;

        void write_text(std::string_view relative, std::string_view content) const {
            test::must(ResolverTree::write_text(relative, content));
        }

        void write_binary(std::string_view relative, std::span<const uint8_t> content) const {
            test::must(ResolverTree::write_binary(relative, content));
        }

        BuildArgs complete_loose_args(BuildType build_type = BuildType::Retail,
                                      ImageType image_type = ImageType::SmallBlock) const {
            return test::must(ResolverTree::complete_loose_args(build_type, image_type));
        }

      private:
        static std::filesystem::path fresh_root() {
            const auto unique =
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            return std::filesystem::temp_directory_path() / ("gxbuild3-resolver-" + unique);
        }
    };

    bool test_ini_payload_lookup_failure_is_terminal() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsecdata.bin\n");
        std::filesystem::create_directory(fixture.path("first/secdata.bin"));
        auto later = Bytes(0x20, 0x63);
        if (!gxbuild3::nand::crypt_secfile(valid_cpu_key(), later)) {
            return require(false, "later secure fixture encrypts");
        }
        fixture.write_binary("second/secdata.bin", later);

        try {
            const auto result = fixture.resolve(args);
            return require(!result && result.error().code == ResolutionErrorCode::AssetNotFound &&
                               result.error().path == fixture.path("first/secdata.bin") &&
                               result.error().item == "secdata.bin",
                           "failed first-priority INI payload inspection is terminal");
        } catch (...) {
            return require(false, "INI payload lookup failures must not escape the resolver");
        }
    }

    bool test_ini_payload_is_required_unless_donor_supplies_same_basename() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        Input donor{};
        donor.image_type = ImageType::SmallBlock;
        donor.metadata.cpu_key = key;
        donor.metadata.smc = make_smc(0x61);
        donor.metadata.keyvault = canonical_keyvault_filled(key, 0x62);
        donor.bootloaders = valid_bootloaders();
        donor.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"DONOR-ONLY.BIN", Bytes{0x44}}};
        const auto donor_bytes = run_build(donor);
        if (!donor_bytes) {
            return require(false, "required-payload donor fixture builds");
        }
        fixture.write_binary("first/nanddump.bin", *donor_bytes);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\ndonor-only.bin\n");

        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        const auto fallback = fixture.resolve(args);
        if (!require_resolved(fallback, "donor FlashFS satisfies a named INI payload") ||
            !require(fallback->input.flashfs_sec && fallback->input.flashfs_sec->size() == 1 &&
                         fallback->input.flashfs_sec->front().second == Bytes{0x44},
                     "donor fallback uses the lowercase basename and preserves its bytes")) {
            return false;
        }

        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[security]\nsub/missing-security.bin\n");
        const auto missing_security = fixture.resolve(args);
        if (!require(!missing_security &&
                         missing_security.error().code == ResolutionErrorCode::AssetNotFound &&
                         missing_security.error().path == fixture.path("working/build.ini") &&
                         missing_security.error().item == "sub/missing-security.bin",
                     "a missing named security payload is an exact error")) {
            return false;
        }

        fixture.write_text(
            "working/build.ini",
            "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\ndonor-only.bin\nsub/missing.bin\n");
        const auto missing = fixture.resolve(args);
        return require(!missing && missing.error().code == ResolutionErrorCode::AssetNotFound &&
                           missing.error().path == fixture.path("working/build.ini") &&
                           missing.error().item == "sub/missing.bin",
                       "a named INI payload absent from donor and roots is an exact error");
    }

    bool test_automatic_patchset_names_and_retail_devkit_behavior() {
        struct Case {
            BuildType type;
            std::string name;
        };
        const std::array cases{
            Case{BuildType::Jtag, "patches_falcon_test.bin"},
            Case{BuildType::Glitch, "patches_fat_test.bin"},
            Case{BuildType::Glitch2, "patches_g2falcon_test.bin"},
            Case{BuildType::Glitch2m, "patches_g2mfalcon_test.bin"},
            Case{BuildType::Glitch3, "patches_g3falcon_test.bin"},
        };
        // devgl's name is checked by test_devgl_resolve_finds_the_sb_key_and_builds_retail_fuses,
        // as it resolves only with an SB key.
        for (const auto& test : cases) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(test.type);
            args.patch_extension = "test";
            fixture.write_binary("first/bin/" + test.name, valid_glitch_patchset());
            if (test.type == BuildType::Jtag) {
                fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));
            } else if (test.type != BuildType::Retail && test.type != BuildType::Devkit) {
                fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
            }
            const auto result = fixture.resolve(args);
            if (!require_resolved(result, "automatic patch fixture resolves") ||
                !require(result->input.patches && result->input.patches->automatic &&
                             result->input.patches->automatic->name == test.name,
                         "automatic patch name uses the exact build-type table and suffix")) {
                return false;
            }
        }

        for (const auto type : {BuildType::Retail, BuildType::Devkit}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(type);
            fixture.write_binary("first/bin/patches_falcon.bin", valid_glitch_patchset());
            const auto result = fixture.resolve(args);
            if (!require(result && (!result->input.patches ||
                                    !result->input.patches->automatic.has_value()),
                         "retail and devkit do not auto-select patchsets")) {
                return false;
            }
        }
        return true;
    }

    // Lines 0-6 for kFuseCbWord, as xerunner's test_build.py states them; lines 1-2 come
    // from the CB, not from the falcon section, and 3-6 are the CPU key halves twice each.
    bool require_fuse_lines_from_cb_word(const Bytes& fuses, const std::string& name) {
        const auto key = valid_cpu_key();
        const Bytes head{0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x0F, 0x0F, 0x0F,
                         0x0F, 0x0F, 0xF0, 0xF0, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Bytes expected = head;
        expected.insert(expected.end(), key.begin(), key.begin() + 8);
        expected.insert(expected.end(), key.begin(), key.begin() + 8);
        expected.insert(expected.end(), key.begin() + 8, key.end());
        expected.insert(expected.end(), key.begin() + 8, key.end());
        return require(fuses.size() >= expected.size() &&
                           std::equal(expected.begin(), expected.end(), fuses.begin()),
                       name + " fuse lines 0-6 follow the CB word and CPU key");
    }

    bool test_jtag_resolve_populates_payloads() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.console = ConsoleType::Falcon;
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "JTAG fixture carrying xell-2f.bin resolves")) {
            return false;
        }
        const auto& payloads = result->input.payloads;
        return require(payloads.has_value(), "JTAG resolution populates input.payloads") &&
               require(payloads->xell && payloads->xell->size() == 0x40000,
                       "xell-2f.bin is loaded verbatim") &&
               require(payloads->rebooter && payloads->rebooter->size() == 0xd40,
                       "the embedded freeBOOT rebooter is loaded at 0xd40 bytes") &&
               require(*payloads->rebooter == gxbuild3::nand::freeboot_rebooter_for("17559"),
                       "the rebooter states the INI's kernel version") &&
               require(payloads->payload && payloads->payload->size() == 0x200,
                       "the embedded SMC payload is loaded at 0x200 bytes") &&
               require(*payloads->payload == gxbuild3::nand::freeboot_payload_for(0xd40),
                       "the payload loads exactly the rebooter") &&
               require(payloads->fuses && payloads->fuses->size() == 0x60,
                       "generated virtual fuses fill the 0x60-byte region") &&
               require_fuse_lines_from_cb_word(*payloads->fuses, "JTAG second CB");
    }

    bool test_jtag_resolve_fails_without_xell() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.console = ConsoleType::Falcon;
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());

        const auto result = fixture.resolve(args);
        return require(!result.has_value(), "JTAG without a XeLL is rejected") &&
               require(result.error().message.find("require a XeLL") != std::string::npos,
                       "the missing-XeLL error names the requirement");
    }

    bool test_glitch_resolve_populates_xell_only() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "glitch2 carrying xell-gggggg.bin resolves")) {
            return false;
        }
        const auto& payloads = result->input.payloads;
        return require(payloads && payloads->xell && payloads->xell->size() == 0x40000,
                       "xell-gggggg.bin is loaded") &&
               require(!payloads->rebooter && !payloads->payload,
                       "glitch carries no JTAG rebooter/payload") &&
               require(!payloads->fuses, "non-manufacturing glitch carries no fuses");
    }

    bool test_glitch2m_resolve_populates_fuses() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2m);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "glitch2m resolves")) {
            return false;
        }
        const auto& payloads = result->input.payloads;
        return require(payloads && payloads->xell && payloads->fuses &&
                           payloads->fuses->size() == 0x60,
                       "glitch2m loads XeLL and generated 0x60 fuses") &&
               require_fuse_lines_from_cb_word(*payloads->fuses, "glitch2m CB_B");
    }

    bool test_glitch2m_without_cb_b_is_refused() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2m);
        args.patch_extension = "test";
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto result = fixture.resolve(args);
        return require(!result.has_value() && result.error().item == "fuses" &&
                           result.error().message.find("CB_B") != std::string::npos,
                       "glitch2m fuses without a CB_B to read the word from are refused");
    }

    // A throwaway key whose file states the SB private key's CRC-32, so the resolver takes it.
    Bytes sb_key_stand_in() {
        return gxbuild3::test::xe_rsa::with_crc32(gxbuild3::test::xe_rsa::shared_private_key(),
                                                  gxbuild3::utils::kSbPrivateKeyCrc32);
    }

    bool test_devgl_resolve_finds_the_sb_key_and_builds_retail_fuses() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        const auto stand_in = sb_key_stand_in();
        // A root's own candidate of the wrong CRC-32 is passed over for its keys folder's.
        fixture.write_binary("first/SB_priv.bin", Bytes(stand_in.size(), 0x11));
        fixture.write_binary("first/keys/sb_PRV.bin", stand_in);

        const auto result = fixture.resolve(args);
        if (!require(gxbuild3::utils::crc32(stand_in) == gxbuild3::utils::kSbPrivateKeyCrc32,
                     "the stand-in key states the SB key's CRC-32") ||
            !require_resolved(result, "devgl resolves with an SB key in a keys folder")) {
            return false;
        }
        const auto& input = result->input;
        // Line 1 names the retail type, line 2 holds no allow bits, lines 7.. count cfldv=3.
        const Bytes type_line{0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xF0};
        const Bytes ldv_line{0xFF, 0xF0, 0, 0, 0, 0, 0, 0};
        const auto& fuses = input.payloads ? input.payloads->fuses : std::nullopt;
        return require(input.sb_private_key == stand_in, "the keys folder's SB key is taken") &&
               require(input.patches && input.patches->automatic &&
                           input.patches->automatic->name == "patches_g2mfalcon_test.bin",
                       "devgl reads the glitch2m patch file") &&
               require(input.payloads && !input.payloads->xell,
                       "devgl leaves XeLL to the FlashFS") &&
               require(fuses && fuses->size() == 0x60 &&
                           std::equal(type_line.begin(), type_line.end(), fuses->begin() + 8) &&
                           std::all_of(fuses->begin() + 0x10, fuses->begin() + 0x18,
                                       [](uint8_t byte) { return byte == 0; }) &&
                           std::equal(ldv_line.begin(), ldv_line.end(), fuses->begin() + 0x38),
                       "devgl fuses state the retail type, no allow bits and the CF LDV");
    }

    bool test_devgl_resolve_without_the_sb_key_is_refused() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        const auto absent = fixture.resolve(args);
        fixture.write_binary("first/keys/SB_priv.bin",
                             gxbuild3::test::xe_rsa::shared_private_key());
        const auto wrong = fixture.resolve(args);
        return require(!absent && absent.error().code == ResolutionErrorCode::SigningKeyNotFound &&
                           absent.error().message.find("No SB_priv.bin") != std::string::npos,
                       "devgl without an SB key is refused") &&
               require(!wrong && wrong.error().code == ResolutionErrorCode::SigningKeyNotFound &&
                           wrong.error().message.find("No candidate") != std::string::npos,
                       "devgl with only a key of another CRC-32 is refused");
    }

    bool test_glitch_resolve_fails_without_xell() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset());

        const auto result = fixture.resolve(args);
        return require(!result.has_value(), "glitch without a XeLL is rejected") &&
               require(result.error().message.find("require a XeLL") != std::string::npos,
                       "the missing-XeLL error names the requirement");
    }

    bool test_glitch3_searches_all_g3_roots_before_g2_fallback() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch3);
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2falcon_test.bin", valid_glitch_patchset(0x22));
        fixture.write_binary("second/bin/patches_g3falcon_test.bin", valid_glitch_patchset(0x33));
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        const auto g3 = fixture.resolve(args);
        if (!require_resolved(g3, "glitch3 fixture resolves") ||
            !require(g3->input.patches && g3->input.patches->automatic &&
                         g3->input.patches->automatic->name == "patches_g3falcon_test.bin" &&
                         g3->input.patches->automatic->data.back() == 0x33,
                     "a later-root g3 patch beats an earlier-root g2 fallback")) {
            return false;
        }

        std::filesystem::remove(fixture.path("second/bin/patches_g3falcon_test.bin"));
        const auto fallback = fixture.resolve(args);
        return require(fallback && fallback->input.patches && fallback->input.patches->automatic &&
                           fallback->input.patches->automatic->name ==
                               "patches_g2falcon_test.bin" &&
                           fallback->input.patches->automatic->data.back() == 0x22,
                       "glitch3 falls back only after every g3 root is exhausted");
    }

    bool test_glitch3_prefers_g3_then_g2_and_fails_cleanly_without_either() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch3);
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));

        const auto neither = fixture.resolve(args);
        if (!require(!neither && neither.error().code == ResolutionErrorCode::PatchsetNotFound &&
                         neither.error().item == "patches_g2falcon.bin" &&
                         neither.error().message.find("patches_g3falcon.bin") !=
                             std::string::npos &&
                         neither.error().message.find("patches_g2falcon.bin") != std::string::npos,
                     "glitch3 without a g3 or g2 patchset fails naming both files")) {
            return false;
        }

        fixture.write_binary("first/bin/patches_g2falcon.bin", valid_glitch_patchset(0x22));
        const auto g2_only = fixture.resolve(args);
        if (!require_resolved(g2_only, "glitch3 with only a g2 patchset resolves") ||
            !require(g2_only->input.patches && g2_only->input.patches->automatic &&
                         g2_only->input.patches->automatic->name == "patches_g2falcon.bin" &&
                         g2_only->input.patches->automatic->data.back() == 0x22,
                     "glitch3 uses the g2 patchset when no g3 patchset exists")) {
            return false;
        }

        fixture.write_binary("first/bin/patches_g3falcon.bin", valid_glitch_patchset(0x33));
        const auto both = fixture.resolve(args);
        return require_resolved(both, "glitch3 with both patchsets resolves") &&
               require(both->input.patches && both->input.patches->automatic &&
                           both->input.patches->automatic->name == "patches_g3falcon.bin" &&
                           both->input.patches->automatic->data.back() == 0x33,
                       "glitch3 prefers the g3 patchset over a g2 one in the same root");
    }

    bool test_missing_patchset_and_addon_errors_are_precise() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        const auto missing_patch = fixture.resolve(args);
        if (!require(!missing_patch &&
                         missing_patch.error().code == ResolutionErrorCode::PatchsetNotFound &&
                         missing_patch.error().item == "patches_g2falcon.bin",
                     "a missing required automatic patch names the exact file")) {
            return false;
        }

        fixture.write_binary("first/bin/patches_g2falcon.bin", valid_glitch_patchset());
        args.addons = {"missing"};
        const auto missing_addon = fixture.resolve(args);
        return require(!missing_addon &&
                           missing_addon.error().code == ResolutionErrorCode::AddonNotFound &&
                           missing_addon.error().item == "missing.bin",
                       "a missing add-on names the exact bin filename");
    }

    bool test_addons_resolve_from_root_bin_in_cli_order() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.source_dirs = {fixture.path("first"), fixture.path("second")};
        args.addons = {"second-addon", "first-addon"};
        fixture.write_binary("first/bin/patches_g2falcon.bin", valid_glitch_patchset());
        fixture.write_binary("first/bin/second-addon.bin", Bytes{0x21});
        fixture.write_binary("second/bin/second-addon.bin", Bytes{0x99});
        fixture.write_binary("second/bin/first-addon.bin", Bytes{0x12});
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        const auto result = fixture.resolve(args);
        return require_resolved(result, "add-on fixture resolves") &&
               require(result->input.patches && result->input.patches->addons.size() == 2,
                       "both add-ons resolve") &&
               require(result->input.patches->addons[0].name == "second-addon.bin" &&
                           result->input.patches->addons[0].data == Bytes{0x21} &&
                           result->input.patches->addons[1].name == "first-addon.bin" &&
                           result->input.patches->addons[1].data == Bytes{0x12},
                       "add-ons preserve CLI order and first-root priority") &&
               [&] {
                   const auto merged =
                       parse_and_merge_patch_set(*result->input.patches, result->input.build_type);
                   if (!require(merged.has_value(), "resolved patches parse and merge")) {
                       return false;
                   }
                   const auto khv = std::find_if(
                       merged->sections.begin(), merged->sections.end(), [](const auto& section) {
                           return section.target == PatchSectionTarget::Khv;
                       });
                   return require(khv != merged->sections.end() && khv->raw_data.size() >= 3 &&
                                      std::equal(khv->raw_data.end() - 3, khv->raw_data.end(),
                                                 Bytes{0xA0, 0x21, 0x12}.begin()),
                                  "resolved add-ons append to KHV in CLI order");
               }();
    }

    bool test_retail_and_devkit_reject_addons_without_automatic_patchset() {
        for (const auto type : {BuildType::Retail, BuildType::Devkit}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(type);
            args.addons = {"extra"};
            fixture.write_binary("first/bin/extra.bin", Bytes{0x41});
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == "extra" &&
                             result.error().message ==
                                 "Add-ons require an automatic patchset and are not supported for "
                                 "retail or devkit builds",
                         "retail and devkit reject add-ons that cannot be applied")) {
                return false;
            }
        }
        return true;
    }

    bool test_direct_build_args_reject_unconfined_patch_components() {
        for (const std::string invalid :
             {"../outside", "/outside", "nested/addon", "addon.bin", "C:\\outside"}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(BuildType::Glitch2);
            args.addons = {invalid};
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == invalid,
                         "direct BuildArgs add-ons are bare ASCII logical names")) {
                return false;
            }
        }

        for (const std::string invalid : {"../falcon", "/falcon", "nested\\falcon", "C:\\falcon"}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(BuildType::Glitch2);
            args.section = invalid;
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == invalid,
                         "direct BuildArgs section cannot escape a filename component")) {
                return false;
            }
        }

        for (const std::string invalid :
             {"_test", "test.alt", "../test", "/test", "nested\\test", "C:\\test"}) {
            ResolverFixture fixture;
            auto args = fixture.complete_loose_args(BuildType::Glitch2);
            args.patch_extension = invalid;
            const auto result = fixture.resolve(args);
            if (!require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                             result.error().path.empty() && result.error().item == invalid,
                         "direct BuildArgs patch suffix is a safe non-underscored component")) {
                return false;
            }
        }

        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Glitch2);
        args.patch_extension = "test_alt";
        fixture.write_binary("first/bin/patches_g2falcon_test_alt.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        const auto valid_internal_underscore = fixture.resolve(args);
        if (!require_resolved(valid_internal_underscore,
                              "an internal-underscore patch suffix resolves") ||
            !require(valid_internal_underscore->input.patches &&
                         valid_internal_underscore->input.patches->automatic &&
                         valid_internal_underscore->input.patches->automatic->name ==
                             "patches_g2falcon_test_alt.bin",
                     "safe internal underscores are retained in automatic patch names")) {
            return false;
        }
        return true;
    }

    bool test_glitch_khv_donor_does_not_resolve_ambiguous_fixed_payloads() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        Input donor{};
        donor.image_type = ImageType::SmallBlock;
        donor.build_type = BuildType::Glitch;
        donor.metadata.cpu_key = key;
        donor.metadata.smc = make_smc(0x63);
        donor.metadata.keyvault = canonical_keyvault_filled(key, 0x64);
        donor.bootloaders = valid_bootloaders();
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", valid_glitch_patchset(0xC4)};
        donor.patches = std::move(patches);
        const auto donor_bytes = run_build(donor);
        if (!require(donor_bytes.has_value(), "small-block Glitch KHV donor fixture builds")) {
            return false;
        }

        const auto extracted = extract_all(*donor_bytes, key);
        if (!require(
                extracted.has_value() && !extracted->payloads,
                "extract_all does not invent fixed payloads from ambiguous Glitch KHV bytes")) {
            return false;
        }

        auto args = fixture.complete_loose_args(BuildType::Glitch);
        args.image_type.reset();
        fixture.write_binary("first/nanddump.bin", *donor_bytes);
        fixture.write_binary("first/xell-gggggg.bin", Bytes(0x40000, 0x5A));
        fixture.write_binary("first/bin/patches_fat.bin", valid_glitch_patchset(0xC4));
        const auto resolved = fixture.resolve(args);
        return require_resolved(resolved, "small-block Glitch KHV donor resolves") &&
               require(!resolved->input.payloads || (!resolved->input.payloads->rebooter &&
                                                     !resolved->input.payloads->fuses),
                       "resolver preserves the conservative ambiguous-KHV payload policy");
    }

    bool test_final_input_is_validated_before_return() {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        fixture.write_binary("first/smc.bin", Bytes{});
        const auto result = fixture.resolve(args);
        return require(!result && result.error().code == ResolutionErrorCode::InvalidInput &&
                           result.error().message == "SMC is required",
                       "validate_input failure becomes a structured InvalidInput error");
    }

    // One BuildRequest as golden lines: the output path relative to the fixture root (the root is
    // a fresh temporary directory), then every Input field through
    // tests/support/render/ExtractProjection.hpp: options, metadata scalars, the size and SHA-1 of
    // every byte vector, FlashFS names in order, patch file names, payloads, and only the size of
    // an SB key.
    std::string render_request(const std::string& label, const ResolverFixture& fixture,
                               const gxbuild3::cli::BuildRequest& request) {
        return label + " output_path=" +
               request.output_path.lexically_relative(fixture.root()).generic_string() + '\n' +
               gxbuild3::test::projection::render(label + ".input", request.input);
    }

    struct DigestCase {
        std::string text;
        bool stable = false;
    };

    // Resolves args twice; both requests must render identically.
    DigestCase digest_resolve(const std::string& label, const ResolverFixture& fixture,
                              const BuildArgs& args) {
        const auto first = fixture.resolve(args);
        const auto second = fixture.resolve(args);
        if (!require_resolved(first, label + " resolves") ||
            !require_resolved(second, label + " resolves again")) {
            return DigestCase{label + " resolution-error\n", false};
        }
        const auto once = render_request(label, fixture, *first);
        const bool stable = require(once == render_request(label, fixture, *second),
                                    label + " resolves to an identical BuildRequest twice");
        return DigestCase{stable ? once : label + " nondeterministic\n", stable};
    }

    // donor.retail: a pinned synthetic donor (CB/CF LDVs, pairing, CF/CG) under a falcon chain
    // of loose CB and CD, a [flashfs] file, a mobile slot, options.ini and a CLI override.
    DigestCase digest_donor_retail(const std::string& label) {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        const auto donor =
            pinned_donor_image(donor_input_with_metadata(ImageType::SmallBlock, key), label);
        if (!donor) {
            return DigestCase{label + " donor-build-error\n", false};
        }
        fixture.write_binary("first/nanddump.bin", *donor);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_binary("first/launch.ini", Bytes{0x41, 0x42});
        fixture.write_binary("first/mobileB.bin", Bytes{0xB2});
        fixture.write_text("working/build.ini",
                           "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\nlaunch.ini\n");
        fixture.write_text("working/options.ini", "nofcrt=true\ncbldv=3\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.console = ConsoleType::Falcon;
        args.image_type.reset();
        args.config = {"cfldv=5", "nomobile=false"};
        return digest_resolve(label, fixture, args);
    }

    // loose.retail: no donor; kv.bin sealed, smc.bin, options.ini metadata, a sealed secdata.bin
    // in [security], a [flashfs] file and a mobile slot.
    DigestCase digest_loose_retail(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        auto secdata = Bytes(0x20, 0x51);
        if (!gxbuild3::nand::crypt_secfile(valid_cpu_key(), secdata)) {
            return DigestCase{label + " secdata-seal-error\n", false};
        }
        fixture.write_binary("first/secdata.bin", secdata);
        fixture.write_binary("first/launch.ini", Bytes{0x43});
        fixture.write_binary("first/mobileA.bin", Bytes{0xA1, 0xA2});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\n"
                                                "launch.ini\n[security]\nsecdata.bin\n");
        return digest_resolve(label, fixture, args);
    }

    // loose.jtag: the falcon JTAG chain (second CB), [version] 17559, patches_falcon_test.bin and
    // xell-2f.bin; payloads carry XeLL, the embedded rebooter and payload, and generated fuses.
    DigestCase digest_loose_jtag(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));
        return digest_resolve(label, fixture, args);
    }

    // loose.devgl: the glitch2m patch file and the throwaway stand-in SB key (XeRsaTestKey.hpp,
    // made to state the SB key's CRC-32) found through the resolver's own lookup in a keys
    // folder. The real SB key is never read; the golden records only the key's size.
    DigestCase digest_loose_devgl(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/keys/SB_priv.bin", sb_key_stand_in());
        return digest_resolve(label, fixture, args);
    }

    // donor-glitch2.retail: a retail resolve from the pinned glitch2 donor (see
    // test_retail_resolve_keeps_donor_payloads_as_today).
    DigestCase digest_retail_from_glitch2_donor(const std::string& label) {
        ResolverFixture fixture;
        const auto donor = pinned_donor_image(glitch2_donor_input(valid_cpu_key()), label);
        if (!donor) {
            return DigestCase{label + " donor-build-error\n", false};
        }
        fixture.write_binary("first/nanddump.bin", *donor);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        return digest_resolve(label, fixture, args);
    }

    // The resolver's whole BuildRequest for a donor, a loose-donor, a JTAG, a devgl and a
    // retail-from-hacked-donor resolve, against tests/golden/resolver_build_requests.txt. Each
    // donor is built twice under a pinned time and nonces, and each case resolves twice; both
    // must be identical.
    bool test_resolution_digests(const gxbuild3::test::GoldenOptions& options) {
        using Digest = DigestCase (*)(const std::string&);
        const std::array<std::pair<std::string_view, Digest>, 5> cases{{
            {"donor.retail", digest_donor_retail},
            {"loose.retail", digest_loose_retail},
            {"loose.jtag", digest_loose_jtag},
            {"loose.devgl", digest_loose_devgl},
            {"donor-glitch2.retail", digest_retail_from_glitch2_donor},
        }};
        std::string rendered;
        size_t stable = 0;
        for (const auto& [label, digest] : cases) {
            const auto result = digest(std::string{label});
            rendered += result.text;
            stable += result.stable ? 1 : 0;
        }
        const bool matched =
            gxbuild3::test::check_golden(options, "resolver_build_requests", rendered);
        std::cout << "resolver BuildRequest digests: resolved twice and identical " << stable << '/'
                  << cases.size() << ", compared " << (matched ? stable : 0) << '/' << cases.size()
                  << " with tests/golden/resolver_build_requests.txt\n";
        return require(matched, "resolver BuildRequest digests match the golden") &&
               require(stable == cases.size(), "every resolver digest case is stable");
    }

    // Today's behaviour, deliberate until decided: resolve seeds its Input from the donor's
    // extract_all, and only the devgl and JTAG/glitch branches replace input.payloads, so a retail
    // resolve from a hacked donor keeps the donor's XeLL. Whether that is a bug is an open
    // question; this pin keeps a resolver split from changing it silently.
    bool test_retail_resolve_keeps_donor_payloads_as_today() {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        const auto donor = pinned_donor_image(glitch2_donor_input(key), "glitch2 donor");
        if (!require(donor.has_value(), "the glitch2 donor builds")) {
            return false;
        }
        const auto extracted = extract_all(*donor, key);
        if (!require(extracted && extracted->payloads && extracted->payloads->xell,
                     "extract_all of the glitch2 donor carries its XeLL payload")) {
            return false;
        }
        fixture.write_binary("first/nanddump.bin", *donor);
        fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
        fixture.write_binary("first/cd.bin", Bytes{0xCD});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
        auto args = fixture.minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.image_type.reset();
        const auto result = fixture.resolve(args);
        if (!require_resolved(result, "a retail resolve from the glitch2 donor")) {
            return false;
        }
        const auto& kept = result->input.payloads;
        const auto& source = *extracted->payloads;
        return require(result->input.build_type == BuildType::Retail,
                       "the resolve is a retail build") &&
               require(!result->input.patches, "a retail resolve carries no patch file") &&
               require(kept.has_value(), "a retail resolve keeps the donor's payloads (today)") &&
               require(kept->xell == source.xell && kept->rebooter == source.rebooter &&
                           kept->fuses == source.fuses && kept->patches == source.patches &&
                           kept->payload == source.payload,
                       "the kept payloads are exactly the donor's extract_all payloads");
    }

} // namespace

int main(int argc, char** argv) {
    const auto options = gxbuild3::test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }
    bool passed = true;
    passed = test_ini_payload_lookup_failure_is_terminal() && passed;
    passed = test_ini_payload_is_required_unless_donor_supplies_same_basename() && passed;
    passed = test_automatic_patchset_names_and_retail_devkit_behavior() && passed;
    passed = test_jtag_resolve_populates_payloads() && passed;
    passed = test_jtag_resolve_fails_without_xell() && passed;
    passed = test_glitch_resolve_populates_xell_only() && passed;
    passed = test_glitch2m_resolve_populates_fuses() && passed;
    passed = test_glitch2m_without_cb_b_is_refused() && passed;
    passed = test_devgl_resolve_finds_the_sb_key_and_builds_retail_fuses() && passed;
    passed = test_devgl_resolve_without_the_sb_key_is_refused() && passed;
    passed = test_glitch_resolve_fails_without_xell() && passed;
    passed = test_glitch3_searches_all_g3_roots_before_g2_fallback() && passed;
    passed = test_glitch3_prefers_g3_then_g2_and_fails_cleanly_without_either() && passed;
    passed = test_missing_patchset_and_addon_errors_are_precise() && passed;
    passed = test_addons_resolve_from_root_bin_in_cli_order() && passed;
    passed = test_retail_and_devkit_reject_addons_without_automatic_patchset() && passed;
    passed = test_direct_build_args_reject_unconfined_patch_components() && passed;
    passed = test_glitch_khv_donor_does_not_resolve_ambiguous_fixed_payloads() && passed;
    passed = test_final_input_is_validated_before_return() && passed;
    passed = test_resolution_digests(*options) && passed;
    passed = test_retail_resolve_keeps_donor_payloads_as_today() && passed;
    return passed ? 0 : 1;
}
