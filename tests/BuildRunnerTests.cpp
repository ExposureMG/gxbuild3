#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "TestResult.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/Stages.hpp"
#include "support/render/ExtractProjection.hpp"
#include "utils/XeRsa.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    // The shared builders (tests/support/builders/), byte for byte what this file defined.
    using gxbuild3::test::append_be32;
    using gxbuild3::test::append_patch_entry;
    using gxbuild3::test::devgl_input;
    using gxbuild3::test::different_valid_cpu_key;
    using gxbuild3::test::digest_input;
    using gxbuild3::test::fresh_input;
    using gxbuild3::test::glitch_input;
    using gxbuild3::test::glitch_patchset;
    using gxbuild3::test::invalid_cpu_key;
    using gxbuild3::test::jtag_input;
    using gxbuild3::test::make_smc;
    using gxbuild3::test::sha1_hex;
    using gxbuild3::test::valid_cpu_key;
    using gxbuild3::test::valid_system_update;
    using gxbuild3::test::valid_xell;

    // The Result-returning donor builder, unwrapped as before: a failure aborts the binary with
    // its description. It goes with the goldens.
    Bytes make_donor(const Input& source,
                     std::initializer_list<std::pair<uint8_t, Bytes>> mobiles) {
        return test::must(gxbuild3::test::make_donor(source, mobiles));
    }

    void set_source_date_epoch(const char* value) {
#ifdef _WIN32
        _putenv_s("SOURCE_DATE_EPOCH", value ? value : "");
#else
        if (value) {
            setenv("SOURCE_DATE_EPOCH", value, 1);
        } else {
            unsetenv("SOURCE_DATE_EPOCH");
        }
#endif
    }

    // run_build output digests (tests/golden/run_build_digests.txt): SmallBlock, NewSmallBlock,
    // BigBlock and Emmc crossed with retail, glitch2, devkit and devgl, each built twice under a
    // pinned build time (SOURCE_DATE_EPOCH in UTC) with every donor nonce filled so no nonce is
    // drawn. The two builds must be byte-identical; the SHA-1 of the output goes to the golden.
    bool test_run_build_output_digests(const gxbuild3::test::GoldenOptions& options) {
        constexpr std::array layouts{std::pair{ImageType::SmallBlock, "small"},
                                     std::pair{ImageType::NewSmallBlock, "newsmall"},
                                     std::pair{ImageType::BigBlock, "big"},
                                     std::pair{ImageType::Emmc, "emmc"}};
        constexpr std::array builds{
            std::pair{BuildType::Retail, "retail"}, std::pair{BuildType::Glitch2, "glitch2"},
            std::pair{BuildType::Devkit, "devkit"}, std::pair{BuildType::Devgl, "devgl"}};

        const auto build_pinned = [](const Input& input) {
            const gxbuild3::test::ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105724");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        };

        std::string rendered;
        size_t total = 0;
        size_t identical = 0;
        bool ok = true;
        for (const auto& [image_type, layout_name] : layouts) {
            for (const auto& [build_type, build_name] : builds) {
                ++total;
                const std::string label = std::string{layout_name} + '.' + build_name;
                const auto input = digest_input(image_type, build_type);
                const auto first = build_pinned(input);
                const auto second = build_pinned(input);
                if (!first || !second) {
                    rendered += label + " error=" +
                                (first ? second.error().message : first.error().message) + '\n';
                    ok = require(false, label + " builds") && ok;
                    continue;
                }
                if (!require(*first == *second, label + " builds byte-identically twice")) {
                    rendered += label + " nondeterministic\n";
                    ok = false;
                    continue;
                }
                ++identical;
                char size[32];
                std::snprintf(size, sizeof(size), "0x%zx", first->size());
                rendered += label + " size=" + size + " sha1=" + sha1_hex(*first) + '\n';
            }
        }
        const bool matched = gxbuild3::test::check_golden(options, "run_build_digests", rendered);
        std::cout << "run_build digests: built twice and identical " << identical << '/' << total
                  << ", compared " << (matched ? identical : 0) << '/' << total
                  << " with tests/golden/run_build_digests.txt\n";
        return require(matched, "run_build output digests match the golden") && ok;
    }

    // Every public extract_* projection (tests/support/render/ExtractProjection.hpp) of two
    // run_build digest outputs, against tests/golden/extract_projections_synthetic.txt:
    //   small.glitch2             CB_A + CB_B, CE, CF/CG in slot 0, patch file and XeLL;
    //   newsmall.devkit           the SB/SC/SD/SE chain, where extract_all_info states the SC
    //                             decrypted while extract_some_info reads it sealed;
    //   newsmall.devkit.zero-key  the same image under the all-zero CPU key: its keyvault was
    //                             sealed under the test console's key, stays sealed, and
    //                             extract_all leaves it out (extract_metadata refuses).
    // Each image is built twice under the pinned build time and donor nonces, and each image
    // is projected twice; both must be identical. The mydata dump's projections live in
    // gxbuild3_orchestration_golden_tests (tests/golden/extract_projections_mydata.txt).
    bool test_extract_projection_snapshots(const gxbuild3::test::GoldenOptions& options) {
        const auto build_pinned = [](const Input& input) {
            const gxbuild3::test::ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105724");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        };
        const auto cpu_key = valid_cpu_key();
        const std::array<uint8_t, 16> zero_key{};
        struct Case {
            std::string_view label;
            ImageType image_type;
            BuildType build_type;
            bool zero_cpu_key;
        };
        constexpr std::array cases{
            Case{"small.glitch2", ImageType::SmallBlock, BuildType::Glitch2, false},
            Case{"newsmall.devkit", ImageType::NewSmallBlock, BuildType::Devkit, false},
            Case{"newsmall.devkit.zero-key", ImageType::NewSmallBlock, BuildType::Devkit, true},
        };

        std::string rendered;
        size_t stable = 0;
        size_t comparisons = 0;
        size_t agreements = 0;
        bool ok = true;
        for (const auto& c : cases) {
            const std::string label{c.label};
            const auto input = digest_input(c.image_type, c.build_type);
            const auto first = build_pinned(input);
            const auto second = build_pinned(input);
            if (!first || !second) {
                rendered += label + " build-error=" +
                            (first ? second.error().message : first.error().message) + '\n';
                ok = require(false, label + " builds") && ok;
                continue;
            }
            if (!require(*first == *second, label + " builds byte-identically twice")) {
                rendered += label + " nondeterministic-build\n";
                ok = false;
                continue;
            }
            const std::span<const uint8_t> key =
                c.zero_cpu_key ? std::span<const uint8_t>(zero_key) : std::span(cpu_key);
            const auto once =
                gxbuild3::test::projection::render_extract_projections(label, *first, key);
            const auto twice =
                gxbuild3::test::projection::render_extract_projections(label, *first, key);
            comparisons += once.comparisons;
            agreements += once.agreements;
            for (const auto& what : once.disagreements) {
                ok = require(false, what + " renders the same as the core's span overload") && ok;
            }
            if (require(once.text == twice.text, label + " projects identically twice")) {
                ++stable;
            } else {
                ok = false;
            }
            rendered += once.text;
        }
        const bool matched =
            gxbuild3::test::check_golden(options, "extract_projections_synthetic", rendered);
        std::cout << "extract projections: inputs stable " << stable << '/' << cases.size()
                  << ", overloads and shims agreed " << agreements << '/' << comparisons
                  << ", compared " << (matched ? stable : 0) << '/' << cases.size()
                  << " with tests/golden/extract_projections_synthetic.txt\n";
        return require(matched, "synthetic extract projections match the golden") && ok;
    }

    std::string_view build_error_code_name(BuildErrorCode code) {
        switch (code) {
            case BuildErrorCode::InvalidInput:
                return "InvalidInput";
            case BuildErrorCode::InvalidDonor:
                return "InvalidDonor";
            case BuildErrorCode::InvalidSmc:
                return "InvalidSmc";
            case BuildErrorCode::InvalidKeyvault:
                return "InvalidKeyvault";
            case BuildErrorCode::InvalidBootloader:
                return "InvalidBootloader";
            case BuildErrorCode::PatchFailure:
                return "PatchFailure";
            case BuildErrorCode::EncryptionFailure:
                return "EncryptionFailure";
            case BuildErrorCode::SerializationFailure:
                return "SerializationFailure";
            case BuildErrorCode::Internal:
                return "Internal";
        }
        return "unknown";
    }

    // run_build failure exits (tests/golden/run_build_failures.txt): one input per exit that an
    // Input can reach, in run_build's stage order (validation, signing key, donor, SMC, keyvault,
    // boot chain, patch file, SD signing, extra stages, metadata and nonces, patch slots,
    // payloads and layout, FlashFS, encryption, write). Each line pins the BuildErrorCode and the
    // whole describe() message, outermost context first, so moving code between functions cannot
    // reorder or drop a context layer unseen. The exits only a fault could reach are listed at
    // the end of the golden as not covered.
    bool test_run_build_failure_exits_keep_code_and_message(
        const gxbuild3::test::GoldenOptions& options) {
        struct Case {
            std::string_view label;
            Input (*input)();
        };
        const std::array cases{
            Case{"validate.cpu-key-length",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key.pop_back();
                     return input;
                 }},
            Case{"validate.devgl-without-sb-key",
                 [] {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key.reset();
                     return input;
                 }},
            Case{"devgl.malformed-sb-key",
                 [] {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key = Bytes(gxbuild3::utils::kXeRsa2048PrivateKeySize, 0);
                     return input;
                 }},
            Case{"donor.not-a-nand",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = Bytes(0x10, 0x5A);
                     return input;
                 }},
            Case{"donor.wrong-cpu-key",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = make_donor(input, {});
                     const auto wrong_key = different_valid_cpu_key();
                     input.metadata.cpu_key.assign(wrong_key.begin(), wrong_key.end());
                     return input;
                 }},
            Case{"smc.too-short",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.smc = Bytes(0x10, 0x11);
                     return input;
                 }},
            Case{"smc.jtag-over-a-clean-smc",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.metadata.smc = make_smc(0x11);
                     return input;
                 }},
            Case{"keyvault.wrong-length",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.keyvault = Bytes(0x10, 0x22);
                     return input;
                 }},
            Case{"chain.orphan-cg0",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg0 = valid_system_update(0x51).second;
                     return input;
                 }},
            Case{"chain.orphan-cg1",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg1 = valid_system_update(0x61).second;
                     return input;
                 }},
            Case{"bootloaders.malformed-cb",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cb_or_a = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"bootloaders.malformed-cf0",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cf0 = Bytes{0x43, 0x46, 0x00};
                     return input;
                 }},
            Case{"bootloaders.cd-without-payload",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCd cd{};
                     cd.header.header.magic = NANDBootloaderMagic::CD;
                     cd.header.header.version = 1;
                     cd.header.header.size = sizeof(cd_header);
                     input.bootloaders.cd = cd.serialize();
                     return input;
                 }},
            Case{"bootloaders.glitch3-without-cb-x",
                 [] {
                     auto input = glitch_input(BuildType::Glitch3,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"bootloaders.glitch1-with-cb-b",
                 [] {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"patch.malformed-patch-file",
                 [] {
                     Bytes patchset;
                     append_be32(patchset, 0x20);
                     append_be32(patchset, 1);
                     append_be32(patchset, 0);
                     append_be32(patchset, 0xFFFFFFFF);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.glitch2-without-cb-b",
                 [] {
                     return glitch_input(BuildType::Glitch2,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                 }},
            Case{"patch.cb-past-32-bit-space",
                 [] {
                     Bytes patchset;
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     append_patch_entry(patchset, 0x30, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.cd-past-32-bit-space",
                 [] {
                     Bytes patchset;
                     append_patch_entry(patchset, 0x20, 0);
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.chain-over-capacity",
                 [] {
                     return glitch_input(BuildType::Glitch, glitch_patchset(0x70000, 0xDEADBEEF,
                                                                            0x30, 0, Bytes{0xA0}));
                 }},
            Case{"extra.malformed-jtag-cb",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cb = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"extra.malformed-jtag-cd",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cd = Bytes{0x43, 0x44, 0x00};
                     return input;
                 }},
            Case{"metadata.cb-without-per-box",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCb cb{};
                     cb.header.header.magic = NANDBootloaderMagic::CB;
                     cb.header.header.version = 1;
                     cb.header.header.size = sizeof(generic_header);
                     input.bootloaders.cb_or_a = cb.serialize();
                     return input;
                 }},
            Case{"slots.jtag-patch-over-0x4000", [] { return jtag_input(Bytes(0x4001, 0x44)); }},
            Case{"slots.khv-over-its-slot",
                 [] {
                     return glitch_input(BuildType::Glitch,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55)));
                 }},
            Case{"payloads.malformed-xell",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     InputPayloads payloads{};
                     payloads.xell = Bytes(0x40000, 0);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"layout.xell-over-the-rebooter",
                 [] {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     InputPayloads payloads{};
                     payloads.xell = valid_xell();
                     payloads.rebooter = Bytes(0x1000, 0x71);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"flashfs.add-a-257th-file",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
                     for (size_t index = 0; index < 257; ++index) {
                         input.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
                     }
                     return input;
                 }},
            Case{"encrypt.invalid-cpu-key",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key = invalid_cpu_key();
                     return input;
                 }},
            Case{"write.mobile-over-a-block",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x800, 2)}});
                     *input.mobiles.slot(0x32) = Bytes(0x4001, 9);
                     return input;
                 }},
        };
        // The exits no Input reaches; only a fault seam could, and none is added.
        constexpr std::array<std::pair<std::string_view, std::string_view>, 19> uncovered{{
            {"donor.read", "FlashImage::read refuses only an empty dump, which run_build skips"},
            {"chain.clear-donor-records",
             "needs a parsed donor whose boot chain runs past its own image; none is built"},
            {"smc.reboot-patch",
             "apply_signature_patch fails only on a null buffer or a bad built-in pattern"},
            {"patch.missing-section",
             "the glitch patch file parser always yields the first, CD and KHV sections"},
            {"patch.cb-apply", "the chain capacity check bounds the patched CB, and an aligned "
                               "patched stage always parses again"},
            {"patch.cb-b-apply", "as patch.cb-apply, for the CB_B"},
            {"patch.cd-apply", "as patch.cb-apply, for the CD"},
            {"sd.sign", "a key that parses (n = pq, consistent exponents) signs and verifies, and "
                        "an SD is never shorter than its 0x260-byte header"},
            {"sd.reparse", "the signed SD keeps the size it parsed with"},
            {"nonces.open-cg", "a CG that parsed opens: prepare_payload repeats the parse's check"},
            {"slots.khv-missing", "the glitch patch file parser always yields a KHV section"},
            {"flashfs.data-limit", "every layout leaves 1..0xFFFF FlashFS blocks"},
            {"flashfs.first-block",
             "no layout lays its fixed payloads past the FlashFS data limit"},
            {"flashfs.format", "every layout's block count fits the FlashFS block map"},
            {"flashfs.reserve-tail", "the tail lies inside the formatted block map"},
            {"flashfs.reserve-bad-block", "a freshly formatted map holds only free or reserved "
                                          "blocks below the data limit"},
            {"flashfs.reserve-payload-blocks",
             "the fixed payload ranges lie inside the formatted block map"},
            {"flashfs.seal-secured-file",
             "sealing fails only on a CPU key that is not 16 bytes, which validation refuses"},
            {"internal.std-exception",
             "run_build's catch: only a std exception (an allocation failure) reaches it"},
        }};

        std::string rendered;
        size_t refused = 0;
        bool ok = true;
        for (const auto& test_case : cases) {
            const std::string label{test_case.label};
            const auto input = test_case.input();
            const auto first = run_build(input);
            const auto second = run_build(input);
            if (first || second) {
                rendered += label + " built\n";
                ok = require(false, label + " is refused") && ok;
                continue;
            }
            if (!require(first.error().code == second.error().code &&
                             first.error().message == second.error().message,
                         label + " is refused the same way twice")) {
                rendered += label + " nondeterministic\n";
                ok = false;
                continue;
            }
            ++refused;
            rendered += label + " code=" + std::string{build_error_code_name(first.error().code)} +
                        " message=" + first.error().message + '\n';
        }
        for (const auto& [label, reason] : uncovered) {
            rendered += "not-covered " + std::string{label} + ": " + std::string{reason} + '\n';
        }
        const bool matched = gxbuild3::test::check_golden(options, "run_build_failures", rendered);
        std::cout << "run_build failure exits: refused " << refused << '/' << cases.size()
                  << ", compared " << (matched ? refused : 0) << '/' << cases.size()
                  << " with tests/golden/run_build_failures.txt, " << uncovered.size()
                  << " exits not covered\n";
        return require(matched, "run_build failure exits match the golden") && ok;
    }
} // namespace

int main(int argc, char** argv) {
    const auto golden = gxbuild3::test::golden_options(argc, argv);
    if (!golden) {
        return 2;
    }
    bool passed = true;
    passed = test_run_build_output_digests(*golden) && passed;
    passed = test_extract_projection_snapshots(*golden) && passed;
    passed = test_run_build_failure_exits_keep_code_and_message(*golden) && passed;
    return passed ? 0 : 1;
}
