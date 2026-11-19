// run_build failure exits (tests/golden/run_build_failures.txt): one input per exit that an
// Input can reach, in run_build's stage order (validation, signing key, donor, SMC, keyvault,
// boot chain, patch file, SD signing, extra stages, metadata and nonces, patch slots,
// payloads and layout, FlashFS, encryption, write). Each line pins the BuildErrorCode and the
// whole describe() message, outermost context first, so moving code between functions cannot
// reorder or drop a context layer unseen. The exits only a fault could reach are listed at
// the end of the golden as not covered.
// The old BuildRunnerTests.cpp test_run_build_failure_exits_keep_code_and_message, verbatim:
// build_error_code_name, the 30-row Case table and the 19-row uncovered table are unchanged.
// Its require() messages are problems now, and its golden compare and summary line are
// RunBuildFailureGolden's. The two inputs built over a donor (donor.wrong-cpu-key and
// write.mobile-over-a-block) used to abort the binary through must() when make_donor failed;
// each Case now returns a Result<Input>, and a failed input is a problem with no golden line.

#include "BuildRunner.hpp"
#include "RunBuildGoldenRender.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "support/Bytes.hpp"
#include "support/Keys.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/Stages.hpp"
#include "utils/XeRsa.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots::run_build_failures {
    namespace {

        using Bytes = std::vector<uint8_t>;
        using nand::BootloaderCb;
        using nand::BootloaderCd;
        using nand::cd_header;
        using nand::generic_header;
        using nand::NANDBootloaderMagic;
        using test::append_be32;
        using test::append_patch_entry;
        using test::devgl_input;
        using test::different_valid_cpu_key;
        using test::fresh_input;
        using test::glitch_input;
        using test::glitch_patchset;
        using test::invalid_cpu_key;
        using test::jtag_input;
        using test::make_donor;
        using test::make_smc;
        using test::valid_system_update;
        using test::valid_xell;

        void require(bool condition, std::string message, std::vector<std::string>& problems) {
            if (!condition) {
                problems.push_back(std::move(message));
            }
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

    } // namespace

    Rendered render() {
        struct Case {
            std::string_view label;
            Result<Input> (*input)();
        };
        const std::array cases{
            Case{"validate.cpu-key-length",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key.pop_back();
                     return input;
                 }},
            Case{"validate.devgl-without-sb-key",
                 []() -> Result<Input> {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key.reset();
                     return input;
                 }},
            Case{"devgl.malformed-sb-key",
                 []() -> Result<Input> {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key = Bytes(gxbuild3::utils::kXeRsa2048PrivateKeySize, 0);
                     return input;
                 }},
            Case{"donor.not-a-nand",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = Bytes(0x10, 0x5A);
                     return input;
                 }},
            Case{"donor.wrong-cpu-key",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     auto donor = make_donor(input, {});
                     if (!donor) {
                         return std::unexpected(std::move(donor.error()));
                     }
                     input.metadata.nand_image = std::move(*donor);
                     const auto wrong_key = different_valid_cpu_key();
                     input.metadata.cpu_key.assign(wrong_key.begin(), wrong_key.end());
                     return input;
                 }},
            Case{"smc.too-short",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.smc = Bytes(0x10, 0x11);
                     return input;
                 }},
            Case{"smc.jtag-over-a-clean-smc",
                 []() -> Result<Input> {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.metadata.smc = make_smc(0x11);
                     return input;
                 }},
            Case{"keyvault.wrong-length",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.keyvault = Bytes(0x10, 0x22);
                     return input;
                 }},
            Case{"chain.orphan-cg0",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg0 = valid_system_update(0x51).second;
                     return input;
                 }},
            Case{"chain.orphan-cg1",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg1 = valid_system_update(0x61).second;
                     return input;
                 }},
            Case{"bootloaders.malformed-cb",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cb_or_a = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"bootloaders.malformed-cf0",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cf0 = Bytes{0x43, 0x46, 0x00};
                     return input;
                 }},
            Case{"bootloaders.cd-without-payload",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCd cd{};
                     cd.header.header.magic = NANDBootloaderMagic::CD;
                     cd.header.header.version = 1;
                     cd.header.header.size = sizeof(cd_header);
                     input.bootloaders.cd = cd.serialize();
                     return input;
                 }},
            Case{"bootloaders.glitch3-without-cb-x",
                 []() -> Result<Input> {
                     auto input = glitch_input(BuildType::Glitch3,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"bootloaders.glitch1-with-cb-b",
                 []() -> Result<Input> {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"patch.malformed-patch-file",
                 []() -> Result<Input> {
                     Bytes patchset;
                     append_be32(patchset, 0x20);
                     append_be32(patchset, 1);
                     append_be32(patchset, 0);
                     append_be32(patchset, 0xFFFFFFFF);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.glitch2-without-cb-b",
                 []() -> Result<Input> {
                     return glitch_input(BuildType::Glitch2,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                 }},
            Case{"patch.cb-past-32-bit-space",
                 []() -> Result<Input> {
                     Bytes patchset;
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     append_patch_entry(patchset, 0x30, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.cd-past-32-bit-space",
                 []() -> Result<Input> {
                     Bytes patchset;
                     append_patch_entry(patchset, 0x20, 0);
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.chain-over-capacity",
                 []() -> Result<Input> {
                     return glitch_input(BuildType::Glitch, glitch_patchset(0x70000, 0xDEADBEEF,
                                                                            0x30, 0, Bytes{0xA0}));
                 }},
            Case{"extra.malformed-jtag-cb",
                 []() -> Result<Input> {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cb = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"extra.malformed-jtag-cd",
                 []() -> Result<Input> {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cd = Bytes{0x43, 0x44, 0x00};
                     return input;
                 }},
            Case{"metadata.cb-without-per-box",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCb cb{};
                     cb.header.header.magic = NANDBootloaderMagic::CB;
                     cb.header.header.version = 1;
                     cb.header.header.size = sizeof(generic_header);
                     input.bootloaders.cb_or_a = cb.serialize();
                     return input;
                 }},
            Case{"slots.jtag-patch-over-0x4000",
                 []() -> Result<Input> { return jtag_input(Bytes(0x4001, 0x44)); }},
            Case{"slots.khv-over-its-slot",
                 []() -> Result<Input> {
                     return glitch_input(BuildType::Glitch,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55)));
                 }},
            Case{"payloads.malformed-xell",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     InputPayloads payloads{};
                     payloads.xell = Bytes(0x40000, 0);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"layout.xell-over-the-rebooter",
                 []() -> Result<Input> {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     InputPayloads payloads{};
                     payloads.xell = valid_xell();
                     payloads.rebooter = Bytes(0x1000, 0x71);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"flashfs.add-a-257th-file",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
                     for (size_t index = 0; index < 257; ++index) {
                         input.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
                     }
                     return input;
                 }},
            Case{"encrypt.invalid-cpu-key",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key = invalid_cpu_key();
                     return input;
                 }},
            Case{"write.mobile-over-a-block",
                 []() -> Result<Input> {
                     auto input = fresh_input(ImageType::SmallBlock);
                     auto donor = make_donor(input, {{0x32, Bytes(0x800, 2)}});
                     if (!donor) {
                         return std::unexpected(std::move(donor.error()));
                     }
                     input.metadata.nand_image = std::move(*donor);
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

        Rendered out;
        out.cases = cases.size();
        out.uncovered = uncovered.size();
        std::string& rendered = out.text;
        for (const auto& test_case : cases) {
            const std::string label{test_case.label};
            const auto input = test_case.input();
            if (!input) {
                require(false, label + " input builds: " + input.error().describe(), out.problems);
                continue;
            }
            const auto first = run_build(*input);
            const auto second = run_build(*input);
            if (first || second) {
                rendered += label + " built\n";
                require(false, label + " is refused", out.problems);
                continue;
            }
            if (!(first.error().code == second.error().code &&
                  first.error().message == second.error().message)) {
                require(false, label + " is refused the same way twice", out.problems);
                rendered += label + " nondeterministic\n";
                continue;
            }
            ++out.refused;
            rendered += label + " code=" + std::string{build_error_code_name(first.error().code)} +
                        " message=" + first.error().message + '\n';
        }
        for (const auto& [label, reason] : uncovered) {
            rendered += "not-covered " + std::string{label} + ": " + std::string{reason} + '\n';
        }
        return out;
    }

    Result<std::string> render_file() {
        Rendered rendered = render();
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the run_build_failures render reports {} problem(s), first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::run_build_failures
