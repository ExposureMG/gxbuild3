#pragma once

// Synthetic run_build inputs shared by the orchestration tests and the run_build goldens: the
// fresh retail input, the update pair, devkit and devgl chains, the pinned donor nonces and the
// digest inputs, plus the Result-returning donor and CF/CG builders. Moved from
// tests/BuildRunnerTests.cpp; tests/golden/run_build_digests.txt, run_build_failures.txt and
// extract_projections_synthetic.txt depend on their bytes. The builders that can fail return a
// Result instead of aborting. No GoogleTest here.

#include "Args.hpp"
#include "Error.hpp"

#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace gxbuild3::test {

    using Bytes = std::vector<uint8_t>;

    // A retail input of the given layout: valid_cpu_key(), make_smc(0x11), a canonical keyvault
    // of 0x22 bytes and valid_bootloaders(). No build type is set (retail).
    [[nodiscard]] Input fresh_input(ImageType image_type);

    // A 0x40000-byte XeLL: the ELF magic, then zeros.
    [[nodiscard]] Bytes valid_xell();

    // A sealed-looking CF/CG pair (marked encrypted, never actually sealed): CF of 0x340 marker
    // bytes with the fixpoint nonce filled with marker + 1, CG of 0x40 marker bytes.
    [[nodiscard]] std::pair<Bytes, Bytes> valid_system_update(uint8_t marker);

    // What a CG carries: run_build opens a supplied sealed CG and seals it again under a new
    // nonce, so a CG is compared by its plaintext with the nonce at +0x10 cleared. nullopt when
    // the CF yields no CG key or the CG is shorter than its header; an error when either stage
    // does not parse or open.
    [[nodiscard]] Result<std::optional<Bytes>> opened_cg(const Bytes& cf_bytes,
                                                         const Bytes& cg_bytes);

    // A plaintext CF (0x340 zero bytes) with the given header fields and its per-box lockdown
    // value and pairing data.
    [[nodiscard]] Result<Bytes> decrypted_cf(uint8_t lockdown_value,
                                             std::array<uint8_t, 3> pairing_data,
                                             uint16_t source_version = 0, uint16_t source_qfe = 0,
                                             uint16_t target_version = 0, uint16_t target_qfe = 0,
                                             uint32_t reserved = 0, uint32_t cg_size = 0);

    // A small-block donor image of source's SMC, keyvault (sealed under source's CPU key) and
    // CB/SC/CD chain, encrypted under the CPU key, with the given mobile blobs (block type,
    // bytes).
    [[nodiscard]] Result<Bytes>
    make_donor(const Input& source, std::initializer_list<std::pair<uint8_t, Bytes>> mobiles);

    // A plaintext CE: key 0x55 bytes, 0x20 bytes of 0xCE.
    [[nodiscard]] Bytes valid_ce();

    // A nonce of 16 value bytes.
    [[nodiscard]] BootloaderNonce filled_nonce(uint8_t value);

    // The first 0x10 bytes of a stage (its nonce slot). The span must hold them.
    [[nodiscard]] Bytes nonce_bytes(std::span<const uint8_t> bytes);

    // A plaintext devkit chain as a release ships it: SB, SC, SD and SE with zero nonces and a
    // recognizable body each. SE states build 17489.
    [[nodiscard]] InputBootloaders devkit_bootloaders();

    // fresh_input(image_type) as a Jasper devkit build on devkit_bootloaders(), pairing
    // 12 34 56.
    [[nodiscard]] Input devkit_input(ImageType image_type);

    // The devgl KHV patch: one two-word entry at 0x1000.
    [[nodiscard]] Bytes devgl_khv();

    // Where devgl_input patches its SD: 0x10 past the SD's end.
    [[nodiscard]] uint32_t devgl_sd_patch_address(const Input& input);

    // A devgl image: the devkit chain with the glitch2m patch file's CD section on its SD, the
    // SD signed again with the throwaway SB key (support/XeRsaTestKey.hpp), and fuses and KHV
    // patches in the second slot.
    [[nodiscard]] Input devgl_input(ImageType image_type);

    // Every nonce run_build would otherwise draw: the four boot-chain positions (A1..A4), CF
    // (B1) and CG (C1).
    [[nodiscard]] DonorNonces pinned_donor_nonces();

    // The synthetic input of one run_build digest. Retail and glitch2 carry a CE and a CF/CG
    // slot; glitch2 also a CB_B, a patch file and a XeLL. Devkit and devgl are the devkit chain.
    // Every donor nonce is pinned.
    [[nodiscard]] Input digest_input(ImageType image_type, BuildType build_type);

    // A 16-byte CPU key that fails the fuse ECC check, so only the steps that seal under the key
    // refuse it.
    [[nodiscard]] Bytes invalid_cpu_key();

    // fresh_input(SmallBlock) as build_type with patchset as its automatic patch file.
    [[nodiscard]] Input glitch_input(BuildType build_type, Bytes patchset);

    // fresh_input(SmallBlock) as a JTAG build on make_jtag_smc(0x11) with
    // jtag_patchset(section4).
    [[nodiscard]] Input jtag_input(Bytes section4);

} // namespace gxbuild3::test
