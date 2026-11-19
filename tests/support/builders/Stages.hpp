#pragma once

// Synthetic SMCs, keyvaults and boot chains shared by the orchestration and resolver tests and
// the run_build and resolver goldens. Moved verbatim from tests/BuildRunnerTests.cpp and
// tests/BuildInputResolverTests.cpp; tests/golden/run_build_digests.txt, run_build_failures.txt,
// extract_projections_synthetic.txt and resolver_build_requests.txt depend on their bytes. No
// GoogleTest here.

#include "Args.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild3::test {

    using Bytes = std::vector<uint8_t>;

    // A plaintext SMC of 0x300 marker bytes with the motherboard byte 0x10 at 0x100.
    [[nodiscard]] Bytes make_smc(uint8_t marker);

    // Writes the JTAG hack mark D0 00 00 1B at 0x200, which a JTAG image requires of its SMC.
    void mark_jtag_smc(Bytes& smc);

    // make_smc(marker) with the JTAG mark.
    [[nodiscard]] Bytes make_jtag_smc(uint8_t marker);

    // Where clean_retail_smc() carries its reboot site.
    inline constexpr size_t kSmcRebootSite = 0x180;

    // A clean retail SMC: motherboard nibble at 0x100, the reboot site "05 ?? E5 ?? B4 05" at
    // 0x180, and the four zero bytes every plaintext SMC ends in.
    [[nodiscard]] Bytes clean_retail_smc();

    // The plaintext as the keyvault codec gives it back after sealing it under cpu_key and
    // opening it again. The key must be valid (the keyvault codec cannot fail on it).
    [[nodiscard]] Bytes canonical_keyvault(std::span<const uint8_t> cpu_key, Bytes plaintext);

    // canonical_keyvault over Keyvault::kSize marker bytes.
    [[nodiscard]] Bytes canonical_keyvault_filled(std::span<const uint8_t> cpu_key, uint8_t marker);

    // canonical_keyvault_filled(cpu_key, marker) sealed under cpu_key, as a kv.bin holds it.
    [[nodiscard]] Bytes encrypted_keyvault(std::span<const uint8_t> cpu_key, uint8_t marker);

    // A plaintext retail chain: CB (0x380 zero bytes), SC (0x20 x 0x53) and CD (0x20 x 0x42,
    // CE hash byte 0 set), each version 1 with a zero nonce.
    [[nodiscard]] InputBootloaders valid_bootloaders();

} // namespace gxbuild3::test
