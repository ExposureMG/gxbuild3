#pragma once

// The CPU keys tests may use. All are public test values; none belongs to a console.
//
//   kBuildAllCpuKey          the key build_all.sh passes with -p (93FB9D01...)
//   kCliFixtureCpuKey        the key of the CLI integration fixture (CliIntegrationTests.cmake)
//   valid_cpu_key()          the first ECC-encoded run of low set bits that cpukey_valid
//                            accepts; it is kCliFixtureCpuKey (53 bits), pinned by
//                            Keys.ValidCpuKeyIsTheFirstEccEncodedBitPrefix
//   different_valid_cpu_key() bits 53..105 set and ECC-encoded: valid and different from
//                            valid_cpu_key(), pinned by Keys.DifferentValidCpuKeyIsBits53To105

#include <array>
#include <cstdint>

namespace gxbuild3::test {

    using CpuKey = std::array<uint8_t, 16>;

    inline constexpr CpuKey kBuildAllCpuKey{0x93, 0xFB, 0x9D, 0x01, 0x19, 0x30, 0xAF, 0xC4,
                                            0x53, 0xAA, 0x75, 0xB1, 0x83, 0xEF, 0xAC, 0x09};

    inline constexpr CpuKey kCliFixtureCpuKey{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x6C, 0xE5, 0x8D};

    [[nodiscard]] constexpr CpuKey valid_cpu_key() {
        return kCliFixtureCpuKey;
    }

    // Computed with XeCryptUidEccEncode, not spelled out.
    [[nodiscard]] CpuKey different_valid_cpu_key();

    // The key with bits [first_bit, end_bit) set (bit b is byte b / 8, mask 1 << (b % 8)),
    // ECC-encoded with XeCryptUidEccEncode.
    [[nodiscard]] CpuKey ecc_encoded_bit_range(unsigned first_bit, unsigned end_bit);

} // namespace gxbuild3::test
