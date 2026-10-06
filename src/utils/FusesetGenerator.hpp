#pragma once

#include "Error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::utils {

    constexpr size_t kFuseLineCount = 12;
    constexpr size_t kFuseLineSize = 8;
    constexpr size_t kFuseRegionSize = kFuseLineCount * kFuseLineSize;
    constexpr size_t kDashboardFuseLineStart = 7;
    constexpr size_t kDashboardFuseLineCount = 5;
    constexpr size_t kDashboardFuseRegionSize = kDashboardFuseLineCount * kFuseLineSize;

    // The big-endian word a plaintext CB carries at 0x3B0: console type in the top byte,
    // console sequence in the next, sequence-allow bits in the low sixteen.
    constexpr size_t kCbWordOffset = 0x3B0;

    struct FusesetGenerationRequest {
        uint32_t cb_word;
        std::array<uint8_t, 16> cpu_key;
        std::optional<std::array<uint8_t, kFuseLineSize>> cb_fuseline;
        std::optional<std::array<uint8_t, kDashboardFuseRegionSize>> dashboard_fuselines;
        std::optional<uint8_t> cf_ldv;
    };

    // The console word at 0x3B0 of a plaintext CB; Truncated when the CB is too short.
    [[nodiscard]] Result<uint32_t> read_cb_word(std::span<const uint8_t> cb);

    // Fuse line 1 for a console type; Unsupported for a type with no fuse encoding.
    [[nodiscard]] Result<std::array<uint8_t, kFuseLineSize>>
    encode_console_type_line(uint8_t console_type);

    [[nodiscard]] std::array<uint8_t, kFuseLineSize>
    encode_sequence_allow_line(uint16_t sequence_allow);

    // Fuse lines 7-11 for a CF LDV; OutOfRange when the LDV exceeds their nibble capacity.
    [[nodiscard]] Result<std::array<uint8_t, kDashboardFuseRegionSize>>
    encode_dashboard_ldv_region(uint8_t cf_ldv);

    [[nodiscard]] Result<std::vector<uint8_t>>
    generate_fuseset(const FusesetGenerationRequest& request);

    // InvalidArgument when the CPU key is not 16 bytes.
    [[nodiscard]] Result<std::vector<uint8_t>>
    generate_fuseset(uint32_t cb_word, std::span<const uint8_t> cpu_key, uint8_t cf_ldv);

} // namespace gxbuild3::utils
