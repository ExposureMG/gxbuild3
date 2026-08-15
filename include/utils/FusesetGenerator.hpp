#pragma once

#include "Args.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace gxbuild3::utils {

constexpr size_t kFuseLineCount = 12;
constexpr size_t kFuseLineSize = 8;
constexpr size_t kFuseRegionSize = kFuseLineCount * kFuseLineSize;
constexpr size_t kDashboardFuseLineStart = 7;
constexpr size_t kDashboardFuseLineCount = 5;
constexpr size_t kDashboardFuseRegionSize = kDashboardFuseLineCount * kFuseLineSize;

enum class FuseConsoleType {
    RetailPhat,
    RetailSlim,
    TestKit,
    Devkit,
};

struct FusesetGenerationRequest {
    FuseConsoleType console_type;
    std::array<uint8_t, 16> cpu_key;
    std::optional<std::array<uint8_t, kFuseLineSize>> cb_fuseline;
    std::optional<std::array<uint8_t, kDashboardFuseRegionSize>> dashboard_fuselines;
    std::optional<uint8_t> cf_ldv;
};

std::optional<FuseConsoleType> resolve_fuse_console_type(ConsoleType console_type,
                                                         BuildType build_type);

std::optional<std::array<uint8_t, kFuseLineSize>> parse_fuse_line(std::string_view hex_line);

std::optional<std::array<uint8_t, kDashboardFuseRegionSize>> encode_dashboard_ldv_region(
    uint8_t cf_ldv);

std::optional<std::vector<uint8_t>> generate_fuseset(const FusesetGenerationRequest& request);

} // namespace gxbuild3::utils
