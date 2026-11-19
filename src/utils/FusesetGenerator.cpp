#include "utils/FusesetGenerator.hpp"

#include <Log.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace gxbuild3::utils {
namespace {

constexpr std::array<uint8_t, kFuseLineSize> kFuseLine00 = {
    0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

constexpr std::array<uint8_t, 6> kFuseLine01Prefix = {
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
};

constexpr std::array<uint8_t, 2> fuse_line01_suffix(FuseConsoleType console_type) {
    switch (console_type) {
        case FuseConsoleType::RetailPhat:
            return {0x0F, 0xF0};
        case FuseConsoleType::RetailSlim:
            return {0xF0, 0xF0};
        case FuseConsoleType::TestKit:
            return {0xF0, 0x0F};
        case FuseConsoleType::Devkit:
            return {0x0F, 0x0F};
    }

    return {0x00, 0x00};
}

bool is_retail_slim(ConsoleType console_type) {
    switch (console_type) {
        case ConsoleType::Trinity:
        case ConsoleType::TrinityBB:
        case ConsoleType::TrinityBigFFS:
        case ConsoleType::Corona:
        case ConsoleType::Corona4G:
        case ConsoleType::Winchester:
        case ConsoleType::Winchester4G:
            return true;
        default:
            return false;
    }
}

void set_fuse_line(std::vector<uint8_t>& fuse_data, size_t line_index,
                   const std::array<uint8_t, kFuseLineSize>& line) {
    const size_t offset = line_index * kFuseLineSize;
    std::copy(line.begin(), line.end(), fuse_data.begin() + static_cast<ptrdiff_t>(offset));
}

void set_dashboard_region(
    std::vector<uint8_t>& fuse_data,
    const std::array<uint8_t, kDashboardFuseRegionSize>& dashboard_region) {
    const size_t offset = kDashboardFuseLineStart * kFuseLineSize;
    std::copy(dashboard_region.begin(), dashboard_region.end(),
              fuse_data.begin() + static_cast<ptrdiff_t>(offset));
}

} // namespace

std::optional<FuseConsoleType> resolve_fuse_console_type(ConsoleType console_type,
                                                         BuildType build_type) {
    if (build_type == BuildType::Devkit) {
        return FuseConsoleType::Devkit;
    }

    return is_retail_slim(console_type) ? FuseConsoleType::RetailSlim
                                        : FuseConsoleType::RetailPhat;
}

std::optional<std::array<uint8_t, kFuseLineSize>> parse_fuse_line(std::string_view hex_line) {
    std::string cleaned;
    cleaned.reserve(hex_line.size());

    for (const char c : hex_line) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            cleaned.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }

    if (cleaned.size() != (kFuseLineSize * 2)) {
        Log::Error("parse_fuse_line: expected {} hex digits, got {}", kFuseLineSize * 2,
                   cleaned.size());
        return std::nullopt;
    }

    std::array<uint8_t, kFuseLineSize> line = {};
    for (size_t i = 0; i < kFuseLineSize; ++i) {
        try {
            line[i] = static_cast<uint8_t>(std::stoul(cleaned.substr(i * 2, 2), nullptr, 16));
        } catch (const std::exception&) {
            Log::Error("parse_fuse_line: invalid byte at index {}", i);
            return std::nullopt;
        }
    }

    return line;
}

std::optional<std::array<uint8_t, kDashboardFuseRegionSize>> encode_dashboard_ldv_region(
    uint8_t cf_ldv) {
    constexpr size_t kDashboardNibbleCount = kDashboardFuseRegionSize * 2;

    if (cf_ldv > kDashboardNibbleCount) {
        Log::Error("encode_dashboard_ldv_region: cf_ldv {} exceeds supported nibble capacity {}",
                   cf_ldv, kDashboardNibbleCount);
        return std::nullopt;
    }

    std::array<uint8_t, kDashboardFuseRegionSize> region = {};

    for (size_t nibble_index = 0; nibble_index < cf_ldv; ++nibble_index) {
        const size_t byte_index = nibble_index / 2;
        const bool high_nibble = (nibble_index % 2) == 0;
        region[byte_index] |= high_nibble ? 0xF0 : 0x0F;
    }

    return region;
}

std::optional<std::vector<uint8_t>> generate_fuseset(const FusesetGenerationRequest& request) {
    if (!request.cb_fuseline) {
        Log::Error("generate_fuseset: raw CB fuseline is required until CB LDV encoding rules are "
                   "fully implemented");
        return std::nullopt;
    }

    std::vector<uint8_t> fuse_data(kFuseRegionSize, 0x00);

    set_fuse_line(fuse_data, 0, kFuseLine00);

    std::array<uint8_t, kFuseLineSize> line01 = {};
    std::copy(kFuseLine01Prefix.begin(), kFuseLine01Prefix.end(), line01.begin());
    const auto line01_suffix = fuse_line01_suffix(request.console_type);
    std::copy(line01_suffix.begin(), line01_suffix.end(), line01.begin() + 6);
    set_fuse_line(fuse_data, 1, line01);

    set_fuse_line(fuse_data, 2, *request.cb_fuseline);

    std::array<uint8_t, kFuseLineSize> cpu_key_hi = {};
    std::copy_n(request.cpu_key.begin(), kFuseLineSize, cpu_key_hi.begin());
    set_fuse_line(fuse_data, 3, cpu_key_hi);
    set_fuse_line(fuse_data, 4, cpu_key_hi);

    std::array<uint8_t, kFuseLineSize> cpu_key_lo = {};
    std::copy_n(request.cpu_key.begin() + kFuseLineSize, kFuseLineSize, cpu_key_lo.begin());
    set_fuse_line(fuse_data, 5, cpu_key_lo);
    set_fuse_line(fuse_data, 6, cpu_key_lo);

    if (request.dashboard_fuselines) {
        set_dashboard_region(fuse_data, *request.dashboard_fuselines);
    } else if (request.cf_ldv) {
        auto dashboard_region = encode_dashboard_ldv_region(*request.cf_ldv);
        if (!dashboard_region) {
            return std::nullopt;
        }
        set_dashboard_region(fuse_data, *dashboard_region);
    }

    return fuse_data;
}

} // namespace gxbuild3::utils
