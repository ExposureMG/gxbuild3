#include "utils/FusesetGenerator.hpp"
#include "utils/Log.hpp"
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
                case ConsoleType::Corona:
                case ConsoleType::Winchester:
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
            Log::Error("Expected {} hex digits for fuse line, got {}", kFuseLineSize * 2,
                       cleaned.size());
            return std::nullopt;
        }

        std::array<uint8_t, kFuseLineSize> line = {};
        for (size_t i = 0; i < kFuseLineSize; ++i) {
            try {
                line[i] = static_cast<uint8_t>(std::stoul(cleaned.substr(i * 2, 2), nullptr, 16));
            } catch (const std::exception&) {
                Log::Error("Invalid fuse byte at index {}", i);
                return std::nullopt;
            }
        }

        return line;
    }

    std::optional<std::array<uint8_t, kFuseLineSize>> encode_cb_ldv_line(uint8_t cb_ldv) {
        constexpr size_t kCbNibbleCount = kFuseLineSize * 2;

        if (cb_ldv > kCbNibbleCount) {
            Log::Error("CB LDV {} exceeds supported nibble capacity {}", cb_ldv,
                       kCbNibbleCount);
            return std::nullopt;
        }

        std::array<uint8_t, kFuseLineSize> line = {};

        for (size_t nibble_index = 0; nibble_index < cb_ldv; ++nibble_index) {
            const size_t byte_index = nibble_index / 2;
            const bool high_nibble = (nibble_index % 2) == 0;
            line[byte_index] |= high_nibble ? 0xF0 : 0x0F;
        }

        return line;
    }

    std::optional<std::array<uint8_t, kDashboardFuseRegionSize>>
    encode_dashboard_ldv_region(uint8_t cf_ldv) {
        constexpr size_t kDashboardNibbleCount = kDashboardFuseRegionSize * 2;

        if (cf_ldv > kDashboardNibbleCount) {
            Log::Error(
                "CF LDV {} exceeds supported nibble capacity {}",
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
        std::array<uint8_t, kFuseLineSize> cb_line = {};
        if (request.cb_fuseline) {
            cb_line = *request.cb_fuseline;
        } else if (request.cb_ldv) {
            auto encoded = encode_cb_ldv_line(*request.cb_ldv);
            if (!encoded) {
                return std::nullopt;
            }
            cb_line = *encoded;
        }

        std::vector<uint8_t> fuse_data(kFuseRegionSize, 0x00);

        set_fuse_line(fuse_data, 0, kFuseLine00);

        std::array<uint8_t, kFuseLineSize> line01 = {};
        std::copy(kFuseLine01Prefix.begin(), kFuseLine01Prefix.end(), line01.begin());
        const auto line01_suffix = fuse_line01_suffix(request.console_type);
        std::copy(line01_suffix.begin(), line01_suffix.end(), line01.begin() + 6);
        set_fuse_line(fuse_data, 1, line01);

        set_fuse_line(fuse_data, 2, cb_line);

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

    std::optional<std::vector<uint8_t>> generate_fuseset(FuseConsoleType console_type,
                                                         std::span<const uint8_t> cpu_key,
                                                         uint8_t cb_ldv, uint8_t cf_ldv) {
        if (cpu_key.size() != 16) {
            Log::Error("CPU key must be exactly 16 bytes, got {}",
                       cpu_key.size());
            return std::nullopt;
        }

        FusesetGenerationRequest req{};
        req.console_type = console_type;
        std::copy_n(cpu_key.data(), 16, req.cpu_key.begin());
        req.cb_ldv = cb_ldv;
        req.cf_ldv = cf_ldv;

        return generate_fuseset(req);
    }

    std::optional<std::vector<uint8_t>> generate_fuseset(ConsoleType console_type,
                                                         BuildType build_type,
                                                         std::span<const uint8_t> cpu_key,
                                                         uint8_t cb_ldv, uint8_t cf_ldv) {
        auto resolved_type = resolve_fuse_console_type(console_type, build_type);
        if (!resolved_type) {
            return std::nullopt;
        }
        return generate_fuseset(*resolved_type, cpu_key, cb_ldv, cf_ldv);
    }

} // namespace gxbuild3::utils
