#include "utils/FusesetGenerator.hpp"

#include "Endian.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace gxbuild3::utils {
    namespace {

        constexpr std::array<uint8_t, kFuseLineSize> kFuseLine00 = {
            0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        };

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

    std::optional<uint32_t> read_cb_word(std::span<const uint8_t> cb) {
        if (cb.size() < kCbWordOffset + sizeof(uint32_t)) {
            Log::Error("CB of 0x{:X} bytes is too short to carry its console word at 0x{:X}",
                       cb.size(), kCbWordOffset);
            return std::nullopt;
        }
        uint32_t wire_value = 0;
        std::memcpy(&wire_value, cb.data() + kCbWordOffset, sizeof(wire_value));
        return bswap32(wire_value);
    }

    std::optional<std::array<uint8_t, kFuseLineSize>>
    encode_console_type_line(uint8_t console_type) {
        // Six 0x0F bytes, then two naming the type: devkit, retail, testkit, retail slim.
        constexpr std::array<std::array<uint8_t, 2>, 4> kTypeSuffixes = {{
            {0x0F, 0x0F},
            {0x0F, 0xF0},
            {0xF0, 0x0F},
            {0xF0, 0xF0},
        }};
        if (console_type >= kTypeSuffixes.size()) {
            Log::Error("CB console type 0x{:02X} has no fuse encoding", console_type);
            return std::nullopt;
        }

        std::array<uint8_t, kFuseLineSize> line = {0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F};
        line[6] = kTypeSuffixes[console_type][0];
        line[7] = kTypeSuffixes[console_type][1];
        return line;
    }

    std::array<uint8_t, kFuseLineSize> encode_sequence_allow_line(uint16_t sequence_allow) {
        // One 0xF nibble per allow bit, bit 0 in the line's top nibble.
        std::array<uint8_t, kFuseLineSize> line = {};
        for (size_t bit = 0; bit < 16; ++bit) {
            if ((sequence_allow & (1U << bit)) != 0) {
                line[bit / 2] |= (bit % 2) == 0 ? 0xF0 : 0x0F;
            }
        }
        return line;
    }

    std::optional<std::array<uint8_t, kDashboardFuseRegionSize>>
    encode_dashboard_ldv_region(uint8_t cf_ldv) {
        constexpr size_t kDashboardNibbleCount = kDashboardFuseRegionSize * 2;

        if (cf_ldv > kDashboardNibbleCount) {
            Log::Error("CF LDV {} exceeds supported nibble capacity {}", cf_ldv,
                       kDashboardNibbleCount);
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
        const auto type_line =
            encode_console_type_line(static_cast<uint8_t>(request.cb_word >> 24));
        if (!type_line) {
            return std::nullopt;
        }
        const auto cb_line = request.cb_fuseline.value_or(
            encode_sequence_allow_line(static_cast<uint16_t>(request.cb_word & 0xFFFF)));

        std::vector<uint8_t> fuse_data(kFuseRegionSize, 0x00);

        set_fuse_line(fuse_data, 0, kFuseLine00);
        set_fuse_line(fuse_data, 1, *type_line);
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

    std::optional<std::vector<uint8_t>>
    generate_fuseset(uint32_t cb_word, std::span<const uint8_t> cpu_key, uint8_t cf_ldv) {
        if (cpu_key.size() != 16) {
            Log::Error("CPU key must be exactly 16 bytes, got {}", cpu_key.size());
            return std::nullopt;
        }

        FusesetGenerationRequest req{};
        req.cb_word = cb_word;
        std::copy_n(cpu_key.data(), 16, req.cpu_key.begin());
        req.cf_ldv = cf_ldv;

        return generate_fuseset(req);
    }

} // namespace gxbuild3::utils
