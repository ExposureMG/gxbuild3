#include "nand/objects/XConfig.hpp"

#include "utils/Log.hpp"

#include <algorithm>
#include <cstring>

namespace gxbuild3::nand {

    namespace {

        constexpr size_t kOffsetStatic = 0x0000;
        constexpr size_t kOffsetStatistic = 0x010E;
        constexpr size_t kOffsetSecured = 0x06E6;
        constexpr size_t kOffsetUser = 0x08E6;
        constexpr size_t kOffsetXnetMachineAcct = 0x0AE3;
        constexpr size_t kOffsetXnetParameters = 0x0CD3;
        constexpr size_t kOffsetMediaCenter = 0x0CE0;
        constexpr size_t kOffsetConsole = 0x142C;
        constexpr size_t kOffsetDvd = 0x1570;
        constexpr size_t kOffsetIptv = 0x1808;
        constexpr size_t kOffsetSystem = 0x1A08;

        constexpr size_t kMinRegionSize = kOffsetSystem + sizeof(xconfig_system_settings_t);

    } // namespace

    Result<SmcConfig> SmcConfig::parse(std::span<const uint8_t> bytes, size_t base_offset) {
        if (base_offset > bytes.size() || bytes.size() - base_offset < kMinRegionSize) {
            return fail(ErrorCode::Truncated,
                        "XConfig region at 0x{:X} needs 0x{:X} bytes, buffer is 0x{:X}",
                        base_offset, kMinRegionSize, bytes.size());
        }

        const uint8_t* base = bytes.data() + base_offset;
        SmcConfig out{};

        auto copy = [&]<typename T>(size_t offset, T& dst) noexcept {
            std::memcpy(&dst, base + offset, sizeof(T));
        };

        copy(kOffsetStatic, out.Static);
        copy(kOffsetStatistic, out.Statistic);
        copy(kOffsetSecured, out.Secured);
        copy(kOffsetUser, out.User);
        copy(kOffsetXnetMachineAcct, out.XnetMachineAccount);
        copy(kOffsetXnetParameters, out.XnetParameters);
        copy(kOffsetMediaCenter, out.MediaCenter);
        copy(kOffsetConsole, out.Console);
        copy(kOffsetDvd, out.Dvd);
        copy(kOffsetIptv, out.Iptv);
        copy(kOffsetSystem, out.System);

        Log::Debug("Parsed SMC Config (XConfig) from offset 0x{:X}", base_offset);

        return out;
    }

    Result<SmcConfig> SmcConfig::parse(const std::vector<uint8_t>& bytes, size_t base_offset) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()), base_offset);
    }

    std::vector<uint8_t> SmcConfig::serialize(size_t total_size, size_t base_offset) const {
        size_t required = base_offset + kMinRegionSize;
        size_t out_size = std::max(total_size, required);
        std::vector<uint8_t> out(out_size, 0x00);
        uint8_t* base = out.data() + base_offset;

        auto copy_to = [&]<typename T>(size_t offset, const T& src) noexcept {
            std::memcpy(base + offset, &src, sizeof(T));
        };

        copy_to(kOffsetStatic, Static);
        copy_to(kOffsetStatistic, Statistic);
        copy_to(kOffsetSecured, Secured);
        copy_to(kOffsetUser, User);
        copy_to(kOffsetXnetMachineAcct, XnetMachineAccount);
        copy_to(kOffsetXnetParameters, XnetParameters);
        copy_to(kOffsetMediaCenter, MediaCenter);
        copy_to(kOffsetConsole, Console);
        copy_to(kOffsetDvd, Dvd);
        copy_to(kOffsetIptv, Iptv);
        copy_to(kOffsetSystem, System);

        return out;
    }

    namespace xconfig {

        Result<SmcConfig> parse(std::span<const uint8_t> buf, size_t base_offset) {
            return SmcConfig::parse(buf, base_offset);
        }

        std::vector<uint8_t> serialize(const SmcConfig& cfg, size_t total_size,
                                       size_t base_offset) {
            return cfg.serialize(total_size, base_offset);
        }

    } // namespace xconfig

} // namespace gxbuild3::nand
