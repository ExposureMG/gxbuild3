#include "bootloaders/XConfig.hpp"

#include <cstring>

namespace XConfig {
    static constexpr size_t kOffsetStatic = 0x0000;
    static constexpr size_t kOffsetStatistic = 0x010E;
    static constexpr size_t kOffsetSecured = 0x06E6;
    static constexpr size_t kOffsetUser = 0x08E6;
    static constexpr size_t kOffsetXnetMachineAcct = 0x0AE3;
    static constexpr size_t kOffsetXnetParameters = 0x0CD3;
    static constexpr size_t kOffsetMediaCenter = 0x0CE0;
    static constexpr size_t kOffsetConsole = 0x142C;
    static constexpr size_t kOffsetDvd = 0x1570;
    static constexpr size_t kOffsetIptv = 0x1808;
    static constexpr size_t kOffsetSystem = 0x1A08;

    static constexpr size_t kMinRegionSize =
        kOffsetSystem + sizeof(xconfig_system_settings_t); // 0x1A18

    std::string_view ParseErrorString(ParseError e) noexcept {
        switch (e) {
            case ParseError::NullBuffer:
                return "null buffer";
            case ParseError::BufferTooSmall:
                return "buffer too small for XConfig region";
        }
        return "unknown";
    }

    std::expected<xconfig_master_t, ParseError> Parse(std::span<const uint8_t> buf,
                                                      size_t base_offset) noexcept {
        if (buf.data() == nullptr)
            return std::unexpected(ParseError::NullBuffer);
        if (buf.size_bytes() < base_offset + kMinRegionSize)
            return std::unexpected(ParseError::BufferTooSmall);

        const uint8_t* base = buf.data() + base_offset;
        xconfig_master_t out{};

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

        return out;
    }

} // namespace XConfig