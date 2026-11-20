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

    uint16_t SmcConfigBlock::compute_checksum(std::span<const uint8_t> bytes) noexcept {
        if (bytes.size() < kSumEnd) {
            return 0;
        }
        uint32_t sum = 0;
        for (size_t i = kSumStart; i < kSumEnd; ++i) {
            sum += bytes[i];
        }
        return static_cast<uint16_t>(~sum);
    }

    bool SmcConfigBlock::checksum_valid(std::span<const uint8_t> bytes) noexcept {
        if (bytes.size() < kSize) {
            return false;
        }
        const auto stored = wire::read<wire::le16>(bytes, 0, "SMC config checksum");
        return stored && stored->get() == compute_checksum(bytes);
    }

    Result<SmcConfigBlock> SmcConfigBlock::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() != kSize) {
            return fail(bytes.size() < kSize ? ErrorCode::Truncated : ErrorCode::Malformed,
                        "SMC config block must be 0x{:X} bytes, got 0x{:X}", kSize, bytes.size());
        }
        if (!checksum_valid(bytes)) {
            return fail(ErrorCode::Malformed, "SMC config block checksum mismatch");
        }
        auto static_part =
            wire::read<nand_xconfig_static>(bytes, kStaticOffset, "SMC config static settings");
        if (!static_part) {
            return std::unexpected(std::move(static_part.error()));
        }
        auto secured_part =
            wire::read<nand_xconfig_secured>(bytes, kSecuredOffset, "SMC config secured settings");
        if (!secured_part) {
            return std::unexpected(std::move(secured_part.error()));
        }

        SmcConfigBlock block{};
        block.static_settings = *static_part;
        block.secured_settings = *secured_part;
        block.reserialize = false;
        block.raw_data.assign(bytes.begin(), bytes.end());
        Log::Debug("Parsed split SMC Config block (0x{:X} bytes)", bytes.size());
        return block;
    }

    Result<SmcConfigBlock> SmcConfigBlock::parse(const std::vector<uint8_t>& bytes) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    std::vector<uint8_t> SmcConfigBlock::serialize() const {
        if (!reserialize) {
            return raw_data;
        }
        std::vector<uint8_t> out =
            raw_data.size() == kSize ? raw_data : std::vector<uint8_t>(kSize, 0xFF);
        (void) wire::write(std::span(out), kStaticOffset, static_settings,
                           "SMC config static settings");
        (void) wire::write(std::span(out), kSecuredOffset, secured_settings,
                           "SMC config secured settings");
        const uint16_t checksum = compute_checksum(out);
        (void) wire::write(std::span(out), 0, wire::le16{checksum}, "SMC config checksum");
        return out;
    }

    Result<StatisticsBlock> StatisticsBlock::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() != kSize) {
            return fail(bytes.size() < kSize ? ErrorCode::Truncated : ErrorCode::Malformed,
                        "Statistics block must be 0x{:X} bytes, got 0x{:X}", kSize, bytes.size());
        }
        auto record = wire::read<nand_xconfig_statistic>(bytes, 0, "statistics block");
        if (!record) {
            return std::unexpected(std::move(record.error()));
        }
        StatisticsBlock block{};
        block.data = *record;
        block.reserialize = false;
        block.raw_data.assign(bytes.begin(), bytes.end());
        Log::Debug("Parsed Statistics block (0x{:X} bytes)", bytes.size());
        return block;
    }

    Result<StatisticsBlock> StatisticsBlock::parse(const std::vector<uint8_t>& bytes) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    bool StatisticsBlock::erased() const noexcept {
        const auto all_ff = [](std::span<const uint8_t> span) noexcept {
            return std::all_of(span.begin(), span.end(), [](uint8_t b) { return b == 0xFF; });
        };
        if (!reserialize) {
            return raw_data.size() == kSize && all_ff(raw_data);
        }
        const auto record_bytes = wire::bytes_of(data);
        if (!all_ff(record_bytes)) {
            return false;
        }
        if (raw_data.size() == kSize) {
            return all_ff(std::span<const uint8_t>(raw_data).subspan(record_bytes.size()));
        }
        return true;
    }

    std::vector<uint8_t> StatisticsBlock::serialize() const {
        if (!reserialize) {
            return raw_data;
        }
        std::vector<uint8_t> out =
            raw_data.size() == kSize ? raw_data : std::vector<uint8_t>(kSize, 0xFF);
        (void) wire::write(std::span(out), 0, data, "statistics block");
        return out;
    }

    Result<ManufacturingBlock> ManufacturingBlock::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() != kSize) {
            return fail(bytes.size() < kSize ? ErrorCode::Truncated : ErrorCode::Malformed,
                        "Manufacturing block must be 0x{:X} bytes, got 0x{:X}", kSize,
                        bytes.size());
        }
        auto record = wire::read<nand_manufacturing_data>(bytes, 0, "manufacturing block");
        if (!record) {
            return std::unexpected(std::move(record.error()));
        }
        ManufacturingBlock block{};
        block.data = *record;
        block.reserialize = false;
        block.raw_data.assign(bytes.begin(), bytes.end());
        Log::Debug("Parsed Manufacturing block (0x{:X} bytes)", bytes.size());
        return block;
    }

    Result<ManufacturingBlock> ManufacturingBlock::parse(const std::vector<uint8_t>& bytes) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    bool ManufacturingBlock::erased() const noexcept {
        const auto all_ff = [](std::span<const uint8_t> span) noexcept {
            return std::all_of(span.begin(), span.end(), [](uint8_t b) { return b == 0xFF; });
        };
        if (!reserialize) {
            return raw_data.size() == kSize && all_ff(raw_data);
        }
        return all_ff(wire::bytes_of(data));
    }

    std::vector<uint8_t> ManufacturingBlock::serialize() const {
        if (!reserialize) {
            return raw_data;
        }
        const auto encoded = wire::encode(data);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

} // namespace gxbuild3::nand
