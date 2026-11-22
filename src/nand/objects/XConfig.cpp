#include "nand/objects/XConfig.hpp"

#include "utils/Log.hpp"

#include <algorithm>

namespace gxbuild3::nand {

    // checkdum is the 16-bit bitwise not of the byte sum over 0x10..0x10C
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
