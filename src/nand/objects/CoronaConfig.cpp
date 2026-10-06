#include "nand/objects/CoronaConfig.hpp"

#include "excrypt.h"
#include "utils/Log.hpp"

#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr size_t kDigestLength = 0x14;
        constexpr size_t kNumberOffset = 0x18;
        constexpr size_t kTableOffset = 0x1C;
        constexpr size_t kBlobsOffset = 0x20;

        uint16_t load16(const uint8_t* p) {
            return static_cast<uint16_t>((p[0] << 8) | p[1]);
        }

        uint32_t load32(const uint8_t* p) {
            return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
        }

        void store16(uint8_t* p, uint16_t value) {
            p[0] = static_cast<uint8_t>(value >> 8);
            p[1] = static_cast<uint8_t>(value);
        }

        void store32(uint8_t* p, uint32_t value) {
            store16(p, static_cast<uint16_t>(value >> 16));
            store16(p + 2, static_cast<uint16_t>(value));
        }

        void digest_of(const uint8_t* block, uint8_t* out) {
            ExCryptSha(block + kDigestLength, CoronaConfig::kSize - kDigestLength, nullptr, 0,
                       nullptr, 0, out, kDigestLength);
        }

    } // namespace

    Result<CoronaConfig> CoronaConfig::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() < kSize) {
            return fail(ErrorCode::Truncated, "anchor block is 0x{:X} bytes, need 0x{:X}",
                        bytes.size(), kSize);
        }

        uint8_t digest[kDigestLength];
        digest_of(bytes.data(), digest);
        if (std::memcmp(digest, bytes.data(), kDigestLength) != 0) {
            return fail(ErrorCode::HashMismatch,
                        "anchor block digest does not match what follows it");
        }

        CoronaConfig cfg;
        cfg.number = load32(bytes.data() + kNumberOffset);
        cfg.table = load16(bytes.data() + kTableOffset);
        for (size_t slot = 0; slot < kBlobSlots; ++slot) {
            cfg.blobs[slot].block = load16(bytes.data() + kBlobsOffset + slot * 4);
            cfg.blobs[slot].length = load16(bytes.data() + kBlobsOffset + slot * 4 + 2);
        }

        Log::Debug("Parsed anchor block {}: filesystem table at block {}", cfg.number, cfg.table);
        return cfg;
    }

    Result<CoronaConfig> CoronaConfig::parse(const std::vector<uint8_t>& bytes) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    std::optional<CoronaConfig>
    CoronaConfig::choose(const std::array<std::span<const uint8_t>, 2>& copies) {
        std::optional<CoronaConfig> best;
        for (const auto& copy : copies) {
            if (copy.size() < kSize) {
                continue;
            }
            auto parsed = parse(copy);
            if (!parsed) {
                Log::Debug("Anchor block copy skipped: {}", parsed.error().describe());
                continue;
            }
            if (!best || parsed->number > best->number) {
                best = std::move(*parsed);
            }
        }
        return best;
    }

    std::vector<uint8_t> CoronaConfig::serialize() const {
        std::vector<uint8_t> out(kSize, 0);
        store32(out.data() + kNumberOffset, number);
        store16(out.data() + kTableOffset, table);
        for (size_t slot = 0; slot < kBlobSlots; ++slot) {
            store16(out.data() + kBlobsOffset + slot * 4, blobs[slot].block);
            store16(out.data() + kBlobsOffset + slot * 4 + 2, blobs[slot].length);
        }
        digest_of(out.data(), out.data());
        return out;
    }

} // namespace gxbuild3::nand
