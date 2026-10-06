#include "nand/objects/CoronaConfig.hpp"

#include "excrypt.h"
#include "utils/Log.hpp"

#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr size_t kDigestLength = 0x14;

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

        auto anchor = wire::read<corona_anchor>(bytes, 0, "anchor block");
        if (!anchor) {
            return std::unexpected(std::move(anchor.error()));
        }

        CoronaConfig cfg;
        cfg.number = anchor->number;
        cfg.table = anchor->table;
        for (size_t slot = 0; slot < kBlobSlots; ++slot) {
            cfg.blobs[slot].block = anchor->blobs[slot].block;
            cfg.blobs[slot].length = anchor->blobs[slot].length;
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
        corona_anchor anchor{};
        anchor.number = number;
        anchor.table = table;
        for (size_t slot = 0; slot < kBlobSlots; ++slot) {
            anchor.blobs[slot].block = blobs[slot].block;
            anchor.blobs[slot].length = blobs[slot].length;
        }
        auto image = wire::encode(anchor);
        digest_of(image.data(), image.data());
        return {image.begin(), image.end()};
    }

} // namespace gxbuild3::nand
