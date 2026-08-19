#include "nand/objects/CoronaConfig.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"

#include <cstring>

namespace gxbuild3::NAND {

std::optional<CoronaConfig> CoronaConfig::parse(std::span<const uint8_t> bytes) {
    if (bytes.size() < sizeof(XE_CORONA_FS_DATA)) {
        Log::Error("Invalid Corona config size: expected {} bytes, got {}",
                   sizeof(XE_CORONA_FS_DATA), bytes.size());
        return std::nullopt;
    }

    XE_CORONA_FS_DATA raw{};
    std::memcpy(&raw, bytes.data(), sizeof(XE_CORONA_FS_DATA));

    CoronaConfig cfg;
    std::memcpy(cfg.data.bSectionDigest, raw.bSectionDigest, sizeof(raw.bSectionDigest));
    cfg.data.dwUnknown = bswap32(raw.dwUnknown);
    cfg.data.dwFSVersion = bswap32(raw.dwFSVersion);
    cfg.data.wFSBlockIdx = bswap16(raw.wFSBlockIdx);
    cfg.data.wUnknown = bswap16(raw.wUnknown);
    cfg.data.wMobile1BlockIdx = bswap16(raw.wMobile1BlockIdx);
    cfg.data.wMobile1Length = bswap16(raw.wMobile1Length);
    std::memcpy(cfg.data.bUnknown2, raw.bUnknown2, sizeof(raw.bUnknown2));
    cfg.data.wMobile2BlockIdx = bswap16(raw.wMobile2BlockIdx);
    cfg.data.wMobile2Length = bswap16(raw.wMobile2Length);
    std::memcpy(cfg.data.bUnknown, raw.bUnknown, sizeof(raw.bUnknown));

    Log::Debug("Parsed Corona config: FSVersion={}, FSBlock={}, Mobile1Block={}, Mobile2Block={}",
               cfg.data.dwFSVersion, cfg.data.wFSBlockIdx, cfg.data.wMobile1BlockIdx, cfg.data.wMobile2BlockIdx);

    return cfg;
}

std::optional<CoronaConfig> CoronaConfig::parse(const std::vector<uint8_t>& bytes) {
    return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
}

std::vector<uint8_t> CoronaConfig::serialize() const {
    XE_CORONA_FS_DATA raw{};
    raw.dwUnknown = bswap32(data.dwUnknown);
    raw.dwFSVersion = bswap32(data.dwFSVersion);
    raw.wFSBlockIdx = bswap16(data.wFSBlockIdx);
    raw.wUnknown = bswap16(data.wUnknown);
    raw.wMobile1BlockIdx = bswap16(data.wMobile1BlockIdx);
    raw.wMobile1Length = bswap16(data.wMobile1Length);
    std::memcpy(raw.bUnknown2, data.bUnknown2, sizeof(data.bUnknown2));
    raw.wMobile2BlockIdx = bswap16(data.wMobile2BlockIdx);
    raw.wMobile2Length = bswap16(data.wMobile2Length);
    std::memcpy(raw.bUnknown, data.bUnknown, sizeof(data.bUnknown));

    ExCryptSha(reinterpret_cast<const uint8_t*>(&raw) + 0x14, 0x1EC,
               nullptr, 0, nullptr, 0,
               raw.bSectionDigest, 0x14);

    std::vector<uint8_t> out(sizeof(XE_CORONA_FS_DATA));
    std::memcpy(out.data(), &raw, sizeof(XE_CORONA_FS_DATA));
    return out;
}

bool CoronaConfig::verify_digest() const {
    auto raw_bytes = serialize();
    bool valid = (std::memcmp(raw_bytes.data(), data.bSectionDigest, 0x14) == 0);
    if (!valid) {
        Log::Warn("Corona config SHA digest mismatch");
    }
    return valid;
}

} // namespace gxbuild3::NAND
