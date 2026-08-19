#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

#pragma pack(push, 1)

typedef struct _XE_CORONA_FS_DATA {
    uint8_t bSectionDigest[0x14];
    uint32_t dwUnknown;
    uint32_t dwFSVersion;
    uint16_t wFSBlockIdx;
    uint16_t wUnknown;
    uint16_t wMobile1BlockIdx;
    uint16_t wMobile1Length;
    uint8_t bUnknown2[0x8];
    uint16_t wMobile2BlockIdx;
    uint16_t wMobile2Length;
    uint8_t bUnknown[0x1D0];
} XE_CORONA_FS_DATA, *PXE_CORONA_FS_DATA;

#pragma pack(pop)

struct CoronaConfig {
    static constexpr size_t kSize = 0x200;

    XE_CORONA_FS_DATA data{};

    static std::optional<CoronaConfig> parse(std::span<const uint8_t> bytes);
    static std::optional<CoronaConfig> parse(const std::vector<uint8_t>& bytes);

    [[nodiscard]] std::vector<uint8_t> serialize() const;
    [[nodiscard]] bool verify_digest() const;
};

using XeCoronaFsData = CoronaConfig;

} // namespace gxbuild3::NAND
