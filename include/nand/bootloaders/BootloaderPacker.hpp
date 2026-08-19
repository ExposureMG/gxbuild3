#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::bootloaders {

    enum class HmacType {
        Default,
        Hmac1920,
        Split,
        Split15574,
    };

    struct BootloaderBlock {
        uint16_t magic{0};
        uint16_t build{0};
        uint16_t flags{0};
        uint32_t size{0};
        std::vector<uint8_t> data;
    };

    bool crypt_single_bl(std::span<uint8_t> data, HmacType hmac_type, uint8_t cur_key[16],
                         const uint8_t cpu_key[16] = nullptr, uint8_t cba_hdr[16] = nullptr,
                         size_t crypt_start = 0x20);

    bool crypt_bootloaders(std::vector<BootloaderBlock>& bls, std::span<const uint8_t> cpu_key);

} // namespace gxbuild3::bootloaders
