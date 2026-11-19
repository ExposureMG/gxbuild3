#pragma once

#include "FlashImage.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::bootloaders {

    struct BootloaderBlock {
        uint16_t magic{0};
        uint16_t build{0};
        uint16_t flags{0};
        uint32_t size{0};
        std::vector<uint8_t> data;
    };

    bool crypt_bootloaders(std::vector<BootloaderBlock>& bls, std::span<const uint8_t> cpu_key);

    std::optional<std::vector<uint8_t>> pack_and_encrypt_bootloaders(const flash_image_t& image,
                                                                    std::span<const uint8_t> cpu_key);

} // namespace gxbuild3::bootloaders
