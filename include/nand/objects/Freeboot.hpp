#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::nand {

    std::span<const uint8_t> freeboot_rebooter();
    std::span<const uint8_t> freeboot_payload();

    std::vector<uint8_t> freeboot_rebooter_for(std::string_view version);

    std::vector<uint8_t> freeboot_payload_for(size_t core_length);

} // namespace gxbuild3::nand
