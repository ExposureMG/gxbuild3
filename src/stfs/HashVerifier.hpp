#pragma once

#include "stfs/Commons.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace gxbuild3::stfs {

    [[nodiscard]] bool verify_data_block(std::span<const std::byte> package, std::uint32_t block,
                                         std::uint32_t header_size,
                                         const std::array<std::byte, 0x14>& top_hash,
                                         std::uint32_t total_blocks);

} // namespace gxbuild3::stfs