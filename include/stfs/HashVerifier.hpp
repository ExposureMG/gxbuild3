#pragma once

#include <Commons.hpp>
#include <array>
#include <cstdint>
#include <span>

namespace stfs {

    [[nodiscard]] bool verifyDataBlock(std::span<const std::byte> package, std::uint32_t block,
                                       std::uint32_t header_size,
                                       const std::array<std::byte, 0x14>& top_hash,
                                       std::uint32_t total_blocks);

} // namespace stfs