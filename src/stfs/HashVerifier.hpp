#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace gxbuild3::stfs {

    // Checks a logical data block against the hash tree rooted at `top_hash`.
    // Fails with HashMismatch when a hash does not match, OutOfRange when a hash table or data
    // block lies outside the package, and InvalidArgument when total_blocks is 0.
    [[nodiscard]] Result<void> verify_data_block(std::span<const std::byte> package,
                                                 std::uint32_t block, std::uint32_t header_size,
                                                 const std::array<std::byte, 0x14>& top_hash,
                                                 std::uint32_t total_blocks);

} // namespace gxbuild3::stfs
