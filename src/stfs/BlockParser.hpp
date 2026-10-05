#pragma once

#include "stfs/Commons.hpp"

#include <cstdint>

namespace gxbuild3::stfs {

    // Byte offset of a physical block. Offsets are 64-bit so large block numbers cannot wrap.
    [[nodiscard]] std::uint64_t block_to_offset(std::uint32_t block, std::uint32_t header_size);

    [[nodiscard]] std::uint32_t compute_data_block_number(std::uint32_t block);

    [[nodiscard]] std::uint32_t compute_level_n_hash_block_number(std::uint32_t block, int level);

} // namespace gxbuild3::stfs