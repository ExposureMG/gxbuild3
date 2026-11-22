#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <cstdint>

namespace gxbuild3::stfs {

    [[nodiscard]] Result<std::uint64_t> block_to_offset(std::uint32_t block,
                                                        std::uint32_t header_size);

    [[nodiscard]] std::uint32_t compute_data_block_number(std::uint32_t block);

    [[nodiscard]] Result<std::uint32_t> compute_level_n_hash_block_number(std::uint32_t block,
                                                                          int level);

} // namespace gxbuild3::stfs
