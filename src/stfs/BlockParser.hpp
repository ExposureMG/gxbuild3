#pragma once

#include "stfs/Commons.hpp"

#include <cstdint>

namespace gxbuild3::stfs {

    // Byte offset of a physical block. Offsets are 64-bit so large block numbers cannot wrap.
    [[nodiscard]] std::uint64_t blockToOffset(std::uint32_t block, std::uint32_t header_size);

    [[nodiscard]] std::uint32_t computeDataBlockNumber(std::uint32_t block);

    [[nodiscard]] std::uint32_t computeLevelNHashBlockNumber(std::uint32_t block, int level);

} // namespace gxbuild3::stfs