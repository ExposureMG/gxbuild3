#pragma once

#include <Commons.hpp>
#include <cstdint>

namespace stfs {

    [[nodiscard]] std::uint32_t blockToOffset(std::uint32_t block, std::uint32_t header_size);

    [[nodiscard]] std::uint32_t computeDataBlockNumber(std::uint32_t block);

    [[nodiscard]] std::uint32_t computeLevelNHashBlockNumber(std::uint32_t block, int level);

} // namespace stfs