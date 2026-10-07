#pragma once

// Helpers shared by the nand test files: whether bytes, or a whole raw page with its spare, read
// erased (every byte 0xFF).

#include "nand/FlashDriver.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace gxbuild3::nand {

    [[nodiscard]] inline bool all_erased(std::span<const uint8_t> bytes) {
        return std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0xFF; });
    }

    [[nodiscard]] inline bool page_is_erased(const Driver& driver, size_t page) {
        return all_erased(driver.read_page_raw(page));
    }

} // namespace gxbuild3::nand
