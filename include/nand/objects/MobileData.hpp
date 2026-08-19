#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

struct MobileData {
    std::optional<std::vector<uint8_t>> x31;
    std::optional<std::vector<uint8_t>> x32;
    std::optional<std::vector<uint8_t>> x33;
    std::optional<std::vector<uint8_t>> x34;
    std::optional<std::vector<uint8_t>> x35;
    std::optional<std::vector<uint8_t>> x36;
    std::optional<std::vector<uint8_t>> x37;
    std::optional<std::vector<uint8_t>> x38;
    std::optional<std::vector<uint8_t>> x39;

    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] size_t total_blocks(size_t block_size) const noexcept;

    [[nodiscard]] std::optional<std::vector<uint8_t>>* get_slot(uint8_t block_type) noexcept;
    [[nodiscard]] const std::optional<std::vector<uint8_t>>* get_slot(uint8_t block_type) const noexcept;
};

inline constexpr bool is_mobile_block_type(uint8_t block_type) noexcept {
    return block_type >= 0x31 && block_type <= 0x39;
}

} // namespace gxbuild3::NAND
