#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild3::bootloaders {

struct XboxupdParts {
    std::vector<uint8_t> cf_raw;
    std::vector<uint8_t> cg_raw;
};

[[nodiscard]] XboxupdParts split_xboxupd_raw(std::span<const uint8_t> xboxupd_bytes);
[[nodiscard]] XboxupdParts split_xboxupd_raw(std::span<const std::byte> xboxupd_bytes);

} // namespace gxbuild3::bootloaders
