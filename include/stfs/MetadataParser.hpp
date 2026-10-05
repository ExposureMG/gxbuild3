#pragma once

#include "stfs/Commons.hpp"

#include <span>

namespace gxbuild3::stfs {

    [[nodiscard]] Metadata parseMetadata(std::span<const std::byte> data);

} // namespace gxbuild3::stfs