#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <span>

namespace gxbuild3::stfs {

    [[nodiscard]] Result<Metadata> parse_metadata(std::span<const std::byte> data);

} // namespace gxbuild3::stfs