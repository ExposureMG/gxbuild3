#pragma once

#include "gxbuild/Error.hpp"
#include "stfs/Commons.hpp"

#include <span>

namespace gxbuild::stfs {

    [[nodiscard]] Result<Metadata> parse_metadata(std::span<const std::byte> data);

} // namespace gxbuild::stfs