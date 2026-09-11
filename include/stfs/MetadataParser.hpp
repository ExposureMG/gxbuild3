#pragma once

#include <Commons.hpp>
#include <span>

namespace stfs {

    [[nodiscard]] Metadata parseMetadata(std::span<const std::byte> data);

} // namespace stfs