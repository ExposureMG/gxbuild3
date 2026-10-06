#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <span>

namespace gxbuild3::stfs {

    // Fails with Truncated for a buffer shorter than the v1 metadata and Malformed for an
    // implausible header size.
    [[nodiscard]] Result<Metadata> parse_metadata(std::span<const std::byte> data);

} // namespace gxbuild3::stfs