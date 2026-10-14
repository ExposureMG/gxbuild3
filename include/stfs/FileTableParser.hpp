#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <span>
#include <vector>

namespace gxbuild3::stfs {

    // Fails with Malformed when the listing is misaligned or an entry name is unusable.
    [[nodiscard]] Result<std::vector<FileEntry>>
    parse_file_listing(std::span<const std::byte> data);

} // namespace gxbuild3::stfs