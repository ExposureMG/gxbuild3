#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <span>
#include <vector>

namespace gxbuild3::stfs {

    [[nodiscard]] Result<std::vector<FileEntry>>
    parse_file_listing(std::span<const std::byte> data);

} // namespace gxbuild3::stfs