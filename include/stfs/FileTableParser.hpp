#pragma once

#include "gxbuild/Error.hpp"
#include "stfs/Commons.hpp"

#include <span>
#include <vector>

namespace gxbuild::stfs {

    [[nodiscard]] Result<std::vector<FileEntry>>
    parse_file_listing(std::span<const std::byte> data);

} // namespace gxbuild::stfs