#pragma once

#include "stfs/Commons.hpp"

#include <span>
#include <vector>

namespace gxbuild3::stfs {

    [[nodiscard]] std::vector<FileEntry> parse_file_listing(std::span<const std::byte> data);

} // namespace gxbuild3::stfs