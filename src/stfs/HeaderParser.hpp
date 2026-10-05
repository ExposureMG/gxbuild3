#pragma once

#include "stfs/Commons.hpp"

#include <filesystem>
#include <span>

namespace gxbuild3::stfs {

    [[nodiscard]] Header parse_header(std::span<const std::byte> data);

    [[nodiscard]] Header read_header_from_file(const std::filesystem::path& path);

} // namespace gxbuild3::stfs