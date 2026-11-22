#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <filesystem>
#include <span>

namespace gxbuild3::stfs {

    [[nodiscard]] Result<Header> parse_header(std::span<const std::byte> data);

    [[nodiscard]] Result<Header> read_header_from_file(const std::filesystem::path& path);

} // namespace gxbuild3::stfs