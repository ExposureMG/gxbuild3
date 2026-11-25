#pragma once

#include "gxbuild/Error.hpp"
#include "stfs/Commons.hpp"

#include <filesystem>
#include <span>

namespace gxbuild::stfs {

    [[nodiscard]] Result<Header> parse_header(std::span<const std::byte> data);

    [[nodiscard]] Result<Header> read_header_from_file(const std::filesystem::path& path);

} // namespace gxbuild::stfs