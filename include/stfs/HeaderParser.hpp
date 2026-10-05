#pragma once

#include "stfs/Commons.hpp"

#include <filesystem>
#include <span>

namespace gxbuild3::stfs {

    [[nodiscard]] Header parseHeader(std::span<const std::byte> data);

    [[nodiscard]] Header readHeaderFromFile(const std::filesystem::path& path);

} // namespace gxbuild3::stfs