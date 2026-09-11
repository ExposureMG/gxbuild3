#pragma once

#include <Commons.hpp>
#include <filesystem>
#include <span>

namespace stfs {

    [[nodiscard]] Header parseHeader(std::span<const std::byte> data);

    [[nodiscard]] Header readHeaderFromFile(const std::filesystem::path& path);

} // namespace stfs