#pragma once

#include <Commons.hpp>
#include <span>
#include <vector>

namespace stfs {

    [[nodiscard]] std::vector<FileEntry> parseFileListing(std::span<const std::byte> data);

} // namespace stfs