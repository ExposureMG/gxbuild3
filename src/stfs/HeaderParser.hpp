#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <filesystem>
#include <span>

namespace gxbuild3::stfs {

    // Fails with Truncated for a buffer shorter than a header and Malformed for unknown magic.
    [[nodiscard]] Result<Header> parse_header(std::span<const std::byte> data);

    // Fails with IoError when the file cannot be opened, otherwise as parse_header.
    [[nodiscard]] Result<Header> read_header_from_file(const std::filesystem::path& path);

} // namespace gxbuild3::stfs