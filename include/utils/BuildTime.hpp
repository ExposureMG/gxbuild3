#pragma once

#include "gxbuild/Error.hpp"

#include <cstdint>
#include <string_view>

namespace gxbuild::utils {

    [[nodiscard]] int64_t build_epoch();

    [[nodiscard]] Result<int64_t> parse_source_date_epoch(std::string_view value);

    [[nodiscard]] uint32_t fat_timestamp(int64_t seconds);

    [[nodiscard]] uint32_t flashfs_build_timestamp(int64_t build_seconds);

} // namespace gxbuild::utils
