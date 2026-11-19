#pragma once

#include "Error.hpp"

#include <cstdint>
#include <string_view>

namespace gxbuild3::utils {

    // A build's time in seconds since the Unix epoch: SOURCE_DATE_EPOCH when it is set to a
    // non-negative decimal number, as reproducible builds state it, and the clock otherwise.
    [[nodiscard]] int64_t build_epoch();

    // SOURCE_DATE_EPOCH's value read as a build time: a non-negative decimal number of
    // seconds. Anything else, including an empty value, is Malformed.
    [[nodiscard]] Result<int64_t> parse_source_date_epoch(std::string_view value);

    // A moment (seconds since the Unix epoch) as a FlashFS directory entry keeps it: the local
    // wall-clock time, in the zone the C library states (TZ when it is set, the system's zone
    // otherwise), with the FAT date in the high 16 bits and the FAT time, in two-second steps,
    // in the low 16. A time FAT cannot state is held to its range, 1980-01-01 to 2107-12-31.
    [[nodiscard]] uint32_t fat_timestamp(int64_t seconds);

    // The stamp xeBuild gives every directory entry of a build: the build's time plus two
    // seconds, in FAT form on the local clock.
    [[nodiscard]] uint32_t flashfs_build_timestamp(int64_t build_seconds);

} // namespace gxbuild3::utils
