#include "nand/objects/SecuredFiles.hpp"
#include "support/Env.hpp"
#include "utils/BuildTime.hpp"

#include <array>
#include <cstdint>
#include <iostream>

using namespace gxbuild3::utils;

namespace {
    bool check(bool condition, const char* message) {
        if (!condition)
            std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    // 2026-10-04 09:22:04 UTC. Its FAT form is the stamp a xeBuild 1.21 reference image's entries
    // carry, there on a summer-time local clock an hour ahead of UTC.
    constexpr int64_t kReferenceSeconds = 1791105724;
    constexpr uint32_t kReferenceStamp = 0x5D444AC2;

    bool test_fat_timestamp_encoding() {
        const gxbuild3::test::ScopedTimeZone utc{"UTC0"};
        return check(fat_timestamp(kReferenceSeconds) == kReferenceStamp,
                     "a moment encodes as FAT date and time") &&
               check(fat_timestamp(kReferenceSeconds + 1) == kReferenceStamp,
                     "FAT time counts seconds in twos") &&
               check(fat_timestamp(315532800) == 0x00210000, "1980-01-01 is the first FAT day") &&
               check(fat_timestamp(0) == 0x00210000, "an earlier moment is held to 1980") &&
               check(fat_timestamp(951782400) == 0x285D0000, "2000-02-29 encodes") &&
               check(fat_timestamp(4354819198) == 0xFF9FBF7D, "2107-12-31 23:59:58 encodes") &&
               check(fat_timestamp(int64_t{1} << 40) == 0xFF9FBF7D,
                     "a later moment is held to 2107");
    }

    bool test_flashfs_build_timestamp_adds_two_seconds() {
        const gxbuild3::test::ScopedTimeZone utc{"UTC0"};
        return check(flashfs_build_timestamp(kReferenceSeconds - 2) == kReferenceStamp,
                     "an entry carries the build's time plus two seconds") &&
               check(flashfs_build_timestamp(kReferenceSeconds - 1) == kReferenceStamp,
                     "and keeps it to the even second");
    }

    // The directory entries take the local clock and the secured files' FILETIME stays UTC: one
    // epoch gives other entry stamps in another zone and the same FILETIME in every zone.
    bool test_fat_timestamp_follows_the_local_zone() {
        const int64_t build = kReferenceSeconds - 2;
        uint32_t utc_stamp = 0;
        uint32_t tokyo_stamp = 0;
        std::array<uint8_t, 8> utc_filetime{};
        std::array<uint8_t, 8> tokyo_filetime{};
        {
            const gxbuild3::test::ScopedTimeZone zone{"UTC0"};
            utc_stamp = flashfs_build_timestamp(build);
            utc_filetime = gxbuild3::nand::secured_file_stamp(build);
        }
        {
            const gxbuild3::test::ScopedTimeZone zone{"JST-9"};
            tokyo_stamp = flashfs_build_timestamp(build);
            tokyo_filetime = gxbuild3::nand::secured_file_stamp(build);
        }
        bool passed =
            check(utc_stamp == kReferenceStamp, "UTC entries state 09:22:04") &&
            check(tokyo_stamp == 0x5D4492C2, "UTC+9 entries state 18:22:04 the same day") &&
            check(utc_filetime == tokyo_filetime, "the FILETIME does not depend on the zone");
        {
            // 1980-01-01 05:00 in UTC+9 is 1979-12-31 20:00 UTC: the local reading is in range.
            const gxbuild3::test::ScopedTimeZone zone{"JST-9"};
            passed = check(fat_timestamp(315532800 - 4 * 3600) == 0x00212800,
                           "the range is held on the local clock") &&
                     passed;
        }
#ifndef _WIN32
        {
            // The reference image was built at 08:22:02 UTC in British summer time, so its entries
            // read an hour later; a month on, past the change back, they read UTC.
            const gxbuild3::test::ScopedTimeZone zone{"GMT0BST,M3.5.0/1,M10.5.0"};
            passed = check(flashfs_build_timestamp(build - 3600) == kReferenceStamp,
                           "summer-time entries take the summer offset") &&
                     check(flashfs_build_timestamp(build - 3600 + 30 * 86400) == 0x5D6342C2,
                           "winter entries take none") &&
                     passed;
        }
#endif
        return passed;
    }

    bool test_parse_source_date_epoch() {
        return check(parse_source_date_epoch("1791105722") == 1791105722,
                     "a decimal SOURCE_DATE_EPOCH reads") &&
               check(parse_source_date_epoch("0") == 0, "zero reads") &&
               check(!parse_source_date_epoch(""), "an empty value is refused") &&
               check(!parse_source_date_epoch("-5"), "a negative value is refused") &&
               check(!parse_source_date_epoch("12a"), "trailing text is refused") &&
               check(!parse_source_date_epoch(" 12"), "leading space is refused");
    }
} // namespace

int main() {
    bool passed = test_fat_timestamp_encoding();
    passed = test_flashfs_build_timestamp_adds_two_seconds() && passed;
    passed = test_fat_timestamp_follows_the_local_zone() && passed;
    passed = test_parse_source_date_epoch() && passed;
    return passed ? 0 : 1;
}
