#include "utils/BuildTime.hpp"

#include <iostream>

using namespace gxbuild3::utils;

namespace {
    bool check(bool condition, const char* message) {
        if (!condition)
            std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    // 2026-10-04 09:22:04 UTC, the stamp a xeBuild 1.21 reference image's entries carry.
    constexpr int64_t kReferenceSeconds = 1791105724;
    constexpr uint32_t kReferenceStamp = 0x5D444AC2;

    bool test_fat_timestamp_encoding() {
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
        return check(flashfs_build_timestamp(kReferenceSeconds - 2) == kReferenceStamp,
                     "an entry carries the build's time plus two seconds") &&
               check(flashfs_build_timestamp(kReferenceSeconds - 1) == kReferenceStamp,
                     "and keeps it to the even second");
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
    passed = test_parse_source_date_epoch() && passed;
    return passed ? 0 : 1;
}
