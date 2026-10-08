// src/utils/BuildTime.hpp: the FAT date and time a FlashFS directory entry keeps (fat_timestamp,
// on the local clock and held to FAT's range), the build stamp xeBuild gives every entry
// (flashfs_build_timestamp, two seconds after the build) and SOURCE_DATE_EPOCH parsing; plus the
// secured files' FILETIME (nand::secured_file_stamp), which stays UTC in every zone.

#include "nand/objects/SecuredFiles.hpp"
#include "support/Env.hpp"
#include "support/Expect.hpp"
#include "utils/BuildTime.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string_view>

namespace gxbuild3::utils {
    namespace {

        // 2026-10-04 09:22:04 UTC. Its FAT form is the stamp a xeBuild 1.21 reference image's
        // entries carry, there on a summer-time local clock an hour ahead of UTC.
        constexpr int64_t kReferenceSeconds = 1791105724;
        constexpr uint32_t kReferenceStamp = 0x5D444AC2u;

        // ---- fat_timestamp on the UTC clock --------------------------------------------------

        // One moment and the FAT date and time it encodes as in UTC.
        struct FatTimestampRow {
            const char* name;
            int64_t seconds;
            uint32_t stamp;
            const char* message;
        };
        GX_PRINT_ROW_AS_NAME(FatTimestampRow)

        class FatTimestamp : public ::testing::TestWithParam<FatTimestampRow> {};

        TEST_P(FatTimestamp, EncodesAsFatDateAndTimeInUtc) {
            const auto& row = GetParam();
            const test::ScopedTimeZone utc{"UTC0"};
            EXPECT_EQ(fat_timestamp(row.seconds), row.stamp) << row.message;
        }

        INSTANTIATE_TEST_SUITE_P(
            Row, FatTimestamp,
            ::testing::Values(FatTimestampRow{"ReferenceMoment", kReferenceSeconds, kReferenceStamp,
                                              "a moment encodes as FAT date and time"},
                              FatTimestampRow{"OddSecondCountsInTwos", kReferenceSeconds + 1,
                                              kReferenceStamp, "FAT time counts seconds in twos"},
                              FatTimestampRow{"FirstFatDay1980", 315532800, 0x00210000u,
                                              "1980-01-01 is the first FAT day"},
                              FatTimestampRow{"EarlierMomentHeldTo1980", 0, 0x00210000u,
                                              "an earlier moment is held to 1980"},
                              FatTimestampRow{"LeapDay2000", 951782400, 0x285D0000u,
                                              "2000-02-29 encodes"},
                              FatTimestampRow{"LastFatMoment2107", 4354819198, 0xFF9FBF7Du,
                                              "2107-12-31 23:59:58 encodes"},
                              FatTimestampRow{"LaterMomentHeldTo2107", int64_t{1} << 40,
                                              0xFF9FBF7Du, "a later moment is held to 2107"}),
            test::RowName{});

        // ---- flashfs_build_timestamp -----------------------------------------------------------

        TEST(FlashFsBuildTimestamp, CarriesTheBuildTimePlusTwoSecondsToTheEvenSecond) {
            const test::ScopedTimeZone utc{"UTC0"};
            EXPECT_EQ(flashfs_build_timestamp(kReferenceSeconds - 2), kReferenceStamp)
                << "an entry carries the build's time plus two seconds";
            EXPECT_EQ(flashfs_build_timestamp(kReferenceSeconds - 1), kReferenceStamp)
                << "and keeps it to the even second";
        }

        // ---- The local zone
        // ---------------------------------------------------------------------- The directory
        // entries take the local clock and the secured files' FILETIME stays UTC: one epoch gives
        // other entry stamps in another zone and the same FILETIME in every zone.

        constexpr int64_t kBuildSeconds = kReferenceSeconds - 2;

        TEST(FatTimestampZone, EntriesFollowTheLocalZone) {
            uint32_t utc_stamp = 0;
            uint32_t tokyo_stamp = 0;
            {
                const test::ScopedTimeZone zone{"UTC0"};
                utc_stamp = flashfs_build_timestamp(kBuildSeconds);
            }
            {
                const test::ScopedTimeZone zone{"JST-9"};
                tokyo_stamp = flashfs_build_timestamp(kBuildSeconds);
            }
            EXPECT_EQ(utc_stamp, kReferenceStamp) << "UTC entries state 09:22:04";
            EXPECT_EQ(tokyo_stamp, 0x5D4492C2u) << "UTC+9 entries state 18:22:04 the same day";
        }

        TEST(FatTimestampZone, SecuredFileStampDoesNotDependOnTheZone) {
            std::array<uint8_t, 8> utc_filetime{};
            std::array<uint8_t, 8> tokyo_filetime{};
            {
                const test::ScopedTimeZone zone{"UTC0"};
                utc_filetime = nand::secured_file_stamp(kBuildSeconds);
            }
            {
                const test::ScopedTimeZone zone{"JST-9"};
                tokyo_filetime = nand::secured_file_stamp(kBuildSeconds);
            }
            EXPECT_EQ(utc_filetime, tokyo_filetime) << "the FILETIME does not depend on the zone";
        }

        TEST(FatTimestampZone, RangeIsHeldOnTheLocalClock) {
            // 1980-01-01 05:00 in UTC+9 is 1979-12-31 20:00 UTC: the local reading is in range.
            const test::ScopedTimeZone zone{"JST-9"};
            EXPECT_EQ(fat_timestamp(315532800 - 4 * 3600), 0x00212800u)
                << "the range is held on the local clock";
        }

        TEST(FatTimestampZone, BritishSummerTimeEntriesTakeTheSummerOffsetAndWinterEntriesNone) {
#ifdef _WIN32
            GTEST_SKIP() << "the POSIX TZ rule GMT0BST,M3.5.0/1,M10.5.0 needs a POSIX C library";
#else
            // The reference image was built at 08:22:02 UTC in British summer time, so its
            // entries read an hour later; a month on, past the change back, they read UTC.
            const test::ScopedTimeZone zone{"GMT0BST,M3.5.0/1,M10.5.0"};
            EXPECT_EQ(flashfs_build_timestamp(kBuildSeconds - 3600), kReferenceStamp)
                << "summer-time entries take the summer offset";
            EXPECT_EQ(flashfs_build_timestamp(kBuildSeconds - 3600 + 30 * 86400), 0x5D6342C2u)
                << "winter entries take none";
#endif
        }

        // ---- parse_source_date_epoch ---------------------------------------------------------

        // One SOURCE_DATE_EPOCH text and the seconds it reads as, or nullopt when it is refused.
        struct SourceDateEpochRow {
            const char* name;
            std::string_view text;
            std::optional<int64_t> seconds;
            const char* message;
        };
        GX_PRINT_ROW_AS_NAME(SourceDateEpochRow)

        class SourceDateEpoch : public ::testing::TestWithParam<SourceDateEpochRow> {};

        TEST_P(SourceDateEpoch, ReadsOnlyANonNegativeDecimal) {
            const auto& row = GetParam();
            const auto parsed = parse_source_date_epoch(row.text);
            if (row.seconds) {
                ASSERT_OK(parsed) << row.message;
                EXPECT_EQ(*parsed, *row.seconds) << row.message;
            } else {
                EXPECT_FALSE(parsed.has_value()) << row.message;
            }
        }

        INSTANTIATE_TEST_SUITE_P(
            Row, SourceDateEpoch,
            ::testing::Values(
                SourceDateEpochRow{"Decimal", "1791105722", 1791105722,
                                   "a decimal SOURCE_DATE_EPOCH reads"},
                SourceDateEpochRow{"Zero", "0", 0, "zero reads"},
                SourceDateEpochRow{"Empty", "", std::nullopt, "an empty value is refused"},
                SourceDateEpochRow{"Negative", "-5", std::nullopt, "a negative value is refused"},
                SourceDateEpochRow{"TrailingText", "12a", std::nullopt, "trailing text is refused"},
                SourceDateEpochRow{"LeadingSpace", " 12", std::nullopt,
                                   "leading space is refused"}),
            test::RowName{});

    } // namespace
} // namespace gxbuild3::utils
