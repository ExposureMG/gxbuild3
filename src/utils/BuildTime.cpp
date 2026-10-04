#include "utils/BuildTime.hpp"

#include "utils/Log.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <string>

namespace gxbuild3::utils {

    namespace {

        std::optional<std::string> environment_value(const char* name) {
#ifdef _MSC_VER
            char* value = nullptr;
            size_t length = 0;
            if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
                return std::nullopt;
            }
            std::string result{value};
            std::free(value);
            return result;
#else
            const char* value = std::getenv(name);
            if (value == nullptr) {
                return std::nullopt;
            }
            return std::string{value};
#endif
        }

        struct CivilDate {
            int64_t year;
            unsigned month;
            unsigned day;
        };

        // The proleptic Gregorian date of a day counted from 1970-01-01.
        CivilDate civil_from_days(int64_t days) {
            days += 719468;
            const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
            const auto day_of_era = static_cast<unsigned>(days - era * 146097);
            const unsigned year_of_era =
                (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
            const unsigned day_of_year =
                day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
            const unsigned month_index = (5 * day_of_year + 2) / 153;
            const unsigned day = day_of_year - (153 * month_index + 2) / 5 + 1;
            const unsigned month = month_index < 10 ? month_index + 3 : month_index - 9;
            const int64_t year = static_cast<int64_t>(year_of_era) + era * 400 + (month <= 2);
            return {year, month, day};
        }

        // The day a proleptic Gregorian date is, counted from 1970-01-01.
        int64_t days_from_civil(int64_t year, unsigned month, unsigned day) {
            year -= month <= 2;
            const int64_t era = (year >= 0 ? year : year - 399) / 400;
            const auto year_of_era = static_cast<unsigned>(year - era * 400);
            const unsigned day_of_year =
                (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
            const unsigned day_of_era =
                year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
            return era * 146097 + static_cast<int64_t>(day_of_era) - 719468;
        }

        constexpr int64_t kDay = 86400;

        // 1980-01-01 00:00:00 and 2107-12-31 23:59:58, the range a FAT stamp states.
        constexpr int64_t kFatFirst = 315532800;
        constexpr int64_t kFatLast = 4354819198;

        // The wall-clock time a moment has in the C library's local zone (TZ when it is set, the
        // system's zone otherwise), as seconds from 1970-01-01 00:00 on that clock. A moment the
        // library cannot convert keeps its UTC reading.
        int64_t local_clock_seconds(int64_t seconds) {
            const auto moment = static_cast<std::time_t>(seconds);
            std::tm local{};
#ifdef _MSC_VER
            _tzset();
            const bool converted = localtime_s(&local, &moment) == 0;
#else
            tzset();
            const bool converted = localtime_r(&moment, &local) != nullptr;
#endif
            if (!converted) {
                return seconds;
            }
            const int64_t days = days_from_civil(int64_t{local.tm_year} + 1900,
                                                 static_cast<unsigned>(local.tm_mon + 1),
                                                 static_cast<unsigned>(local.tm_mday));
            return days * kDay + int64_t{local.tm_hour} * 3600 + int64_t{local.tm_min} * 60 +
                   std::min(local.tm_sec, 59);
        }

    } // namespace

    std::optional<int64_t> parse_source_date_epoch(std::string_view value) {
        if (value.empty()) {
            return std::nullopt;
        }
        int64_t seconds = 0;
        const auto [end, status] =
            std::from_chars(value.data(), value.data() + value.size(), seconds);
        if (status != std::errc{} || end != value.data() + value.size() || seconds < 0) {
            return std::nullopt;
        }
        return seconds;
    }

    int64_t build_epoch() {
        if (const auto value = environment_value("SOURCE_DATE_EPOCH")) {
            if (const auto seconds = parse_source_date_epoch(*value)) {
                return *seconds;
            }
            Log::Warn("SOURCE_DATE_EPOCH is not a number of seconds; the clock is used");
        }
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    uint32_t fat_timestamp(int64_t seconds) {
        // No zone is two days from UTC, so a moment held to two days either side of FAT's range
        // keeps its place against that range on every local clock.
        seconds = std::clamp(seconds, kFatFirst - 2 * kDay, kFatLast + 2 * kDay);
        seconds = std::clamp(local_clock_seconds(seconds), kFatFirst, kFatLast);
        const int64_t days = seconds / kDay;
        const auto clock = static_cast<uint32_t>(seconds % kDay);
        const auto date = civil_from_days(days);
        const auto fat_date =
            static_cast<uint32_t>(((date.year - 1980) << 9) | (date.month << 5) | date.day);
        const uint32_t fat_time =
            ((clock / 3600) << 11) | (((clock / 60) % 60) << 5) | ((clock % 60) / 2);
        return (fat_date << 16) | fat_time;
    }

    uint32_t flashfs_build_timestamp(int64_t build_seconds) {
        if (build_seconds > std::numeric_limits<int64_t>::max() - 2) {
            return fat_timestamp(build_seconds);
        }
        return fat_timestamp(build_seconds + 2);
    }

} // namespace gxbuild3::utils
