#pragma once

// Holds the C library's local zone to a TZ value for a test's scope and gives back the zone the
// process had when the scope ends, so a test that reads local time passes in any zone.

#include <cstdlib>
#include <ctime>
#include <optional>
#include <string>

class ScopedTimeZone {
  public:
    explicit ScopedTimeZone(const char* zone) : previous_(current()) { set(zone); }

    ~ScopedTimeZone() { set(previous_ ? previous_->c_str() : nullptr); }

    ScopedTimeZone(const ScopedTimeZone&) = delete;
    ScopedTimeZone& operator=(const ScopedTimeZone&) = delete;

  private:
    static std::optional<std::string> current() {
#ifdef _MSC_VER
        char* value = nullptr;
        size_t length = 0;
        if (_dupenv_s(&value, &length, "TZ") != 0 || value == nullptr) {
            return std::nullopt;
        }
        std::string result{value};
        std::free(value);
        return result;
#else
        const char* value = std::getenv("TZ");
        return value ? std::optional<std::string>{value} : std::nullopt;
#endif
    }

    static void set(const char* zone) {
#ifdef _WIN32
        _putenv_s("TZ", zone ? zone : "");
        _tzset();
#else
        if (zone) {
            setenv("TZ", zone, 1);
        } else {
            unsetenv("TZ");
        }
        tzset();
#endif
    }

    std::optional<std::string> previous_;
};
