#pragma once

// Scoped process-environment changes for tests. Every change is undone in a destructor, so a
// binary passes under --gtest_shuffle in one process exactly as it does one case per process.

#include "ScopedTimeZone.hpp"

#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3::test {

    // The variable's value, or nullopt when it is unset.
    [[nodiscard]] inline std::optional<std::string> env_value(const char* name) {
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
        return value ? std::optional<std::string>{value} : std::nullopt;
#endif
    }

    // Sets (or, with nullopt, unsets) an environment variable for a scope and gives back the
    // previous value, or the previous absence, when the scope ends.
    class ScopedEnv {
      public:
        ScopedEnv(std::string name, std::optional<std::string> value)
            : name_(std::move(name)), previous_(env_value(name_.c_str())) {
            set(value);
        }

        ~ScopedEnv() { set(previous_); }

        ScopedEnv(const ScopedEnv&) = delete;
        ScopedEnv& operator=(const ScopedEnv&) = delete;

      private:
        void set(const std::optional<std::string>& value) const {
#ifdef _WIN32
            _putenv_s(name_.c_str(), value ? value->c_str() : "");
#else
            if (value) {
                setenv(name_.c_str(), value->c_str(), 1);
            } else {
                unsetenv(name_.c_str());
            }
#endif
        }

        std::string name_;
        std::optional<std::string> previous_;
    };

    // The build time build_all.sh and the goldens pin (SOURCE_DATE_EPOCH, UTC seconds).
    inline constexpr std::string_view kPinnedSourceDateEpoch = "1791105724";

    // Pins the build time: SOURCE_DATE_EPOCH and an explicit TZ (local time feeds the FlashFS
    // directory stamps), both restored when the scope ends.
    class PinnedBuildTime {
      public:
        explicit PinnedBuildTime(std::string_view epoch = kPinnedSourceDateEpoch,
                                 const char* zone = "UTC")
            : epoch_("SOURCE_DATE_EPOCH", std::string{epoch}), zone_(zone) {}

      private:
        ScopedEnv epoch_;
        ::ScopedTimeZone zone_;
    };

} // namespace gxbuild3::test
