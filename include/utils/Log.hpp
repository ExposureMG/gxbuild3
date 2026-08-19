#pragma once

#include <cassert>
#include <memory>
#include <source_location>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <type_traits>
#include <utility>

template <typename... Args>
struct LogFormatWithLoc {
    spdlog::format_string_t<Args...> fmt;
    std::source_location loc;

    template <typename S>
    consteval LogFormatWithLoc(const S& s, std::source_location l = std::source_location::current())
        : fmt(s), loc(l) {}
};

class Log {
  public:
    static void Init() {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("%^[%l]%$ [%s] %v");

        s_Logger = std::make_shared<spdlog::logger>("GxBuild3", console_sink);
        spdlog::register_logger(s_Logger);

        s_Logger->set_level(DefaultLevel());
        s_Logger->flush_on(spdlog::level::err);
    }

    static void SetLevel(spdlog::level::level_enum level) {
        if (!s_Logger) return;
        s_Logger->set_level(level);
    }

    static void SetVerbose(bool verbose) {
        SetLevel(verbose ? spdlog::level::trace : DefaultLevel());
    }

    static void Shutdown() {
        spdlog::drop("GxBuild3");
        s_Logger.reset();
    }

    template <typename... Args>
    static void Trace(LogFormatWithLoc<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->log(spdlog::source_loc{fmt.loc.file_name(), static_cast<int>(fmt.loc.line()), fmt.loc.function_name()},
                      spdlog::level::trace, fmt.fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Debug(LogFormatWithLoc<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->log(spdlog::source_loc{fmt.loc.file_name(), static_cast<int>(fmt.loc.line()), fmt.loc.function_name()},
                      spdlog::level::debug, fmt.fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Info(LogFormatWithLoc<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->log(spdlog::source_loc{fmt.loc.file_name(), static_cast<int>(fmt.loc.line()), fmt.loc.function_name()},
                      spdlog::level::info, fmt.fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Warn(LogFormatWithLoc<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->log(spdlog::source_loc{fmt.loc.file_name(), static_cast<int>(fmt.loc.line()), fmt.loc.function_name()},
                      spdlog::level::warn, fmt.fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Error(LogFormatWithLoc<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->log(spdlog::source_loc{fmt.loc.file_name(), static_cast<int>(fmt.loc.line()), fmt.loc.function_name()},
                      spdlog::level::err, fmt.fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Critical(LogFormatWithLoc<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->log(spdlog::source_loc{fmt.loc.file_name(), static_cast<int>(fmt.loc.line()), fmt.loc.function_name()},
                      spdlog::level::critical, fmt.fmt, std::forward<Args>(args)...);
    }

  private:
    static constexpr spdlog::level::level_enum DefaultLevel() {
        return spdlog::level::info;
    }

    static std::shared_ptr<spdlog::logger> s_Logger;
};
