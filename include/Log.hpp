#pragma once

#include <cassert>
#include <memory>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <utility>

class Log {
  public:
    static void Init() {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("%^[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v%$");

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
    static void Trace(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->trace(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Info(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->info(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Warn(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->warn(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Error(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->error(fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void Critical(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (!s_Logger) return;
        s_Logger->critical(fmt, std::forward<Args>(args)...);
    }

  private:
    static constexpr spdlog::level::level_enum DefaultLevel() {
#ifdef NDEBUG
        return spdlog::level::info;
#else
        return spdlog::level::trace;
#endif
    }

    static std::shared_ptr<spdlog::logger> s_Logger;
};
