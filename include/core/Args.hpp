#pragma once

#include "gxbuild/Types.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace gxbuild {

    inline const std::map<std::string, BuildType> kBuildTypeMap = {
        {"retail", BuildType::Retail},     {"jtag", BuildType::Jtag},
        {"glitch", BuildType::Glitch},     {"glitch2", BuildType::Glitch2},
        {"glitch2m", BuildType::Glitch2m}, {"glitch3", BuildType::Glitch3},
        {"devkit", BuildType::Devkit},     {"devgl", BuildType::Devgl},
    };

    inline const std::map<std::string, ConsoleType> kConsoleTypeMap = {
        {"xenon", ConsoleType::Xenon},
        {"zephyr", ConsoleType::Zephyr},
        {"falcon", ConsoleType::Falcon},
        {"jasper", ConsoleType::Jasper},
        {"jasper256", ConsoleType::Jasper},
        {"jasper512", ConsoleType::Jasper},
        {"jasperbb", ConsoleType::Jasper},
        {"jasperbigffs", ConsoleType::Jasper},
        {"trinity", ConsoleType::Trinity},
        {"trinitybb", ConsoleType::Trinity},
        {"trinitybigffs", ConsoleType::Trinity},
        {"corona", ConsoleType::Corona},
        {"corona4g", ConsoleType::Corona},
        {"winchester", ConsoleType::Winchester},
        {"winchester4g", ConsoleType::Winchester},
    };

    struct NoPatch {
        bool cb = false;
        bool cd = false;
        bool khv = false;
    };

    [[nodiscard]] NoPatch resolve_no_patch(const OptionsArgs& options);

    class OptionsManager {
      public:
        OptionsManager() = default;
        explicit OptionsManager(OptionsArgs args);

        bool parse(std::string_view raw_args);

        static bool is_known_option(std::string_view name);
        static bool is_bool_option(std::string_view name);
        static std::optional<uint8_t> power_on_reason(std::string_view name);
        static std::optional<uint32_t> parse_u32(std::string_view raw);
        static std::optional<uint16_t> parse_u16(std::string_view raw);
        static std::optional<std::array<uint8_t, 6>> parse_mac_id(std::string_view raw);
        static std::optional<std::array<uint8_t, 16>> parse_dvd_key(std::string_view raw);
        bool has(std::string_view name) const;

        bool set_bool(std::string_view name, bool value);
        bool set(std::string_view name, std::string_view value);

        std::optional<bool> get_bool(std::string_view name) const;
        std::optional<std::string> get_string(std::string_view name) const;

        const OptionsArgs& data() const noexcept { return m_args; }
        OptionsArgs& data() noexcept { return m_args; }

      private:
        OptionsArgs m_args{};
    };

} // namespace gxbuild
