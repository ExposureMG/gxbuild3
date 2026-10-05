#pragma once

#include "GxBuildTypes.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace gxbuild3 {

    // The public types, visible unqualified throughout the internal gxbuild3 namespaces.
    using GxBuild::OptionsArgs;
    using GxBuild::AllNandInfo;
    using GxBuild::BootloaderChainInfo;
    using GxBuild::BootloaderEntryInfo;
    using GxBuild::BootloaderNonce;
    using GxBuild::BuildError;
    using GxBuild::BuildErrorCode;
    using GxBuild::BuildResult;
    using GxBuild::BuildType;
    using GxBuild::ConsoleType;
    using GxBuild::DonorNonces;
    using GxBuild::FlashFsFileInfo;
    using GxBuild::FlashFsSummaryInfo;
    using GxBuild::ImageType;
    using GxBuild::Input;
    using GxBuild::InputBootloaders;
    using GxBuild::InputMetadata;
    using GxBuild::InputMobileData;
    using GxBuild::InputPatches;
    using GxBuild::InputPatchFile;
    using GxBuild::InputPayloads;
    using GxBuild::InputRawPatch;
    using GxBuild::KeyvaultSummaryInfo;
    using GxBuild::SmcSummaryInfo;

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

    // The stages whose automatic patches are skipped. `noblpatch` is the older spelling of
    // `nopatch=cb+cd`.
    [[nodiscard]] NoPatch ResolveNoPatch(const OptionsArgs& options);

    class OptionsManager {
      public:
        OptionsManager() = default;
        explicit OptionsManager(OptionsArgs args);

        bool parse(std::string_view raw_args);

        static bool is_known_option(std::string_view name);
        static bool is_bool_option(std::string_view name);
        // The header byte for a power-on reason named by xellbutton, xellbutton2 or dualboot
        // (any case): the device in the high nibble, the button in the low one, as xeBuild
        // writes it. Nothing for a name xeBuild does not take.
        static std::optional<uint8_t> power_on_reason(std::string_view name);
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

} // namespace gxbuild3
