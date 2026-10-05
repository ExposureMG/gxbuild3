#pragma once

#include "GxBuildTypes.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>

// The public types, visible unqualified throughout the internal gxbuild3 namespaces.
namespace gxbuild3 {
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
    using GxBuild::OptionsArgs;
    using GxBuild::SmcSummaryInfo;
} // namespace gxbuild3

inline const std::map<std::string, GxBuild::BuildType> kBuildTypeMap = {
    {"retail", GxBuild::BuildType::Retail},     {"jtag", GxBuild::BuildType::Jtag},
    {"glitch", GxBuild::BuildType::Glitch},     {"glitch2", GxBuild::BuildType::Glitch2},
    {"glitch2m", GxBuild::BuildType::Glitch2m}, {"glitch3", GxBuild::BuildType::Glitch3},
    {"devkit", GxBuild::BuildType::Devkit},     {"devgl", GxBuild::BuildType::Devgl},
};

inline const std::map<std::string, GxBuild::ConsoleType> kConsoleTypeMap = {
    {"xenon", GxBuild::ConsoleType::Xenon},
    {"zephyr", GxBuild::ConsoleType::Zephyr},
    {"falcon", GxBuild::ConsoleType::Falcon},
    {"jasper", GxBuild::ConsoleType::Jasper},
    {"jasper256", GxBuild::ConsoleType::Jasper},
    {"jasper512", GxBuild::ConsoleType::Jasper},
    {"jasperbb", GxBuild::ConsoleType::Jasper},
    {"jasperbigffs", GxBuild::ConsoleType::Jasper},
    {"trinity", GxBuild::ConsoleType::Trinity},
    {"trinitybb", GxBuild::ConsoleType::Trinity},
    {"trinitybigffs", GxBuild::ConsoleType::Trinity},
    {"corona", GxBuild::ConsoleType::Corona},
    {"corona4g", GxBuild::ConsoleType::Corona},
    {"winchester", GxBuild::ConsoleType::Winchester},
    {"winchester4g", GxBuild::ConsoleType::Winchester},
};

struct NoPatch {
    bool cb = false;
    bool cd = false;
    bool khv = false;
};

// The stages whose automatic patches are skipped. `noblpatch` is the older spelling of
// `nopatch=cb+cd`.
[[nodiscard]] NoPatch ResolveNoPatch(const GxBuild::OptionsArgs& options);

class OptionsManager {
  public:
    OptionsManager() = default;
    explicit OptionsManager(GxBuild::OptionsArgs args);

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

    const GxBuild::OptionsArgs& data() const noexcept { return m_args; }
    GxBuild::OptionsArgs& data() noexcept { return m_args; }

  private:
    GxBuild::OptionsArgs m_args{};
};
