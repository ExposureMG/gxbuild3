#include "InputValidator.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3 {

    namespace {

        bool requires_automatic_patchset(BuildType build_type) {
            switch (build_type) {
                case BuildType::Jtag:
                case BuildType::Glitch:
                case BuildType::Glitch2:
                case BuildType::Glitch2m:
                case BuildType::Glitch3:
                case BuildType::Devgl:
                    return true;
                case BuildType::Retail:
                case BuildType::Devkit:
                    return false;
            }
            return false;
        }

        bool has_automatic_patchset(const Input& input) {
            return input.patches.has_value() && input.patches->automatic.has_value();
        }

        bool is_blank(std::string_view text) {
            return std::all_of(text.begin(), text.end(),
                               [](unsigned char c) { return std::isspace(c) != 0; });
        }

    } // namespace

    std::expected<void, InputError> validate_input(const Input& input) {
        if (input.metadata.cpu_key.size() != 16) {
            return std::unexpected(
                InputError{InputErrorCode::InvalidCpuKey, "CPU key must contain exactly 16 bytes"});
        }
        if (!input.metadata.smc.has_value() || input.metadata.smc->empty()) {
            return std::unexpected(InputError{InputErrorCode::MissingSmc, "SMC is required"});
        }
        if (!input.metadata.keyvault.has_value() || input.metadata.keyvault->empty()) {
            return std::unexpected(
                InputError{InputErrorCode::MissingKeyvault, "Keyvault is required"});
        }
        if (input.bootloaders.cb_or_a.empty()) {
            return std::unexpected(
                InputError{InputErrorCode::MissingCb, "CB or A bootloader is required"});
        }
        if (input.bootloaders.cd.empty()) {
            return std::unexpected(
                InputError{InputErrorCode::MissingCd, "CD bootloader is required"});
        }

        if (input.build_type == BuildType::Devgl &&
            (!input.sb_private_key || input.sb_private_key->empty())) {
            return std::unexpected(InputError{
                InputErrorCode::MissingSigningKey,
                "A devgl image's patched SD is signed again, which needs the SB private key"});
        }

        const bool has_automatic = has_automatic_patchset(input);
        if (requires_automatic_patchset(input.build_type) && !has_automatic) {
            return std::unexpected(InputError{InputErrorCode::MissingPatchset,
                                              "Build type requires an automatic patchset"});
        }
        if (!requires_automatic_patchset(input.build_type) &&
            (has_automatic || (input.patches && !input.patches->addons.empty()))) {
            return std::unexpected(InputError{InputErrorCode::UnexpectedPatchset,
                                              "Build type does not allow patch data"});
        }

        if (input.payloads && input.payloads->payload && input.payloads->payload->size() != 0x200) {
            return std::unexpected(InputError{InputErrorCode::InvalidPayloadSize,
                                              "Payload must contain exactly 0x200 bytes"});
        }
        if (input.payloads && input.payloads->rebooter &&
            input.payloads->rebooter->size() > 0x1000) {
            return std::unexpected(
                InputError{InputErrorCode::InvalidRebooterSize,
                           "Rebooter payload must not exceed the 0x1000-byte region"});
        }
        if (input.payloads && input.payloads->fuses && input.payloads->fuses->size() != 0x60) {
            return std::unexpected(
                InputError{InputErrorCode::InvalidFusesSize,
                           "Virtual fuses payload must contain exactly 0x60 bytes"});
        }
        if (input.metadata.smc_config && input.metadata.smc_config->size() != 0x400) {
            return std::unexpected(InputError{InputErrorCode::InvalidSettingsBlockSize,
                                              "SMC config block must contain exactly 0x400 bytes"});
        }
        for (const auto* block : {&input.metadata.statistics, &input.metadata.manufacturing}) {
            if (*block && (*block)->size() != 0x1000) {
                return std::unexpected(InputError{
                    InputErrorCode::InvalidSettingsBlockSize,
                    "Statistics and manufacturing blocks must contain exactly 0x1000 bytes"});
            }
        }
        for (const auto& [name, button] : {std::pair{"xellbutton", &input.options.xellbutton},
                                           std::pair{"xellbutton2", &input.options.xellbutton2},
                                           std::pair{"dualboot", &input.options.dualboot}}) {
            if (*button && !OptionsManager::power_on_reason(**button)) {
                return std::unexpected(
                    InputError{InputErrorCode::InvalidOption,
                               std::string(name) + " names no known button: '" + **button + "'"});
            }
        }
        static constexpr std::array<
            std::pair<std::string_view, std::optional<std::string> OptionsArgs::*>, 10>
            kU32Options{{
                {"cputemp", &OptionsArgs::cputemp},
                {"gputemp", &OptionsArgs::gputemp},
                {"edramtemp", &OptionsArgs::edramtemp},
                {"overcputemp", &OptionsArgs::overcputemp},
                {"overgputemp", &OptionsArgs::overgputemp},
                {"overedramtemp", &OptionsArgs::overedramtemp},
                {"cpufan", &OptionsArgs::cpufan},
                {"gpufan", &OptionsArgs::gpufan},
                {"avregion", &OptionsArgs::avregion},
                {"dvdregion", &OptionsArgs::dvdregion},
            }};
        for (const auto& [name, member] : kU32Options) {
            const auto& opt = input.options.*member;
            if (opt && !is_blank(*opt) && !OptionsManager::parse_u32(*opt)) {
                return std::unexpected(
                    InputError{InputErrorCode::InvalidOption,
                               std::string(name) +
                                   " is not a valid unsigned 32-bit integer: '" + *opt + "'"});
            }
        }
        if (input.options.gameregion && !is_blank(*input.options.gameregion) &&
            !OptionsManager::parse_u16(*input.options.gameregion)) {
            return std::unexpected(InputError{
                InputErrorCode::InvalidOption,
                "gameregion is not a valid unsigned 16-bit integer: '" +
                    *input.options.gameregion + "'"});
        }
        if (input.options.macid && !is_blank(*input.options.macid) &&
            !OptionsManager::parse_mac_id(*input.options.macid)) {
            return std::unexpected(InputError{
                InputErrorCode::InvalidOption,
                "macid must contain 12 hexadecimal digits (with optional ':' separators): '" +
                    *input.options.macid + "'"});
        }
        if (input.options.dvdkey && !is_blank(*input.options.dvdkey) &&
            !OptionsManager::parse_dvd_key(*input.options.dvdkey)) {
            return std::unexpected(
                InputError{InputErrorCode::InvalidOption,
                           "dvdkey must contain 32 hexadecimal digits: '" + *input.options.dvdkey +
                               "'"});
        }

        return {};
    }

} // namespace gxbuild3
