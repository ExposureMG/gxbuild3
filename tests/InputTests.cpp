#include "Args.hpp"
#include "InputValidator.hpp"

#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

using namespace gxbuild3;

namespace {

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    Input valid_input() {
        Input input{};
        input.build_type = BuildType::Retail;
        input.image_type = ImageType::SmallBlock;
        input.metadata.cpu_key.assign(16, 0x11);
        input.metadata.smc = std::vector<uint8_t>(0x100, 0x22);
        input.metadata.keyvault = std::vector<uint8_t>(0x4000, 0x33);
        input.bootloaders.cb_or_a = {0x43, 0x42};
        input.bootloaders.cd = {0x43, 0x44};
        return input;
    }

    bool test_typed_image_layout() {
        Input input{};
        input.image_type = ImageType::BigBlock;
        return require(input.image_type == ImageType::BigBlock,
                       "input stores one typed image layout");
    }

    bool test_mobile_slot_mapping() {
        InputMobileData mobiles{};
        *mobiles.slot(0x31) = std::vector<uint8_t>{1};
        *mobiles.slot(0x39) = std::vector<uint8_t>{9};
        return require(mobiles.slot(0x31)->value().front() == 1, "mobile A maps to 0x31") &&
               require(mobiles.slot(0x39)->value().front() == 9, "mobile I maps to 0x39") &&
               require(mobiles.slot(0x30) == nullptr, "invalid mobile slot is rejected");
    }

    bool test_validation_rejects_missing_required_values() {
        auto input = valid_input();
        input.metadata.cpu_key.pop_back();
        if (!require(ValidateInput(input).error().code == InputErrorCode::InvalidCpuKey,
                     "a CPU key must contain exactly 16 bytes")) {
            return false;
        }

        input = valid_input();
        input.metadata.smc.reset();
        if (!require(ValidateInput(input).error().code == InputErrorCode::MissingSmc,
                     "an SMC is required")) {
            return false;
        }

        input = valid_input();
        input.metadata.keyvault.reset();
        if (!require(ValidateInput(input).error().code == InputErrorCode::MissingKeyvault,
                     "a keyvault is required")) {
            return false;
        }

        input = valid_input();
        input.bootloaders.cb_or_a.clear();
        if (!require(ValidateInput(input).error().code == InputErrorCode::MissingCb,
                     "a CB or A bootloader is required")) {
            return false;
        }

        input = valid_input();
        input.bootloaders.cd.clear();
        return require(ValidateInput(input).error().code == InputErrorCode::MissingCd,
                       "a CD bootloader is required");
    }

    bool test_glitch_requires_patchset() {
        auto input = valid_input();
        input.build_type = BuildType::Glitch2;
        const auto result = ValidateInput(input);
        return require(!result && result.error().code == InputErrorCode::MissingPatchset,
                       "glitch2 requires an automatic patchset");
    }

    bool test_retail_rejects_automatic_patchset() {
        auto input = valid_input();
        input.patches = InputPatches{.automatic = InputPatchFile{"auto", {0x01}}, .addons = {}};
        const auto result = ValidateInput(input);
        return require(!result && result.error().code == InputErrorCode::UnexpectedPatchset,
                       "retail rejects an automatic patchset");
    }

    bool test_retail_and_devkit_reject_addon_patch_data() {
        for (const auto build_type : {BuildType::Retail, BuildType::Devkit}) {
            auto input = valid_input();
            input.build_type = build_type;
            input.patches = InputPatches{.automatic = std::nullopt,
                                         .addons = {InputPatchFile{"addon", {0x01}}}};
            const auto result = ValidateInput(input);
            if (!require(!result && result.error().code == InputErrorCode::UnexpectedPatchset,
                         "retail and devkit reject add-on patch data")) {
                return false;
            }
        }
        return true;
    }

    Input valid_jtag_input() {
        auto input = valid_input();
        input.build_type = BuildType::Jtag;
        input.patches = InputPatches{.automatic = InputPatchFile{"auto", {0x01}}, .addons = {}};
        return input;
    }

    bool test_payload_and_rebooter_sizes() {
        auto input = valid_jtag_input();
        input.payloads = InputPayloads{};
        input.payloads->payload = std::vector<uint8_t>(0x200, 0x00);
        input.payloads->rebooter = std::vector<uint8_t>(0xd40, 0x00);
        if (!require(ValidateInput(input).has_value(),
                     "a 0x200 payload with a 0xd40 rebooter is valid")) {
            return false;
        }

        input.payloads->rebooter = std::vector<uint8_t>(0x1000, 0x00);
        if (!require(ValidateInput(input).has_value(),
                     "a rebooter that exactly fills its 0x1000-byte region is valid")) {
            return false;
        }

        input.payloads->rebooter = std::vector<uint8_t>(0xd40, 0x00);
        input.payloads->payload = std::vector<uint8_t>(0x100, 0x00);
        const auto short_payload = ValidateInput(input);
        if (!require(!short_payload &&
                         short_payload.error().code == InputErrorCode::InvalidPayloadSize,
                     "a payload must contain exactly 0x200 bytes")) {
            return false;
        }

        input.payloads->payload = std::vector<uint8_t>(0x200, 0x00);
        input.payloads->rebooter = std::vector<uint8_t>(0x1001, 0x00);
        const auto oversized = ValidateInput(input);
        return require(!oversized && oversized.error().code == InputErrorCode::InvalidRebooterSize,
                       "a rebooter must not exceed its 0x1000-byte region");
    }

    bool test_settings_block_sizes() {
        auto input = valid_input();
        input.metadata.smc_config = std::vector<uint8_t>(0x400, 0x00);
        input.metadata.statistics = std::vector<uint8_t>(0x1000, 0xFF);
        input.metadata.manufacturing = std::vector<uint8_t>(0x1000, 0xFF);
        if (!require(ValidateInput(input).has_value(),
                     "0x400 of settings and 0x1000 of statistics and manufacturing are valid")) {
            return false;
        }

        input.metadata.smc_config = std::vector<uint8_t>(0x3FF, 0x00);
        const auto short_config = ValidateInput(input);
        if (!require(!short_config &&
                         short_config.error().code == InputErrorCode::InvalidSettingsBlockSize,
                     "a settings block must contain exactly 0x400 bytes")) {
            return false;
        }

        input.metadata.smc_config.reset();
        input.metadata.manufacturing = std::vector<uint8_t>(0x1001, 0xFF);
        const auto long_block = ValidateInput(input);
        return require(!long_block &&
                           long_block.error().code == InputErrorCode::InvalidSettingsBlockSize,
                       "a manufacturing block must contain exactly 0x1000 bytes");
    }

    bool test_nopatch_options_accumulate_stage_by_stage() {
        OptionsManager options;
        if (!require(options.parse("nopatch=cb") && options.get_string("nopatch") == "cb",
                     "nopatch takes one stage") ||
            !require(options.parse("nopatch=khv,nopatch=cd") &&
                         options.get_string("nopatch") == "cb+cd+khv",
                     "repeated nopatch settings accumulate in stage order") ||
            !require(!options.set("nopatch", "ce") && !options.set("nopatch", "cb+cd") &&
                         options.get_string("nopatch") == "cb+cd+khv",
                     "an unknown stage or a joined list is refused and the earlier value kept")) {
            return false;
        }
        const auto all = ResolveNoPatch(options.data());
        OptionsArgs legacy;
        legacy.noblpatch = true;
        const auto old = ResolveNoPatch(legacy);
        return require(all.cb && all.cd && all.khv, "every named stage is skipped") &&
               require(old.cb && old.cd && !old.khv,
                       "noblpatch still means nopatch=cb and nopatch=cd") &&
               require(options.set("nopatch", "") && !options.has("nopatch"),
                       "a blank nopatch clears the list");
    }

    bool test_button_options_take_xebuild_names_only() {
        OptionsManager options;
        if (!require(OptionsManager::power_on_reason("power") == 0x11 &&
                         OptionsManager::power_on_reason(" Eject ") == 0x12 &&
                         OptionsManager::power_on_reason("wiredx") == 0x5A &&
                         OptionsManager::power_on_reason("wiredxb3") == 0x5A,
                     "button names map to xeBuild's header bytes in any case") ||
            !require(!OptionsManager::power_on_reason("0x11") &&
                         !OptionsManager::power_on_reason("") &&
                         !OptionsManager::power_on_reason("powerbutton"),
                     "a number or an unknown name is no button") ||
            !require(options.set("xellbutton", "Power") && options.set("xellbutton2", "remox") &&
                         options.set("dualboot", "kiosk"),
                     "xellbutton, xellbutton2 and dualboot take button names") ||
            !require(!options.set("xellbutton", "bogus") &&
                         options.get_string("xellbutton") == "Power",
                     "an unknown button is refused and the earlier value kept")) {
            return false;
        }
        OptionsManager blank;
        if (!require(blank.set("xellbutton2", "") && !blank.has("xellbutton2") &&
                         blank.set("xellbutton2", "remox") && blank.set("xellbutton2", " ") &&
                         !blank.has("xellbutton2"),
                     "a blank button names none")) {
            return false;
        }

        auto input = valid_input();
        input.options = options.data();
        if (!require(ValidateInput(input).has_value(), "named buttons validate")) {
            return false;
        }
        input.options.dualboot = "sideways";
        const auto result = ValidateInput(input);
        return require(!result && result.error().code == InputErrorCode::InvalidOption,
                       "an unknown button supplied directly is rejected");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_typed_image_layout() && passed;
    passed = test_mobile_slot_mapping() && passed;
    passed = test_validation_rejects_missing_required_values() && passed;
    passed = test_glitch_requires_patchset() && passed;
    passed = test_retail_rejects_automatic_patchset() && passed;
    passed = test_retail_and_devkit_reject_addon_patch_data() && passed;
    passed = test_payload_and_rebooter_sizes() && passed;
    passed = test_settings_block_sizes() && passed;
    passed = test_button_options_take_xebuild_names_only() && passed;
    passed = test_nopatch_options_accumulate_stage_by_stage() && passed;
    return passed ? 0 : 1;
}
