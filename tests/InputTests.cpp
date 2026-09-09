#include "Args.hpp"
#include "InputValidator.hpp"

#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

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

} // namespace

int main() {
    bool passed = true;
    passed = test_typed_image_layout() && passed;
    passed = test_mobile_slot_mapping() && passed;
    passed = test_validation_rejects_missing_required_values() && passed;
    passed = test_glitch_requires_patchset() && passed;
    passed = test_retail_rejects_automatic_patchset() && passed;
    passed = test_retail_and_devkit_reject_addon_patch_data() && passed;
    return passed ? 0 : 1;
}
