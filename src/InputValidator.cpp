#include "InputValidator.hpp"

#include <expected>

namespace {

    bool requires_automatic_patchset(BuildType build_type) {
        switch (build_type) {
            case BuildType::Jtag:
            case BuildType::Glitch:
            case BuildType::Glitch2:
            case BuildType::Glitch2m:
            case BuildType::Glitch3:
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

} // namespace

std::expected<void, InputError> ValidateInput(const Input& input) {
    if (input.metadata.cpu_key.size() != 16) {
        return std::unexpected(
            InputError{InputErrorCode::InvalidCpuKey, "CPU key must contain exactly 16 bytes"});
    }
    if (!input.metadata.smc.has_value() || input.metadata.smc->empty()) {
        return std::unexpected(InputError{InputErrorCode::MissingSmc, "SMC is required"});
    }
    if (!input.metadata.keyvault.has_value() || input.metadata.keyvault->empty()) {
        return std::unexpected(InputError{InputErrorCode::MissingKeyvault, "Keyvault is required"});
    }
    if (input.bootloaders.cb_or_a.empty()) {
        return std::unexpected(
            InputError{InputErrorCode::MissingCb, "CB or A bootloader is required"});
    }
    if (input.bootloaders.cd.empty()) {
        return std::unexpected(InputError{InputErrorCode::MissingCd, "CD bootloader is required"});
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

    if (input.payloads && input.payloads->payload.has_value()) {
        return std::unexpected(
            InputError{InputErrorCode::UnsupportedCustomPayload,
                       "Custom payload is unsupported because no on-disk format contract exists"});
    }
    if (input.payloads && input.payloads->rebooter &&
        input.payloads->rebooter->size() != 0x1000) {
        return std::unexpected(InputError{InputErrorCode::InvalidRebooterSize,
                                          "Rebooter payload must contain exactly 0x1000 bytes"});
    }
    if (input.payloads && input.payloads->fuses && input.payloads->fuses->size() != 0x60) {
        return std::unexpected(
            InputError{InputErrorCode::InvalidFusesSize,
                       "Virtual fuses payload must contain exactly 0x60 bytes"});
    }

    const bool has_donor_backing = input.metadata.nand_image && !input.metadata.nand_image->empty();
    if (!has_donor_backing && input.image_type == ImageType::Emmc) {
        for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
            const auto* slot = input.mobiles.slot(block_type);
            if (slot && *slot) {
                return std::unexpected(
                    InputError{InputErrorCode::UnsupportedMobileData,
                               "eMMC Corona metadata supports mobile slots 0x31 and 0x32 only"});
            }
        }
    }

    return {};
}
