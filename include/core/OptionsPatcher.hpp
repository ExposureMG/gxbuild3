#pragma once

#include "core/Args.hpp"
#include "excrypt.h"
#include "gxbuild/Error.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/XConfig.hpp"

#include <optional>

namespace gxbuild {

    void apply_smc_config_options(std::optional<nand::SmcConfigBlock>& smc_config,
                                  const OptionsArgs& options);

    void apply_keyvault_options(nand::Keyvault& keyvault, const OptionsArgs& options,
                                BuildType build_type);

    [[nodiscard]] Result<void> apply_glitch_bootloader_patches(
        nand::FlashImage& flash_image, BuildType build_type, const OptionsArgs& options,
        std::optional<nand::ParsedPatchSet>& parsed_patchset);

    [[nodiscard]] Result<void> resign_devgl_sd(nand::FlashImage& flash_image,
                                               const EXCRYPT_RSAPRV_2048& sd_signing_key);

} // namespace gxbuild
