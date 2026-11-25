#include "core/BuildRunner.hpp"
#include "core/InputValidator.hpp"
#include "core/OptionsPatcher.hpp"
#include "excrypt.h"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "nand/objects/XConfig.hpp"
#include "nand/objects/XeLL.hpp"
#include "utils/BuildTime.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <exception>
#include <expected>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild {

    using namespace nand;

    namespace {

        // small-block devkits use a 64mb image with the small-block spare layout
        std::pair<Driver::ImageSize, Driver::DriverMode> driver_config(ImageType type,
                                                                       BuildType build_type) {
            const auto small_size = build_type == BuildType::Devkit ? Driver::ImageSize::Bigordevkit
                                                                    : Driver::ImageSize::Smallblock;
            switch (type) {
                case ImageType::SmallBlock:
                    return {small_size, Driver::DriverMode::Small};
                case ImageType::NewSmallBlock:
                    return {small_size, Driver::DriverMode::NewSmall};
                case ImageType::BigBlock:
                    return {Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big};
                case ImageType::Emmc:
                    return {Driver::ImageSize::Emmcblock, Driver::DriverMode::Emmc};
            }
            std::unreachable();
        }

        template <class Bootloader, class Target>
        [[nodiscard]] Result<void> parse_stage_into(Target& target, std::span<const uint8_t> bytes,
                                                    std::string_view name) {
            auto parsed = Bootloader::parse(bytes);
            if (!parsed) {
                return std::unexpected(
                    std::move(parsed.error()).add_context(std::format("Failed to parse {}", name)));
            }
            target = std::move(*parsed);
            return {};
        }

        [[nodiscard]] Result<void> parse_input_bootloaders(FlashImage& flash_image,
                                                           const Input& input) {
            const auto& bootloaders = input.bootloaders;
            const auto supplied = [](const std::optional<std::vector<uint8_t>>& bytes) {
                return bytes && !bytes->empty();
            };
            if (auto parsed = parse_stage_into<BootloaderCb>(flash_image.cb_section.cb_or_A,
                                                             bootloaders.cb_or_a, "CB/A");
                !parsed) {
                return parsed;
            }
            if (supplied(bootloaders.cb_x)) {
                if (auto parsed = parse_stage_into<BootloaderCb>(flash_image.cb_section.cb_x,
                                                                 *bootloaders.cb_x, "CB_X");
                    !parsed) {
                    return parsed;
                }
                if (input.build_type == BuildType::Glitch3) {
                    // forces cbx to be treated as decrypted and applies the v1 rgh3 register fix if needed
                    flash_image.cb_section.cb_x->decrypted = true;
                    flash_image.cb_section.cb_x->populate_metadata();
                    if (flash_image.cb_section.cb_x->patch_rgh3_v1_cb_x()) {
                        Log::Info("Applied the RGH2to3 v1 fix to the RGH3 CB_X");
                    }
                }
            }
            if (supplied(bootloaders.cb_b)) {
                if (auto parsed = parse_stage_into<BootloaderCb>(flash_image.cb_section.cb_B,
                                                                 *bootloaders.cb_b, "CB_B");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.sc)) {
                if (auto parsed = parse_stage_into<BootloaderSc>(flash_image.cb_section.sc,
                                                                 *bootloaders.sc, "SC");
                    !parsed) {
                    return parsed;
                }
            }
            if (auto parsed = parse_stage_into<BootloaderCd>(flash_image.kernel_section.cd,
                                                             bootloaders.cd, "CD");
                !parsed) {
                return parsed;
            }
            if (supplied(bootloaders.ce)) {
                if (auto parsed = parse_stage_into<BootloaderCe>(flash_image.kernel_section.ce,
                                                                 *bootloaders.ce, "CE");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cf0)) {
                if (auto parsed = parse_stage_into<BootloaderCf>(flash_image.system_update_0.cf,
                                                                 *bootloaders.cf0, "CF0");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cg0)) {
                if (auto parsed = parse_stage_into<BootloaderCg>(flash_image.system_update_0.cg,
                                                                 *bootloaders.cg0, "CG0");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cf1)) {
                if (auto parsed = parse_stage_into<BootloaderCf>(flash_image.system_update_1.cf,
                                                                 *bootloaders.cf1, "CF1");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cg1)) {
                if (auto parsed = parse_stage_into<BootloaderCg>(flash_image.system_update_1.cg,
                                                                 *bootloaders.cg1, "CG1");
                    !parsed) {
                    return parsed;
                }
            }
            // devkit stages are supplied in plaintext and the nand header takes se's build version.
            if (flash_image.devkit_chain()) {
                auto& sb = flash_image.cb_section.cb_or_A;
                sb.decrypted = true;
                sb.populate_metadata();
                if (flash_image.cb_section.sc) {
                    flash_image.cb_section.sc->decrypted = true;
                }
                flash_image.kernel_section.cd.decrypted = true;
                if (auto& se = flash_image.kernel_section.ce; se) {
                    se->decrypted = true;
                    if (input.build_type == BuildType::Devkit) {
                        flash_image.header.version = se->header.header.version;
                    }
                }
            }
            return {};
        }

        std::optional<ConsoleType> console_of(SmcMotherboard board) {
            switch (board) {
                case SmcMotherboard::Xenon:
                    return ConsoleType::Xenon;
                case SmcMotherboard::Zephyr:
                    return ConsoleType::Zephyr;
                case SmcMotherboard::Falcon:
                    return ConsoleType::Falcon;
                case SmcMotherboard::Jasper:
                    return ConsoleType::Jasper;
                case SmcMotherboard::Trinity:
                    return ConsoleType::Trinity;
                case SmcMotherboard::Corona:
                    return ConsoleType::Corona;
                case SmcMotherboard::Winchester:
                    return ConsoleType::Winchester;
                case SmcMotherboard::Unknown:
                    return std::nullopt;
            }
            return std::nullopt;
        }

        uint16_t copyright_year(ConsoleType console, BuildType build_type) {
            switch (console) {
                case ConsoleType::Xenon:
                case ConsoleType::Zephyr:
                    return 2005;
                case ConsoleType::Falcon:
                    return 2007;
                case ConsoleType::Jasper:
                    return build_type == BuildType::Jtag ? 2008 : 2009;
                case ConsoleType::Trinity:
                case ConsoleType::Corona:
                case ConsoleType::Winchester:
                    return 2010;
            }
            std::unreachable();
        }

        constexpr uint16_t kDevkitCopyrightYear = 2010;

        constexpr size_t kCopyrightLength = sizeof(nand_header::copyright);

        bool is_hacked(BuildType build_type) {
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
            std::unreachable();
        }

        // packs dualboot, hardware flags, and xell buttons into the 32-bit header word at 0x4C
        uint32_t boot_flags(BuildType build_type, const OptionsArgs& options) {
            if (!is_hacked(build_type)) {
                return 0;
            }
            const auto button = [](const std::optional<std::string>& name) -> uint8_t {
                return name ? OptionsManager::power_on_reason(*name).value_or(0) : 0;
            };
            constexpr uint8_t kEject = 0x12;
            const bool jtag = build_type == BuildType::Jtag;
            const bool nodvd = options.nodvd.value_or(false);
            const bool olddvd = options.olddvd.value_or(false);

            const uint8_t reason = options.xellbutton  ? button(options.xellbutton)
                                   : (nodvd || olddvd) ? 0
                                                       : kEject;
            const uint8_t second = button(options.xellbutton2);
            uint8_t boot_options =
                (options.cygnos.value_or(false) || options.demon.value_or(false)) ? 1 : 0;
            if (jtag && nodvd) {
                boot_options |= 2;
            } else if (jtag && !olddvd) {
                boot_options |= 4;
            }
            uint8_t dualboot = jtag ? button(options.dualboot) : 0;
            if (dualboot && (dualboot == reason || dualboot == second)) {
                Log::Warn("dualboot names a XeLL button; the setting is ignored");
                dualboot = 0;
            }
            return uint32_t(dualboot) << 24 | uint32_t(boot_options) << 16 |
                   uint32_t(second == reason ? 0 : second) << 8 | reason;
        }

        void write_copyright(nand_header& header, uint16_t year) {
            const std::string text = "\xA9 2004-" + std::to_string(year) +
                                     " Microsoft Corporation. All rights reserved.";
            std::fill_n(header.copyright, kCopyrightLength, uint8_t{0});
            std::memcpy(header.copyright, text.data(), std::min(text.size(), kCopyrightLength - 1));
        }

        [[nodiscard]] Result<void> init_build_image(const Input& input, FlashImage& flash_image,
                                                    std::optional<DonorNonces>& donor_nonces) {
            bool has_donor = false;
            std::optional<ConsoleType> donor_console;

            if (input.metadata.nand_image && !input.metadata.nand_image->empty()) {
                Log::Info("Building image from donor NAND dump...");
                auto donor_img = FlashImage::read(*input.metadata.nand_image);
                if (!donor_img) {
                    return fail(ErrorCode::InvalidArgument,
                                "Failed to parse donor NAND dump: it is empty");
                }
                if (auto parsed = donor_img->parse(); !parsed) {
                    return with_context(std::move(parsed), "Failed to parse donor NAND dump");
                }
                if (auto decrypted = donor_img->decrypt_all(input.metadata.cpu_key); !decrypted) {
                    return with_context(std::move(decrypted),
                                        "Failed to decrypt donor NAND dump components");
                }
                if (!donor_nonces) {
                    donor_nonces = donor_img->collect_nonces();
                }
                // start from a fresh image if a devkit build changes the donor's nand size
                const auto target = driver_config(input.image_type, input.build_type);
                const bool donor_shape = donor_img->flash_driver.image_size() == target.first &&
                                         donor_img->flash_driver.driver_mode() == target.second;
                if (input.build_type != BuildType::Devkit || donor_shape) {
                    has_donor = true;
                    if (donor_img->smc) {
                        donor_console = console_of(donor_img->smc->motherboard);
                    }
                    flash_image = std::move(*donor_img);
                } else {
                    Log::Debug("Laying the devkit image fresh beside its donor's shape");
                    flash_image = FlashImage::create(target.first, target.second, input.build_type);
                }
            } else {
                Log::Debug("Configuring fresh NAND image layout");
                const auto [image_size, driver_mode] =
                    driver_config(input.image_type, input.build_type);
                flash_image = FlashImage::create(image_size, driver_mode, input.build_type);
            }

            flash_image.build_type = input.build_type;

            if (input.metadata.smc_config) {
                auto parsed = SmcConfigBlock::parse(*input.metadata.smc_config);
                if (!parsed) {
                    return std::unexpected(
                        std::move(parsed.error())
                            .add_context("Failed to parse input SMC config block"));
                }
                flash_image.smc_config = std::move(*parsed);
            }
            if (input.metadata.statistics) {
                auto parsed = StatisticsBlock::parse(*input.metadata.statistics);
                if (!parsed) {
                    return std::unexpected(
                        std::move(parsed.error())
                            .add_context("Failed to parse input statistics block"));
                }
                flash_image.statistics = std::move(*parsed);
            }
            if (input.metadata.manufacturing) {
                auto parsed = ManufacturingBlock::parse(*input.metadata.manufacturing);
                if (!parsed) {
                    return std::unexpected(
                        std::move(parsed.error())
                            .add_context("Failed to parse input manufacturing block"));
                }
                flash_image.manufacturing = std::move(*parsed);
            }
            apply_smc_config_options(flash_image.smc_config, input.options);

            const auto smc = Smc::parse(*input.metadata.smc);
            if (!smc) {
                return std::unexpected(
                    Error(smc.error()).add_context("Failed to parse input SMC"));
            }
            flash_image.smc = *smc;

            if (input.build_type == BuildType::Jtag && !input.options.smcnocheck.value_or(false) &&
                !smc_has_jtag_mark(flash_image.smc->data)) {
                return fail(ErrorCode::Unsupported,
                            "Clean SMC binary found: a JTAG image needs a hacked SMC "
                            "(the smcnocheck option builds with this one anyway)");
            }

            const auto keyvault = Keyvault::parse(*input.metadata.keyvault);
            if (!keyvault) {
                return std::unexpected(
                    Error(keyvault.error()).add_context("Failed to parse input keyvault"));
            }
            flash_image.keyvault = *keyvault;
            flash_image.keyvault->encrypted = false;
            apply_keyvault_options(*flash_image.keyvault, input.options, input.build_type);

            flash_image.header.pairing = input.build_type == BuildType::Devkit ? 0x8000 : 0;

            // keep the donor copyright string unless the board changed or we're building a jtag jasper
            const bool donor_copyright_usable =
                has_donor && !std::all_of(std::begin(flash_image.header.copyright),
                                          std::begin(flash_image.header.copyright) + kCopyrightLength,
                                          [](uint8_t byte) { return byte == 0; });
            const bool jtag_jasper =
                input.build_type == BuildType::Jtag && input.console == ConsoleType::Jasper;
            if (input.build_type == BuildType::Devkit) {
                write_copyright(flash_image.header, kDevkitCopyrightYear);
            } else if (input.console &&
                       (!donor_copyright_usable || donor_console != input.console || jtag_jasper)) {
                write_copyright(flash_image.header, copyright_year(*input.console, input.build_type));
            }
            flash_image.header.hack_flags = is_hacked(input.build_type) ? 1 : 0;
            flash_image.header.boot_flags = boot_flags(input.build_type, input.options);
            return {};
        }

        [[nodiscard]] Result<void> populate_and_patch_bootloaders(
            FlashImage& flash_image, const Input& input, const std::optional<DonorNonces>& donor_nonces,
            const std::optional<EXCRYPT_RSAPRV_2048>& sd_signing_key,
            std::optional<ParsedPatchSet>& parsed_patchset) {
            const auto supplied = [](const std::optional<std::vector<uint8_t>>& bootloader) {
                return bootloader && !bootloader->empty();
            };
            if (supplied(input.bootloaders.cg0) && !supplied(input.bootloaders.cf0)) {
                return fail(ErrorCode::InvalidArgument,
                            "CG0 was supplied without its required CF0 parent");
            }
            if (supplied(input.bootloaders.cg1) && !supplied(input.bootloaders.cf1)) {
                return fail(ErrorCode::InvalidArgument,
                            "CG1 was supplied without its required CF1 parent");
            }

            if (auto cleared = flash_image.clear_bootloader_chain(); !cleared) {
                return with_context(std::move(cleared), "Failed to clear donor bootloader records");
            }
            flash_image.preserve_layout = false;
            flash_image.cb_section.cb_x.reset();
            flash_image.cb_section.cb_B.reset();
            flash_image.cb_section.sc.reset();
            flash_image.kernel_section.ce.reset();
            flash_image.system_update_0 = SystemUpdate{};
            flash_image.system_update_1 = SystemUpdate{};
            if (auto parsed = parse_input_bootloaders(flash_image, input); !parsed) {
                return parsed;
            }

            if (flash_image.kernel_section.cd.data.empty()) {
                return fail(ErrorCode::Truncated,
                            "Required CD bootloader has no payload and cannot be serialized");
            }

            if (input.build_type == BuildType::Glitch3 &&
                (!flash_image.cb_section.cb_x || flash_image.cb_section.cb_x->data.empty() ||
                 flash_image.cb_section.cb_x->header.header.version != 15432 ||
                 !flash_image.cb_section.cb_B || flash_image.cb_section.cb_B->data.empty())) {
                return fail(ErrorCode::InvalidArgument,
                            "Glitch3 requires CB_A, CB_X (15432), and CB_B");
            }

            if (input.build_type == BuildType::Glitch && flash_image.cb_section.cb_x) {
                return fail(ErrorCode::Unsupported,
                            "glitch1/RGH1 does not support a CB_X (use glitch3)");
            }

            if (input.patches && input.patches->automatic) {
                auto parsed = parse_and_merge_patch_set(*input.patches, input.build_type);
                if (!parsed) {
                    return std::unexpected(std::move(parsed.error()));
                }
                parsed_patchset = std::move(*parsed);
            }

            if (auto patched = apply_glitch_bootloader_patches(
                    flash_image, input.build_type, input.options, parsed_patchset);
                !patched) {
                return patched;
            }
            if (sd_signing_key) {
                if (auto signed_sd = resign_devgl_sd(flash_image, *sd_signing_key); !signed_sd) {
                    return signed_sd;
                }
            }

            if (input.bootloaders.extra_cb) {
                if (auto parsed = parse_stage_into<BootloaderCb>(
                        flash_image.payloads.extra_cb, *input.bootloaders.extra_cb, "JTAG extra CB");
                    !parsed) {
                    return parsed;
                }
            }
            if (input.bootloaders.extra_cd) {
                if (auto parsed = parse_stage_into<BootloaderCd>(
                        flash_image.payloads.extra_cd, *input.bootloaders.extra_cd, "JTAG extra CD");
                    !parsed) {
                    return parsed;
                }
            }
            if (input.bootloaders.extra_se) {
                if (auto parsed = parse_stage_into<BootloaderCe>(
                        flash_image.payloads.extra_se, *input.bootloaders.extra_se, "JTAG extra SE");
                    !parsed) {
                    return parsed;
                }
            }

            if (const auto metadata =
                    flash_image.apply_bootloader_metadata(input.metadata, input.build_type);
                !metadata) {
                return metadata;
            }
            if (const auto nonces = flash_image.apply_nonces(donor_nonces); !nonces) {
                return nonces;
            }
            return {};
        }

        [[nodiscard]] Result<void> populate_payloads(FlashImage& flash_image, const Input& input,
                                                     std::optional<ParsedPatchSet> parsed_patchset) {
            if (parsed_patchset) {
                flash_image.payloads.patchset = std::move(parsed_patchset);
            }

            if (input.payloads) {
                const bool chain_past_xell =
                    input.build_type == BuildType::Glitch2m &&
                    nand::detail::laid_boot_chain_end(flash_image) > nand::detail::kXellOffset;
                if (chain_past_xell && input.payloads->xell && !input.payloads->xell->empty()) {
                    Log::Warn(
                        "Skipping XeLL: the boot chain runs past its slot, there is not enough room");
                } else if (input.payloads->xell && !input.payloads->xell->empty()) {
                    auto xell_parsed = XeLL::parse(*input.payloads->xell);
                    if (!xell_parsed) {
                        return std::unexpected(std::move(xell_parsed.error())
                                                   .add_context("Failed to parse XeLL payload"));
                    }
                    flash_image.payloads.xell = std::move(*xell_parsed);
                    Log::Info("Adding XeLL payload (version='{}', size=0x{:X})",
                              flash_image.payloads.xell->metadata.version,
                              flash_image.payloads.xell->data.size());
                }
                if (input.payloads->rebooter) {
                    flash_image.payloads.rebooter = input.payloads->rebooter;
                    Log::Info("Adding Rebooter payload (size=0x{:X})",
                              flash_image.payloads.rebooter->size());
                }
                if (input.payloads->fuses) {
                    flash_image.payloads.fuses = input.payloads->fuses;
                    Log::Info("Adding virtual fuses payload (size=0x{:X})",
                              flash_image.payloads.fuses->size());
                }
                if (input.payloads->payload) {
                    flash_image.payloads.payload = input.payloads->payload;
                    Log::Info("Adding SMC payload (size=0x{:X})",
                              flash_image.payloads.payload->size());
                }
            }

            if (const auto layout = flash_image.payload_layout(); !layout) {
                return layout;
            }

            flash_image.raw_patches = input.raw_patches;
            return {};
        }

        [[nodiscard]] Result<void> populate_storage(FlashImage& flash_image, const Input& input) {
            if (input.flashfs_sec) {
                Log::Info("Populating Flash File System ({} files)", input.flashfs_sec->size());
                const int64_t build_seconds = gxbuild::utils::build_epoch();
                if (auto fs = flash_image.format_filesystem(
                        gxbuild::utils::flashfs_build_timestamp(build_seconds));
                    !fs) {
                    return std::unexpected(std::move(fs.error()));
                }

                const SecuredFileBuild secured_build{build_seconds,
                                                     is_zero_cpu_key(input.metadata.cpu_key)
                                                         ? uint8_t{0}
                                                         : input.metadata.cf_ldv.value_or(1)};
                for (const auto& [name, data] : *input.flashfs_sec) {
                    const auto file_data = sealed_flashfs_file(name, data, input, secured_build);
                    if (!file_data) {
                        return std::unexpected(
                            Error(file_data.error())
                                .add_context(
                                    std::format("Failed to encrypt secure FlashFS file '{}'", name)));
                    }
                    Log::Debug("Adding FlashFS file: '{}' ({} bytes)", name, file_data->size());
                    if (const auto added = flash_image.filesystem->add_file(name, *file_data); !added) {
                        return std::unexpected(
                            Error(added.error()).add_context("Failed to add a Flash File System file"));
                    }
                }
            }

            if (!flash_image.mobile_data) {
                for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                    const auto* slot = input.mobiles.slot(block_type);
                    if (slot && *slot) {
                        flash_image.mobile_data = MobileData{};
                        break;
                    }
                }
            }
            if (flash_image.mobile_data) {
                for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                    const auto* override_slot = input.mobiles.slot(block_type);
                    if (override_slot && *override_slot) {
                        *flash_image.mobile_data->get_slot(block_type) = **override_slot;
                    }
                }
                if (flash_image.flash_driver.driver_mode() == Driver::DriverMode::Emmc) {
                    for (uint8_t block_type = 0x35; block_type <= 0x39; ++block_type) {
                        auto* slot = flash_image.mobile_data->get_slot(block_type);
                        if (*slot && !(*slot)->empty()) {
                            Log::Warn("Mobile data type 0x{:02X} has no slot in an eMMC anchor block; "
                                      "it is left out",
                                      block_type);
                        }
                        slot->reset();
                    }
                }
            }
            return {};
        }

    } // namespace

    Result<std::vector<uint8_t>> run_build(const Input& input) try {
        if (const auto validation = validate_input(input); !validation) {
            return std::unexpected(validation.error());
        }

        std::optional<EXCRYPT_RSAPRV_2048> sd_signing_key;
        if (input.build_type == BuildType::Devgl) {
            EXCRYPT_RSAPRV_2048 key{};
            if (input.sb_private_key->size() != sizeof(EXCRYPT_RSAPRV_2048)) {
                return fail(ErrorCode::Malformed,
                            "The SB private key is not a well-formed XeCrypt RSA-2048 private key");
            }
            std::memcpy(&key, input.sb_private_key->data(), sizeof(key));
            if (ExCryptBnQwBeRsaPrvValidate(&key.rsa) == 0) {
                return fail(ErrorCode::Malformed,
                            "The SB private key is not a well-formed XeCrypt RSA-2048 private key");
            }
            sd_signing_key = key;
        }

        FlashImage flash_image{};
        std::optional<DonorNonces> donor_nonces = input.metadata.donor_nonces;
        if (auto init = init_build_image(input, flash_image, donor_nonces); !init) {
            return std::unexpected(std::move(init.error()));
        }

        std::optional<ParsedPatchSet> parsed_patchset;
        if (auto boot = populate_and_patch_bootloaders(flash_image, input, donor_nonces,
                                                       sd_signing_key, parsed_patchset);
            !boot) {
            return std::unexpected(std::move(boot.error()));
        }
        if (auto payloads = populate_payloads(flash_image, input, std::move(parsed_patchset));
            !payloads) {
            return std::unexpected(std::move(payloads.error()));
        }
        if (auto storage = populate_storage(flash_image, input); !storage) {
            return std::unexpected(std::move(storage.error()));
        }

        Log::Debug("Encrypting NAND image components");
        if (auto encrypted = flash_image.encrypt_all(input.metadata.cpu_key, input.build_type);
            !encrypted) {
            return std::unexpected(std::move(encrypted.error())
                                       .add_context("Failed to encrypt NAND image components"));
        }

        auto output = flash_image.write();
        if (!output) {
            return std::unexpected(
                std::move(output.error()).add_context("Failed to write/serialize built NAND image"));
        }

        return std::move(*output);
    } catch (const std::exception& exception) {
        return fail(ErrorCode::Internal, "{}", exception.what());
    }

} // namespace gxbuild
