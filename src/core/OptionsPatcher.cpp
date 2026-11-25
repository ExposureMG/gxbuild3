#include "core/OptionsPatcher.hpp"

#include "core/Wire.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/bootloaders/Common.hpp"
#include "patchers/Patcher.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace gxbuild {

    using namespace nand;

    namespace {

        bool is_blank_option(const std::optional<std::string>& opt) {
            return !opt || std::all_of(opt->begin(), opt->end(),
                                       [](unsigned char c) { return std::isspace(c) != 0; });
        }

        constexpr size_t kSdSignatureOffset = 0x20;
        constexpr size_t kSdHashResume = kSdSignatureOffset + sizeof(EXCRYPT_SIG);
        constexpr std::array<uint8_t, 10> kSdSignatureSalt{
            'X', 'B', 'O', 'X', '_', 'R', 'O', 'M', '_', '4'};

        std::array<uint8_t, 20> sd_rot_sum_sha(std::span<const uint8_t> sd) {
            std::vector<uint8_t> covered(sd.begin(), sd.begin() + 0x10);
            covered.insert(covered.end(), sd.begin() + kSdHashResume, sd.end());
            std::array<uint8_t, 20> hash{};
            ExCryptRotSumSha(covered.data(), static_cast<uint32_t>(covered.size()), covered.data(),
                             0, hash.data(), static_cast<uint32_t>(hash.size()));
            return hash;
        }

        bool verify_sd_signature(std::span<const uint8_t> sd, const EXCRYPT_RSA* pubkey) {
            if (sd.size() < kSdHashResume) {
                return false;
            }
            const auto hash = sd_rot_sum_sha(sd);
            EXCRYPT_SIG sig{};
            std::memcpy(&sig, sd.data() + kSdSignatureOffset, sizeof(sig));
            return ExCryptBnQwBeSigVerify(&sig, hash.data(), kSdSignatureSalt.data(), pubkey) != 0;
        }

        Result<void> sign_sd(std::vector<uint8_t>& sd, const EXCRYPT_RSAPRV_2048& key) {
            if (sd.size() < kSdHashResume) {
                return fail(ErrorCode::Truncated,
                            "SD of 0x{:X} bytes is too short to hold a signature (0x{:X})",
                            sd.size(), kSdHashResume);
            }
            sd.resize((sd.size() + 0x0F) & ~size_t{0x0F}, 0);
            if (auto stored = wire::write<wire::be32>(
                    std::span<uint8_t>(sd), 0x0C, wire::be32(static_cast<uint32_t>(sd.size())),
                    "SD size");
                !stored) {
                return stored;
            }
            const auto hash = sd_rot_sum_sha(sd);
            EXCRYPT_SIG sig{};
            if (ExCryptBnQwBeSigCreate(&sig, hash.data(), kSdSignatureSalt.data(), &key.rsa) == 0) {
                return fail(ErrorCode::Internal, "Could not create RSA-2048 SD signature");
            }
            std::memcpy(sd.data() + kSdSignatureOffset, &sig, sizeof(sig));
            return {};
        }

        size_t align_16(size_t value) {
            return (value + 0x0F) & ~size_t{0x0F};
        }

        [[nodiscard]] Result<size_t> patched_bootloader_size(size_t current_size,
                                                             const ParsedPatchSection& section,
                                                             std::string_view stage_name) {
            uint64_t required_end = current_size;
            for (const auto& entry : section.entries) {
                if (entry.words.size() < entry.length) {
                    return fail(ErrorCode::Malformed, "{} patch entry has too few words",
                                stage_name);
                }
                const uint64_t entry_end = static_cast<uint64_t>(entry.address) +
                                           static_cast<uint64_t>(entry.length) * sizeof(uint32_t);
                required_end = std::max(required_end, entry_end);
            }
            if (required_end > std::numeric_limits<uint32_t>::max()) {
                return fail(ErrorCode::OutOfRange, "{} patch exceeds the 32-bit address space",
                            stage_name);
            }
            return static_cast<size_t>(required_end);
        }

        [[nodiscard]] Result<std::vector<uint8_t>>
        apply_bootloader_patch(std::vector<uint8_t> bytes, const ParsedPatchSection& section,
                               size_t target_capacity, std::string_view stage_name) {
            const auto required_end = patched_bootloader_size(bytes.size(), section, stage_name);
            if (!required_end) {
                return std::unexpected(required_end.error());
            }
            if (align_16(*required_end) > target_capacity) {
                return fail(ErrorCode::OutOfRange, "{} patch exceeds its boot-chain capacity",
                            stage_name);
            }

            // grows the stage to fit out-of-bounds patches and updates the header size.
            bytes.resize(align_16(*required_end), 0);
            const XePatchSection xe_section{section.identifier, section.entries};
            const auto applied = gxbuild::patchers::apply_patch_section(
                bytes.data(), static_cast<uint32_t>(bytes.size()), xe_section);
            if (!applied) {
                return std::unexpected(
                    Error(applied.error())
                        .add_context(std::format("Failed to apply {} patch section", stage_name)));
            }

            if (bytes.size() < sizeof(generic_header)) {
                return fail(ErrorCode::Truncated, "{} patch target has no bootloader header",
                            stage_name);
            }
            const auto patched_size = static_cast<uint32_t>(bytes.size());
            if (auto patched = wire::patch<generic_header>(
                    bytes, 0, "patched bootloader header",
                    [patched_size](generic_header& header) { header.size = patched_size; });
                !patched) {
                return std::unexpected(std::move(patched.error()));
            }
            return bytes;
        }

    } // namespace

    void apply_smc_config_options(std::optional<SmcConfigBlock>& smc_config,
                                  const OptionsArgs& options) {
        static constexpr std::array<std::optional<std::string> OptionsArgs::*, 12>
            kSmcConfigOptions{{
                &OptionsArgs::cputemp,
                &OptionsArgs::gputemp,
                &OptionsArgs::edramtemp,
                &OptionsArgs::overcputemp,
                &OptionsArgs::overgputemp,
                &OptionsArgs::overedramtemp,
                &OptionsArgs::cpufan,
                &OptionsArgs::gpufan,
                &OptionsArgs::avregion,
                &OptionsArgs::gameregion,
                &OptionsArgs::dvdregion,
                &OptionsArgs::macid,
            }};
        const bool any_set =
            std::any_of(kSmcConfigOptions.begin(), kSmcConfigOptions.end(),
                        [&options](auto member) { return !is_blank_option(options.*member); });
        if (!any_set) {
            return;
        }
        if (!smc_config.has_value()) {
            Log::Warn("SMC config options were supplied, but no SMC config block is present; "
                      "skipping");
            return;
        }

        constexpr uint32_t kSmcTempMin = 40;
        constexpr uint32_t kSmcTempMax = 120;
        constexpr uint32_t kSmcFanMin = 40;
        constexpr uint32_t kSmcFanMax = 100;
        constexpr uint8_t kFanOverride = 0x80;
        constexpr uint8_t kFanAuto = 0x7F;

        SmcConfigBlock& cfg = *smc_config;
        bool modified = false;
        struct FieldTarget {
            std::string_view name;
            const std::optional<std::string>* opt;
            uint8_t* field;
        };

        const std::array<FieldTarget, 6> temp_targets{{
            {"cputemp", &options.cputemp, &cfg.static_settings.smc.setpoint.cpu},
            {"gputemp", &options.gputemp, &cfg.static_settings.smc.setpoint.gpu},
            {"edramtemp", &options.edramtemp, &cfg.static_settings.smc.setpoint.edram},
            {"overcputemp", &options.overcputemp, &cfg.static_settings.smc.overload.cpu},
            {"overgputemp", &options.overgputemp, &cfg.static_settings.smc.overload.gpu},
            {"overedramtemp", &options.overedramtemp, &cfg.static_settings.smc.overload.edram},
        }};
        for (const auto& target_item : temp_targets) {
            if (is_blank_option(*target_item.opt)) {
                continue;
            }
            const auto parsed = OptionsManager::parse_u32(**target_item.opt);
            if (!parsed || *parsed == 0) {
                continue;
            }
            if (*parsed < kSmcTempMin || *parsed > kSmcTempMax) {
                Log::Warn("Option {} value {} is out of range ({}-{}), ignoring", target_item.name,
                          *parsed, kSmcTempMin, kSmcTempMax);
                continue;
            }
            const auto target = static_cast<uint8_t>(*parsed);
            if (*target_item.field != target) {
                *target_item.field = target;
                modified = true;
            }
        }

        const std::array<FieldTarget, 2> fan_targets{{
            {"cpufan", &options.cpufan, &cfg.static_settings.smc.cpu_fan},
            {"gpufan", &options.gpufan, &cfg.static_settings.smc.gpu_fan},
        }};
        for (const auto& target_item : fan_targets) {
            if (is_blank_option(*target_item.opt)) {
                continue;
            }
            const auto parsed = OptionsManager::parse_u32(**target_item.opt);
            if (!parsed) {
                continue;
            }
            // fan speed 0 means auto (0x7F), otherwise set bit 7 to force a fixed percentage
            if (*parsed == 0) {
                if (*target_item.field != kFanAuto) {
                    *target_item.field = kFanAuto;
                    modified = true;
                }
                continue;
            }
            if (*parsed < kSmcFanMin || *parsed > kSmcFanMax) {
                Log::Warn("Option {} value {} is out of range ({}-{}), ignoring", target_item.name,
                          *parsed, kSmcFanMin, kSmcFanMax);
                continue;
            }
            const auto target = static_cast<uint8_t>(*parsed | kFanOverride);
            if (*target_item.field != target) {
                *target_item.field = target;
                modified = true;
            }
        }

        if (!is_blank_option(options.avregion)) {
            if (const auto parsed = OptionsManager::parse_u32(*options.avregion);
                parsed && cfg.secured_settings.av_region.get() != *parsed) {
                cfg.secured_settings.av_region = *parsed;
                modified = true;
            }
        }
        if (!is_blank_option(options.gameregion)) {
            if (const auto parsed = OptionsManager::parse_u16(*options.gameregion);
                parsed && *parsed != 0 && cfg.secured_settings.game_region.get() != *parsed) {
                cfg.secured_settings.game_region = *parsed;
                modified = true;
            }
        }
        if (!is_blank_option(options.dvdregion)) {
            if (const auto parsed = OptionsManager::parse_u32(*options.dvdregion);
                parsed && cfg.secured_settings.dvd_region.get() != *parsed) {
                cfg.secured_settings.dvd_region = *parsed;
                modified = true;
            }
        }
        if (!is_blank_option(options.macid)) {
            if (const auto parsed = OptionsManager::parse_mac_id(*options.macid);
                parsed &&
                !std::equal(parsed->begin(), parsed->end(), std::begin(cfg.secured_settings.mac_address))) {
                std::copy(parsed->begin(), parsed->end(), std::begin(cfg.secured_settings.mac_address));
                modified = true;
            }
        }

        if (modified) {
            cfg.reserialize = true;
            Log::Info("Patched SMC config block from build options");
        }
    }

    void apply_keyvault_options(Keyvault& keyvault, const OptionsArgs& options,
                                BuildType build_type) {
        if (is_blank_option(options.dvdkey)) {
            return;
        }
        const auto dvd_key = OptionsManager::parse_dvd_key(*options.dvdkey);
        if (!dvd_key) {
            return;
        }
        if (build_type == BuildType::Retail) {
            Log::Info("Retail image: skipping dvdkey patch to preserve keyvault signature");
            return;
        }
        if (!std::equal(dvd_key->begin(), dvd_key->end(), std::begin(keyvault.data.b1ADvdKey))) {
            std::copy(dvd_key->begin(), dvd_key->end(), std::begin(keyvault.data.b1ADvdKey));
            keyvault.reserialize = true;
            Log::Info("Patched DVD key into keyvault");
        }
    }

    Result<void> apply_glitch_bootloader_patches(FlashImage& flash_image, BuildType build_type,
                                                 const OptionsArgs& options,
                                                 std::optional<ParsedPatchSet>& parsed_patchset) {
        if (!parsed_patchset || parsed_patchset->kind != PatchSetKind::Glitch) {
            return {};
        }
        const NoPatch no_patch = resolve_no_patch(options);
        if (no_patch.khv) {
            for (auto& section : parsed_patchset->sections) {
                if (section.target == PatchSectionTarget::Khv) {
                    section.raw_data.clear();
                }
            }
        }
        if (no_patch.cb && no_patch.cd) {
            return {};
        }

        const bool devgl = build_type == BuildType::Devgl;
        // edge case where split-cb glitch1 applies its cb patch section to cbb instead
        const bool glitch1_cbb = build_type == BuildType::Glitch && flash_image.cb_section.cb_B;
        const auto first_target =
            build_type == BuildType::Glitch ? PatchSectionTarget::Cb : PatchSectionTarget::Cbb;
        const auto* first_section =
            devgl || no_patch.cb ? nullptr
                                 : nand::detail::find_patch_section(*parsed_patchset, first_target);
        const auto* cd_section =
            no_patch.cd ? nullptr
                        : nand::detail::find_patch_section(*parsed_patchset, PatchSectionTarget::Cd);
        if ((!devgl && !no_patch.cb && !first_section) || (!no_patch.cd && !cd_section)) {
            return fail(ErrorCode::Malformed,
                        "Glitch patchset is missing a bootloader patch section");
        }
        if (!devgl && !no_patch.cb && first_target == PatchSectionTarget::Cbb &&
            !flash_image.cb_section.cb_B) {
            return fail(ErrorCode::InvalidArgument,
                        "Automatic patchset targets CBB, but no CBB was supplied");
        }

        constexpr size_t kStageCount = 6;
        std::array<size_t, kStageCount> stage_sizes{};
        FlashImage::for_each_present_stage(
            flash_image, [&stage_sizes](BootStageId id, std::string_view, const auto& stage) {
                stage_sizes[static_cast<size_t>(id)] = stage.serialize().size();
            });
        // skip the normal boot chain size cap if the unpatched chain already runs past xell's offset
        size_t unpatched_total = 0;
        for (const size_t size : stage_sizes) {
            unpatched_total += align_16(size);
        }
        const size_t cb_a_index = static_cast<size_t>(BootStageId::CbA);
        const size_t cb_b_index = static_cast<size_t>(BootStageId::CbB);
        const size_t cd_index = static_cast<size_t>(BootStageId::Cd);
        const size_t first_index =
            (first_target == PatchSectionTarget::Cb && !glitch1_cbb) ? cb_a_index : cb_b_index;
        if (first_section) {
            const auto first_size = patched_bootloader_size(
                stage_sizes[first_index], *first_section,
                (first_target == PatchSectionTarget::Cb && !glitch1_cbb) ? "CB" : "CBB");
            if (!first_size) {
                return std::unexpected(first_size.error());
            }
            stage_sizes[first_index] = *first_size;
        }
        if (cd_section) {
            const auto cd_size =
                patched_bootloader_size(stage_sizes[cd_index], *cd_section, "CD");
            if (!cd_size) {
                return std::unexpected(cd_size.error());
            }
            stage_sizes[cd_index] = *cd_size;
        }

        const bool is_big_or_emmc =
            flash_image.flash_driver.driver_mode() == Driver::DriverMode::Big ||
            flash_image.flash_driver.driver_mode() == Driver::DriverMode::Emmc;
        const size_t boot_chain_limit = devgl            ? flash_image.patch_slot_offset()
                                        : is_big_or_emmc ? 0xC0000
                                                         : 0x70000;
        constexpr size_t boot_chain_start = 0x8000;
        const size_t boot_chain_capacity = boot_chain_limit - boot_chain_start;
        size_t aligned_total = 0;
        for (const size_t size : stage_sizes) {
            aligned_total += align_16(size);
        }
        if (aligned_total > boot_chain_capacity && unpatched_total <= boot_chain_capacity) {
            return fail(ErrorCode::OutOfRange,
                        "Patched bootloader chain exceeds the space before patch slots");
        }
        const size_t effective_capacity =
            unpatched_total > boot_chain_capacity
                ? flash_image.flash_driver.block_size_clean() *
                          flash_image.flash_driver.block_count() -
                      boot_chain_start
                : boot_chain_capacity;
        const auto target_capacity = [&](size_t target_index) {
            size_t other_total = 0;
            for (size_t index = 0; index < stage_sizes.size(); ++index) {
                if (index != target_index) {
                    other_total += align_16(stage_sizes[index]);
                }
            }
            return effective_capacity - other_total;
        };

        auto patch_and_reparse = [&](auto& bootloader, PatchSectionTarget target, size_t capacity,
                                     std::string_view stage_name) -> Result<void> {
            const auto* section = nand::detail::find_patch_section(*parsed_patchset, target);
            if (!section) {
                return {};
            }
            auto patched =
                apply_bootloader_patch(bootloader.serialize(), *section, capacity, stage_name);
            if (!patched) {
                return std::unexpected(std::move(patched.error()));
            }
            auto reparsed = std::decay_t<decltype(bootloader)>::parse(*patched);
            if (!reparsed) {
                return std::unexpected(
                    std::move(reparsed.error())
                        .add_context(std::format("Failed to reparse patched {}", stage_name)));
            }
            bootloader = std::move(*reparsed);
            return {};
        };

        if (first_section && first_target == PatchSectionTarget::Cb && glitch1_cbb) {
            if (auto patched = patch_and_reparse(*flash_image.cb_section.cb_B, first_target,
                                                 target_capacity(cb_b_index), "CBB");
                !patched) {
                return patched;
            }
        } else if (first_section && first_target == PatchSectionTarget::Cb) {
            if (auto patched = patch_and_reparse(flash_image.cb_section.cb_or_A, first_target,
                                                 target_capacity(cb_a_index), "CB");
                !patched) {
                return patched;
            }
        } else if (first_section) {
            if (auto patched = patch_and_reparse(*flash_image.cb_section.cb_B, first_target,
                                                 target_capacity(cb_b_index), "CBB");
                !patched) {
                return patched;
            }
        }
        if (cd_section) {
            if (auto patched = patch_and_reparse(flash_image.kernel_section.cd,
                                                 PatchSectionTarget::Cd, target_capacity(cd_index),
                                                 "CD");
                !patched) {
                return patched;
            }
        }
        if (flash_image.devkit_chain()) {
            flash_image.kernel_section.cd.decrypted = true;
        }
        return {};
    }

    Result<void> resign_devgl_sd(FlashImage& flash_image,
                                 const EXCRYPT_RSAPRV_2048& sd_signing_key) {
        auto& sd = flash_image.kernel_section.cd;
        auto sd_bytes = sd.serialize();
        if (verify_sd_signature(sd_bytes, &sd_signing_key.rsa)) {
            return {};
        }
        Log::Info("SD {} failed its signature check; signing it again with the SB private key",
                  sd.header.header.version);
        auto signed_sd = sign_sd(sd_bytes, sd_signing_key);
        if (signed_sd && !verify_sd_signature(sd_bytes, &sd_signing_key.rsa)) {
            signed_sd = fail(ErrorCode::SignatureMismatch,
                             "Signed SD signature could not be verified");
        }
        if (!signed_sd) {
            return with_context(std::move(signed_sd),
                                "Could not sign the SD with the SB private key");
        }
        auto reparsed = BootloaderCd::parse(sd_bytes);
        if (!reparsed) {
            return std::unexpected(
                std::move(reparsed.error()).add_context("Failed to parse the signed SD"));
        }
        sd = std::move(*reparsed);
        sd.decrypted = true;
        return {};
    }

} // namespace gxbuild
