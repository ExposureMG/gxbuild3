#include "core/NandExtractor.hpp"

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace gxbuild {

    using namespace nand;

    namespace {

        ImageType image_type_from_driver(Driver::DriverMode mode) {
            switch (mode) {
                case Driver::DriverMode::Small:
                    return ImageType::SmallBlock;
                case Driver::DriverMode::NewSmall:
                    return ImageType::NewSmallBlock;
                case Driver::DriverMode::Big:
                    return ImageType::BigBlock;
                case Driver::DriverMode::Emmc:
                    return ImageType::Emmc;
            }
            std::unreachable();
        }

        // pulls cf ldv and pairing data from whichever update slot has the higher ldv
        void extract_cf_metadata(const FlashImage& image, InputMetadata& metadata) {
            const auto slot = nand::detail::max_ldv_slot(image);
            if (!slot) {
                return;
            }
            const auto& perbox =
                *(*slot == 0 ? image.system_update_0 : image.system_update_1).cf->perbox;
            metadata.cf_ldv = perbox.lockdown_value;
            std::array<uint8_t, 3> pairing{};
            std::memcpy(pairing.data(), perbox.pairing_data, pairing.size());
            metadata.cf_pairing_data = pairing;
        }

        struct CbMetadata {
            uint8_t ldv = 0;
            std::array<uint8_t, 3> pairing{};
            uint8_t console_type = 0;
            uint8_t console_sequence = 0;
            uint16_t console_sequence_allow = 0;
        };

        CbMetadata read_cb_metadata(const CbSection& cb) {
            CbMetadata metadata{};
            const auto& cb_a = cb.cb_or_A;
            if (!cb_a.data.empty()) {
                if (cb_a.perbox.has_value()) {
                    metadata.ldv = cb_a.perbox->lockdown_value;
                    std::memcpy(metadata.pairing.data(), cb_a.perbox->pairing_data,
                                metadata.pairing.size());
                }
                metadata.console_type = cb_a.header.console_seq_allow.console_type;
                metadata.console_sequence = cb_a.header.console_seq_allow.console_sequence;
                metadata.console_sequence_allow =
                    cb_a.header.console_seq_allow.console_sequence_allow.get();
            }
            // cbb per-box ldv and pairing override cba when present
            if (cb.cb_B.has_value() && !cb.cb_B->data.empty() && cb.cb_B->perbox.has_value()) {
                metadata.ldv = cb.cb_B->perbox->lockdown_value;
                std::memcpy(metadata.pairing.data(), cb.cb_B->perbox->pairing_data,
                            metadata.pairing.size());
            }
            return metadata;
        }

        void extract_settings_blocks(const FlashImage& img, InputMetadata& meta) {
            if (img.smc_config) {
                meta.smc_config = img.smc_config->serialize();
            } else {
                meta.smc_config.reset();
            }
            if (img.statistics) {
                meta.statistics = img.statistics->serialize();
            } else {
                meta.statistics.reset();
            }
            if (img.manufacturing) {
                meta.manufacturing = img.manufacturing->serialize();
            } else {
                meta.manufacturing.reset();
            }
        }

        [[nodiscard]] Result<void> parse_nand(FlashImage& image,
                                              std::span<const uint8_t> nand_image) {
            auto read =
                FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
            if (!read) {
                return fail(ErrorCode::InvalidArgument, "the NAND image is empty");
            }
            image = std::move(*read);
            return with_context(image.parse(), "Failed to parse the NAND image structure");
        }

        [[nodiscard]] Result<void> check_cpu_key(std::span<const uint8_t> cpu_key) {
            if (cpu_key.size() != 16) {
                return fail(ErrorCode::InvalidArgument, "the CPU key must be 16 bytes (got {})",
                            cpu_key.size());
            }
            return {};
        }

        [[nodiscard]] Result<void> decrypt_nand(FlashImage& image,
                                                std::span<const uint8_t> cpu_key) {
            return with_context(image.decrypt_all(cpu_key),
                                "Failed to decrypt the NAND image components with the CPU key");
        }

        [[nodiscard]] Result<void> open_nand(FlashImage& image, std::span<const uint8_t> nand_image,
                                             std::span<const uint8_t> cpu_key) {
            if (auto checked = check_cpu_key(cpu_key); !checked) {
                return checked;
            }
            if (auto parsed = parse_nand(image, nand_image); !parsed) {
                return parsed;
            }
            return decrypt_nand(image, cpu_key);
        }

        std::string fixed_string(std::span<const uint8_t> bytes) {
            const auto end = std::ranges::find(bytes, uint8_t{0});
            return std::string(bytes.begin(), end);
        }

        void project_header(const nand_header& header, AllNandInfo& info) {
            info.header_magic = header.magic.get();
            info.header_version = header.version.get();
            info.header_flags = header.flags.get();
            info.header_size = header.size.get();
            info.copyright = fixed_string(header.copyright);
        }

        template <class Stage>
        BootloaderEntryInfo summarize_stage(std::string_view name, const Stage& stage,
                                            std::optional<bool> decrypted_override = {}) {
            BootloaderEntryInfo entry{};
            entry.name = name;
            entry.version = stage.header.header.version.get();
            entry.size = stage.header.header.size.get();
            entry.flags = stage.header.header.flags.get();
            entry.entrypoint = stage.header.header.entrypoint.get();
            entry.present = true;
            entry.decrypted = decrypted_override ? *decrypted_override : stage.is_decrypted();
            return entry;
        }

        SmcSummaryInfo summarize_smc(const Smc& smc) {
            SmcSummaryInfo summary{};
            summary.present = true;
            summary.version = smc.version;
            summary.motherboard_name = std::string(smc_motherboard_name(smc.motherboard));
            summary.type_name = std::string(smc_type_name(smc.variant));
            summary.size = static_cast<uint32_t>(smc.data.size());
            summary.decrypted = !smc.encrypted;
            return summary;
        }

        std::optional<BootloaderEntryInfo>& stage_entry_slot(BootloaderChainInfo& chain,
                                                             BootStageId id) {
            switch (id) {
                case BootStageId::CbA:
                    return chain.cb_a;
                case BootStageId::CbX:
                    return chain.cb_x;
                case BootStageId::CbB:
                    return chain.cb_b;
                case BootStageId::Sc:
                    return chain.sc;
                case BootStageId::Cd:
                    return chain.cd;
                case BootStageId::Ce:
                    return chain.ce;
            }
            std::unreachable();
        }

        void populate_extracted_metadata(const FlashImage& img, InputMetadata& meta) {
            const auto cb = read_cb_metadata(img.cb_section);
            meta.cb_ldv = cb.ldv;
            meta.pairing_data = cb.pairing;
            meta.console_type = cb.console_type;
            meta.console_sequence = cb.console_sequence;
            meta.console_sequence_allow = cb.console_sequence_allow;
            extract_cf_metadata(img, meta);
            meta.donor_nonces = img.collect_nonces();
            extract_settings_blocks(img, meta);
        }

    } // namespace

    Result<AllNandInfo> extract_some_info(std::span<const uint8_t> nand_image) {
        FlashImage img{};
        if (auto parsed = parse_nand(img, nand_image); !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }

        AllNandInfo info{};
        project_header(img.header, info);
        info.block_type = image_type_from_driver(img.flash_driver.driver_mode());

        FlashImage::for_each_present_stage(
            img, [&info](BootStageId id, std::string_view name, const auto& stage) {
                if (!stage.data.empty()) {
                    stage_entry_slot(info.bootloaders, id) = summarize_stage(name, stage);
                }
            });
        if (img.system_update_0.cf && !img.system_update_0.cf->data.empty()) {
            info.bootloaders.cf_0 = summarize_stage("CF_0", *img.system_update_0.cf);
        }
        if (img.system_update_0.cg && !img.system_update_0.cg->data.empty()) {
            info.bootloaders.cg_0 = summarize_stage("CG_0", *img.system_update_0.cg);
        }
        if (img.system_update_1.cf && !img.system_update_1.cf->data.empty()) {
            info.bootloaders.cf_1 = summarize_stage("CF_1", *img.system_update_1.cf);
        }
        if (img.system_update_1.cg && !img.system_update_1.cg->data.empty()) {
            info.bootloaders.cg_1 = summarize_stage("CG_1", *img.system_update_1.cg);
        }

        if (img.smc) {
            info.smc = summarize_smc(*img.smc);
        }

        return info;
    }

    Result<AllNandInfo> extract_some_info(const std::vector<uint8_t>& nand_image) {
        return extract_some_info(std::span<const uint8_t>(nand_image));
    }

    Result<InputMetadata> extract_metadata(std::span<const uint8_t> nand_image,
                                           std::span<const uint8_t> cpu_key) {
        if (auto checked = check_cpu_key(cpu_key); !checked) {
            return std::unexpected(std::move(checked.error()));
        }
        FlashImage img{};
        if (auto parsed = parse_nand(img, nand_image); !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }
        if (!img.keyvault.has_value()) {
            return fail(ErrorCode::NotFound, "the NAND image does not contain a valid keyvault");
        }
        if (auto decrypted = decrypt_nand(img, cpu_key); !decrypted) {
            return std::unexpected(std::move(decrypted.error()));
        }

        auto& kv = *img.keyvault;
        if (kv.encrypted) {
            return fail(ErrorCode::AuthFailed, "the keyvault does not open under the CPU key");
        }
        InputMetadata meta{};
        meta.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
        meta.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
        meta.keyvault = kv.serialize();

        populate_extracted_metadata(img, meta);

        Log::Debug(
            "Extracted metadata: CB LDV={}, CF LDV={}, ConsoleType=0x{:02X}, Sequence=0x{:02X}",
            meta.cb_ldv, meta.cf_ldv ? std::to_string(*meta.cf_ldv) : "none", meta.console_type,
            meta.console_sequence);

        return meta;
    }

    Result<InputMetadata> extract_metadata(const std::vector<uint8_t>& nand_image,
                                           const std::vector<uint8_t>& cpu_key) {
        return extract_metadata(std::span<const uint8_t>(nand_image),
                                std::span<const uint8_t>(cpu_key));
    }

    Result<AllNandInfo> extract_all_info(std::span<const uint8_t> nand_image,
                                         std::span<const uint8_t> cpu_key) {
        FlashImage img{};
        if (auto opened = open_nand(img, nand_image, cpu_key); !opened) {
            return std::unexpected(std::move(opened.error()));
        }

        AllNandInfo info{};
        info.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
        info.block_type = image_type_from_driver(img.flash_driver.driver_mode());

        project_header(img.header, info);

        FlashImage::for_each_present_stage(
            img, [&info](BootStageId id, std::string_view name, const auto& stage) {
                if (stage.data.empty()) {
                    return;
                }
                const std::optional<bool> decrypted_override =
                    id == BootStageId::Sc ? std::optional<bool>{true} : std::nullopt;
                auto entry = summarize_stage(name, stage, decrypted_override);
                if constexpr (std::is_same_v<std::decay_t<decltype(stage)>, BootloaderCb>) {
                    if (id == BootStageId::CbA || id == BootStageId::CbB) {
                        if (stage.perbox.has_value()) {
                            const uint8_t ldv = stage.perbox->lockdown_value;
                            const auto pd = std::to_array(stage.perbox->pairing_data);
                            entry.ldv = ldv;
                            entry.pairing_data = pd;
                            info.bootloaders.cb_ldv = ldv;
                            info.bootloaders.cb_pairing_data = pd;
                        }
                        if (stage.is_decrypted() &&
                            stage.data.size() >= sizeof(cb_header) - sizeof(generic_header)) {
                            entry.console_sequence = stage.header.console_seq_allow.console_sequence;
                            info.bootloaders.cb_console_sequence = entry.console_sequence;
                        }
                    }
                }
                stage_entry_slot(info.bootloaders, id) = std::move(entry);
            });

        if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
            const auto& cf_0 = *img.system_update_0.cf;
            auto entry = summarize_stage("CF_0", cf_0);
            if (cf_0.perbox.has_value()) {
                const auto pd = std::to_array(cf_0.perbox->pairing_data);
                entry.ldv = cf_0.perbox->lockdown_value;
                entry.pairing_data = pd;
                info.bootloaders.cf0_ldv = cf_0.perbox->lockdown_value;
                info.bootloaders.cf0_pairing_data = pd;
            }
            info.bootloaders.cf_0 = entry;
        }

        if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
            info.bootloaders.cg_0 = summarize_stage("CG_0", *img.system_update_0.cg);
        }

        if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
            const auto& cf_1 = *img.system_update_1.cf;
            auto entry = summarize_stage("CF_1", cf_1);
            if (cf_1.perbox.has_value()) {
                const auto pd = std::to_array(cf_1.perbox->pairing_data);
                entry.ldv = cf_1.perbox->lockdown_value;
                entry.pairing_data = pd;
                info.bootloaders.cf1_ldv = cf_1.perbox->lockdown_value;
                info.bootloaders.cf1_pairing_data = pd;
            }
            info.bootloaders.cf_1 = entry;
        }

        if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
            info.bootloaders.cg_1 = summarize_stage("CG_1", *img.system_update_1.cg);
        }

        if (img.smc.has_value()) {
            info.smc = summarize_smc(*img.smc);
        }

        if (img.filesystem.has_value()) {
            info.flashfs.present = true;
            auto file_list = img.filesystem->list_files();
            for (const auto& filename : file_list) {
                auto stat_opt = img.filesystem->stat(filename);
                if (stat_opt.has_value()) {
                    FlashFsFileInfo file_info{};
                    file_info.filename = filename;
                    file_info.block_number = stat_opt->block_number;
                    file_info.length = stat_opt->length;
                    file_info.timestamp = stat_opt->timestamp;
                    info.flashfs.files.push_back(file_info);
                }
            }
        }

        if (img.keyvault.has_value()) {
            info.raw_keyvault = img.keyvault->serialize();
            info.keyvault = summarize_keyvault(*img.keyvault);
        }

        return info;
    }

    Result<AllNandInfo> extract_all_info(const std::vector<uint8_t>& nand_image,
                                         const std::vector<uint8_t>& cpu_key) {
        return extract_all_info(std::span<const uint8_t>(nand_image),
                                std::span<const uint8_t>(cpu_key));
    }

    Result<Input> extract_all(std::span<const uint8_t> nand_image,
                              std::span<const uint8_t> cpu_key) {
        FlashImage img{};
        if (auto opened = open_nand(img, nand_image, cpu_key); !opened) {
            return std::unexpected(std::move(opened.error()));
        }

        Input out{};
        if (img.build_type == BuildType::Devkit) {
            out.build_type = BuildType::Devkit;
        }
        if (img.payloads.patchset && img.build_type) {
            out.build_type = *img.build_type;
            out.patches = InputPatches{};
            out.patches->automatic =
                InputPatchFile{"extracted", serialize_patch_set(*img.payloads.patchset)};
        }
        out.metadata.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
        out.metadata.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
        out.image_type = image_type_from_driver(img.flash_driver.driver_mode());

        FlashImage::for_each_present_stage(
            img, [&out](BootStageId id, std::string_view, const auto& stage) {
                if (stage.data.empty()) {
                    return;
                }
                auto bytes = stage.serialize();
                switch (id) {
                    case BootStageId::CbA:
                        out.bootloaders.cb_or_a = std::move(bytes);
                        break;
                    case BootStageId::CbX:
                        out.bootloaders.cb_x = std::move(bytes);
                        break;
                    case BootStageId::CbB:
                        out.bootloaders.cb_b = std::move(bytes);
                        break;
                    case BootStageId::Sc:
                        out.bootloaders.sc = std::move(bytes);
                        break;
                    case BootStageId::Cd:
                        out.bootloaders.cd = std::move(bytes);
                        break;
                    case BootStageId::Ce:
                        out.bootloaders.ce = std::move(bytes);
                        break;
                }
            });

        if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
            out.bootloaders.cf0 = img.system_update_0.cf->serialize();
        }

        if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
            out.bootloaders.cg0 = img.system_update_0.cg->serialize();
        }

        if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
            out.bootloaders.cf1 = img.system_update_1.cf->serialize();
        }

        if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
            out.bootloaders.cg1 = img.system_update_1.cg->serialize();
        }

        populate_extracted_metadata(img, out.metadata);

        if (img.smc.has_value()) {
            out.metadata.smc = img.smc->data;
        }

        // skip the donor kv if it couldn't be decrypted with a zero cpu key
        if (img.keyvault.has_value() && !img.keyvault->encrypted) {
            out.metadata.keyvault = img.keyvault->serialize();
        }

        if (img.filesystem.has_value()) {
            std::vector<std::pair<std::string, std::vector<uint8_t>>> files;
            auto file_list = img.filesystem->list_files();
            for (const auto& filename : file_list) {
                auto file_data = img.filesystem->get_file(filename);
                if (!file_data.has_value()) {
                    Log::Warn("FlashFS file '{}' could not be read from the image; it is left out",
                              filename);
                    continue;
                }
                if (is_cpu_keyed_secfile(filename)) {
                    if (auto crypted = crypt_secfile(cpu_key, *file_data); !crypted) {
                        return std::unexpected(
                            std::move(crypted.error())
                                .add_context(std::format(
                                    "Failed to decrypt secure FlashFS file '{}'", filename)));
                    }
                }
                if (is_console_secured_file(filename)) {
                    out.metadata.console_secured_files.emplace_back(filename, *file_data);
                }
                files.emplace_back(filename, std::move(*file_data));
            }
            out.flashfs_sec = std::move(files);
        }

        if (img.mobile_data.has_value()) {
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                const auto* donor_slot = img.mobile_data->get_slot(block_type);
                if (donor_slot && *donor_slot) {
                    *out.mobiles.slot(block_type) = **donor_slot;
                }
            }
        }

        InputPayloads payloads{};
        bool has_payloads = false;
        if (img.payloads.xell.has_value()) {
            payloads.xell = img.payloads.xell->data;
            has_payloads = true;
        }
        if (img.payloads.rebooter.has_value()) {
            payloads.rebooter = img.payloads.rebooter;
            has_payloads = true;
        }
        if (img.payloads.fuses.has_value()) {
            payloads.fuses = img.payloads.fuses;
            has_payloads = true;
        }
        if (img.payloads.payload.has_value()) {
            payloads.payload = img.payloads.payload;
            has_payloads = true;
        }
        if (has_payloads) {
            out.payloads = std::move(payloads);
        }

        return out;
    }

    Result<Input> extract_all(const std::vector<uint8_t>& nand_image,
                              const std::vector<uint8_t>& cpu_key) {
        return extract_all(std::span<const uint8_t>(nand_image), std::span<const uint8_t>(cpu_key));
    }

} // namespace gxbuild
