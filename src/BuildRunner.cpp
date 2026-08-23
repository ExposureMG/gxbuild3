#include "BuildRunner.hpp"

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
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
#include "nand/objects/XConfig.hpp"
#include "nand/objects/XeLL.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include <cstring>

using namespace gxbuild3::NAND;

std::optional<std::vector<uint8_t>> RunBuild(const Input& input) {
    FlashImage flash_image{};

    if (input.metadata.nand_image && !input.metadata.nand_image->empty()) {
        Log::Info("Building image from donor NAND dump...");
        auto donor_img = FlashImage::read(*input.metadata.nand_image);
        if (!donor_img || !donor_img->parse()) {
            Log::Error("Failed to parse donor NAND dump");
            return std::nullopt;
        }
        if (!donor_img->decrypt_all(input.metadata.cpu_key)) {
            Log::Error("Failed to decrypt donor NAND dump components");
            return std::nullopt;
        }
        flash_image = std::move(*donor_img);
    } else {
        Driver::DriverMode driver_mode = Driver::DriverMode::Small;
        Driver::ImageSize image_size = Driver::ImageSize::Smallblock;

        if (input.overrides.ksb_image) {
            driver_mode = Driver::DriverMode::Emmc;
            image_size = Driver::ImageSize::Emmcblock;
        } else if (input.overrides.psb_image) {
            driver_mode = Driver::DriverMode::NewSmall;
            image_size = Driver::ImageSize::Smallblock;
        } else if (input.overrides.xsb_image) {
            driver_mode = Driver::DriverMode::Small;
            image_size = Driver::ImageSize::Smallblock;
        }

        Log::Debug("Configuring fresh NAND image layout");
        flash_image.flash_driver = Driver(image_size, driver_mode);
    }

    flash_image.header.pairing = static_cast<uint16_t>(
        (input.metadata.pairing_data[0] << 8) | input.metadata.pairing_data[1]
    );

    if (!input.bootloaders.cb_or_a.empty()) {
        flash_image.cb_section.cb_or_A = BootloaderCb::parse(input.bootloaders.cb_or_a);
        Log::Info("Adding CB_A / 2BL (version {}, size 0x{:X})",
                  flash_image.cb_section.cb_or_A.header.header.version,
                  flash_image.cb_section.cb_or_A.header.header.size);
    }

    if (input.bootloaders.cb_x && !input.bootloaders.cb_x->empty()) {
        flash_image.cb_section.cb_x = BootloaderCb::parse(*input.bootloaders.cb_x);
        Log::Info("Adding CB_X (version {}, size 0x{:X})",
                  flash_image.cb_section.cb_x->header.header.version,
                  flash_image.cb_section.cb_x->header.header.size);
    }

    if (input.bootloaders.cb_b && !input.bootloaders.cb_b->empty()) {
        flash_image.cb_section.cb_B = BootloaderCb::parse(*input.bootloaders.cb_b);
        Log::Info("Adding CB_B (version {}, size 0x{:X})",
                  flash_image.cb_section.cb_B->header.header.version,
                  flash_image.cb_section.cb_B->header.header.size);
    }

    if (!input.bootloaders.cd.empty()) {
        flash_image.kernel_section.cd = BootloaderCd::parse(input.bootloaders.cd);
        Log::Info("Adding CD / 4BL (version {}, size 0x{:X})",
                  flash_image.kernel_section.cd.header.header.version,
                  flash_image.kernel_section.cd.header.header.size);
    }

    if (input.bootloaders.ce && !input.bootloaders.ce->empty()) {
        flash_image.kernel_section.ce = BootloaderCe::parse(*input.bootloaders.ce);
        Log::Info("Adding CE / 5BL (version {}, size 0x{:X})",
                  flash_image.kernel_section.ce->header.header.version,
                  flash_image.kernel_section.ce->header.header.size);
    }

    if (input.bootloaders.cf0 && !input.bootloaders.cf0->empty()) {
        flash_image.system_update_0.cf = BootloaderCf::parse(*input.bootloaders.cf0);
        Log::Info("Adding CF0 / 6BL (version {}, size 0x{:X})",
                  flash_image.system_update_0.cf->header.header.version,
                  flash_image.system_update_0.cf->header.header.size);
    }

    if (input.bootloaders.cg0 && !input.bootloaders.cg0->empty()) {
        flash_image.system_update_0.cg = BootloaderCg::parse(*input.bootloaders.cg0);
        Log::Info("Adding CG0 / 7BL (version {}, size 0x{:X})",
                  flash_image.system_update_0.cg->header.header.version,
                  flash_image.system_update_0.cg->header.header.size);
    }

    if (input.bootloaders.cf1 && !input.bootloaders.cf1->empty()) {
        flash_image.system_update_1.cf = BootloaderCf::parse(*input.bootloaders.cf1);
        Log::Info("Adding CF1 / 6BL (version {}, size 0x{:X})",
                  flash_image.system_update_1.cf->header.header.version,
                  flash_image.system_update_1.cf->header.header.size);
    }

    if (input.bootloaders.cg1 && !input.bootloaders.cg1->empty()) {
        flash_image.system_update_1.cg = BootloaderCg::parse(*input.bootloaders.cg1);
        Log::Info("Adding CG1 / 7BL (version {}, size 0x{:X})",
                  flash_image.system_update_1.cg->header.header.version,
                  flash_image.system_update_1.cg->header.header.size);
    }

    if (input.payloads) {
        if (input.payloads->xell && !input.payloads->xell->empty()) {
            auto xell_parsed = XeLL::parse(*input.payloads->xell);
            if (!xell_parsed) {
                Log::Error("Failed to parse XeLL payload (invalid ELF magic or size)");
                return std::nullopt;
            }
            flash_image.payloads.xell = std::move(xell_parsed);
            Log::Info("Adding XeLL payload (version='{}', size=0x{:X})",
                      flash_image.payloads.xell->metadata.version,
                      flash_image.payloads.xell->data.size());
        }
        if (input.payloads->rebooter) {
            flash_image.payloads.rebooter = input.payloads->rebooter;
            Log::Info("Adding Rebooter payload (size=0x{:X})", flash_image.payloads.rebooter->size());
        }
        if (input.payloads->fuses) {
            flash_image.payloads.fuses = input.payloads->fuses;
            Log::Info("Adding virtual fuses payload (size=0x{:X})", flash_image.payloads.fuses->size());
        }
        if (input.payloads->payload) {
            flash_image.payloads.payload = input.payloads->payload;
            Log::Info("Adding custom payload (size=0x{:X})", flash_image.payloads.payload->size());
        }
    }

    if (input.flashfs_sec && !input.flashfs_sec->empty()) {
        Log::Info("Populating Flash File System ({} files)", input.flashfs_sec->size());
        FlashFileSystem fs{};
        const size_t total_blocks = flash_image.flash_driver.block_count();
        fs.format(total_blocks);
        fs.set_driver(&flash_image.flash_driver);
        flash_image.filesystem = std::move(fs);

        for (const auto& [name, data] : *input.flashfs_sec) {
            std::vector<uint8_t> file_data = data;
            if (input.metadata.cpu_key.size() >= 16 && (name == "secdata.bin" || name == "extended.bin")) {
                crypt_secfile(input.metadata.cpu_key, file_data);
                Log::Debug("Encrypted secure file '{}' with CPU key", name);
            }
            Log::Debug("Adding FlashFS file: '{}' ({} bytes)", name, file_data.size());
            flash_image.filesystem->add_file(name, file_data);
        }
    }

    Log::Debug("Encrypting NAND image components");
    if (!flash_image.encrypt_all(input.metadata.cpu_key)) {
        Log::Error("Failed to encrypt NAND image components");
        return std::nullopt;
    }

    auto output = flash_image.write();
    if (output.empty()) {
        Log::Error("Failed to write/serialize built NAND image");
        return std::nullopt;
    }

    return output;
}

std::optional<InputMetadata> ExtractMetadata(
    std::span<const uint8_t> nand_image,
    std::span<const uint8_t> cpu_key
) {
    if (cpu_key.size() != 16) {
        Log::Error("Cannot extract metadata: CPU key must be 16 bytes (got {})", cpu_key.size());
        return std::nullopt;
    }
    if (nand_image.empty()) {
        Log::Error("Cannot extract metadata: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse donor NAND image structure");
        return std::nullopt;
    }

    auto& img = *img_opt;
    if (!img.keyvault.has_value()) {
        Log::Error("Donor NAND image does not contain a valid keyvault");
        return std::nullopt;
    }

    if (!img.decrypt_all(cpu_key)) {
        Log::Error("Failed to decrypt donor NAND image components during metadata extraction");
        return std::nullopt;
    }

    auto& kv = *img.keyvault;
    InputMetadata meta{};
    meta.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
    meta.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
    meta.keyvault = kv.serialize();

    uint8_t cb_ldv = 0;
    uint8_t pairing_data[3] = {};
    uint8_t console_type = 0;
    uint8_t console_sequence = 0;
    uint16_t console_sequence_allow = 0;

    auto& cb_a = img.cb_section.cb_or_A;
    if (!cb_a.data.empty()) {
        if (cb_a.perbox.has_value()) {
            cb_ldv = cb_a.perbox->lockdown_value;
            std::memcpy(pairing_data, cb_a.perbox->pairing_data, 3);
        }

        console_type = cb_a.header.console_seq_allow.console_type;
        console_sequence = cb_a.header.console_seq_allow.console_sequence;
        console_sequence_allow = cb_a.header.console_seq_allow.console_sequence_allow;
    }

    // CB_B, when present, overrides CB_A's LDV/pairing data — independent of
    // whether CB_A itself parsed, matching ExtractAll()/ExtractAllInfo().
    if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
        auto& cb_b = *img.cb_section.cb_B;
        if (cb_b.perbox.has_value()) {
            cb_ldv = cb_b.perbox->lockdown_value;
            // Some CB_B images carry a corrected LDV byte at a fixed offset
            // that supersedes the perbox value — same check ExtractAllInfo()
            // and ExtractAll() already apply.
            if (cb_b.data.size() > 0x3B1 - sizeof(generic_header) &&
                cb_b.data[0x3B1 - sizeof(generic_header)] <= 16) {
                cb_ldv = cb_b.data[0x3B1 - sizeof(generic_header)];
            }
            std::memcpy(pairing_data, cb_b.perbox->pairing_data, 3);
        }
    }

    meta.cb_ldv = cb_ldv;
    std::memcpy(meta.pairing_data, pairing_data, 3);
    meta.console_type = console_type;
    meta.console_sequence = console_sequence;
    meta.console_sequence_allow = console_sequence_allow;

    if (img.system_update_0.cf.has_value()) {
        auto& cf = *img.system_update_0.cf;
        if (!cf.is_decrypted()) {
            cf.decrypt(key_1bl);
        }

        if (cf.perbox.has_value()) {
            meta.cf_ldv = cf.perbox->lockdown_value;
        }
    }

    Log::Debug("Extracted metadata: CB LDV={}, CF LDV={}, ConsoleType=0x{:02X}, Sequence=0x{:02X}",
               meta.cb_ldv, meta.cf_ldv ? std::to_string(*meta.cf_ldv) : "none",
               meta.console_type, meta.console_sequence);

    return meta;
}

std::optional<InputMetadata> ExtractMetadata(
    const std::vector<uint8_t>& nand_image,
    const std::vector<uint8_t>& cpu_key
) {
    return ExtractMetadata(
        std::span<const uint8_t>(nand_image),
        std::span<const uint8_t>(cpu_key)
    );
}

std::optional<AllNandInfo> ExtractAllInfo(
    std::span<const uint8_t> nand_image,
    std::span<const uint8_t> cpu_key
) {
    if (cpu_key.size() != 16) {
        Log::Error("Cannot extract NAND info: CPU key must be 16 bytes (got {})", cpu_key.size());
        return std::nullopt;
    }
    if (nand_image.empty()) {
        Log::Error("Cannot extract NAND info: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse donor NAND image structure");
        return std::nullopt;
    }

    auto& img = *img_opt;

    if (!img.decrypt_all(cpu_key)) {
        Log::Error("Failed to decrypt donor NAND image components with provided CPU key");
        return std::nullopt;
    }

    AllNandInfo info{};
    info.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());

    info.header_magic = img.header.magic;
    info.header_version = img.header.version;
    info.header_flags = img.header.flags;
    info.header_size = img.header.size;
    info.copyright = std::string(reinterpret_cast<const char*>(img.header.copyright),
                                 strnlen(reinterpret_cast<const char*>(img.header.copyright), sizeof(img.header.copyright)));

    if (!img.cb_section.cb_or_A.data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CB_A";
        entry.version = img.cb_section.cb_or_A.header.header.version;
        entry.size = img.cb_section.cb_or_A.header.header.size;
        entry.flags = img.cb_section.cb_or_A.header.header.flags;
        entry.entrypoint = img.cb_section.cb_or_A.header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.cb_section.cb_or_A.is_decrypted();
        if (img.cb_section.cb_or_A.perbox.has_value()) {
            entry.ldv = img.cb_section.cb_or_A.perbox->lockdown_value;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.cb_section.cb_or_A.perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cb_ldv = img.cb_section.cb_or_A.perbox->lockdown_value;
            info.bootloaders.cb_pairing_data = pd;
        }
        info.bootloaders.cb_a = entry;
    }

    if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CB_B";
        entry.version = img.cb_section.cb_B->header.header.version;
        entry.size = img.cb_section.cb_B->header.header.size;
        entry.flags = img.cb_section.cb_B->header.header.flags;
        entry.entrypoint = img.cb_section.cb_B->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.cb_section.cb_B->is_decrypted();
        if (img.cb_section.cb_B->perbox.has_value()) {
            uint8_t ldv = img.cb_section.cb_B->perbox->lockdown_value;
            if (img.cb_section.cb_B->data.size() > 0x3B1 - sizeof(generic_header) &&
                img.cb_section.cb_B->data[0x3B1 - sizeof(generic_header)] <= 16) {
                ldv = img.cb_section.cb_B->data[0x3B1 - sizeof(generic_header)];
            }
            entry.ldv = ldv;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.cb_section.cb_B->perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cb_ldv = ldv;
            info.bootloaders.cb_pairing_data = pd;
        }
        info.bootloaders.cb_b = entry;
    }

    if (img.cb_section.cb_x.has_value() && !img.cb_section.cb_x->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CB_X";
        entry.version = img.cb_section.cb_x->header.header.version;
        entry.size = img.cb_section.cb_x->header.header.size;
        entry.flags = img.cb_section.cb_x->header.header.flags;
        entry.entrypoint = img.cb_section.cb_x->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.cb_section.cb_x->is_decrypted();
        info.bootloaders.cb_x = entry;
    }

    if (img.cb_section.sc.has_value() && !img.cb_section.sc->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "SC";
        entry.version = img.cb_section.sc->header.header.version;
        entry.size = img.cb_section.sc->header.header.size;
        entry.flags = img.cb_section.sc->header.header.flags;
        entry.entrypoint = img.cb_section.sc->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = true;
        info.bootloaders.sc = entry;
    }

    if (!img.kernel_section.cd.data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CD";
        entry.version = img.kernel_section.cd.header.header.version;
        entry.size = img.kernel_section.cd.header.header.size;
        entry.flags = img.kernel_section.cd.header.header.flags;
        entry.entrypoint = img.kernel_section.cd.header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.kernel_section.cd.is_decrypted();
        info.bootloaders.cd = entry;
    }

    if (img.kernel_section.ce.has_value() && !img.kernel_section.ce->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CE";
        entry.version = img.kernel_section.ce->header.header.version;
        entry.size = img.kernel_section.ce->header.header.size;
        entry.flags = img.kernel_section.ce->header.header.flags;
        entry.entrypoint = img.kernel_section.ce->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.kernel_section.ce->is_decrypted();
        info.bootloaders.ce = entry;
    }

    if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CF_0";
        entry.version = img.system_update_0.cf->header.header.version;
        entry.size = img.system_update_0.cf->header.header.size;
        entry.flags = img.system_update_0.cf->header.header.flags;
        entry.entrypoint = img.system_update_0.cf->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_0.cf->is_decrypted();
        if (img.system_update_0.cf->perbox.has_value()) {
            entry.ldv = img.system_update_0.cf->perbox->lockdown_value;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.system_update_0.cf->perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cf0_ldv = img.system_update_0.cf->perbox->lockdown_value;
            info.bootloaders.cf0_pairing_data = pd;
        }
        info.bootloaders.cf_0 = entry;
    }

    if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CG_0";
        entry.version = img.system_update_0.cg->header.header.version;
        entry.size = img.system_update_0.cg->header.header.size;
        entry.flags = img.system_update_0.cg->header.header.flags;
        entry.entrypoint = img.system_update_0.cg->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_0.cg->is_decrypted();
        info.bootloaders.cg_0 = entry;
    }

    if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CF_1";
        entry.version = img.system_update_1.cf->header.header.version;
        entry.size = img.system_update_1.cf->header.header.size;
        entry.flags = img.system_update_1.cf->header.header.flags;
        entry.entrypoint = img.system_update_1.cf->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_1.cf->is_decrypted();
        if (img.system_update_1.cf->perbox.has_value()) {
            entry.ldv = img.system_update_1.cf->perbox->lockdown_value;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.system_update_1.cf->perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cf1_ldv = img.system_update_1.cf->perbox->lockdown_value;
            info.bootloaders.cf1_pairing_data = pd;
        }
        info.bootloaders.cf_1 = entry;
    }

    if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CG_1";
        entry.version = img.system_update_1.cg->header.header.version;
        entry.size = img.system_update_1.cg->header.header.size;
        entry.flags = img.system_update_1.cg->header.header.flags;
        entry.entrypoint = img.system_update_1.cg->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_1.cg->is_decrypted();
        info.bootloaders.cg_1 = entry;
    }

    if (img.smc.has_value()) {
        info.smc.present = true;
        info.smc.version = img.smc->version;
        info.smc.motherboard_name = std::string(smc_motherboard_name(img.smc->motherboard));
        info.smc.type_name = std::string(smc_type_name(img.smc->variant));
        info.smc.size = static_cast<uint32_t>(img.smc->data.size());
        info.smc.decrypted = !img.smc->encrypted;
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
        auto& kv = *img.keyvault;
        info.keyvault.present = true;
        info.keyvault.decrypted = !kv.encrypted;
        info.raw_keyvault = kv.serialize();

        info.keyvault.serial_number = std::string(kv.data.sz14ConsoleSerialNumber,
                                                  strnlen(kv.data.sz14ConsoleSerialNumber, sizeof(kv.data.sz14ConsoleSerialNumber)));
        info.keyvault.dvd_key = Utils::bytes_to_hex(kv.data.b1ADvdKey);
        info.keyvault.console_id_raw = Utils::bytes_to_hex(kv.data.b36ConsoleCertificate.ConsoleId);

        uint64_t cid_val = (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[0]) << 28) |
                           (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[1]) << 20) |
                           (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[2]) << 12) |
                           (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[3]) << 4) |
                           (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[4]) >> 4);
        uint8_t last_digit = kv.data.b36ConsoleCertificate.ConsoleId[4] & 0x0F;
        char cid_buf[32];
        std::snprintf(cid_buf, sizeof(cid_buf), "%011llu%u", static_cast<unsigned long long>(cid_val), last_digit);
        info.keyvault.console_id_friendly = cid_buf;

        if (kv.raw_data.size() >= 0xCAD) {
            info.keyvault.osig = std::string(reinterpret_cast<const char*>(kv.raw_data.data() + 0xC92),
                                             strnlen(reinterpret_cast<const char*>(kv.raw_data.data() + 0xC92), 28));
        }
        info.keyvault.mfr_date = std::string(kv.data.b36ConsoleCertificate.ManufacturingDate,
                                             strnlen(kv.data.b36ConsoleCertificate.ManufacturingDate, sizeof(kv.data.b36ConsoleCertificate.ManufacturingDate)));

        info.keyvault.region_raw = bswap16(kv.data.w16GameRegion);
        switch (info.keyvault.region_raw) {
            case 0x00FF: info.keyvault.region_name = "NTSC/US"; break;
            case 0x01FE: info.keyvault.region_name = "NTSC/JAP"; break;
            case 0x01FF: info.keyvault.region_name = "NTSC/JAP"; break;
            case 0x02FE: info.keyvault.region_name = "PAL/EU"; break;
            case 0x02FF: info.keyvault.region_name = "PAL/AUS"; break;
            case 0x01FC: info.keyvault.region_name = "NTSC/KOR"; break;
            case 0x01FA: info.keyvault.region_name = "NTSC/HK"; break;
            case 0x0101: info.keyvault.region_name = "NTSC/CHINA"; break;
            case 0xFFFF: info.keyvault.region_name = "Devkit"; break;
            default: info.keyvault.region_name = "Unknown"; break;
        }

        bool is_type1 = true;
        for (size_t i = 0; i < 8; ++i) {
            uint8_t b = kv.data.b39SpecialKeyVaultSignature[sizeof(kv.data.b39SpecialKeyVaultSignature) - 8 + i];
            if (b != 0x00 && b != 0xFF) {
                is_type1 = false;
                break;
            }
        }
        info.keyvault.kv_type = is_type1 ? 1 : 2;
        info.keyvault.fcrt_required = ((kv.data.w4OddFeatures & 0x0120) != 0);
    }

    return info;
}

std::optional<AllNandInfo> ExtractAllInfo(
    const std::vector<uint8_t>& nand_image,
    const std::vector<uint8_t>& cpu_key
) {
    return ExtractAllInfo(
        std::span<const uint8_t>(nand_image),
        std::span<const uint8_t>(cpu_key)
    );
}

std::optional<Input> ExtractAll(
    std::span<const uint8_t> nand_image,
    std::span<const uint8_t> cpu_key
) {
    if (cpu_key.size() != 16) {
        Log::Error("Cannot extract NAND: CPU key must be 16 bytes (got {})", cpu_key.size());
        return std::nullopt;
    }
    if (nand_image.empty()) {
        Log::Error("Cannot extract NAND: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse donor NAND image structure");
        return std::nullopt;
    }

    auto& img = *img_opt;

    if (!img.decrypt_all(cpu_key)) {
        Log::Error("Failed to decrypt donor NAND image components with provided CPU key");
        return std::nullopt;
    }

    Input out{};
    out.metadata.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());

    uint8_t cb_ldv = 0;
    uint8_t pairing_data[3] = {0};
    uint8_t console_type = 0;
    uint8_t console_sequence = 0;
    uint16_t console_sequence_allow = 0;

    if (!img.cb_section.cb_or_A.data.empty()) {
        out.bootloaders.cb_or_a = img.cb_section.cb_or_A.serialize();
        console_type = img.cb_section.cb_or_A.header.console_seq_allow.console_type;
        console_sequence = img.cb_section.cb_or_A.header.console_seq_allow.console_sequence;
        console_sequence_allow = img.cb_section.cb_or_A.header.console_seq_allow.console_sequence_allow;
        if (img.cb_section.cb_or_A.perbox.has_value()) {
            cb_ldv = img.cb_section.cb_or_A.perbox->lockdown_value;
            std::memcpy(pairing_data, img.cb_section.cb_or_A.perbox->pairing_data, 3);
        }
    }

    if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
        out.bootloaders.cb_b = img.cb_section.cb_B->serialize();
        if (img.cb_section.cb_B->perbox.has_value()) {
            cb_ldv = img.cb_section.cb_B->perbox->lockdown_value;
            if (img.cb_section.cb_B->data.size() > 0x3B1 - sizeof(generic_header) &&
                img.cb_section.cb_B->data[0x3B1 - sizeof(generic_header)] <= 16) {
                cb_ldv = img.cb_section.cb_B->data[0x3B1 - sizeof(generic_header)];
            }
            std::memcpy(pairing_data, img.cb_section.cb_B->perbox->pairing_data, 3);
        }
    }

    if (img.cb_section.cb_x.has_value() && !img.cb_section.cb_x->data.empty()) {
        out.bootloaders.cb_x = img.cb_section.cb_x->serialize();
    }

    if (!img.kernel_section.cd.data.empty()) {
        out.bootloaders.cd = img.kernel_section.cd.serialize();
    }

    if (img.kernel_section.ce.has_value() && !img.kernel_section.ce->data.empty()) {
        out.bootloaders.ce = img.kernel_section.ce->serialize();
    }

    if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
        out.bootloaders.cf0 = img.system_update_0.cf->serialize();
        if (img.system_update_0.cf->perbox.has_value()) {
            out.metadata.cf_ldv = img.system_update_0.cf->perbox->lockdown_value;
        }
    }

    if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
        out.bootloaders.cg0 = img.system_update_0.cg->serialize();
    }

    if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
        out.bootloaders.cf1 = img.system_update_1.cf->serialize();
        if (!out.metadata.cf_ldv.has_value() && img.system_update_1.cf->perbox.has_value()) {
            out.metadata.cf_ldv = img.system_update_1.cf->perbox->lockdown_value;
        }
    }

    if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
        out.bootloaders.cg1 = img.system_update_1.cg->serialize();
    }

    out.metadata.cb_ldv = cb_ldv;
    std::memcpy(out.metadata.pairing_data, pairing_data, 3);
    out.metadata.console_type = console_type;
    out.metadata.console_sequence = console_sequence;
    out.metadata.console_sequence_allow = console_sequence_allow;

    if (img.smc.has_value()) {
        out.metadata.smc = img.smc->data;
    }

    if (img.keyvault.has_value()) {
        out.metadata.keyvault = img.keyvault->serialize();
    }

    if (img.filesystem.has_value()) {
        std::vector<std::pair<std::string, std::vector<uint8_t>>> files;
        auto file_list = img.filesystem->list_files();
        for (const auto& filename : file_list) {
            auto file_data = img.filesystem->get_file(filename);
            if (file_data.has_value()) {
                files.emplace_back(filename, std::move(*file_data));
            }
        }
        out.flashfs_sec = std::move(files);
    }

    return out;
}

std::optional<Input> ExtractAll(
    const std::vector<uint8_t>& nand_image,
    const std::vector<uint8_t>& cpu_key
) {
    return ExtractAll(
        std::span<const uint8_t>(nand_image),
        std::span<const uint8_t>(cpu_key)
    );
}
