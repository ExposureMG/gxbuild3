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
        if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
            auto& cb_b = *img.cb_section.cb_B;

            if (cb_b.perbox.has_value()) {
                cb_ldv = cb_b.perbox->lockdown_value;
                std::memcpy(pairing_data, cb_b.perbox->pairing_data, 3);
            } else if (cb_a.perbox.has_value()) {
                cb_ldv = cb_a.perbox->lockdown_value;
                std::memcpy(pairing_data, cb_a.perbox->pairing_data, 3);
            }
        } else {
            if (cb_a.perbox.has_value()) {
                cb_ldv = cb_a.perbox->lockdown_value;
                std::memcpy(pairing_data, cb_a.perbox->pairing_data, 3);
            }
        }

        console_type = cb_a.header.console_seq_allow.console_type;
        console_sequence = cb_a.header.console_seq_allow.console_sequence;
        console_sequence_allow = cb_a.header.console_seq_allow.console_sequence_allow;
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
