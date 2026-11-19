#include "nand/FlashImage.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"
#include "nand/FlashDriver.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/XConfig.hpp"
#include "nand/objects/XeLL.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

namespace {

    constexpr uint32_t kKeyvaultOffset = 0x4000;
    constexpr uint32_t kEntryOffset = 0x8000;
    constexpr uint32_t kSmallPatchslotOffset = 0x70000;
    constexpr uint32_t kBigPatchslotOffset = 0xC0000;
    constexpr uint32_t kSmallFsOffset = 0x10000;
    constexpr uint32_t kBigFsOffset = 0x20000;

    constexpr uint32_t kJTAGRebooterOffset = 0x90000;
    constexpr uint32_t kJTAGvFusesOffset = 0x95000;

    inline constexpr uint32_t align_16(uint32_t value) noexcept {
        return (value + 0x0FU) & ~0x0FU;
    }

} // namespace

std::optional<FlashImage> FlashImage::read(std::vector<uint8_t> raw_image) {
    if (raw_image.empty()) {
        return std::nullopt;
    }

    FlashImage image{};
    image.flash_driver = Driver(std::move(raw_image));
    return image;
}

bool FlashImage::parse() {
    if (flash_driver.block_count() == 0) {
        Log::Error("Cannot parse NAND image: flash driver has 0 blocks");
        return false;
    }

    const auto& image_bytes = std::as_const(flash_driver).serialize();
    if (image_bytes.size() < sizeof(nand_header)) {
        Log::Error("Cannot parse NAND image: image size ({} bytes) smaller than NAND header", image_bytes.size());
        return false;
    }

    auto header_span = flash_driver.read_offset(0, sizeof(nand_header));
    if (header_span.size() < sizeof(nand_header)) {
        Log::Error("Failed to read NAND header");
        return false;
    }

    nand_header raw{};
    std::memcpy(&raw, header_span.data(), sizeof(nand_header));

    header.magic = bswap16(raw.magic);
    header.version = bswap16(raw.version);
    header.pairing = bswap16(raw.pairing);
    header.flags = bswap16(raw.flags);
    header.entrypoint = bswap32(raw.entrypoint);
    header.size = bswap32(raw.size);
    std::memcpy(header.copyright, raw.copyright, sizeof(header.copyright));
    std::memcpy(header.reserved, raw.reserved, sizeof(header.reserved));
    header.kv_size = bswap32(raw.kv_size);
    header.cf_offset = bswap32(raw.cf_offset);
    header.patch_slots = bswap16(raw.patch_slots);
    header.kv_version = bswap16(raw.kv_version);
    header.kv_addr = bswap32(raw.kv_addr);
    header.fs_addr = bswap32(raw.fs_addr);
    header.smc_config_offset = bswap32(raw.smc_config_offset);
    header.smc_boot_size = bswap32(raw.smc_boot_size);
    header.smc_boot_offset = bswap32(raw.smc_boot_offset);

    Log::Debug("Parsed NAND header: magic=0x{:04X}, version=0x{:04X}, entry=0x{:08X}, kv_addr=0x{:08X}",
               header.magic, header.version, header.entrypoint, header.kv_addr);

    const uint32_t smc_size = (header.smc_boot_size > 0 && header.smc_boot_size <= kKeyvaultOffset)
                                  ? header.smc_boot_size
                                  : 0x3000;
    const uint32_t smc_offset = kKeyvaultOffset - smc_size;
    auto smc_bytes = flash_driver.read_clean(smc_offset, smc_size);
    if (!smc_bytes.empty()) {
        smc = Smc::parse(smc_bytes);
        Log::Debug("Extracted SMC from NAND (0x{:X} bytes)", smc_bytes.size());
    }

    auto kv_bytes = flash_driver.read_clean(kKeyvaultOffset, Keyvault::kSize);
    if (!kv_bytes.empty()) {
        keyvault = Keyvault::parse(kv_bytes);
        Log::Debug("Extracted Keyvault from NAND (0x{:X} bytes)", kv_bytes.size());
    }

    size_t cursor = kEntryOffset;
    while (cursor + sizeof(generic_header) <= image_bytes.size()) {
        auto bldr_hdr_span = flash_driver.read_offset(cursor, sizeof(generic_header));
        if (bldr_hdr_span.size() < sizeof(generic_header)) {
            break;
        }

        generic_header bldr_hdr{};
        std::memcpy(&bldr_hdr, bldr_hdr_span.data(), sizeof(generic_header));

        uint16_t magic = bswap16(bldr_hdr.magic);
        uint16_t version = bswap16(bldr_hdr.version);
        uint32_t bldr_size = bswap32(bldr_hdr.size);

        if (bldr_size == 0 || bldr_size > 0x100000 || cursor + bldr_size > image_bytes.size()) {
            break;
        }

        auto bldr_data = flash_driver.read_clean(cursor, bldr_size);

        if (magic == 0x4342) {
            if (version == 15432) {
                cb_section.cb_x = BootloaderCb::parse(bldr_data);
            } else if (cb_section.cb_or_A.data.empty()) {
                cb_section.cb_or_A = BootloaderCb::parse(bldr_data);
            } else {
                cb_section.cb_B = BootloaderCb::parse(bldr_data);
            }
            Log::Debug("Parsed CB bootloader at offset 0x{:X} (version {}, size 0x{:X})", cursor, version, bldr_size);
        } else if (magic == 0x5343) {
            cb_section.sc = BootloaderSc::parse(bldr_data);
            Log::Debug("Parsed SC bootloader at offset 0x{:X} (version {}, size 0x{:X})", cursor, version, bldr_size);
        } else if (magic == 0x4344) {
            kernel_section.cd = BootloaderCd::parse(bldr_data);
            Log::Debug("Parsed CD bootloader at offset 0x{:X} (version {}, size 0x{:X})", cursor, version, bldr_size);
        } else if (magic == 0x4345) {
            kernel_section.ce = BootloaderCe::parse(bldr_data);
            Log::Debug("Parsed CE bootloader at offset 0x{:X} (version {}, size 0x{:X})", cursor, version, bldr_size);
        } else {
            break;
        }

        cursor += align_16(bldr_size);
    }

    const bool is_big_or_emmc = (flash_driver.driver_mode() == Driver::DriverMode::Big ||
                                 flash_driver.driver_mode() == Driver::DriverMode::Emmc);
    const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
    const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;

    auto parse_patchslot = [&](uint32_t base_offset, SystemUpdate& slot) {
        if (base_offset + sizeof(generic_header) > image_bytes.size()) {
            return;
        }
        auto slot_hdr_span = flash_driver.read_offset(base_offset, sizeof(generic_header));
        if (slot_hdr_span.size() < sizeof(generic_header)) {
            return;
        }

        generic_header slot_hdr{};
        std::memcpy(&slot_hdr, slot_hdr_span.data(), sizeof(generic_header));
        if (bswap16(slot_hdr.magic) == 0x4346) {
            uint32_t cf_size = bswap32(slot_hdr.size);
            if (cf_size > 0 && base_offset + cf_size <= image_bytes.size()) {
                auto cf_data = flash_driver.read_clean(base_offset, cf_size);
                slot.cf = BootloaderCf::parse(cf_data);

                size_t cg_offset = base_offset + align_16(cf_size);
                if (cg_offset + sizeof(generic_header) <= image_bytes.size()) {
                    auto cg_hdr_span = flash_driver.read_offset(cg_offset, sizeof(generic_header));
                    if (cg_hdr_span.size() == sizeof(generic_header)) {
                        generic_header cg_hdr{};
                        std::memcpy(&cg_hdr, cg_hdr_span.data(), sizeof(generic_header));
                        if (bswap16(cg_hdr.magic) == 0x4347) {
                            uint32_t cg_size = bswap32(cg_hdr.size);
                            if (cg_size > 0 && cg_offset + cg_size <= image_bytes.size()) {
                                auto cg_data = flash_driver.read_clean(cg_offset, cg_size);
                                slot.cg = BootloaderCg::parse(cg_data);
                            }
                        }
                    }
                }
            }
        }
    };

    parse_patchslot(patch_base, system_update_0);
    parse_patchslot(patch_base + slot_stride, system_update_1);

    const size_t total_blocks = flash_driver.block_count();
    const size_t block_size = flash_driver.block_size_clean();

    if (total_blocks >= 4 && block_size > 0) {
        const size_t smc_cfg_offset = (total_blocks - 4) * block_size;
        auto cfg_bytes = flash_driver.read_offset(smc_cfg_offset, 0x10000);
        if (!cfg_bytes.empty()) {
            smc_config = SmcConfig::parse(cfg_bytes, 0);
        }
    }

    if (flash_driver.driver_mode() == Driver::DriverMode::Emmc) {
        if (total_blocks >= 6) {
            const size_t cc_offset = (total_blocks - 6) * 0x4000;
            auto cc_bytes = flash_driver.read_offset(cc_offset, 0x200);
            if (!cc_bytes.empty()) {
                corona_config = CoronaConfig::parse(cc_bytes);
            }
        }

        if (corona_config) {
            MobileData mob{};
            if (corona_config->data.wMobile1Length > 0) {
                size_t m1_offset = static_cast<size_t>(corona_config->data.wMobile1BlockIdx) * 0x4000;
                size_t m1_len = static_cast<size_t>(corona_config->data.wMobile1Length) * 0x4000;
                auto m1_span = flash_driver.read_offset(m1_offset, m1_len);
                if (!m1_span.empty()) {
                    mob.x31 = std::vector<uint8_t>(m1_span.begin(), m1_span.end());
                }
            }
            if (corona_config->data.wMobile2Length > 0) {
                size_t m2_offset = static_cast<size_t>(corona_config->data.wMobile2BlockIdx) * 0x4000;
                size_t m2_len = static_cast<size_t>(corona_config->data.wMobile2Length) * 0x4000;
                auto m2_span = flash_driver.read_offset(m2_offset, m2_len);
                if (!m2_span.empty()) {
                    mob.x32 = std::vector<uint8_t>(m2_span.begin(), m2_span.end());
                }
            }
            if (!mob.empty()) {
                mobile_data = std::move(mob);
            }

            FlashFileSystem fs{};
            if (fs.load(flash_driver, corona_config->data.wFSBlockIdx)) {
                filesystem = std::move(fs);
            }
        }
    } else {
        MobileData mob{};
        for (size_t blk = 0; blk < total_blocks; ++blk) {
            auto meta = flash_driver.interpret_block(blk);
            if (is_mobile_block_type(meta.block_type)) {
                auto* slot = mob.get_slot(meta.block_type);
                if (slot && !(*slot)) {
                    auto blk_data = flash_driver.read_block(blk);
                    if (!blk_data.empty()) {
                        *slot = std::move(blk_data);
                    }
                }
            }
        }
        if (!mob.empty()) {
            mobile_data = std::move(mob);
        }

        std::optional<size_t> best_root;
        uint32_t best_seq = 0;
        for (size_t blk = 0; blk < total_blocks; ++blk) {
            auto meta = flash_driver.interpret_block(blk);
            if (meta.block_type == 0x30 && !meta.is_bad) {
                if (!best_root || meta.sequence > best_seq) {
                    best_root = blk;
                    best_seq = meta.sequence;
                }
            }
        }

        if (best_root) {
            FlashFileSystem fs{};
            if (fs.load(flash_driver, static_cast<uint16_t>(*best_root))) {
                filesystem = std::move(fs);
            }
        }
    }

    if (kJTAGRebooterOffset + sizeof(generic_header) <= image_bytes.size()) {
        auto reb_span = flash_driver.read_offset(kJTAGRebooterOffset, 0x1000);
        if (!reb_span.empty() && std::any_of(reb_span.begin(), reb_span.end(), [](uint8_t b) { return b != 0x00 && b != 0xFF; })) {
            payloads.rebooter = std::vector<uint8_t>(reb_span.begin(), reb_span.end());
        }
    }

    if (kJTAGvFusesOffset + 0x60 <= image_bytes.size()) {
        auto fuse_span = flash_driver.read_offset(kJTAGvFusesOffset, 0x60);
        if (!fuse_span.empty() && std::any_of(fuse_span.begin(), fuse_span.end(), [](uint8_t b) { return b != 0x00 && b != 0xFF; })) {
            payloads.fuses = std::vector<uint8_t>(fuse_span.begin(), fuse_span.end());
        }
    }

    constexpr uint32_t kJtagXellOffset = kJTAGvFusesOffset + 0x60;
    if (kJtagXellOffset + 0x40000 <= image_bytes.size()) {
        auto xell_span = flash_driver.read_offset(kJtagXellOffset, 0x40000);
        if (xell_span.size() == 0x40000) {
            payloads.xell = XeLL::parse(xell_span);
        }
    }

    if (!payloads.xell && patch_base + 0x40000 <= image_bytes.size()) {
        auto xell_span = flash_driver.read_offset(patch_base, 0x40000);
        if (xell_span.size() == 0x40000) {
            payloads.xell = XeLL::parse(xell_span);
        }
    }

    return true;
}

bool FlashImage::write_to_driver() const {
    if (flash_driver.block_count() == 0) {
        return false;
    }

    auto& driver = const_cast<Driver&>(flash_driver);

    const bool is_big_or_emmc = (driver.driver_mode() == Driver::DriverMode::Big ||
                                 driver.driver_mode() == Driver::DriverMode::Emmc);
    const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
    const uint32_t fs_base = is_big_or_emmc ? kBigFsOffset : kSmallFsOffset;
    const size_t total_blocks = driver.block_count();
    const size_t block_size = driver.block_size_clean();

    const size_t smc_len = smc ? smc->data.size() : 0x3000;
    const uint32_t smc_offset = kKeyvaultOffset - static_cast<uint32_t>(smc_len);
    const size_t smc_cfg_offset = (total_blocks >= 4) ? (total_blocks - 4) * block_size : 0;

    nand_header raw{};
    raw.magic = bswap16(header.magic ? header.magic : 0xFF4F);
    raw.version = bswap16(header.version ? header.version : 0x0760);
    raw.pairing = bswap16(header.pairing);
    raw.flags = bswap16(header.flags);
    raw.entrypoint = bswap32(header.entrypoint ? header.entrypoint : kEntryOffset);
    raw.size = bswap32(header.size);
    std::memcpy(raw.copyright, header.copyright, sizeof(raw.copyright));
    std::memcpy(raw.reserved, header.reserved, sizeof(raw.reserved));
    raw.kv_size = bswap32(header.kv_size ? header.kv_size : Keyvault::kSize);
    raw.cf_offset = bswap32(header.cf_offset ? header.cf_offset : patch_base);
    raw.patch_slots = bswap16(header.patch_slots ? header.patch_slots : 2);
    raw.kv_version = bswap16(header.kv_version ? header.kv_version : 0x0712);
    raw.kv_addr = bswap32(header.kv_addr ? header.kv_addr : kKeyvaultOffset);
    raw.fs_addr = bswap32(header.fs_addr ? header.fs_addr : fs_base);
    raw.smc_config_offset = bswap32(header.smc_config_offset ? header.smc_config_offset : static_cast<uint32_t>(smc_cfg_offset));
    raw.smc_boot_size = bswap32(static_cast<uint32_t>(smc_len));
    raw.smc_boot_offset = bswap32(smc_offset);

    driver.write_offset(0, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&raw), sizeof(raw)));

    if (smc) {
        driver.write_offset(smc_offset, smc->data);
    }

    if (keyvault) {
        auto kv_data = keyvault->serialize();
        driver.write_offset(kKeyvaultOffset, kv_data);
    }

    size_t cursor = kEntryOffset;
    if (!cb_section.cb_or_A.data.empty()) {
        auto cb_a = cb_section.cb_or_A.serialize();
        driver.write_offset(cursor, cb_a);
        cursor += align_16(static_cast<uint32_t>(cb_a.size()));
    }
    if (cb_section.cb_x) {
        auto cb_x = cb_section.cb_x->serialize();
        driver.write_offset(cursor, cb_x);
        cursor += align_16(static_cast<uint32_t>(cb_x.size()));
    }
    if (cb_section.cb_B) {
        auto cb_b = cb_section.cb_B->serialize();
        driver.write_offset(cursor, cb_b);
        cursor += align_16(static_cast<uint32_t>(cb_b.size()));
    }
    if (cb_section.sc) {
        auto sc = cb_section.sc->serialize();
        driver.write_offset(cursor, sc);
        cursor += align_16(static_cast<uint32_t>(sc.size()));
    }
    if (!kernel_section.cd.data.empty()) {
        auto cd = kernel_section.cd.serialize();
        driver.write_offset(cursor, cd);
        cursor += align_16(static_cast<uint32_t>(cd.size()));
    }
    if (kernel_section.ce) {
        auto ce = kernel_section.ce->serialize();
        driver.write_offset(cursor, ce);
        cursor += align_16(static_cast<uint32_t>(ce.size()));
    }

    auto write_patchslot = [&](uint32_t base_offset, const SystemUpdate& slot) {
        if (slot.cf) {
            auto cf_bytes = slot.cf->serialize();
            driver.write_offset(base_offset, cf_bytes);
            if (slot.cg) {
                auto cg_bytes = slot.cg->serialize();
                driver.write_offset(base_offset + align_16(static_cast<uint32_t>(cf_bytes.size())), cg_bytes);
            }
        }
    };

    const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
    write_patchslot(patch_base, system_update_0);
    write_patchslot(patch_base + slot_stride, system_update_1);

    if (smc_config && total_blocks >= 4) {
        auto cfg_bytes = smc_config->serialize(0x10000, static_cast<uint32_t>(smc_cfg_offset));
        driver.write_offset(smc_cfg_offset, cfg_bytes);
    }

    NandLayout layout{};
    const size_t fs_blk_size = (driver.driver_mode() == Driver::DriverMode::Emmc) ? 0x4000 : block_size;
    size_t current_blk = fs_base / fs_blk_size;

    if (mobile_data) {
        for (uint8_t bt = 0x31; bt <= 0x39; ++bt) {
            const auto* slot = mobile_data->get_slot(bt);
            if (slot && *slot && !(*slot)->empty()) {
                const auto& mdata = **slot;
                size_t blks_needed = (mdata.size() + fs_blk_size - 1) / fs_blk_size;
                for (size_t b = 0; b < blks_needed; ++b) {
                    size_t chunk_off = b * fs_blk_size;
                    size_t chunk_len = std::min(fs_blk_size, mdata.size() - chunk_off);
                    driver.write_block(current_blk + b, std::span<const uint8_t>(mdata.data() + chunk_off, chunk_len));
                }
                layout.mobile_blocks.push_back({bt, static_cast<uint16_t>(current_blk), static_cast<uint16_t>(blks_needed)});
                current_blk += blks_needed;
            }
        }
    }

    if (filesystem) {
        layout.fs_root_block = static_cast<uint16_t>(current_blk);
        layout.fs_version = filesystem->version();
        layout.fs_size = static_cast<uint16_t>(filesystem->blockmap().size());
        auto& fs = const_cast<FlashFileSystem&>(*filesystem);
        fs.set_driver(&driver);
        if (!fs.save()) {
            Log::Error("Failed to save Flash File System to NAND driver");
            return false;
        }
    }

    if (driver.driver_mode() == Driver::DriverMode::Emmc) {
        CoronaConfig cc = corona_config.value_or(CoronaConfig{});
        cc.data.dwFSVersion = layout.fs_version;
        cc.data.wFSBlockIdx = layout.fs_root_block;
        for (const auto& mob : layout.mobile_blocks) {
            if (mob.block_type == 0x31) {
                cc.data.wMobile1BlockIdx = mob.start_block;
                cc.data.wMobile1Length = mob.block_count;
            } else if (mob.block_type == 0x32) {
                cc.data.wMobile2BlockIdx = mob.start_block;
                cc.data.wMobile2Length = mob.block_count;
            }
        }

        if (total_blocks >= 6) {
            auto cc_bytes = cc.serialize();
            driver.write_offset((total_blocks - 6) * 0x4000, cc_bytes);
            driver.write_offset((total_blocks - 5) * 0x4000, cc_bytes);
        }
    } else {
        driver.set_layout(layout);
    }

    if (payloads.rebooter) {
        driver.write_offset(kJTAGRebooterOffset, *payloads.rebooter);
    }
    if (payloads.fuses) {
        driver.write_offset(kJTAGvFusesOffset, *payloads.fuses);
    }
    if (payloads.xell) {
        const auto& xell_bytes = payloads.xell->data;
        if (payloads.rebooter) {
            driver.write_offset(kJTAGvFusesOffset + 0x60, xell_bytes);
        } else {
            driver.write_offset(patch_base, xell_bytes);
        }
    }

    return true;
}

std::vector<uint8_t> FlashImage::write() const {
    if (!const_cast<FlashImage*>(this)->write_to_driver()) {
        return {};
    }
    return const_cast<Driver&>(flash_driver).serialize();
}

bool FlashImage::decrypt_all(std::span<const uint8_t> cpu_key) {
    try {
        if (!cb_section.cb_or_A.data.empty() && !cb_section.cb_or_A.is_decrypted()) {
            cb_section.cb_or_A.decrypt(key_1bl);
        }

        if (cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
            !cb_section.cb_B->is_decrypted()) {
            if (!cb_section.cb_or_A.derived_key.has_value()) {
                Log::Error("Cannot decrypt CB_B: CB_A derived key is missing");
                return false;
            }
            if ((cb_section.cb_B->header.header.flags & 0x1000) == 0x1000) {
                cb_section.cb_B->decrypt_v2(cb_section.cb_or_A.header,
                                             cb_section.cb_or_A.derived_key->data(), cpu_key.data());
            } else {
                cb_section.cb_B->decrypt_v1(cb_section.cb_or_A.derived_key->data(), cpu_key.data());
            }
        }

        if (!kernel_section.cd.data.empty() && !kernel_section.cd.is_decrypted()) {
            if (cb_section.cb_B.has_value() && cb_section.cb_B->derived_key.has_value()) {
                kernel_section.cd.decrypt(cb_section.cb_B->derived_key->data());
            } else if (cb_section.cb_or_A.derived_key.has_value()) {
                kernel_section.cd.decrypt(cb_section.cb_or_A.derived_key->data());
            } else {
                Log::Error("Cannot decrypt CD: parent derived key is missing");
                return false;
            }
        }

        if (kernel_section.ce.has_value() && !kernel_section.ce->data.empty() &&
            !kernel_section.ce->is_decrypted()) {
            if (!kernel_section.cd.decrypted) {
                Log::Error("Cannot decrypt CE: CD is not decrypted");
                return false;
            }
            kernel_section.ce->decrypt(kernel_section.cd.header.key);
        }

        if (system_update_0.cf.has_value() && !system_update_0.cf->is_decrypted()) {
            system_update_0.cf->decrypt(key_1bl);
        }
        if (system_update_1.cf.has_value() && !system_update_1.cf->is_decrypted()) {
            system_update_1.cf->decrypt(key_1bl);
        }

        if (smc.has_value() && smc->encrypted) {
            smc->decrypt();
        }

        if (keyvault.has_value() && keyvault->encrypted && !cpu_key.empty()) {
            if (!keyvault->decrypt(cpu_key)) {
                Log::Error("Failed to decrypt Keyvault with provided CPU key");
                return false;
            }
        }
    } catch (const std::exception& e) {
        Log::Error("Decryption error in FlashImage: {}", e.what());
        return false;
    }

    return true;
}

bool FlashImage::encrypt_all(std::span<const uint8_t> cpu_key) {
    try {
        if (!cb_section.cb_or_A.data.empty() && cb_section.cb_or_A.is_decrypted()) {
            cb_section.cb_or_A.encrypt(key_1bl);
        }

        if (cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
            cb_section.cb_B->is_decrypted()) {
            if (!cb_section.cb_or_A.derived_key.has_value()) {
                Log::Error("Cannot encrypt CB_B: CB_A derived key is missing");
                return false;
            }
            if ((cb_section.cb_B->header.header.flags & 0x1000) == 0x1000) {
                cb_section.cb_B->encrypt_v2(cb_section.cb_or_A.header,
                                             cb_section.cb_or_A.derived_key->data(), cpu_key.data());
            } else {
                cb_section.cb_B->encrypt_v1(cb_section.cb_or_A.derived_key->data(), cpu_key.data());
            }
        }

        if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted()) {
            if (cb_section.cb_B.has_value() && cb_section.cb_B->derived_key.has_value()) {
                kernel_section.cd.encrypt(cb_section.cb_B->derived_key->data());
            } else if (cb_section.cb_or_A.derived_key.has_value()) {
                kernel_section.cd.encrypt(cb_section.cb_or_A.derived_key->data());
            } else {
                Log::Error("Cannot encrypt CD: parent derived key is missing");
                return false;
            }
        }

        if (kernel_section.ce.has_value() && !kernel_section.ce->data.empty() &&
            kernel_section.ce->is_decrypted()) {
            kernel_section.ce->encrypt(kernel_section.cd.header.key);
        }

        if (system_update_0.cf.has_value() && system_update_0.cf->is_decrypted()) {
            system_update_0.cf->encrypt(key_1bl);
            if (!cpu_key.empty()) {
                system_update_0.cf->calc_mac(key_1bl, cpu_key.data());
            }
        }
        if (system_update_1.cf.has_value() && system_update_1.cf->is_decrypted()) {
            system_update_1.cf->encrypt(key_1bl);
            if (!cpu_key.empty()) {
                system_update_1.cf->calc_mac(key_1bl, cpu_key.data());
            }
        }

        if (smc.has_value() && !smc->encrypted) {
            smc->encrypt();
        }

        if (keyvault.has_value() && !keyvault->encrypted && !cpu_key.empty()) {
            if (!keyvault->encrypt(cpu_key)) {
                Log::Error("Failed to encrypt Keyvault with provided CPU key");
                return false;
            }
        }
    } catch (const std::exception& e) {
        Log::Error("Encryption error in FlashImage: {}", e.what());
        return false;
    }

    return true;
}

} // namespace gxbuild3::NAND