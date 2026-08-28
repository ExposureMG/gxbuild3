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
#include <limits>
#include <span>
#include <utility>
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

    std::optional<size_t> smc_config_offset(const Driver& driver) {
        const size_t total_blocks = driver.block_count();
        if (total_blocks < 4 || driver.block_size_clean() == 0) {
            return std::nullopt;
        }

        size_t reserve_block = 0;
        switch (driver.driver_mode()) {
            case Driver::DriverMode::Big:
                reserve_block = 0x1E0;
                break;
            case Driver::DriverMode::Emmc:
                reserve_block = 0xC00;
                break;
            case Driver::DriverMode::Small:
            case Driver::DriverMode::NewSmall:
                reserve_block = 0x3E0;
                break;
        }

        reserve_block = std::min(reserve_block, total_blocks);
        if (reserve_block < 4) {
            return std::nullopt;
        }
        return (reserve_block - 4) * driver.block_size_clean();
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

    auto header_span = std::as_const(flash_driver).read_offset(0, sizeof(nand_header));
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
        auto bldr_hdr_bytes = flash_driver.read_clean(cursor, sizeof(generic_header));
        if (bldr_hdr_bytes.size() < sizeof(generic_header)) {
            break;
        }

        generic_header bldr_hdr{};
        std::memcpy(&bldr_hdr, bldr_hdr_bytes.data(), sizeof(generic_header));

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
        auto slot_hdr_bytes = flash_driver.read_clean(base_offset, sizeof(generic_header));
        if (slot_hdr_bytes.size() < sizeof(generic_header)) {
            return;
        }

        generic_header slot_hdr{};
        std::memcpy(&slot_hdr, slot_hdr_bytes.data(), sizeof(generic_header));
        if (bswap16(slot_hdr.magic) == 0x4346) {
            uint32_t cf_size = bswap32(slot_hdr.size);
            if (cf_size > 0 && base_offset + cf_size <= image_bytes.size()) {
                auto cf_data = flash_driver.read_clean(base_offset, cf_size);
                slot.cf = BootloaderCf::parse(cf_data);

                size_t cg_offset = base_offset + align_16(cf_size);
                if (cg_offset + sizeof(generic_header) <= image_bytes.size()) {
                    auto cg_hdr_bytes = flash_driver.read_clean(cg_offset, sizeof(generic_header));
                    if (cg_hdr_bytes.size() == sizeof(generic_header)) {
                        generic_header cg_hdr{};
                        std::memcpy(&cg_hdr, cg_hdr_bytes.data(), sizeof(generic_header));
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

    if (auto cfg_offset = smc_config_offset(flash_driver)) {
        auto cfg_bytes = std::as_const(flash_driver).read_offset(*cfg_offset, 0x10000);
        if (!cfg_bytes.empty()) {
            smc_config = SmcConfig::parse(cfg_bytes, 0);
        }
    }

    if (flash_driver.driver_mode() == Driver::DriverMode::Emmc) {
        if (total_blocks >= 6) {
            const size_t cc_offset = (total_blocks - 6) * 0x4000;
            auto cc_bytes = std::as_const(flash_driver).read_offset(cc_offset, 0x200);
            if (!cc_bytes.empty()) {
                corona_config = CoronaConfig::parse(cc_bytes);
            }
        }

        if (corona_config) {
            MobileData mob{};
            if (corona_config->data.wMobile1Length > 0) {
                size_t m1_offset = static_cast<size_t>(corona_config->data.wMobile1BlockIdx) * 0x4000;
                size_t m1_len = static_cast<size_t>(corona_config->data.wMobile1Length) * 0x4000;
                auto m1_span = std::as_const(flash_driver).read_offset(m1_offset, m1_len);
                if (!m1_span.empty()) {
                    mob.x31 = std::vector<uint8_t>(m1_span.begin(), m1_span.end());
                }
            }
            if (corona_config->data.wMobile2Length > 0) {
                size_t m2_offset = static_cast<size_t>(corona_config->data.wMobile2BlockIdx) * 0x4000;
                size_t m2_len = static_cast<size_t>(corona_config->data.wMobile2Length) * 0x4000;
                auto m2_span = std::as_const(flash_driver).read_offset(m2_offset, m2_len);
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
        struct MobileCandidate {
            uint32_t sequence = 0;
            std::vector<std::pair<size_t, BlockMetadata>> blocks;
        };

        std::array<std::vector<MobileCandidate>, 9> candidates;
        for (size_t blk = 0; blk < total_blocks; ++blk) {
            auto meta = flash_driver.interpret_block(blk);
            if (!is_mobile_block_type(meta.block_type) || meta.is_bad) {
                continue;
            }

            auto& type_candidates = candidates[meta.block_type - 0x31];
            if (type_candidates.empty() || type_candidates.back().sequence != meta.sequence ||
                type_candidates.back().blocks.back().first + 1 != blk) {
                type_candidates.push_back(MobileCandidate{meta.sequence, {}});
            }
            type_candidates.back().blocks.emplace_back(blk, meta);
        }

        MobileData mob{};
        for (size_t type_idx = 0; type_idx < candidates.size(); ++type_idx) {
            auto& type_candidates = candidates[type_idx];
            if (type_candidates.empty()) {
                continue;
            }

            const auto& latest = *std::max_element(
                type_candidates.begin(), type_candidates.end(),
                [](const MobileCandidate& lhs, const MobileCandidate& rhs) {
                    return lhs.sequence < rhs.sequence;
                });

            std::vector<uint8_t> data;
            for (size_t block_pos = 0; block_pos < latest.blocks.size(); ++block_pos) {
                const auto [block_idx, meta] = latest.blocks[block_pos];
                auto block_data = flash_driver.read_block(block_idx);
                if (block_data.empty()) {
                    data.clear();
                    break;
                }
                data.insert(data.end(), block_data.begin(), block_data.end());
                if (block_pos + 1 == latest.blocks.size() && meta.page_count > 0 &&
                    meta.page_count < flash_driver.pages_per_block()) {
                    const size_t valid_size =
                        (latest.blocks.size() - 1) * block_size + meta.page_count * 512;
                    data.resize(std::min(valid_size, data.size()));
                }
            }

            if (!data.empty()) {
                const auto& first_meta = latest.blocks.front().second;
                if (first_meta.fs_size > 0 && first_meta.fs_size < data.size()) {
                    data.resize(first_meta.fs_size);
                }
                auto* slot = mob.get_slot(static_cast<uint8_t>(type_idx + 0x31));
                if (slot) {
                    *slot = std::move(data);
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
            const bool is_filesystem_root = meta.block_type == 0x2C || meta.block_type == 0x30;
            if (is_filesystem_root && !meta.is_bad && meta.sequence != 0) {
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

    if (kJTAGRebooterOffset + 0x1000 <= image_bytes.size()) {
        auto reb_span = std::as_const(flash_driver).read_offset(kJTAGRebooterOffset, 0x1000);
        if (!reb_span.empty() && std::any_of(reb_span.begin(), reb_span.end(), [](uint8_t b) { return b != 0x00 && b != 0xFF; })) {
            payloads.rebooter = std::vector<uint8_t>(reb_span.begin(), reb_span.end());
        }
    }

    if (kJTAGvFusesOffset + 0x60 <= image_bytes.size()) {
        auto fuse_span = std::as_const(flash_driver).read_offset(kJTAGvFusesOffset, 0x60);
        if (!fuse_span.empty() && std::any_of(fuse_span.begin(), fuse_span.end(), [](uint8_t b) { return b != 0x00 && b != 0xFF; })) {
            payloads.fuses = std::vector<uint8_t>(fuse_span.begin(), fuse_span.end());
        }
    }

    constexpr uint32_t kJtagXellOffset = kJTAGvFusesOffset + 0x60;
    if (kJtagXellOffset + 0x40000 <= image_bytes.size()) {
        auto xell_span = std::as_const(flash_driver).read_offset(kJtagXellOffset, 0x40000);
        if (xell_span.size() == 0x40000) {
            payloads.xell = XeLL::parse(xell_span);
        }
    }

    if (!payloads.xell && patch_base + 0x40000 <= image_bytes.size()) {
        auto xell_span = std::as_const(flash_driver).read_offset(patch_base, 0x40000);
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
    if (smc_len > kKeyvaultOffset - sizeof(nand_header)) {
        Log::Error("SMC payload (0x{:X} bytes) does not fit before the keyvault", smc_len);
        return false;
    }
    const uint32_t smc_offset = kKeyvaultOffset - static_cast<uint32_t>(smc_len);
    const auto smc_cfg_offset = smc_config_offset(driver);

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
    raw.smc_config_offset = bswap32(
        header.smc_config_offset ? header.smc_config_offset : static_cast<uint32_t>(smc_cfg_offset.value_or(0)));
    raw.smc_boot_size = bswap32(static_cast<uint32_t>(smc_len));
    raw.smc_boot_offset = bswap32(smc_offset);

    if (!driver.write_offset(0, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&raw), sizeof(raw)))) {
        return false;
    }

    if (smc) {
        if (!driver.write_offset(smc_offset, smc->data)) {
            return false;
        }
    }

    if (keyvault) {
        auto kv_data = keyvault->serialize();
        if (!driver.write_offset(kKeyvaultOffset, kv_data)) {
            return false;
        }
    }

    size_t cursor = kEntryOffset;
    if (!cb_section.cb_or_A.data.empty()) {
        auto cb_a = cb_section.cb_or_A.serialize();
        if (!driver.write_offset(cursor, cb_a)) {
            return false;
        }
        cursor += align_16(static_cast<uint32_t>(cb_a.size()));
    }
    if (cb_section.cb_x) {
        auto cb_x = cb_section.cb_x->serialize();
        if (!driver.write_offset(cursor, cb_x)) {
            return false;
        }
        cursor += align_16(static_cast<uint32_t>(cb_x.size()));
    }
    if (cb_section.cb_B) {
        auto cb_b = cb_section.cb_B->serialize();
        if (!driver.write_offset(cursor, cb_b)) {
            return false;
        }
        cursor += align_16(static_cast<uint32_t>(cb_b.size()));
    }
    if (cb_section.sc) {
        auto sc = cb_section.sc->serialize();
        if (!driver.write_offset(cursor, sc)) {
            return false;
        }
        cursor += align_16(static_cast<uint32_t>(sc.size()));
    }
    if (!kernel_section.cd.data.empty()) {
        auto cd = kernel_section.cd.serialize();
        if (!driver.write_offset(cursor, cd)) {
            return false;
        }
        cursor += align_16(static_cast<uint32_t>(cd.size()));
    }
    if (kernel_section.ce) {
        auto ce = kernel_section.ce->serialize();
        if (!driver.write_offset(cursor, ce)) {
            return false;
        }
        cursor += align_16(static_cast<uint32_t>(ce.size()));
    }

    size_t highest_used_offset = cursor;

    auto write_patchslot = [&](uint32_t base_offset, const SystemUpdate& slot,
                               size_t& end_offset) -> bool {
        end_offset = base_offset;
        if (slot.cf) {
            auto cf_bytes = slot.cf->serialize();
            if (!driver.write_offset(base_offset, cf_bytes)) {
                return false;
            }
            end_offset = base_offset + align_16(static_cast<uint32_t>(cf_bytes.size()));
            if (slot.cg) {
                auto cg_bytes = slot.cg->serialize();
                if (!driver.write_offset(end_offset, cg_bytes)) {
                    return false;
                }
                end_offset += align_16(static_cast<uint32_t>(cg_bytes.size()));
            }
            highest_used_offset = std::max(highest_used_offset, end_offset);
        }
        return true;
    };

    const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
    size_t slot0_end = patch_base;
    if (!write_patchslot(patch_base, system_update_0, slot0_end)) {
        return false;
    }
    if (patch_base + slot_stride >= slot0_end) {
        size_t slot1_end = patch_base + slot_stride;
        if (!write_patchslot(patch_base + slot_stride, system_update_1, slot1_end)) {
            return false;
        }
    } else {
        // CG0 was too large and overflowed into the second slot. Skip CF1/CG1 and update header.
        raw.patch_slots = bswap16(1);
        if (!driver.write_offset(0, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&raw), sizeof(raw)))) {
            return false;
        }
    }

    if (smc_config) {
        if (!smc_cfg_offset) {
            return false;
        }
        auto cfg_bytes = smc_config->serialize(0x10000);
        if (!driver.write_offset(*smc_cfg_offset, cfg_bytes)) {
            return false;
        }
    }

    NandLayout layout{};
    const size_t fs_blk_size = (driver.driver_mode() == Driver::DriverMode::Emmc) ? 0x4000 : block_size;

    size_t min_blk = (highest_used_offset + fs_blk_size - 1) / fs_blk_size;
    size_t current_blk = std::max<size_t>(fs_base / fs_blk_size, min_blk);

    auto find_filesystem_free_run = [&](size_t start_block,
                                        size_t requested_blocks) -> std::optional<size_t> {
        if (!filesystem || requested_blocks == 0) {
            return std::nullopt;
        }
        const auto& blockmap = filesystem->blockmap();
        if (requested_blocks > blockmap.size()) {
            return std::nullopt;
        }
        for (size_t candidate = start_block;
             candidate <= blockmap.size() - requested_blocks; ++candidate) {
            bool all_free = true;
            for (size_t block = candidate; block < candidate + requested_blocks; ++block) {
                if (blockmap[block] != BlockMapStatus::Free) {
                    all_free = false;
                    break;
                }
            }
            if (all_free) {
                return candidate;
            }
        }
        return std::nullopt;
    };

    auto* mutable_filesystem = filesystem ? &const_cast<FlashFileSystem&>(*filesystem) : nullptr;

    if (mobile_data) {
        for (uint8_t bt = 0x31; bt <= 0x39; ++bt) {
            const auto* slot = mobile_data->get_slot(bt);
            if (slot && *slot && !(*slot)->empty()) {
                const auto& mdata = **slot;
                size_t blks_needed = (mdata.size() + fs_blk_size - 1) / fs_blk_size;
                if (blks_needed == 0 || blks_needed > total_blocks ||
                    current_blk > total_blocks - blks_needed) {
                    Log::Error("Mobile data type 0x{:02X} does not fit in NAND", bt);
                    return false;
                }
                if (filesystem) {
                    auto free_start = find_filesystem_free_run(current_blk, blks_needed);
                    if (!free_start) {
                        Log::Error("Mobile data type 0x{:02X} overlaps FlashFS allocations", bt);
                        return false;
                    }
                    current_blk = *free_start;
                }
                for (size_t b = 0; b < blks_needed; ++b) {
                    size_t chunk_off = b * fs_blk_size;
                    size_t chunk_len = std::min(fs_blk_size, mdata.size() - chunk_off);
                    if (!driver.write_block(current_blk + b,
                                            std::span<const uint8_t>(mdata.data() + chunk_off, chunk_len))) {
                        return false;
                    }
                }
                if (mutable_filesystem &&
                    !mutable_filesystem->reserve_blocks(current_blk, blks_needed)) {
                    Log::Error("Failed to reserve mobile data type 0x{:02X} in FlashFS", bt);
                    return false;
                }
                layout.mobile_blocks.push_back({bt, static_cast<uint16_t>(current_blk),
                                                static_cast<uint16_t>(blks_needed), 1,
                                                static_cast<uint32_t>(mdata.size())});
                current_blk += blks_needed;
            }
        }
    }

    if (filesystem) {
        auto root_start = find_filesystem_free_run(current_blk, 1);
        if (!root_start || *root_start > std::numeric_limits<uint16_t>::max() ||
            !mutable_filesystem->set_root_block(static_cast<uint16_t>(*root_start))) {
            Log::Error("Failed to place FlashFS root block after payload allocations");
            return false;
        }
        layout.fs_root_block = static_cast<uint16_t>(*root_start);
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
        cc.data.wFSBlockIdx = layout.fs_root_block.value_or(0);
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
            if (!driver.write_offset((total_blocks - 6) * 0x4000, cc_bytes) ||
                !driver.write_offset((total_blocks - 5) * 0x4000, cc_bytes)) {
                return false;
            }
        }
    } else {
        driver.set_layout(layout);
    }

    if (payloads.rebooter) {
        if (!driver.write_offset(kJTAGRebooterOffset, *payloads.rebooter)) {
            return false;
        }
    }
    if (payloads.fuses) {
        if (!driver.write_offset(kJTAGvFusesOffset, *payloads.fuses)) {
            return false;
        }
    }
    if (payloads.xell) {
        const auto& xell_bytes = payloads.xell->data;
        if (payloads.rebooter) {
            if (!driver.write_offset(kJTAGvFusesOffset + 0x60, xell_bytes)) {
                return false;
            }
        } else {
            if (!driver.write_offset(patch_base, xell_bytes)) {
                return false;
            }
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
            if ((cb_section.cb_or_A.header.header.flags & 0x1000) == 0x1000) {
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
                const uint8_t* cd_cpu_key = nullptr;
                if (cb_section.cb_or_A.requires_cpu_key_for_cd()) {
                    if (cpu_key.size() < 16) {
                        Log::Error("Cannot decrypt CD: single-CB chain requires a CPU key");
                        return false;
                    }
                    cd_cpu_key = cpu_key.data();
                }
                kernel_section.cd.decrypt(cb_section.cb_or_A.derived_key->data(), cd_cpu_key);
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
        const bool cd_requires_cpu_key =
            !cb_section.cb_B.has_value() && cb_section.cb_or_A.requires_cpu_key_for_cd();

        if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted() &&
            cd_requires_cpu_key && cpu_key.size() < 16) {
            Log::Error("Cannot encrypt CD: single-CB chain requires a CPU key");
            return false;
        }

        if (!cb_section.cb_or_A.data.empty() && cb_section.cb_or_A.is_decrypted()) {
            cb_section.cb_or_A.encrypt(key_1bl);
        }

        if (cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
            cb_section.cb_B->is_decrypted()) {
            if (!cb_section.cb_or_A.derived_key.has_value()) {
                Log::Error("Cannot encrypt CB_B: CB_A derived key is missing");
                return false;
            }
            if ((cb_section.cb_or_A.header.header.flags & 0x1000) == 0x1000) {
                cb_section.cb_B->encrypt_v2(cb_section.cb_or_A.header,
                                             cb_section.cb_or_A.derived_key->data(), cpu_key.data());
            } else {
                cb_section.cb_B->encrypt_v1(cb_section.cb_or_A.derived_key->data(), cpu_key.data());
            }
        }

        if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted()) {
            if (cb_section.cb_B.has_value()) {
                if (!cb_section.cb_B->derived_key.has_value()) {
                    Log::Error("Cannot encrypt CD: CB_B derived key is missing");
                    return false;
                }
                kernel_section.cd.encrypt(cb_section.cb_B->derived_key->data());
            } else if (cb_section.cb_or_A.derived_key.has_value()) {
                kernel_section.cd.encrypt(cb_section.cb_or_A.derived_key->data(),
                                          cd_requires_cpu_key ? cpu_key.data() : nullptr);
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
