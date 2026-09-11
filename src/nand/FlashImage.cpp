#include "nand/FlashImage.hpp"

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
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
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
        constexpr uint32_t kJTAGPatchesOffset = 0x91000;
        constexpr uint32_t kJTAGPatchesSize = 0x4000;
        constexpr uint32_t kJTAGvFusesOffset = 0x95000;

        inline constexpr uint32_t align_16(uint32_t value) noexcept {
            return (value + 0x0FU) & ~0x0FU;
        }

        bool checked_add(size_t left, size_t right, size_t& result) {
            if (right > std::numeric_limits<size_t>::max() - left) {
                return false;
            }
            result = left + right;
            return true;
        }

        bool checked_align_16(size_t value, size_t& result) {
            if (value > std::numeric_limits<size_t>::max() - 0x0FU) {
                return false;
            }
            result = (value + 0x0FU) & ~size_t{0x0FU};
            return true;
        }

        uint32_t xell_offset(uint32_t patch_base, bool is_jtag_patchset, bool is_glitch_patchset,
                             const Payloads& payloads) {
            if (is_jtag_patchset) {
                return kJTAGvFusesOffset + 0x60;
            }
            return (is_glitch_patchset || !payloads.rebooter) ? patch_base
                                                              : kJTAGvFusesOffset + 0x60;
        }

        uint32_t system_update_base(uint32_t patch_base, bool is_jtag_patchset,
                                    bool is_glitch_patchset, const Payloads& payloads) {
            return patch_base +
                   (payloads.xell && xell_offset(patch_base, is_jtag_patchset, is_glitch_patchset,
                                                 payloads) == patch_base
                        ? XeLL::kSize
                        : 0);
        }

        bool ranges_overlap(size_t first_offset, size_t first_length, size_t second_offset,
                            size_t second_length) {
            if (first_length == 0 || second_length == 0) {
                return false;
            }
            size_t first_end = 0;
            size_t second_end = 0;
            return !checked_add(first_offset, first_length, first_end) ||
                   !checked_add(second_offset, second_length, second_end) ||
                   (first_offset < second_end && second_offset < first_end);
        }

        template <typename T>
        bool has_parsed_bootloader_header(const T& bootloader, uint16_t expected_magic,
                                          size_t minimum_size) {
            return bootloader.header.header.magic == expected_magic &&
                   bootloader.header.header.size >= minimum_size;
        }

        struct PayloadRange {
            std::string_view name;
            size_t offset;
            size_t length;
        };

        const ParsedPatchSection* find_patch_section(const ParsedPatchSet& patchset,
                                                     PatchSectionTarget target) {
            const auto section = std::find_if(patchset.sections.begin(), patchset.sections.end(),
                                              [target](const ParsedPatchSection& candidate) {
                                                  return candidate.target == target;
                                              });
            return section == patchset.sections.end() ? nullptr : &*section;
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
            Log::Error("Cannot parse NAND image: image size ({} bytes) smaller than NAND header",
                       image_bytes.size());
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

        Log::Debug("Parsed NAND header: magic=0x{:04X}, version=0x{:04X}, entry=0x{:08X}, "
                   "kv_addr=0x{:08X}",
                   header.magic, header.version, header.entrypoint, header.kv_addr);

        const uint32_t smc_size =
            (header.smc_boot_size > 0 && header.smc_boot_size <= kKeyvaultOffset)
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
                Log::Debug("Parsed CB bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else if (magic == 0x5343) {
                cb_section.sc = BootloaderSc::parse(bldr_data);
                Log::Debug("Parsed SC bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else if (magic == 0x4344) {
                kernel_section.cd = BootloaderCd::parse(bldr_data);
                Log::Debug("Parsed CD bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else if (magic == 0x4345) {
                kernel_section.ce = BootloaderCe::parse(bldr_data);
                Log::Debug("Parsed CE bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else {
                break;
            }

            cursor += align_16(bldr_size);
        }

        const bool is_big_or_emmc = (flash_driver.driver_mode() == Driver::DriverMode::Big ||
                                     flash_driver.driver_mode() == Driver::DriverMode::Emmc);
        const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
        const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
        const uint32_t patchslot_base =
            header.cf_offset != 0 && header.cf_offset != 0xFFFFFFFF ? header.cf_offset : patch_base;

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
                        auto cg_hdr_bytes =
                            flash_driver.read_clean(cg_offset, sizeof(generic_header));
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

        parse_patchslot(patchslot_base, system_update_0);
        parse_patchslot(patchslot_base + slot_stride, system_update_1);

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
                    size_t m1_offset =
                        static_cast<size_t>(corona_config->data.wMobile1BlockIdx) * 0x4000;
                    size_t m1_len =
                        static_cast<size_t>(corona_config->data.wMobile1Length) * 0x4000;
                    auto m1_span = std::as_const(flash_driver).read_offset(m1_offset, m1_len);
                    if (!m1_span.empty()) {
                        mob.x31 = std::vector<uint8_t>(m1_span.begin(), m1_span.end());
                    }
                }
                if (corona_config->data.wMobile2Length > 0) {
                    size_t m2_offset =
                        static_cast<size_t>(corona_config->data.wMobile2BlockIdx) * 0x4000;
                    size_t m2_len =
                        static_cast<size_t>(corona_config->data.wMobile2Length) * 0x4000;
                    auto m2_span = std::as_const(flash_driver).read_offset(m2_offset, m2_len);
                    if (!m2_span.empty()) {
                        mob.x32 = std::vector<uint8_t>(m2_span.begin(), m2_span.end());
                    }
                }
                if (!mob.empty()) {
                    mobile_data = std::move(mob);
                }

                if (corona_config->data.wFSBlockIdx != 0) {
                    FlashFileSystem fs{};
                    if (fs.load(flash_driver, corona_config->data.wFSBlockIdx)) {
                        filesystem = std::move(fs);
                    }
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

                const auto& latest =
                    *std::max_element(type_candidates.begin(), type_candidates.end(),
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

        const auto parse_xell_at = [&](size_t offset) -> std::optional<XeLL> {
            if (offset > image_bytes.size() || XeLL::kSize > image_bytes.size() - offset) {
                return std::nullopt;
            }
            auto xell_span = std::as_const(flash_driver).read_offset(offset, XeLL::kSize);
            return xell_span.size() == XeLL::kSize ? XeLL::parse(xell_span) : std::nullopt;
        };

        // BuildType is not serialized. A shifted CF base is the layout evidence that a
        // A shifted CF base declares that patch-base XeLL owns the whole 0x40000-byte interval.
        // On small-block images that interval includes the historical JTAG rebooter/fuse probes,
        // so do not turn its bytes into phantom JTAG payloads. Big-block and eMMC fixed ranges
        // are disjoint and remain independently recoverable. Without either exact XeLL layout
        // marker, arbitrary Glitch KHV bytes at 0x90000 are indistinguishable from a standalone
        // rebooter, so fixed payloads require an exact JTAG XeLL at its historical offset.
        constexpr uint32_t kJtagXellOffset = kJTAGvFusesOffset + 0x60;
        const bool patch_base_xell_layout =
            header.cf_offset == patch_base + static_cast<uint32_t>(XeLL::kSize);
        const bool patch_base_xell_owns_rebooter =
            patch_base_xell_layout &&
            ranges_overlap(patch_base, XeLL::kSize, kJTAGRebooterOffset, 0x1000);
        const bool patch_base_xell_owns_fuses =
            patch_base_xell_layout &&
            ranges_overlap(patch_base, XeLL::kSize, kJTAGvFusesOffset, 0x60);
        const bool patch_base_xell_owns_jtag_xell =
            patch_base_xell_layout && !is_big_or_emmc &&
            ranges_overlap(patch_base, XeLL::kSize, kJtagXellOffset, XeLL::kSize);
        if (patch_base_xell_layout) {
            payloads.xell = parse_xell_at(patch_base);
        }

        if (!payloads.xell && !patch_base_xell_owns_jtag_xell) {
            payloads.xell = parse_xell_at(kJtagXellOffset);
        }

        if (payloads.xell && !patch_base_xell_owns_rebooter) {
            if (kJTAGRebooterOffset + 0x1000 <= image_bytes.size()) {
                auto reb_span =
                    std::as_const(flash_driver).read_offset(kJTAGRebooterOffset, 0x1000);
                if (!reb_span.empty() &&
                    std::any_of(reb_span.begin(), reb_span.end(),
                                [](uint8_t b) { return b != 0x00 && b != 0xFF; })) {
                    payloads.rebooter = std::vector<uint8_t>(reb_span.begin(), reb_span.end());
                }
            }
        }

        if (payloads.xell && !patch_base_xell_owns_fuses) {
            if (kJTAGvFusesOffset + 0x60 <= image_bytes.size()) {
                auto fuse_span = std::as_const(flash_driver).read_offset(kJTAGvFusesOffset, 0x60);
                if (!fuse_span.empty() &&
                    std::any_of(fuse_span.begin(), fuse_span.end(),
                                [](uint8_t b) { return b != 0x00 && b != 0xFF; })) {
                    payloads.fuses = std::vector<uint8_t>(fuse_span.begin(), fuse_span.end());
                }
            }
        }

        return true;
    }

    bool FlashImage::write_to_driver() const {
        if (flash_driver.block_count() == 0) {
            return false;
        }

        if (const auto layout_error = payload_layout_error(); layout_error) {
            Log::Error("{}", *layout_error);
            return false;
        }

        auto& driver = const_cast<Driver&>(flash_driver);

        const bool is_big_or_emmc = (driver.driver_mode() == Driver::DriverMode::Big ||
                                     driver.driver_mode() == Driver::DriverMode::Emmc);
        const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
        const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
        const bool is_glitch_patchset =
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == patch_base + static_cast<uint32_t>(XeLL::kSize));
        const bool is_jtag_patchset =
            payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag;
        const uint32_t patchslot_base =
            system_update_base(patch_base, is_jtag_patchset, is_glitch_patchset, payloads);

        const uint32_t fs_base = is_big_or_emmc ? kBigFsOffset : kSmallFsOffset;
        const size_t total_blocks = driver.block_count();
        const size_t block_size = driver.block_size_clean();
        const size_t data_block_limit = driver.data_block_limit();
        if (data_block_limit == 0) {
            Log::Error("No usable NAND blocks remain below the geometry-reserved tail");
            return false;
        }

        const auto payload_block_ranges = active_payload_block_ranges();

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
        raw.size = bswap32(header.size ? header.size : kEntryOffset);
        std::memcpy(raw.copyright, header.copyright, sizeof(raw.copyright));
        std::memcpy(raw.reserved, header.reserved, sizeof(raw.reserved));
        raw.kv_size = bswap32(header.kv_size ? header.kv_size : Keyvault::kSize);
        raw.cf_offset = bswap32(patchslot_base);
        raw.patch_slots = bswap16(2);
        raw.kv_version = bswap16(header.kv_version ? header.kv_version : 0x0712);
        raw.kv_addr = bswap32(header.kv_addr ? header.kv_addr : kKeyvaultOffset);
        raw.fs_addr = bswap32(header.fs_addr ? header.fs_addr : fs_base);
        raw.smc_config_offset =
            bswap32(header.smc_config_offset ? header.smc_config_offset
                                             : static_cast<uint32_t>(smc_cfg_offset.value_or(0)));
        raw.smc_boot_size = bswap32(static_cast<uint32_t>(smc_len));
        raw.smc_boot_offset = bswap32(smc_offset);

        if (!driver.write_offset(
                0, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&raw), sizeof(raw)))) {
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

        size_t slot0_end = patchslot_base;
        if (!write_patchslot(patchslot_base, system_update_0, slot0_end)) {
            return false;
        }
        if (patchslot_base + slot_stride >= slot0_end) {
            size_t slot1_end = patchslot_base + slot_stride;
            if (!write_patchslot(patchslot_base + slot_stride, system_update_1, slot1_end)) {
                return false;
            }
        } else {
            // CG0 was too large and overflowed into the second slot. The layout validator
            // permits this only when no slot one replacement was supplied.
            raw.patch_slots = bswap16(1);
            if (!driver.write_offset(0, std::span<const uint8_t>(
                                            reinterpret_cast<const uint8_t*>(&raw), sizeof(raw)))) {
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
        const size_t fs_blk_size =
            (driver.driver_mode() == Driver::DriverMode::Emmc) ? 0x4000 : block_size;

        size_t min_blk = (highest_used_offset + fs_blk_size - 1) / fs_blk_size;
        size_t current_blk = std::max<size_t>(fs_base / fs_blk_size, min_blk);

        auto* mutable_filesystem =
            filesystem ? &const_cast<FlashFileSystem&>(*filesystem) : nullptr;
        if (mutable_filesystem) {
            // A donor FlashImage may have been moved since parsing its filesystem.
            // Rebind before checking allocation geometry, not just before saving.
            mutable_filesystem->set_driver(&driver);
        }

        auto find_data_free_run = [&](size_t start_block,
                                      size_t requested_blocks) -> std::optional<size_t> {
            if (requested_blocks == 0 || requested_blocks > data_block_limit ||
                start_block > data_block_limit - requested_blocks) {
                return std::nullopt;
            }
            for (size_t candidate = start_block; candidate <= data_block_limit - requested_blocks;
                 ++candidate) {
                bool all_free = true;
                for (size_t block = candidate; block < candidate + requested_blocks; ++block) {
                    if (driver.is_bad_block(block) ||
                        std::any_of(
                            payload_block_ranges.begin(), payload_block_ranges.end(),
                            [block](const BlockRange& range) { return range.contains(block); }) ||
                        (filesystem && !filesystem->is_block_free(block))) {
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


        // A donor may have a longer mobile allocation than an input overlay. Clear the old
        // mobile metadata before recording the replacement layout so parsing cannot append
        // stale donor blocks to the new mobile data sequence.
        if (driver.driver_mode() != Driver::DriverMode::Emmc) {
            for (size_t block = 0; block < total_blocks; ++block) {
                if (!is_mobile_block_type(driver.interpret_block(block).block_type)) {
                    continue;
                }
                BlockMetadata cleared{};
                cleared.logical_block_id = static_cast<uint16_t>(block);
                cleared.is_bad = driver.is_bad_block(block);
                driver.write_block_metadata(block, cleared);
            }
        }

        if (filesystem && driver.driver_mode() != Driver::DriverMode::Emmc) {
            for (size_t block = 0; block < total_blocks; ++block) {
                const auto old_meta = driver.interpret_block(block);
                if (old_meta.block_type != 0x2C && old_meta.block_type != 0x30) {
                    continue;
                }
                BlockMetadata cleared{};
                cleared.logical_block_id = static_cast<uint16_t>(block);
                cleared.is_bad = old_meta.is_bad;
                driver.write_block_metadata(block, cleared);
            }
        }

        if (mobile_data) {
            for (uint8_t bt = 0x31; bt <= 0x39; ++bt) {
                const auto* slot = mobile_data->get_slot(bt);
                if (slot && *slot && !(*slot)->empty()) {
                    const auto& mdata = **slot;
                    size_t blks_needed = (mdata.size() + fs_blk_size - 1) / fs_blk_size;
                    if (blks_needed == 0) {
                        Log::Error("Mobile data type 0x{:02X} does not fit in NAND", bt);
                        return false;
                    }
                    auto free_start = find_data_free_run(current_blk, blks_needed);
                    if (!free_start) {
                        Log::Error(
                            "Mobile data type 0x{:02X} does not fit below reserved NAND tail", bt);
                        return false;
                    }
                    current_blk = *free_start;
                    for (size_t b = 0; b < blks_needed; ++b) {
                        size_t chunk_off = b * fs_blk_size;
                        size_t chunk_len = std::min(fs_blk_size, mdata.size() - chunk_off);
                        if (!driver.write_block(
                                current_blk + b,
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
            auto root_start = find_data_free_run(current_blk, 1);
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
            cc.data.wMobile1BlockIdx = 0;
            cc.data.wMobile1Length = 0;
            cc.data.wMobile2BlockIdx = 0;
            cc.data.wMobile2Length = 0;
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
            if (!driver.write_offset(
                    xell_offset(patch_base, is_jtag_patchset, is_glitch_patchset, payloads),
                    xell_bytes)) {
                return false;
            }
        }
        const size_t glitch_patch_floor = patch_base + slot_stride + 0x10;
        const size_t glitch_patch_cursor =
            std::max<size_t>(patchslot_base + 2 * slot_stride, highest_used_offset);
        const size_t glitch_patch_offset = std::max<size_t>(
            align_16(static_cast<uint32_t>(glitch_patch_cursor)), glitch_patch_floor);
        if (payloads.patchset) {
            std::vector<uint8_t> patch_bytes;
            size_t patch_offset = 0;
            size_t patch_capacity = 0;
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                patch_bytes = BinaryParser::SerializePatchSet(*payloads.patchset);
                patch_offset = kJTAGPatchesOffset;
                patch_capacity = kJTAGPatchesSize;
            } else {
                const auto* khv = find_patch_section(*payloads.patchset, PatchSectionTarget::Khv);
                if (!khv) {
                    return false;
                }
                patch_bytes = khv->raw_data;
                patch_offset = glitch_patch_offset;
                patch_capacity = slot_stride - 0x10;
            }
            if (patch_bytes.size() > patch_capacity) {
                Log::Error("Patch payload (0x{:X} bytes) exceeds its 0x{:X}-byte region",
                           patch_bytes.size(), patch_capacity);
                return false;
            }
            if (payloads.xell &&
                ranges_overlap(patch_offset, patch_bytes.size(),
                               is_jtag_patchset ? kJTAGvFusesOffset + 0x60
                                                : (is_glitch_patchset || !payloads.rebooter
                                                       ? patch_base
                                                       : kJTAGvFusesOffset + 0x60),
                               payloads.xell->data.size())) {
                Log::Error("Patch payload overlaps the reserved XeLL region");
                return false;
            }
            if (payloads.rebooter &&
                ranges_overlap(patch_offset, patch_bytes.size(), kJTAGRebooterOffset,
                               payloads.rebooter->size())) {
                Log::Error("Patch payload overlaps the reserved rebooter region");
                return false;
            }
            if (payloads.fuses && ranges_overlap(patch_offset, patch_bytes.size(),
                                                 kJTAGvFusesOffset, payloads.fuses->size())) {
                Log::Error("Patch payload overlaps the reserved virtual-fuse region");
                return false;
            }
            if (!patch_bytes.empty() && !driver.write_offset(patch_offset, patch_bytes)) {
                return false;
            }
        }

        return true;
    }

    bool FlashImage::clear_bootloader_chain() {
        if (flash_driver.block_count() == 0) {
            return false;
        }

        size_t boot_chain_end = kEntryOffset;
        bool size_is_valid = true;
        const auto account_for = [&boot_chain_end, &size_is_valid](const auto& bootloader) {
            size_t aligned_size = 0;
            if (!checked_align_16(bootloader.serialize().size(), aligned_size) ||
                !checked_add(boot_chain_end, aligned_size, boot_chain_end)) {
                size_is_valid = false;
            }
        };
        if (has_parsed_bootloader_header(cb_section.cb_or_A, NANDBootloaderMagic::CB,
                                         sizeof(generic_header))) {
            account_for(cb_section.cb_or_A);
        }
        if (cb_section.cb_x) {
            account_for(*cb_section.cb_x);
        }
        if (cb_section.cb_B) {
            account_for(*cb_section.cb_B);
        }
        if (cb_section.sc) {
            account_for(*cb_section.sc);
        }
        if (has_parsed_bootloader_header(kernel_section.cd, NANDBootloaderMagic::CD,
                                         sizeof(cd_header))) {
            account_for(kernel_section.cd);
        }
        if (kernel_section.ce) {
            account_for(*kernel_section.ce);
        }

        if (!size_is_valid) {
            return false;
        }
        const std::vector<uint8_t> cleared_chain(boot_chain_end - kEntryOffset, 0);
        if (!flash_driver.write_offset(kEntryOffset, cleared_chain)) {
            return false;
        }

        const bool is_big_or_emmc = (flash_driver.driver_mode() == Driver::DriverMode::Big ||
                                     flash_driver.driver_mode() == Driver::DriverMode::Emmc);
        const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
        const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
        const uint32_t donor_patchslot_base =
            header.cf_offset != 0 && header.cf_offset != 0xFFFFFFFF ? header.cf_offset : patch_base;
        const auto clear_patchslot = [&](uint32_t base_offset, const SystemUpdate& slot) {
            if (!slot.cf) {
                return true;
            }
            size_t span_size = align_16(static_cast<uint32_t>(slot.cf->serialize().size()));
            if (slot.cg) {
                span_size += align_16(static_cast<uint32_t>(slot.cg->serialize().size()));
            }
            return flash_driver.write_offset(base_offset, std::vector<uint8_t>(span_size, 0));
        };
        return clear_patchslot(donor_patchslot_base, system_update_0) &&
               clear_patchslot(donor_patchslot_base + slot_stride, system_update_1);
    }

    std::vector<BlockRange> FlashImage::active_payload_block_ranges() const {
        std::vector<BlockRange> ranges;
        const bool is_big_or_emmc = (flash_driver.driver_mode() == Driver::DriverMode::Big ||
                                     flash_driver.driver_mode() == Driver::DriverMode::Emmc);
        const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
        const bool is_glitch_patchset =
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == patch_base + static_cast<uint32_t>(XeLL::kSize));
        const bool is_jtag_patchset =
            payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag;
        const auto add_range = [&ranges, this](size_t offset, size_t length) {
            if (const auto range = flash_driver.block_range_for_byte_interval(offset, length)) {
                ranges.push_back(*range);
            }
        };

        if (payloads.rebooter) {
            add_range(kJTAGRebooterOffset, payloads.rebooter->size());
        }
        if (payloads.fuses) {
            add_range(kJTAGvFusesOffset, payloads.fuses->size());
        }
        if (payloads.xell && !payloads.xell->data.empty()) {
            add_range(xell_offset(patch_base, is_jtag_patchset, is_glitch_patchset, payloads),
                      payloads.xell->data.size());
        }
        if (payloads.patchset) {
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                add_range(kJTAGPatchesOffset,
                          BinaryParser::SerializePatchSet(*payloads.patchset).size());
            } else if (const auto* khv =
                           find_patch_section(*payloads.patchset, PatchSectionTarget::Khv)) {
                const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
                const size_t patchslot_base =
                    system_update_base(patch_base, is_jtag_patchset, is_glitch_patchset, payloads);
                const size_t patch_floor = patch_base + slot_stride + 0x10;
                const size_t slot0_end = [&] {
                    if (!system_update_0.cf) {
                        return patchslot_base;
                    }
                    size_t end =
                        patchslot_base +
                        align_16(static_cast<uint32_t>(system_update_0.cf->serialize().size()));
                    if (system_update_0.cg) {
                        end +=
                            align_16(static_cast<uint32_t>(system_update_0.cg->serialize().size()));
                    }
                    return end;
                }();
                size_t patchslot_end = slot0_end;
                if (slot0_end <= patchslot_base + slot_stride && system_update_1.cf) {
                    size_t slot1_end =
                        patchslot_base + slot_stride +
                        align_16(static_cast<uint32_t>(system_update_1.cf->serialize().size()));
                    if (system_update_1.cg) {
                        slot1_end +=
                            align_16(static_cast<uint32_t>(system_update_1.cg->serialize().size()));
                    }
                    patchslot_end = std::max(patchslot_end, slot1_end);
                }
                const size_t cursor = std::max(patchslot_base + 2 * slot_stride, patchslot_end);
                add_range(std::max<size_t>(align_16(static_cast<uint32_t>(cursor)), patch_floor),
                          khv->raw_data.size());
            }
        }
        return ranges;
    }

    std::optional<std::string> FlashImage::payload_layout_error() const {
        const bool is_big_or_emmc = (flash_driver.driver_mode() == Driver::DriverMode::Big ||
                                     flash_driver.driver_mode() == Driver::DriverMode::Emmc);
        const uint32_t patch_base = is_big_or_emmc ? kBigPatchslotOffset : kSmallPatchslotOffset;
        const uint32_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
        const bool is_glitch_patchset =
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == patch_base + static_cast<uint32_t>(XeLL::kSize));
        const bool is_jtag_patchset =
            payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag;
        const uint32_t patchslot_base =
            system_update_base(patch_base, is_jtag_patchset, is_glitch_patchset, payloads);

        const bool has_cb = has_parsed_bootloader_header(
            cb_section.cb_or_A, NANDBootloaderMagic::CB, sizeof(generic_header));
        const bool has_cd = has_parsed_bootloader_header(kernel_section.cd, NANDBootloaderMagic::CD,
                                                         sizeof(cd_header));
        if (has_cb && cb_section.cb_or_A.data.empty()) {
            return "Required CB/A bootloader has no payload and cannot be serialized";
        }
        if (has_cd && kernel_section.cd.data.empty()) {
            return "Required CD bootloader has no payload and cannot be serialized";
        }

        if (system_update_0.cg && !system_update_0.cf) {
            return "System-update CG0 requires a corresponding CF0";
        }
        if (system_update_1.cg && !system_update_1.cf) {
            return "System-update CG1 requires a corresponding CF1";
        }

        std::vector<PayloadRange> ranges;
        std::optional<std::string> arithmetic_error;
        const auto add_range = [&ranges, &arithmetic_error](std::string_view name, size_t offset,
                                                            size_t length) {
            if (length != 0) {
                size_t end = 0;
                if (!checked_add(offset, length, end)) {
                    arithmetic_error = "Payload layout range overflow for " + std::string(name);
                    return;
                }
                ranges.push_back(PayloadRange{name, offset, length});
            }
        };

        // Keep XeLL first so a collision explains that its historically fixed placement is the
        // conflicting writer, rather than implying that the fixed JTAG payload moved.
        if (payloads.xell) {
            add_range("XeLL",
                      xell_offset(patch_base, is_jtag_patchset, is_glitch_patchset, payloads),
                      payloads.xell->data.size());
        }
        if (payloads.rebooter) {
            add_range("rebooter", kJTAGRebooterOffset, payloads.rebooter->size());
        }
        if (payloads.fuses) {
            add_range("virtual-fuse payload", kJTAGvFusesOffset, payloads.fuses->size());
        }

        size_t boot_chain_end = kEntryOffset;
        const auto account_for_bootloader = [&boot_chain_end,
                                             &arithmetic_error](const auto& bootloader) {
            if (arithmetic_error) {
                return;
            }
            size_t aligned_size = 0;
            if (!checked_align_16(bootloader.serialize().size(), aligned_size) ||
                !checked_add(boot_chain_end, aligned_size, boot_chain_end)) {
                arithmetic_error = "Serialized boot chain exceeds the addressable payload layout";
            }
        };
        if (has_cb) {
            account_for_bootloader(cb_section.cb_or_A);
        }
        if (cb_section.cb_x) {
            account_for_bootloader(*cb_section.cb_x);
        }
        if (cb_section.cb_B) {
            account_for_bootloader(*cb_section.cb_B);
        }
        if (cb_section.sc) {
            account_for_bootloader(*cb_section.sc);
        }
        if (has_cd) {
            account_for_bootloader(kernel_section.cd);
        }
        if (kernel_section.ce) {
            account_for_bootloader(*kernel_section.ce);
        }
        if (arithmetic_error) {
            return arithmetic_error;
        }
        add_range("serialized boot chain", kEntryOffset, boot_chain_end - kEntryOffset);
        if (arithmetic_error) {
            return arithmetic_error;
        }

        size_t highest_used_offset = boot_chain_end;

        const auto add_system_update = [&add_range, &highest_used_offset, &arithmetic_error](
                                           std::string_view cf_name, std::string_view cg_name,
                                           size_t base,
                                           const SystemUpdate& slot) -> std::optional<size_t> {
            size_t end = base;
            if (!slot.cf) {
                return end;
            }
            const auto cf_bytes = slot.cf->serialize();
            add_range(cf_name, base, cf_bytes.size());
            size_t aligned_size = 0;
            if (arithmetic_error || !checked_align_16(cf_bytes.size(), aligned_size) ||
                !checked_add(base, aligned_size, end)) {
                arithmetic_error = "System-update CF span exceeds the addressable payload layout";
                return std::nullopt;
            }
            if (slot.cg) {
                const auto cg_bytes = slot.cg->serialize();
                add_range(cg_name, end, cg_bytes.size());
                if (arithmetic_error || !checked_align_16(cg_bytes.size(), aligned_size) ||
                    !checked_add(end, aligned_size, end)) {
                    arithmetic_error =
                        "System-update CG span exceeds the addressable payload layout";
                    return std::nullopt;
                }
            }
            highest_used_offset = std::max(highest_used_offset, end);
            return end;
        };

        const auto slot0_end = add_system_update("system-update CF0", "system-update CG0",
                                                 patchslot_base, system_update_0);
        size_t slot1_base = 0;
        if (!slot0_end || !checked_add(patchslot_base, slot_stride, slot1_base)) {
            return arithmetic_error.value_or(
                "System-update slot base exceeds the addressable payload layout");
        }
        if (*slot0_end > slot1_base && system_update_1.cf) {
            return "System-update CF0/CG0 exceeds its slot stride while CF1/CG1 is supplied";
        }
        if (*slot0_end <= slot1_base) {
            add_system_update("system-update CF1", "system-update CG1", slot1_base,
                              system_update_1);
            if (arithmetic_error) {
                return arithmetic_error;
            }
        }

        if (payloads.patchset) {
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                const auto patch_bytes = BinaryParser::SerializePatchSet(*payloads.patchset);
                add_range("JTAG patch payload", kJTAGPatchesOffset, patch_bytes.size());
            } else if (const auto* khv =
                           find_patch_section(*payloads.patchset, PatchSectionTarget::Khv)) {
                size_t patch_floor = 0;
                size_t second_slot_end = 0;
                size_t patch_cursor_aligned = 0;
                if (!checked_add(patch_base, slot_stride, patch_floor) ||
                    !checked_add(patch_floor, 0x10, patch_floor) ||
                    !checked_add(slot1_base, slot_stride, second_slot_end) ||
                    !checked_align_16(std::max(second_slot_end, highest_used_offset),
                                      patch_cursor_aligned)) {
                    return "Glitch KHV placement exceeds the addressable payload layout";
                }
                const size_t patch_offset = std::max(patch_cursor_aligned, patch_floor);
                add_range("Glitch KHV payload", patch_offset, khv->raw_data.size());
            }
        }

        if (arithmetic_error) {
            return arithmetic_error;
        }

        for (size_t first = 0; first < ranges.size(); ++first) {
            for (size_t second = first + 1; second < ranges.size(); ++second) {
                if (ranges_overlap(ranges[first].offset, ranges[first].length,
                                   ranges[second].offset, ranges[second].length)) {
                    return "Payload layout collision: " + std::string(ranges[first].name) +
                           " overlaps " + std::string(ranges[second].name);
                }
            }
        }
        return std::nullopt;
    }

    std::vector<uint8_t> FlashImage::write() const {
        if (!const_cast<FlashImage*>(this)->write_to_driver()) {
            return {};
        }
        return const_cast<Driver&>(flash_driver).serialize();
    }

    bool FlashImage::decrypt_all(std::span<const uint8_t> cpu_key) {
        try {
            // Use the parser's full plaintext check, not is_decrypted()'s legacy
            // single-byte hint: encrypted CBs can contain that byte by chance.
            if (!cb_section.cb_or_A.data.empty() && !cb_section.cb_or_A.decrypted) {
                cb_section.cb_or_A.decrypt(key_1bl);
            }

            if (cb_section.cb_x && !cb_section.cb_x->data.empty() &&
                !cb_section.cb_x->decrypted) {
                if (!cb_section.cb_or_A.derived_key) {
                    Log::Error("Cannot decrypt CB_X: CB_A derived key is missing");
                    return false;
                }
                const std::array<uint8_t, 16> zero_cpu_key{};
                if ((cb_section.cb_or_A.header.header.flags & 0x1000) != 0) {
                    cb_section.cb_x->decrypt_v2(cb_section.cb_or_A.header,
                                               cb_section.cb_or_A.derived_key->data(),
                                               zero_cpu_key.data());
                } else {
                    cb_section.cb_x->decrypt_v1(cb_section.cb_or_A.derived_key->data(),
                                               zero_cpu_key.data());
                }
            }

            // CB_X loads the real CB_B as plaintext. Its key slot is already the
            // handoff key (as written by RGH2to3), not a nonce to derive again.
            if (cb_section.cb_x && cb_section.cb_B && cb_section.cb_B->data.size() >= 16) {
                cb_section.cb_B->decrypted = true;
                cb_section.cb_B->populate_metadata();
                std::array<uint8_t, 16> key{};
                std::copy_n(cb_section.cb_B->data.begin(), key.size(), key.begin());
                cb_section.cb_B->derived_key = key;
            }

            if (cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
                !cb_section.cb_B->decrypted) {
                if (!cb_section.cb_or_A.derived_key.has_value()) {
                    Log::Error("Cannot decrypt CB_B: CB_A derived key is missing");
                    return false;
                }
                if ((cb_section.cb_or_A.header.header.flags & 0x1000) == 0x1000) {
                    cb_section.cb_B->decrypt_v2(cb_section.cb_or_A.header,
                                                cb_section.cb_or_A.derived_key->data(),
                                                cpu_key.data());
                } else {
                    cb_section.cb_B->decrypt_v1(cb_section.cb_or_A.derived_key->data(),
                                                cpu_key.data());
                }
            }

            if (cb_section.sc.has_value() && !cb_section.sc->data.empty() &&
                !cb_section.sc->is_decrypted() &&
                std::any_of(std::begin(cb_section.sc->header.key),
                            std::end(cb_section.sc->header.key),
                            [](uint8_t byte) { return byte != 0; })) {
                const auto* parent_key = cb_section.cb_B && cb_section.cb_B->derived_key
                                             ? &*cb_section.cb_B->derived_key
                                             : cb_section.cb_or_A.derived_key
                                                   ? &*cb_section.cb_or_A.derived_key
                                                   : nullptr;
                if (!parent_key) {
                    Log::Error("Cannot decrypt SC: parent CB derived key is missing");
                    return false;
                }
                cb_section.sc->decrypt(parent_key->data());
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
            if (system_update_0.cg.has_value() && !system_update_0.cg->is_decrypted()) {
                if (!system_update_0.cf.has_value() || !system_update_0.cf->is_decrypted()) {
                    Log::Error("Cannot decrypt CG0: parent CF0 is missing or not decrypted");
                    return false;
                }
                system_update_0.cg->decrypt(system_update_0.cf->header.cg_key);
            }
            if (system_update_1.cg.has_value() && !system_update_1.cg->is_decrypted()) {
                if (!system_update_1.cf.has_value() || !system_update_1.cf->is_decrypted()) {
                    Log::Error("Cannot decrypt CG1: parent CF1 is missing or not decrypted");
                    return false;
                }
                system_update_1.cg->decrypt(system_update_1.cf->header.cg_key);
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

    bool FlashImage::encrypt_all(std::span<const uint8_t> cpu_key, BuildType build_type) {
        try {
            const bool plaintext_cb_b = build_type == BuildType::Glitch3;
            const bool plaintext_cd = plaintext_cb_b || build_type == BuildType::Glitch2 ||
                                      build_type == BuildType::Glitch2m;
            if (plaintext_cb_b &&
                (!cb_section.cb_x || cb_section.cb_x->data.empty() || !cb_section.cb_B ||
                 !cb_section.cb_B->decrypted)) {
                Log::Error("Glitch3 requires CB_X and a plaintext CB_B");
                return false;
            }
            if (plaintext_cd && !kernel_section.cd.is_decrypted()) {
                Log::Error("Glitch2/3 requires a plaintext CD input");
                return false;
            }
            const bool cd_requires_cpu_key =
                !cb_section.cb_B.has_value() && cb_section.cb_or_A.requires_cpu_key_for_cd();

            if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted() &&
                cd_requires_cpu_key && cpu_key.size() < 16) {
                Log::Error("Cannot encrypt CD: single-CB chain requires a CPU key");
                return false;
            }

            if (!cb_section.cb_or_A.data.empty() && cb_section.cb_or_A.decrypted) {
                cb_section.cb_or_A.encrypt(key_1bl);
            }

            if (plaintext_cb_b && cb_section.cb_x->decrypted) {
                if (!cb_section.cb_or_A.derived_key) {
                    Log::Error("Cannot encrypt CB_X: CB_A derived key is missing");
                    return false;
                }
                const std::array<uint8_t, 16> zero_cpu_key{};
                if ((cb_section.cb_or_A.header.header.flags & 0x1000) != 0) {
                    cb_section.cb_x->encrypt_v2(cb_section.cb_or_A.header,
                                               cb_section.cb_or_A.derived_key->data(),
                                               zero_cpu_key.data());
                } else {
                    cb_section.cb_x->encrypt_v1(cb_section.cb_or_A.derived_key->data(),
                                               zero_cpu_key.data());
                }
            }

            if (plaintext_cb_b && cb_section.cb_B->derived_key) {
                // An encrypted replacement CB_B may have been decrypted for metadata.
                // Preserve its derived handoff key when emitting it in plaintext.
                std::copy(cb_section.cb_B->derived_key->begin(), cb_section.cb_B->derived_key->end(),
                          cb_section.cb_B->data.begin());
            }

            if (!plaintext_cb_b && cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
                cb_section.cb_B->decrypted) {
                if (!cb_section.cb_or_A.derived_key.has_value()) {
                    Log::Error("Cannot encrypt CB_B: CB_A derived key is missing");
                    return false;
                }
                if ((cb_section.cb_or_A.header.header.flags & 0x1000) == 0x1000) {
                    cb_section.cb_B->encrypt_v2(cb_section.cb_or_A.header,
                                                cb_section.cb_or_A.derived_key->data(),
                                                cpu_key.data());
                } else {
                    cb_section.cb_B->encrypt_v1(cb_section.cb_or_A.derived_key->data(),
                                                cpu_key.data());
                }
            }

            if (!plaintext_cd && !kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted()) {
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
