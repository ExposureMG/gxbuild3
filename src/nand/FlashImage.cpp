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

namespace gxbuild3::nand {

    namespace {

        constexpr uint32_t kKeyvaultOffset = 0x4000;
        constexpr uint32_t kEntryOffset = 0x8000;
        // XeLL sits at 0x70000 on every shape and is 0x40000 long. The slots follow it, rounded
        // up by the shape's erase block, or follow the chain when there is no XeLL.
        constexpr uint32_t kXellOffset = 0x70000;
        // A JTAG image is laid out by the loader it carries, whose neighbours sit at addresses
        // compiled into it: the slot pair at 0x70000 and 0x80000 on every shape, the core at
        // 0x90000.
        constexpr uint32_t kJtagSlotOffset = 0x70000;
        constexpr uint32_t kJtagWindowOffset = 0x90000;
        constexpr uint32_t kDevglSlotOffset = 0xD0000;
        constexpr uint32_t kSmallFsOffset = 0x10000;
        constexpr uint32_t kBigFsOffset = 0x20000;

        // Everything in the JTAG window is counted from kJtagWindowOffset.
        constexpr uint32_t kJTAGPatchesSize = 0x4000;

        // xeBuild lays a built image in 16 KiB blocks on erased flash: the block holding the
        // end of the boot chain is programmed zero past it, and every byte nothing lays stays
        // erased.
        constexpr size_t kLayBlockSize = 0x4000;

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

        // The step the update slots round up by: the erase block of the shape, never under
        // 0x10000. Big block is the 0x20000 of Jasper's chip.
        inline uint32_t slot_round(Driver::DriverMode mode) {
            return mode == Driver::DriverMode::Big ? 0x20000 : 0x10000;
        }

        inline uint32_t round_up(uint32_t value, uint32_t step) {
            return (value + step - 1) / step * step;
        }

        // Where a retail image's first update slot sits: the end of the chain rounded up by
        // slot_round(). A retail chain ends at 0x6CB20, which makes it 0x70000, and 0x80000
        // on big block.
        inline uint32_t retail_slot_offset(Driver::DriverMode mode) {
            return mode == Driver::DriverMode::Big ? 0x80000 : 0x70000;
        }

        // Where the first update slot sits behind XeLL: 0xB0000, or 0xC0000 on big block.
        inline uint32_t glitch_slot_offset(Driver::DriverMode mode) {
            return round_up(kXellOffset + static_cast<uint32_t>(XeLL::kSize), slot_round(mode));
        }

        // How many CG tails (sysupdate.xexpN) open the directory.
        size_t leading_cg_tails(const FlashFileSystem& filesystem) {
            const auto& entries = filesystem.entries();
            const auto first_other =
                std::find_if(entries.begin(), entries.end(), [](const FlashFileSystemEntry& entry) {
                    const std::string_view name(entry.filename,
                                                strnlen(entry.filename, kMaxFilenameLength));
                    return !name.starts_with("sysupdate.xexp");
                });
            return static_cast<size_t>(first_other - entries.begin());
        }

        bool is_jtag_image(const FlashImage& image) {
            return image.build_type == BuildType::Jtag ||
                   (image.payloads.patchset && image.payloads.patchset->kind == PatchSetKind::Jtag);
        }

        struct JtagExtraOffsets {
            size_t cb;
            size_t cd;
        };

        // The JTAG second CB/CD sit in the window tail, directly past the fixed-size XeLL, with
        // the CD following a 16-byte-aligned CB.
        JtagExtraOffsets jtag_extra_offsets(uint32_t window_base, const Payloads& payloads) {
            const size_t cb = window_base + 0x5060 + XeLL::kSize;
            if (!payloads.extra_cb) {
                return {cb, cb};
            }
            return {cb,
                    cb + align_16(static_cast<uint32_t>(payloads.extra_cb->serialize().size()))};
        }

        uint32_t xell_offset(bool is_jtag_patchset, bool is_glitch_patchset,
                             const Payloads& payloads) {
            if (is_jtag_patchset) {
                return kJtagWindowOffset + 0x5060;
            }
            return is_glitch_patchset
                       ? kXellOffset
                       : (!payloads.rebooter ? kXellOffset : kJtagWindowOffset + 0x5060);
        }

        uint32_t system_update_base(uint32_t slot_base, uint32_t round, bool is_jtag_patchset,
                                    bool is_glitch_patchset, const Payloads& payloads) {
            if (!payloads.xell) {
                return slot_base;
            }
            const uint32_t offset = xell_offset(is_jtag_patchset, is_glitch_patchset, payloads);
            return offset <= slot_base
                       ? std::max<uint32_t>(
                             slot_base,
                             round_up(offset + static_cast<uint32_t>(XeLL::kSize), round))
                       : slot_base;
        }

        uint32_t slot_size(const FlashImage& image) {
            if (image.preserve_layout)
                return image.header.fs_addr && image.header.fs_addr != 0xFFFFFFFF
                           ? image.header.fs_addr
                           : 0x10000;
            if (is_jtag_image(image)) {
                return 0x10000;
            }
            return image.flash_driver.driver_mode() == Driver::Big ? 0x20000 : 0x10000;
        }
        // Where the serialized boot chain ends, counted from kEntryOffset.
        size_t boot_chain_end(const FlashImage& image) {
            size_t end = kEntryOffset;
            const auto add = [&end](const auto& bootloader) {
                end += align_16(static_cast<uint32_t>(bootloader.serialize().size()));
            };
            if (!image.cb_section.cb_or_A.data.empty())
                add(image.cb_section.cb_or_A);
            if (image.cb_section.cb_x)
                add(*image.cb_section.cb_x);
            if (image.cb_section.cb_B)
                add(*image.cb_section.cb_B);
            if (image.cb_section.sc)
                add(*image.cb_section.sc);
            if (!image.kernel_section.cd.data.empty())
                add(image.kernel_section.cd);
            if (image.kernel_section.ce)
                add(*image.kernel_section.ce);
            return end;
        }

        uint32_t update_base(const FlashImage& image, bool jtag, bool glitch) {
            if (image.preserve_layout && image.header.cf_offset &&
                image.header.cf_offset != 0xFFFFFFFF)
                return image.header.cf_offset;
            // A devkit image's first slot follows its chain at the next erase block: 0xD4000
            // behind the 17489 chain on small block, 0xE0000 on big block (xeBuild 1.21).
            if (image.build_type == BuildType::Devkit) {
                return round_up(static_cast<uint32_t>(boot_chain_end(image)),
                                static_cast<uint32_t>(image.flash_driver.block_size_clean()));
            }
            const auto mode = image.flash_driver.driver_mode();
            // A devgl image states its first slot at 0xD0000, rounded up by the shape's slot
            // step, inside the SE that runs past it, and lays its fuses and KHV patches one
            // stride on (xeBuild 1.21 devgl: 0xD0000 on Jasper and Corona 4 GB, 0xE0000 on big
            // block).
            if (image.build_type == BuildType::Devgl) {
                return round_up(kDevglSlotOffset, slot_round(mode));
            }
            const uint32_t slot_base = jtag ? kJtagSlotOffset : retail_slot_offset(mode);
            return system_update_base(slot_base, slot_round(mode), jtag, glitch, image.payloads);
        }

        bool manufacturing(const FlashImage& image) {
            return image.build_type == BuildType::Glitch2m ||
                   image.build_type == BuildType::Devgl ||
                   (image.payloads.patchset && image.payloads.patchset->manufacturing);
        }
        size_t khv_prefix(const FlashImage& image) {
            return manufacturing(image) ? 0x60 : 0x10;
        }
        uint32_t fuse_offset(const FlashImage& image, uint32_t update_base, uint32_t stride,
                             uint32_t window_base) {
            return manufacturing(image) ? update_base + stride : window_base + 0x5000;
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

        // A devkit chain holds its SB and SD where a retail chain holds its CB and CD.
        uint16_t devkit_magic(uint16_t magic) {
            switch (magic) {
                case NANDBootloaderMagic::CB:
                    return NANDBootloaderMagic::SB;
                case NANDBootloaderMagic::CD:
                    return NANDBootloaderMagic::SD;
                default:
                    return magic;
            }
        }

        template <typename T>
        bool has_parsed_bootloader_header(const T& bootloader, uint16_t expected_magic,
                                          size_t minimum_size) {
            return (bootloader.header.header.magic == expected_magic ||
                    bootloader.header.header.magic == devkit_magic(expected_magic)) &&
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

        // The settings block is 0x400 bytes laid in a 0x1000 span, the rest 0xFF. Its head holds
        // the one's complement of the byte sum over [0x10, 0x10C), little-endian. Checked
        // against the settings blocks of real small-block and big-block dumps.
        constexpr size_t kSmcConfigLength = 0x400;
        // The settings, statistics and manufacturing blocks are each laid in 0x1000 bytes at
        // the head of their erase block; the rest of that block stays erased.
        constexpr size_t kSettingsSpan = 0x1000;

        bool smc_config_sums(std::span<const uint8_t> block) {
            if (block.size() < kSmcConfigLength) {
                return false;
            }
            uint32_t sum = 0;
            for (size_t i = 0x10; i < 0x10C; ++i) {
                sum += block[i];
            }
            const uint16_t expected = static_cast<uint16_t>(~sum);
            return (block[0] | (block[1] << 8)) == expected;
        }

        // Lays one of the console's 0x1000-byte blocks (settings, statistics, manufacturing) at
        // the head of its erase block, as xeBuild does: the erase block is erased, the bytes
        // go in and their pages carry a type-0 spare naming the block. A block of all 0xFF
        // stays erased, as on a console that keeps none. A bad block keeps its spare.
        bool lay_settings_block(Driver& driver, size_t offset, std::span<const uint8_t> bytes) {
            const size_t block_size = driver.block_size_clean();
            const size_t block = offset / block_size;
            const bool bad = driver.is_bad_block(block);
            if (!bad) {
                driver.erase_block(block);
            }
            if (std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0xFF; })) {
                return true;
            }
            if (!driver.write_offset(offset, bytes)) {
                return false;
            }
            if (!bad && driver.driver_mode() != Driver::DriverMode::Emmc) {
                BlockMetadata meta{};
                meta.logical_block_id = static_cast<uint16_t>(block);
                driver.write_page_metadata(offset / 512, (bytes.size() + 511) / 512, meta);
            }
            return true;
        }

        // Where the settings block sits: the last block before the reserved tail, which is
        // 0xF7C000 on a 16 MB image, 0x3DFC000 on a 64 MB small-block devkit image, 0x3BE0000
        // on big block and 0x2FFC000 on eMMC. The statistics and manufacturing blocks lie one
        // and two erase blocks below it.
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
                    reserve_block = total_blocks > 0x400 ? total_blocks - total_blocks / 32 : 0x3E0;
                    break;
            }

            reserve_block = std::min(reserve_block, total_blocks);
            if (reserve_block < 4) {
                return std::nullopt;
            }
            return (reserve_block - 1) * driver.block_size_clean();
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

        preserve_layout = true;
        header.magic = bswap16(raw.magic);
        header.version = bswap16(raw.version);
        header.pairing = bswap16(raw.pairing);
        header.flags = bswap16(raw.flags);
        header.entrypoint = bswap32(raw.entrypoint);
        header.size = bswap32(raw.size);
        std::memcpy(header.copyright, raw.copyright, sizeof(header.copyright));
        header.hack_flags = bswap32(raw.hack_flags);
        header.boot_flags = bswap32(raw.boot_flags);
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

            // A stage is sealed through its 16-byte rounding, so it is read with it: the
            // rounding then opens back to the zeros it was sealed from.
            auto bldr_data = flash_driver.read_clean(cursor, align_16(bldr_size));

            if (magic == NANDBootloaderMagic::SB && cb_section.cb_or_A.data.empty()) {
                cb_section.cb_or_A = BootloaderCb::parse(bldr_data);
                Log::Debug("Parsed SB bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else if (magic == NANDBootloaderMagic::SD) {
                kernel_section.cd = BootloaderCd::parse(bldr_data);
                Log::Debug("Parsed SD bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else if (magic == NANDBootloaderMagic::SE) {
                kernel_section.ce = BootloaderCe::parse(bldr_data);
                Log::Debug("Parsed SE bootloader at offset 0x{:X} (version {}, size 0x{:X})",
                           cursor, version, bldr_size);
            } else if (magic == 0x4342) {
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

        const auto slot_mode = flash_driver.driver_mode();
        const uint32_t slot_stride =
            header.fs_addr && header.fs_addr != 0xFFFFFFFF ? header.fs_addr : 0x10000;
        const uint32_t patchslot_base = header.cf_offset != 0 && header.cf_offset != 0xFFFFFFFF
                                            ? header.cf_offset
                                            : retail_slot_offset(slot_mode);

        bool invalid_continuation = false;
        auto parse_patchslot = [&](uint32_t base_offset, SystemUpdate& slot) {
            slot = SystemUpdate{};
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
                                    const size_t prefix = std::min<size_t>(
                                        cg_size, base_offset + slot_stride > cg_offset
                                                     ? base_offset + slot_stride - cg_offset
                                                     : 0);
                                    if (prefix < cg_size) {
                                        auto decoded_cf = *slot.cf;
                                        decoded_cf.decrypt(key_1bl);
                                        const auto& table = decoded_cf.data;
                                        const size_t count =
                                            table.size() >= 2 ? (size_t(table[0]) << 8) | table[1]
                                                              : 0;
                                        const size_t needed = (cg_size - prefix + 0x3FFF) / 0x4000;
                                        if (count > 0 && count <= 223 && count != needed) {
                                            invalid_continuation = true;
                                            return;
                                        }
                                        if (count == needed && count <= 223 &&
                                            table.size() >= 2 + count * 2) {
                                            cg_data = flash_driver.read_clean(cg_offset, prefix);
                                            for (size_t i = 0; i < count; ++i) {
                                                const uint16_t block =
                                                    (uint16_t(table[2 + i * 2]) << 8) |
                                                    table[3 + i * 2];
                                                if (size_t(block) * 0x4000 >=
                                                        flash_driver.data_block_limit() *
                                                            flash_driver.block_size_clean() ||
                                                    std::find(slot.cg_spill_blocks.begin(),
                                                              slot.cg_spill_blocks.end(), block) !=
                                                        slot.cg_spill_blocks.end()) {
                                                    invalid_continuation = true;
                                                    return;
                                                }
                                                const size_t length = std::min<size_t>(
                                                    0x4000, cg_size - cg_data.size());
                                                auto part = flash_driver.read_clean(
                                                    size_t(block) * 0x4000, length);
                                                if (part.size() != length) {
                                                    invalid_continuation = true;
                                                    return;
                                                }
                                                cg_data.insert(cg_data.end(), part.begin(),
                                                               part.end());
                                                slot.cg_spill_blocks.push_back(block);
                                            }
                                        }
                                    }
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
        if (invalid_continuation)
            return false;

        std::vector<uint8_t> inferred_khv;
        const auto valid_khv_at = [&](size_t offset, size_t prefix) {
            const auto bytes =
                flash_driver.read_clean(offset, slot_stride > prefix ? slot_stride - prefix : 0);
            size_t cursor = 0, records = 0;
            const auto word = [&](size_t at) {
                return (uint32_t(bytes[at]) << 24) | (uint32_t(bytes[at + 1]) << 16) |
                       (uint32_t(bytes[at + 2]) << 8) | bytes[at + 3];
            };
            while (cursor + 4 <= bytes.size()) {
                const uint32_t address = word(cursor);
                cursor += 4;
                if (address == 0xFFFFFFFF) {
                    if (records)
                        inferred_khv.assign(bytes.begin(), bytes.begin() + cursor);
                    return records != 0;
                }
                if ((address & 3) || cursor + 4 > bytes.size())
                    return false;
                const uint32_t count = word(cursor);
                cursor += 4;
                if (!count || count > (bytes.size() - cursor) / 4)
                    return false;
                cursor += size_t(count) * 4;
                ++records;
            }
            return false;
        };
        const size_t overlay = size_t(patchslot_base) + slot_stride;
        // A development chain names its type: devkit when the header states 0x8000 at 0x04,
        // as a devkit image does, or the second slot holds no glitch2m fuses and KHV patches;
        // devgl otherwise.
        if (devkit_chain()) {
            build_type = header.pairing != 0x8000 && valid_khv_at(overlay + 0x60, 0x60)
                             ? BuildType::Devgl
                             : BuildType::Devkit;
        } else if (valid_khv_at(overlay + 0x10, 0x10)) {
            build_type = BuildType::Glitch2;
        } else if (valid_khv_at(overlay + 0x60, 0x60)) {
            build_type = BuildType::Glitch2m;
        }

        const size_t total_blocks = flash_driver.block_count();
        const size_t block_size = flash_driver.block_size_clean();

        if (auto cfg_offset = smc_config_offset(flash_driver)) {
            auto cfg_bytes = std::as_const(flash_driver).read_offset(*cfg_offset, kSmcConfigLength);
            if (cfg_bytes.size() == kSmcConfigLength && smc_config_sums(cfg_bytes)) {
                smc_config = std::vector<uint8_t>(cfg_bytes.begin(), cfg_bytes.end());
            }
            if (*cfg_offset >= 2 * block_size) {
                auto stats = flash_driver.read_clean(*cfg_offset - block_size, kSettingsSpan);
                if (stats.size() == kSettingsSpan) {
                    statistics = std::move(stats);
                }
                auto manu = flash_driver.read_clean(*cfg_offset - 2 * block_size, kSettingsSpan);
                if (manu.size() == kSettingsSpan) {
                    manufacturing = std::move(manu);
                }
            }
        }

        if (flash_driver.driver_mode() == Driver::DriverMode::Emmc) {
            // An eMMC has no spare bytes to scan, so two anchor blocks at fixed offsets say
            // where the settings blobs and the filesystem table went.
            const auto& readable = std::as_const(flash_driver);
            const auto first = readable.read_offset(CoronaConfig::kOffsets[0], CoronaConfig::kSize);
            const auto second =
                readable.read_offset(CoronaConfig::kOffsets[1], CoronaConfig::kSize);
            corona_config = CoronaConfig::choose(
                {std::span<const uint8_t>(first), std::span<const uint8_t>(second)});

            if (corona_config) {
                MobileData mob{};
                for (size_t slot = 0; slot < CoronaConfig::kBlobSlots; ++slot) {
                    const auto& blob = corona_config->blobs[slot];
                    if (blob.length == 0) {
                        continue;
                    }
                    auto bytes =
                        readable.read_offset(static_cast<size_t>(blob.block) * 0x4000, blob.length);
                    auto* target =
                        mob.get_slot(static_cast<uint8_t>(CoronaConfig::kFirstBlobType + slot));
                    if (target && bytes.size() == blob.length) {
                        *target = std::vector<uint8_t>(bytes.begin(), bytes.end());
                    }
                }
                if (!mob.empty()) {
                    mobile_data = std::move(mob);
                }

                if (corona_config->table != 0) {
                    FlashFileSystem fs{};
                    if (fs.load(flash_driver, corona_config->table)) {
                        filesystem = std::move(fs);
                    }
                }
            }
        } else {
            // Each blob copy fills consecutive pages that share its type, version and free
            // count, and only those pages carry its spare. A console appends a new copy
            // after the last one in the same block, so the free count falls with each copy,
            // and opens another block under a higher version when one fills. The live copy
            // is therefore the one with the highest version and, within it, the lowest free
            // count; a tie goes to the later copy.
            struct MobileCopy {
                bool found = false;
                uint32_t sequence = 0;
                uint8_t free_count = 0;
                size_t first_page = 0;
                size_t page_count = 0;
                uint16_t length = 0;
            };
            std::array<MobileCopy, 9> latest{};
            const size_t pages_per_block = flash_driver.pages_per_block();
            for (size_t blk = 0; blk < total_blocks; ++blk) {
                if (flash_driver.is_bad_block(blk)) {
                    continue;
                }
                for (size_t page = blk * pages_per_block; page < (blk + 1) * pages_per_block;
                     ++page) {
                    const auto meta = flash_driver.interpret_page(page);
                    if (!is_mobile_block_type(meta.block_type)) {
                        continue;
                    }
                    auto& copy = latest[meta.block_type - 0x31];
                    if (copy.found && copy.sequence == meta.sequence &&
                        copy.free_count == meta.page_count &&
                        copy.first_page + copy.page_count == page) {
                        ++copy.page_count;
                        continue;
                    }
                    if (!copy.found || meta.sequence > copy.sequence ||
                        (meta.sequence == copy.sequence && meta.page_count <= copy.free_count)) {
                        copy =
                            MobileCopy{true, meta.sequence, meta.page_count, page, 1, meta.fs_size};
                    }
                }
            }

            MobileData mob{};
            for (size_t type_idx = 0; type_idx < latest.size(); ++type_idx) {
                const auto& copy = latest[type_idx];
                if (!copy.found) {
                    continue;
                }
                // The spare states the length in bytes; a copy cannot run past its block.
                const size_t room = (pages_per_block - copy.first_page % pages_per_block) * 512;
                const size_t length =
                    std::min<size_t>(copy.length != 0 ? copy.length : copy.page_count * 512, room);
                auto data = flash_driver.read_clean(copy.first_page * 512, length);
                auto* slot = mob.get_slot(static_cast<uint8_t>(type_idx + 0x31));
                if (slot && data.size() == length) {
                    *slot = std::move(data);
                }
            }
            if (!mob.empty()) {
                mobile_data = std::move(mob);
            }

            std::optional<size_t> best_root;
            uint32_t best_seq = 0;
            const size_t clusters_per_block = flash_driver.block_size_clean() / 0x4000;
            for (size_t blk = 0; blk < total_blocks * clusters_per_block; ++blk) {
                auto meta = flash_driver.interpret_cluster(blk);
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
                fs.set_larger_filesystem(build_type == BuildType::Devkit);
                if (fs.load(flash_driver, static_cast<uint16_t>(*best_root / clusters_per_block),
                            *best_root % clusters_per_block)) {
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

        if (!inferred_khv.empty()) {
            if (build_type != BuildType::Glitch2m && build_type != BuildType::Devgl)
                build_type = cb_section.cb_x   ? BuildType::Glitch3
                             : cb_section.cb_B ? BuildType::Glitch2
                                               : BuildType::Glitch;
            // The NAND contains already-patched CB/CD. Rebuild with empty bootloader
            // sections and the recovered runtime stream, avoiding double application.
            std::vector<uint8_t> automatic(8, 0xFF);
            automatic.insert(automatic.end(), inferred_khv.begin(), inferred_khv.end());
            ParsedPatchSet recovered;
            if (BinaryParser::ParsePatchSet(automatic, *build_type, recovered))
                payloads.patchset = std::move(recovered);
        }
        const uint32_t window_base = kJtagWindowOffset;
        payloads.xell = devkit_chain() ? std::nullopt : parse_xell_at(kXellOffset);
        if (payloads.xell) {
            if (!build_type)
                build_type = BuildType::Glitch2;
        } else if (!build_type && header.cf_offset != glitch_slot_offset(slot_mode)) {
            payloads.xell = parse_xell_at(window_base + 0x5060);
            if (payloads.xell && !build_type)
                build_type = BuildType::Jtag;
        }
        const auto nonempty = [](const auto& bytes) {
            return std::any_of(bytes.begin(), bytes.end(),
                               [](uint8_t b) { return b != 0 && b != 0xFF; });
        };
        if (build_type == BuildType::Glitch2m || build_type == BuildType::Devgl) {
            auto bytes = flash_driver.read_clean(overlay, 0x60);
            if (bytes.size() == 0x60)
                payloads.fuses = std::move(bytes);
        } else if (build_type == BuildType::Jtag) {
            auto rebooter = flash_driver.read_clean(window_base, 0x1000);
            if (rebooter.size() == 0x1000 && nonempty(rebooter))
                payloads.rebooter = std::move(rebooter);
            auto fuses = flash_driver.read_clean(window_base + 0x5000, 0x60);
            if (fuses.size() == 0x60 && nonempty(fuses))
                payloads.fuses = std::move(fuses);
        }

        return true;
    }

    bool FlashImage::devkit_chain() const {
        return cb_section.cb_or_A.header.header.magic == NANDBootloaderMagic::SB;
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

        // A built image starts from erased flash, so whatever this writer does not lay (an
        // unused update slot, free filesystem blocks, the remap pool, a donor's old data)
        // stays erased: 0xFF data and, on NAND, an erased spare. A bad block keeps its marker.
        // A parsed dump written back keeps its bytes.
        if (!preserve_layout) {
            for (size_t block = 0; block < driver.block_count(); ++block) {
                if (!driver.is_bad_block(block)) {
                    driver.erase_block(block);
                }
            }
        }

        const bool is_big_or_emmc = (driver.driver_mode() == Driver::DriverMode::Big ||
                                     driver.driver_mode() == Driver::DriverMode::Emmc);
        const auto slot_mode = driver.driver_mode();
        const uint32_t slot_stride = slot_size(*this);
        const bool is_glitch_patchset =
            (build_type &&
             (*build_type == BuildType::Glitch || *build_type == BuildType::Glitch2 ||
              *build_type == BuildType::Glitch2m || *build_type == BuildType::Glitch3)) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == glitch_slot_offset(slot_mode));
        const bool is_jtag_patchset =
            (build_type == BuildType::Jtag) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag);
        const uint32_t patchslot_base = update_base(*this, is_jtag_patchset, is_glitch_patchset);
        const uint32_t window_base = kJtagWindowOffset;

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
        // The legacy bootloader-chain scanner used by tools such as J-Runner
        // advances from the NAND header using this size.  It must therefore
        // terminate at the first system-update slot, not retain a donor image's
        // earlier boot-chain boundary.
        raw.size = bswap32(patchslot_base);
        std::memcpy(raw.copyright, header.copyright, sizeof(raw.copyright));
        raw.hack_flags = bswap32(header.hack_flags);
        raw.boot_flags = bswap32(header.boot_flags);
        std::memcpy(raw.reserved, header.reserved, sizeof(raw.reserved));
        raw.kv_size = bswap32(header.kv_size ? header.kv_size : Keyvault::kSize);
        raw.cf_offset = bswap32(patchslot_base);
        // Two update slots on every image, as xeBuild states them. On a glitch image the
        // second is the KHV patch slot, which the kernel passes over for want of a CF.
        raw.patch_slots = bswap16(2);
        raw.kv_version = bswap16(header.kv_version ? header.kv_version : 0x0712);
        raw.kv_addr = bswap32(header.kv_addr ? header.kv_addr : kKeyvaultOffset);
        raw.fs_addr = bswap32(slot_stride); // Runtime dwSysUpdateSlotSize (header + 0x70).
        // Zero on every image, a donor's value or not: xeBuild never states the settings
        // block here (xerunner build.py `header`), and the three console dumps measured
        // carry zero. The block is found by its place in the layout instead.
        raw.smc_config_offset = 0;
        raw.smc_boot_size = bswap32(static_cast<uint32_t>(smc_len));
        raw.smc_boot_offset = bswap32(smc_offset);

        if (!driver.write_offset(
                0, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&raw), sizeof(raw)))) {
            return false;
        }
        // On a built image the header block is programmed zero from the header to the SMC.
        if (!preserve_layout &&
            !driver.write_offset(sizeof(raw), std::vector<uint8_t>(smc_offset - sizeof(raw), 0))) {
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
        if (!preserve_layout) {
            const size_t block_end = (cursor + kLayBlockSize - 1) / kLayBlockSize * kLayBlockSize;
            if (!driver.write_offset(cursor, std::vector<uint8_t>(block_end - cursor, 0))) {
                return false;
            }
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
                    if (end_offset > base_offset + slot_stride)
                        return false;
                    const size_t prefix =
                        slot.cg_spill_blocks.empty()
                            ? cg_bytes.size()
                            : std::min<size_t>(cg_bytes.size(),
                                               base_offset + slot_stride - end_offset);
                    if (end_offset + prefix > base_offset + slot_stride) {
                        Log::Error("CG continuation has not been allocated before serialization");
                        return false;
                    }
                    if (!driver.write_offset(end_offset, std::span(cg_bytes).first(prefix)))
                        return false;
                    size_t consumed = prefix;
                    for (uint16_t block : slot.cg_spill_blocks) {
                        const size_t count = std::min<size_t>(0x4000, cg_bytes.size() - consumed);
                        if (!driver.write_offset(size_t(block) * 0x4000,
                                                 std::span(cg_bytes).subspan(consumed, count)))
                            return false;
                        consumed += count;
                    }
                    if (consumed != cg_bytes.size())
                        return false;
                    end_offset += align_16(static_cast<uint32_t>(prefix));
                }
                highest_used_offset = std::max(highest_used_offset, end_offset);
            }
            return true;
        };

        // A CG longer than its slot continues in spill blocks, so each slot ends within its
        // own stride.
        size_t slot0_end = patchslot_base;
        if (!write_patchslot(patchslot_base, system_update_0, slot0_end)) {
            return false;
        }
        size_t slot1_end = patchslot_base + slot_stride;
        if (!write_patchslot(patchslot_base + slot_stride, system_update_1, slot1_end)) {
            return false;
        }

        if (smc_config) {
            if (!smc_cfg_offset) {
                return false;
            }
            if (smc_config->size() != kSmcConfigLength || !smc_config_sums(*smc_config)) {
                Log::Error("SMC config block is not 0x{:X} bytes with a sound checksum",
                           kSmcConfigLength);
                return false;
            }
            std::vector<uint8_t> cfg_bytes(kSettingsSpan, 0xFF);
            std::copy(smc_config->begin(), smc_config->end(), cfg_bytes.begin());
            if (!lay_settings_block(driver, *smc_cfg_offset, cfg_bytes)) {
                return false;
            }
        }
        const std::array<std::pair<const std::optional<std::vector<uint8_t>>*, size_t>, 2>
            console_blocks{{{&statistics, 1}, {&manufacturing, 2}}};
        for (const auto& [bytes, steps] : console_blocks) {
            if (!*bytes) {
                continue;
            }
            if (!smc_cfg_offset || *smc_cfg_offset < steps * block_size) {
                return false;
            }
            if ((*bytes)->size() != kSettingsSpan) {
                Log::Error("Statistics and manufacturing blocks must be 0x{:X} bytes",
                           kSettingsSpan);
                return false;
            }
            if (!lay_settings_block(driver, *smc_cfg_offset - steps * block_size, **bytes)) {
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

        // Every older blob copy goes: a donor's mobile blocks are erased before the blobs are
        // laid again, so no stale copy can outrank or trail the new ones.
        if (driver.driver_mode() != Driver::DriverMode::Emmc) {
            for (size_t block = 0; block < total_blocks; ++block) {
                if (!is_mobile_block_type(driver.interpret_block(block).block_type)) {
                    continue;
                }
                if (driver.is_bad_block(block)) {
                    BlockMetadata cleared{};
                    cleared.logical_block_id = static_cast<uint16_t>(block);
                    cleared.is_bad = true;
                    driver.write_block_metadata(block, cleared);
                    continue;
                }
                driver.erase_block(block);
            }
        }

        if (filesystem && driver.driver_mode() != Driver::DriverMode::Emmc) {
            const size_t ratio = driver.block_size_clean() / 0x4000;
            for (size_t cluster = 0; cluster < total_blocks * ratio; ++cluster) {
                const auto old_meta = driver.interpret_cluster(cluster);
                if (old_meta.block_type != 0x2C && old_meta.block_type != 0x30) {
                    continue;
                }
                BlockMetadata cleared{};
                cleared.logical_block_id = static_cast<uint16_t>(cluster / ratio);
                cleared.is_bad = old_meta.is_bad;
                driver.write_cluster_metadata(cluster, cleared);
            }
        }

        if (mobile_data) {
            // One version of each blob, as xeBuild lays them, in type order. Small block gives
            // each its own block; big block packs them 0x800 apart in one erase block, where
            // the free count is kept in those slots; eMMC gives each its own blocks and
            // names them in the anchors, which hold types 0x31-0x34 only.
            const bool emmc = driver.driver_mode() == Driver::DriverMode::Emmc;
            const bool big = driver.driver_mode() == Driver::DriverMode::Big;
            const size_t pages_per_block = driver.pages_per_block();
            constexpr size_t kBigSlotPages = 0x800 / 512;
            std::optional<size_t> open_block;
            size_t next_page = 0;
            for (uint8_t bt = 0x31; bt <= 0x39; ++bt) {
                const auto* slot = mobile_data->get_slot(bt);
                if (!slot || !*slot || (*slot)->empty()) {
                    continue;
                }
                if (emmc && size_t(bt - CoronaConfig::kFirstBlobType) >= CoronaConfig::kBlobSlots) {
                    Log::Warn("Mobile data type 0x{:02X} has no slot in an eMMC anchor block; "
                              "it is left out",
                              bt);
                    continue;
                }
                const auto& mdata = **slot;
                const size_t limit =
                    std::min<size_t>(emmc ? std::numeric_limits<uint16_t>::max() : fs_blk_size,
                                     std::numeric_limits<uint16_t>::max());
                if (mdata.size() > limit) {
                    Log::Error("Mobile data type 0x{:02X} is 0x{:X} bytes; one copy holds at "
                               "most 0x{:X}",
                               bt, mdata.size(), limit);
                    return false;
                }
                const size_t pages = (mdata.size() + 511) / 512;
                const size_t used_pages =
                    big ? (pages + kBigSlotPages - 1) / kBigSlotPages * kBigSlotPages : pages;
                const size_t blocks_needed =
                    emmc ? (mdata.size() + fs_blk_size - 1) / fs_blk_size : 1;
                if (!big || !open_block || next_page + used_pages > pages_per_block) {
                    auto free_start = find_data_free_run(current_blk, blocks_needed);
                    if (!free_start || *free_start > std::numeric_limits<uint16_t>::max()) {
                        Log::Error(
                            "Mobile data type 0x{:02X} does not fit below reserved NAND tail", bt);
                        return false;
                    }
                    for (size_t b = 0; b < blocks_needed; ++b) {
                        driver.erase_block(*free_start + b);
                    }
                    // The table states a blob's blocks free (xeBuild 1.21); they are only
                    // kept from the files and the root here.
                    if (mutable_filesystem &&
                        !mutable_filesystem->withhold_blocks(*free_start, blocks_needed,
                                                             BlockMapStatus::Free)) {
                        Log::Error("Failed to reserve mobile data type 0x{:02X} in FlashFS", bt);
                        return false;
                    }
                    // On big block the blobs start on an erase block, and the table never
                    // names the clusters stepped over between the last file and them.
                    if (mutable_filesystem && big && !open_block) {
                        const size_t ratio = driver.block_size_clean() / 0x4000;
                        const size_t blob_cluster = *free_start * ratio;
                        const size_t floor = blob_cluster >= ratio ? blob_cluster - ratio : 0;
                        size_t cluster = blob_cluster;
                        while (cluster > floor &&
                               filesystem->blockmap()[cluster - 1] == BlockMapStatus::Free) {
                            --cluster;
                        }
                        if (cluster < blob_cluster &&
                            !mutable_filesystem->withhold_clusters(cluster, blob_cluster - cluster,
                                                                   BlockMapStatus::Unnamed)) {
                            return false;
                        }
                    }
                    open_block = *free_start;
                    next_page = 0;
                    current_blk = *free_start + blocks_needed;
                }
                if (!driver.write_offset(*open_block * fs_blk_size + next_page * 512, mdata)) {
                    return false;
                }
                const size_t free_pages = emmc ? 0 : pages_per_block - next_page - used_pages;
                layout.mobile_blocks.push_back(
                    {bt, static_cast<uint16_t>(*open_block), static_cast<uint16_t>(next_page),
                     static_cast<uint16_t>(pages),
                     static_cast<uint8_t>(big ? free_pages / kBigSlotPages : free_pages), 1,
                     static_cast<uint32_t>(mdata.size())});
                next_page += used_pages;
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
            layout.big_fs_size = filesystem->big_fs_size();
            auto& fs = const_cast<FlashFileSystem&>(*filesystem);
            fs.set_driver(&driver);
            if (!fs.save()) {
                Log::Error("Failed to save Flash File System to NAND driver");
                return false;
            }
            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            for (const uint16_t cluster : fs.get_all_file_blocks()) {
                layout.fs_data_blocks.push_back(
                    static_cast<uint16_t>(cluster / clusters_per_block));
            }
        }

        // The JTAG patch buffer is programmed whole, its erased tail included.
        if (is_jtag_patchset && payloads.patchset &&
            payloads.patchset->kind == PatchSetKind::Jtag) {
            layout.programmed_ranges.emplace_back(window_base + 0x1000, kJTAGPatchesSize);
        }
        // xeBuild's JTAG image has 0x03 0x50 in spare bytes 10 and 11 of the page holding the SMC
        // payload, in every shape and with the same payload; nothing else stamps them.
        if (is_jtag_patchset && payloads.payload) {
            layout.spare_overrides.push_back({0x200, 10, {0x03, 0x50}});
        }

        if (driver.driver_mode() == Driver::DriverMode::Emmc) {
            CoronaConfig cc{};
            cc.table = layout.fs_root_block.value_or(0);
            for (const auto& mob : layout.mobile_blocks) {
                const size_t slot = size_t(mob.block_type) - CoronaConfig::kFirstBlobType;
                cc.blobs[slot] = {mob.start_block, static_cast<uint16_t>(mob.data_size)};
            }

            // The copies are numbered 1 and 2, each given CoronaConfig::kSpan with zeros
            // after the structure; the rest of its block stays erased.
            for (size_t copy = 0; copy < CoronaConfig::kOffsets.size(); ++copy) {
                cc.number = static_cast<uint32_t>(copy + 1);
                auto cc_bytes = cc.serialize();
                cc_bytes.resize(CoronaConfig::kSpan, 0);
                cc_bytes.resize(CoronaConfig::kBlockSize, 0xFF);
                if (!driver.write_offset(CoronaConfig::kOffsets[copy], cc_bytes)) {
                    return false;
                }
            }
        } else {
            driver.set_layout(layout);
        }

        // Remove any donor CF/CG header and stale bytes from the owned overlay.
        // Direct parsed images retain a recovered patchset, so it is rewritten below.
        if (is_glitch_patchset && payloads.patchset) {
            const std::vector<uint8_t> erased_overlay(slot_stride, 0xFF);
            if (!driver.write_offset(patchslot_base + slot_stride, erased_overlay))
                return false;
        }
        if (payloads.payload) {
            if (!driver.write_offset(0x200, *payloads.payload)) {
                return false;
            }
        }
        // xeBuild programs the bytes after each JTAG window item zero, up to the next item or the
        // end of the 16 KiB block that holds the item's end.
        const auto zero_fill = [&driver](size_t from, size_t to) {
            return from >= to || driver.write_offset(from, std::vector<uint8_t>(to - from, 0));
        };
        const auto zero_to_block_end = [&zero_fill](size_t end) {
            return zero_fill(end, (end + kLayBlockSize - 1) / kLayBlockSize * kLayBlockSize);
        };
        if (payloads.rebooter) {
            if (!driver.write_offset(window_base, *payloads.rebooter)) {
                return false;
            }
            if (is_jtag_patchset &&
                !zero_fill(window_base + payloads.rebooter->size(), window_base + 0x1000)) {
                return false;
            }
        }
        if (payloads.fuses) {
            if (!driver.write_offset(fuse_offset(*this, patchslot_base, slot_stride, window_base),
                                     *payloads.fuses)) {
                return false;
            }
        }
        if (payloads.xell) {
            const auto& xell_bytes = payloads.xell->data;
            if (!driver.write_offset(xell_offset(is_jtag_patchset, is_glitch_patchset, payloads),
                                     xell_bytes)) {
                return false;
            }
        }
        const size_t glitch_patch_offset = patchslot_base + slot_stride + khv_prefix(*this);
        if (payloads.patchset) {
            std::vector<uint8_t> patch_bytes;
            size_t patch_offset = 0;
            size_t patch_capacity = 0;
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                patch_bytes = BinaryParser::SerializePatchSet(*payloads.patchset);
                patch_offset = window_base + 0x1000;
                patch_capacity = kJTAGPatchesSize;
            } else {
                const auto* khv = find_patch_section(*payloads.patchset, PatchSectionTarget::Khv);
                if (!khv) {
                    return false;
                }
                patch_bytes = BinaryParser::SerializeKhvPayload(*khv);
                patch_offset = glitch_patch_offset;
                patch_capacity = slot_stride - khv_prefix(*this);
            }
            if (patch_bytes.size() > patch_capacity) {
                Log::Error("Patch payload (0x{:X} bytes) exceeds its 0x{:X}-byte region",
                           patch_bytes.size(), patch_capacity);
                return false;
            }
            if (payloads.xell &&
                ranges_overlap(patch_offset, patch_bytes.size(),
                               xell_offset(is_jtag_patchset, is_glitch_patchset, payloads),
                               payloads.xell->data.size())) {
                Log::Error("Patch payload overlaps the reserved XeLL region");
                return false;
            }
            if (payloads.rebooter && ranges_overlap(patch_offset, patch_bytes.size(), window_base,
                                                    payloads.rebooter->size())) {
                Log::Error("Patch payload overlaps the reserved rebooter region");
                return false;
            }
            if (payloads.fuses &&
                ranges_overlap(patch_offset, patch_bytes.size(),
                               fuse_offset(*this, patchslot_base, slot_stride, window_base),
                               payloads.fuses->size())) {
                Log::Error("Patch payload overlaps the reserved virtual-fuse region");
                return false;
            }
            if (!patch_bytes.empty() && !driver.write_offset(patch_offset, patch_bytes)) {
                return false;
            }
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                const size_t patch_end = patch_offset + patch_bytes.size();
                const size_t block_end =
                    (patch_end + kLayBlockSize - 1) / kLayBlockSize * kLayBlockSize;
                const size_t region_end = patch_offset + patch_capacity;
                // The patch buffer is programmed whole: zero to the end of its block, then
                // erased bytes, written as pages, up to its fixed length.
                if (!zero_fill(patch_end, block_end) ||
                    (block_end < region_end &&
                     !driver.write_offset(block_end,
                                          std::vector<uint8_t>(region_end - block_end, 0xFF)))) {
                    return false;
                }
            }
            // xeBuild programs the rest of the patch slot's first 0x4000 bytes zero after the
            // KHV terminator; the slot past them stays erased.
            const size_t khv_end = patch_offset + patch_bytes.size();
            const size_t zero_end = size_t(patchslot_base) + slot_stride + kLayBlockSize;
            if (payloads.patchset->kind != PatchSetKind::Jtag && khv_end < zero_end &&
                !driver.write_offset(khv_end, std::vector<uint8_t>(zero_end - khv_end, 0))) {
                return false;
            }
        }

        // The JTAG second CB/CD live in the window tail, directly past the fixed-size XeLL.
        if (is_jtag_patchset) {
            const auto extra = jtag_extra_offsets(window_base, payloads);
            if (payloads.extra_cb &&
                !driver.write_offset(extra.cb, payloads.extra_cb->serialize())) {
                return false;
            }
            if (payloads.extra_cd &&
                !driver.write_offset(extra.cd, payloads.extra_cd->serialize())) {
                return false;
            }
            const size_t second_chain_end =
                payloads.extra_cd   ? extra.cd + payloads.extra_cd->serialize().size()
                : payloads.extra_cb ? extra.cb + payloads.extra_cb->serialize().size()
                                    : 0;
            if (second_chain_end != 0 && !zero_to_block_end(second_chain_end)) {
                return false;
            }
        }

        const size_t clean_size = total_blocks * block_size;
        for (const auto& patch : raw_patches) {
            if (patch.offset > clean_size || patch.data.size() > clean_size - patch.offset) {
                Log::Error("[rawpatch] '{}' (0x{:X} bytes at 0x{:X}) runs past the image",
                           patch.name, patch.data.size(), patch.offset);
                return false;
            }
            if (!driver.write_offset(patch.offset, patch.data)) {
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

        const auto slot_mode = flash_driver.driver_mode();
        const uint32_t slot_stride = slot_size(*this);
        const uint32_t donor_patchslot_base =
            header.cf_offset != 0 && header.cf_offset != 0xFFFFFFFF ? header.cf_offset
                                                                    : retail_slot_offset(slot_mode);
        const auto clear_patchslot = [&](uint32_t base_offset, const SystemUpdate& slot) {
            if (!slot.cf) {
                return true;
            }
            size_t span_size = align_16(static_cast<uint32_t>(slot.cf->serialize().size()));
            if (slot.cg) {
                span_size += slot.cg_spill_blocks.empty()
                                 ? align_16(static_cast<uint32_t>(slot.cg->serialize().size()))
                                 : std::min<size_t>(align_16(slot.cg->serialize().size()),
                                                    slot_stride - span_size);
            }
            return flash_driver.write_offset(base_offset, std::vector<uint8_t>(span_size, 0xFF));
        };
        return clear_patchslot(donor_patchslot_base, system_update_0) &&
               clear_patchslot(donor_patchslot_base + slot_stride, system_update_1);
    }

    uint32_t FlashImage::patch_slot_offset() const {
        return update_slots_end() - slot_size(*this);
    }

    uint32_t FlashImage::update_slots_end() const {
        const auto slot_mode = flash_driver.driver_mode();
        const bool is_glitch_patchset =
            (build_type &&
             (*build_type == BuildType::Glitch || *build_type == BuildType::Glitch2 ||
              *build_type == BuildType::Glitch2m || *build_type == BuildType::Glitch3)) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == glitch_slot_offset(slot_mode));
        const bool is_jtag_patchset = is_jtag_image(*this);
        return update_base(*this, is_jtag_patchset, is_glitch_patchset) + 2 * slot_size(*this);
    }

    std::vector<BlockRange> FlashImage::active_payload_block_ranges() const {
        std::vector<BlockRange> ranges;
        const auto slot_mode = flash_driver.driver_mode();
        const bool is_glitch_patchset =
            (build_type &&
             (*build_type == BuildType::Glitch || *build_type == BuildType::Glitch2 ||
              *build_type == BuildType::Glitch2m || *build_type == BuildType::Glitch3)) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == glitch_slot_offset(slot_mode));
        const bool is_jtag_patchset =
            (build_type == BuildType::Jtag) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag);
        const uint32_t slot_stride = slot_size(*this);
        const uint32_t patchslot_base = update_base(*this, is_jtag_patchset, is_glitch_patchset);
        const uint32_t window_base = kJtagWindowOffset;
        const auto add_range = [&ranges, this](size_t offset, size_t length) {
            if (const auto range = flash_driver.block_range_for_byte_interval(offset, length)) {
                ranges.push_back(*range);
            }
        };

        if (payloads.payload) {
            add_range(0x200, payloads.payload->size());
        }
        if (payloads.rebooter) {
            add_range(window_base, payloads.rebooter->size());
        }
        if (payloads.fuses) {
            add_range(fuse_offset(*this, patchslot_base, slot_stride, window_base),
                      payloads.fuses->size());
        }
        if (payloads.xell && !payloads.xell->data.empty()) {
            add_range(xell_offset(is_jtag_patchset, is_glitch_patchset, payloads),
                      payloads.xell->data.size());
        }
        if (is_glitch_patchset)
            add_range(patchslot_base + slot_stride, slot_stride);
        if (payloads.patchset) {
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                add_range(window_base + 0x1000,
                          BinaryParser::SerializePatchSet(*payloads.patchset).size());
            }
        }
        if (is_jtag_patchset) {
            const auto extra = jtag_extra_offsets(window_base, payloads);
            if (payloads.extra_cb) {
                add_range(extra.cb, payloads.extra_cb->serialize().size());
            }
            if (payloads.extra_cd) {
                add_range(extra.cd, payloads.extra_cd->serialize().size());
            }
        }
        return ranges;
    }

    std::optional<std::string> FlashImage::payload_layout_error() const {
        const auto slot_mode = flash_driver.driver_mode();
        const uint32_t slot_stride = slot_size(*this);
        const bool is_glitch_patchset =
            (build_type &&
             (*build_type == BuildType::Glitch || *build_type == BuildType::Glitch2 ||
              *build_type == BuildType::Glitch2m || *build_type == BuildType::Glitch3)) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Glitch) ||
            (payloads.xell && header.cf_offset == glitch_slot_offset(slot_mode));
        const bool is_jtag_patchset =
            (build_type == BuildType::Jtag) ||
            (payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag);
        const uint32_t patchslot_base = update_base(*this, is_jtag_patchset, is_glitch_patchset);
        const uint32_t window_base = kJtagWindowOffset;

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

        if (is_glitch_patchset && system_update_1.cf)
            return "Glitch overlay owns the second update slot; CF1/CG1 cannot be supplied";
        for (const auto* slot : {&system_update_0, &system_update_1}) {
            if (slot->cf &&
                align_16(slot->cf->serialize().size()) + (slot->cg ? sizeof(cg_header) : 0) >
                    slot_stride)
                return "CF leaves insufficient room in its update slot";
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
            add_range("XeLL", xell_offset(is_jtag_patchset, is_glitch_patchset, payloads),
                      payloads.xell->data.size());
        }
        if (payloads.payload) {
            add_range("SMC payload", 0x200, payloads.payload->size());
        }
        if (payloads.rebooter) {
            add_range("rebooter", window_base, payloads.rebooter->size());
        }
        if (payloads.fuses) {
            add_range("virtual-fuse payload",
                      fuse_offset(*this, patchslot_base, slot_stride, window_base),
                      payloads.fuses->size());
        }
        if (is_jtag_patchset) {
            const auto extra = jtag_extra_offsets(window_base, payloads);
            if (payloads.extra_cb) {
                add_range("JTAG extra CB", extra.cb, payloads.extra_cb->serialize().size());
            }
            if (payloads.extra_cd) {
                add_range("JTAG extra CD", extra.cd, payloads.extra_cd->serialize().size());
            }
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

        const auto add_system_update =
            [&add_range, &highest_used_offset, &arithmetic_error,
             slot_stride](std::string_view cf_name, std::string_view cg_name, size_t base,
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
                // Only the prefix resides in the slot; encrypt_all allocates any tail
                // through the CF continuation table for every build type.
                add_range(cg_name, end,
                          std::min<size_t>(cg_bytes.size(), end < base + slot_stride
                                                                ? base + slot_stride - end
                                                                : 0));
                if (arithmetic_error || !checked_align_16(cg_bytes.size(), aligned_size) ||
                    !checked_add(end, aligned_size, end)) {
                    arithmetic_error =
                        "System-update CG span exceeds the addressable payload layout";
                    return std::nullopt;
                }
            }
            end = std::min<size_t>(end, base + slot_stride);
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
                add_range("JTAG patch payload", window_base + 0x1000, patch_bytes.size());
            } else if (const auto* khv =
                           find_patch_section(*payloads.patchset, PatchSectionTarget::Khv)) {
                if (BinaryParser::SerializeKhvPayload(*khv).size() >
                    slot_stride - khv_prefix(*this))
                    return "Glitch KHV payload exceeds its patch-slot region";
                add_range("Glitch KHV payload", slot1_base + khv_prefix(*this),
                          slot_stride - khv_prefix(*this));
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

            if (cb_section.cb_x && !cb_section.cb_x->data.empty() && !cb_section.cb_x->decrypted) {
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
                cb_section.cb_B->decrypt_cb_b(cb_section.cb_or_A.header,
                                              cb_section.cb_or_A.derived_key->data(),
                                              cpu_key.data());
            }

            // SC is keyed from sixteen zero bytes, not from its parent. One with a zero nonce
            // is taken as plaintext.
            if (cb_section.sc.has_value() && !cb_section.sc->data.empty() &&
                !cb_section.sc->is_decrypted() &&
                std::any_of(std::begin(cb_section.sc->header.key),
                            std::end(cb_section.sc->header.key),
                            [](uint8_t byte) { return byte != 0; })) {
                cb_section.sc->decrypt(BootloaderSc::kZeroSecret);
            }

            if (!kernel_section.cd.data.empty() && !kernel_section.cd.is_decrypted()) {
                if (devkit_chain()) {
                    if (!cb_section.sc || !cb_section.sc->derived_key) {
                        Log::Error("Cannot decrypt SD: the SC key is missing");
                        return false;
                    }
                    kernel_section.cd.decrypt(cb_section.sc->derived_key->data());
                } else if (cb_section.cb_B.has_value() &&
                           cb_section.cb_B->derived_key.has_value()) {
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
                // When CD arrived plaintext, its key slot is already the handoff
                // key. For encrypted CD, use the key derived during decryption.
                kernel_section.ce->decrypt(kernel_section.cd.derived_key
                                               ? kernel_section.cd.derived_key->data()
                                               : kernel_section.cd.header.key);
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
                const auto cg_key = system_update_0.cf->cg_key();
                if (!cg_key) {
                    Log::Error("Cannot decrypt CG0: CF0 payload lacks a 7BL nonce at +0x330");
                    return false;
                }
                system_update_0.cg->decrypt(cg_key->data());
            }
            if (system_update_1.cg.has_value() && !system_update_1.cg->is_decrypted()) {
                if (!system_update_1.cf.has_value() || !system_update_1.cf->is_decrypted()) {
                    Log::Error("Cannot decrypt CG1: parent CF1 is missing or not decrypted");
                    return false;
                }
                const auto cg_key = system_update_1.cf->cg_key();
                if (!cg_key) {
                    Log::Error("Cannot decrypt CG1: CF1 payload lacks a 7BL nonce at +0x330");
                    return false;
                }
                system_update_1.cg->decrypt(cg_key->data());
            }

            if (smc.has_value() && smc->encrypted) {
                smc->decrypt();
            }

            // A console's keyvault does not open under the all-zero CPU key (only an image built
            // under that key carries one that does), so under it a keyvault that does not open
            // stays sealed and the build takes the console's from a kv.bin instead.
            if (keyvault.has_value() && keyvault->encrypted && !cpu_key.empty()) {
                if (is_zero_cpu_key(cpu_key)) {
                    if (auto opened = open_loose_keyvault(cpu_key, keyvault->raw_data);
                        opened && opened->form == LooseKeyvault::Form::Sealed) {
                        keyvault->raw_data = std::move(opened->plain);
                        std::memcpy(&keyvault->data, keyvault->raw_data.data(),
                                    sizeof(XE_KEYVAULT_DATA));
                        keyvault->encrypted = false;
                    } else {
                        Log::Warn("The keyvault does not open under the all-zero CPU key; it is "
                                  "left sealed");
                    }
                } else if (!keyvault->decrypt(cpu_key)) {
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
            if (plaintext_cb_b && (!cb_section.cb_x || cb_section.cb_x->data.empty() ||
                                   !cb_section.cb_B || !cb_section.cb_B->decrypted)) {
                Log::Error("Glitch3 requires CB_X and a plaintext CB_B");
                return false;
            }
            const bool devkit = devkit_chain();
            if (devkit && (!cb_section.sc || cb_section.sc->data.empty())) {
                Log::Error("A devkit chain needs an SC to key its SD");
                return false;
            }
            const bool cd_requires_cpu_key = !devkit && !cb_section.cb_B.has_value() &&
                                             cb_section.cb_or_A.requires_cpu_key_for_cd();

            if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted() &&
                cd_requires_cpu_key && cpu_key.size() < 16) {
                Log::Error("Cannot encrypt CD: single-CB chain requires a CPU key");
                return false;
            }

            // CB_B binds the final encrypted SMC on every split chain, whatever the image
            // type (xerunner build.py `chain`); a retail single CB binds it as well.
            // Glitch3 emits CB_B plaintext, so it binds nothing here.
            const bool bind_cb_b = cb_section.cb_B.has_value() && !plaintext_cb_b;
            // A devkit SB carries the console's block bound to the SMC, as a retail single CB
            // does (xeBuild 1.21 devkit); a devgl SB is zero-paired and binds nothing.
            const bool bind_single_cb =
                (build_type == BuildType::Retail && cd_requires_cpu_key) ||
                (devkit && build_type != BuildType::Devgl && cb_section.cb_or_A.decrypted);
            // A JTAG image's second CB carries the console's block itself, bound to the SMC
            // under its own 1BL-derived key (xerunner build.py `_wears_console`).
            const bool bind_extra_cb = payloads.extra_cb.has_value() &&
                                       !payloads.extra_cb->data.empty() &&
                                       payloads.extra_cb->decrypted;
            if (bind_cb_b || bind_single_cb || bind_extra_cb) {
                if (cpu_key.size() != 16 || !smc || smc->data.empty() ||
                    smc->data.size() % 4 != 0) {
                    Log::Error("CB authentication requires a CPU key and an aligned SMC");
                    return false;
                }
                // Authentication covers the exact SMC ciphertext written to NAND.
                if (!smc->encrypted)
                    smc->encrypt();
            }

            if (!cb_section.cb_or_A.data.empty() && cb_section.cb_or_A.decrypted) {
                if (bind_single_cb)
                    cb_section.cb_or_A.encrypt_retail(key_1bl, cpu_key, smc->data);
                else
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

            if (plaintext_cb_b) {
                if (cb_section.cb_B->data.size() < 16) {
                    Log::Error("Plaintext CB_B has no handoff key");
                    return false;
                }
                if (cb_section.cb_B->derived_key) {
                    // An encrypted replacement CB_B may have been decrypted for metadata.
                    // Preserve its derived handoff key when emitting it in plaintext.
                    std::copy(cb_section.cb_B->derived_key->begin(),
                              cb_section.cb_B->derived_key->end(), cb_section.cb_B->data.begin());
                } else {
                    // Plaintext CB_B already carries its runtime key, as in RGH2to3.
                    // CD is encrypted with this key, not the CB_X key or a new HMAC.
                    cb_section.cb_B->derived_key.emplace();
                    std::copy_n(cb_section.cb_B->data.begin(), 16,
                                cb_section.cb_B->derived_key->begin());
                }
            }

            if (!plaintext_cb_b && cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
                cb_section.cb_B->decrypted) {
                if (!cb_section.cb_or_A.derived_key.has_value()) {
                    Log::Error("Cannot encrypt CB_B: CB_A derived key is missing");
                    return false;
                }
                // Computes the digest, or zeros it for a manufacturing chain or a zero
                // CPU key, then seals under CB_A's regime.
                cb_section.cb_B->encrypt_retail(cb_section.cb_or_A.derived_key->data(), cpu_key,
                                                smc->data, &cb_section.cb_or_A.header);
            }

            // A devkit SC is sealed under the zero secret; its key seals SD. A sealed SC is
            // opened first, so its key is known.
            if (devkit) {
                auto& sc = *cb_section.sc;
                if (!sc.decrypted) {
                    sc.decrypt(BootloaderSc::kZeroSecret);
                }
                sc.encrypt(BootloaderSc::kZeroSecret);
            }

            // xeBuild's CB_B patches keep CD decryption enabled. Plaintext CD is
            // specific to separate XeLL ECC payloads, not these dashboard builds.
            if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted()) {
                if (devkit) {
                    kernel_section.cd.encrypt(cb_section.sc->derived_key->data());
                } else if (cb_section.cb_B.has_value()) {
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
                if (!kernel_section.cd.derived_key) {
                    Log::Error("Cannot encrypt CE: CD derived key is missing");
                    return false;
                }
                kernel_section.ce->encrypt(kernel_section.cd.derived_key->data());
            }

            // The JTAG second chain: its CB sealed under HMAC(1BL key, nonce) with the
            // console's block bound to the SMC, and its CD under HMAC(CB key, nonce) with no
            // CPU-key pass, which only a retail single-CB chain takes.
            if (bind_extra_cb) {
                payloads.extra_cb->encrypt_retail(key_1bl, cpu_key, smc->data);
            }
            if (payloads.extra_cd && !payloads.extra_cd->data.empty() &&
                payloads.extra_cd->is_decrypted()) {
                if (!payloads.extra_cb || !payloads.extra_cb->derived_key) {
                    Log::Error("Cannot encrypt the JTAG second CD: its CB key is missing");
                    return false;
                }
                payloads.extra_cd->encrypt(payloads.extra_cb->derived_key->data());
            }

            const bool glitch_layout =
                build_type == BuildType::Glitch || build_type == BuildType::Glitch2 ||
                build_type == BuildType::Glitch2m || build_type == BuildType::Glitch3;
            const size_t stride = slot_size(*this);
            auto prepare_update = [&](SystemUpdate& slot, const char* filename) {
                if (!slot.cf || !slot.cg)
                    return true;
                if (slot.cg->decrypted) {
                    slot.cf->decrypt(key_1bl);
                    const auto cg_key = slot.cf->cg_key();
                    if (!cg_key) {
                        Log::Error("Cannot encrypt CG: CF payload lacks a 7BL nonce at +0x330");
                        return false;
                    }
                    slot.cg->encrypt(cg_key->data());
                }
                const auto cg = slot.cg->serialize();
                const size_t cf_size = align_16(slot.cf->serialize().size());
                if (cf_size + sizeof(cg_header) > stride)
                    return false;
                const size_t prefix = std::min(cg.size(), stride - cf_size);
                if (prefix == cg.size()) {
                    slot.cf->decrypt(key_1bl);
                    if (slot.cf->data.size() >= 0x1C0)
                        std::fill_n(slot.cf->data.begin(), 0x1C0, 0);
                    slot.cg_spill_blocks.clear();
                    if (filesystem) {
                        filesystem->set_driver(&flash_driver);
                        if (filesystem->exists(filename) && !filesystem->delete_file(filename))
                            return false;
                    }
                    return true;
                }
                if (!filesystem) {
                    Log::Error("CG continuation requires a Flash File System");
                    return false;
                }
                filesystem->set_driver(&flash_driver);
                for (auto range : active_payload_block_ranges())
                    if (!filesystem->reserve_blocks(range.start_block, range.block_count))
                        return false;
                const bool jtag_layout =
                    build_type == BuildType::Jtag ||
                    (payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag);
                const size_t base = update_base(*this, jtag_layout, glitch_layout);
                if (const auto range = flash_driver.block_range_for_byte_interval(base, 2 * stride))
                    if (!filesystem->reserve_blocks(range->start_block, range->block_count))
                        return false;
                if (filesystem->exists(filename) && !filesystem->delete_file(filename))
                    return false;
                // A built image lists each CG tail first, in slot order, and lays it on the
                // filesystem's first free blocks, directly past the slots (xeBuild 1.21).
                // A parsed image keeps its other files where they are.
                if (preserve_layout) {
                    if (!filesystem->add_file(filename, std::span(cg).subspan(prefix)))
                        return false;
                } else {
                    if (!filesystem->insert_file(leading_cg_tails(*filesystem), filename,
                                                 std::span(cg).subspan(prefix)))
                        return false;
                }
                auto entry = filesystem->stat(filename);
                if (!entry)
                    return false;
                auto chain = filesystem->get_chain(entry->block_number);
                if (chain.size() > 223 || chain.size() != (cg.size() - prefix + 0x3FFF) / 0x4000)
                    return false;
                slot.cf->decrypt(key_1bl);
                if (slot.cf->data.size() < 0x1C0)
                    return false;
                std::fill_n(slot.cf->data.begin(), 0x1C0, 0);
                slot.cf->data[0] = uint8_t(chain.size() >> 8);
                slot.cf->data[1] = uint8_t(chain.size());
                for (size_t i = 0; i < chain.size(); ++i) {
                    slot.cf->data[2 + i * 2] = uint8_t(chain[i] >> 8);
                    slot.cf->data[3 + i * 2] = uint8_t(chain[i]);
                }
                slot.cg_spill_blocks = std::move(chain);
                return true;
            };
            if (!prepare_update(system_update_0, "sysupdate.xexp1") ||
                !prepare_update(system_update_1, "sysupdate.xexp2"))
                return false;

            if (system_update_0.cf.has_value() && system_update_0.cf->is_decrypted()) {
                system_update_0.cf->serialize_perbox();
                if (!cpu_key.empty() && update_slot_binds_console(build_type, 0)) {
                    system_update_0.cf->calc_mac(key_1bl, cpu_key.data());
                }
                system_update_0.cf->encrypt(key_1bl);
            }
            if (system_update_1.cf.has_value() && system_update_1.cf->is_decrypted()) {
                system_update_1.cf->serialize_perbox();
                if (!cpu_key.empty() && update_slot_binds_console(build_type, 1)) {
                    system_update_1.cf->calc_mac(key_1bl, cpu_key.data());
                }
                system_update_1.cf->encrypt(key_1bl);
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

} // namespace gxbuild3::nand
