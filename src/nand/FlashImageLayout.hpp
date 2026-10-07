#pragma once

// Internal to FlashImage. The layout constants and helpers the FlashImage translation units
// (FlashImageLayout.cpp, FlashImageParse.cpp, FlashImageWrite.cpp, FlashImageCrypt.cpp) share,
// and the pieces of FlashImage::payload_layout declared here so tests can drive the overflow
// paths a real image cannot reach (defined in FlashImageLayout.cpp).

#include "Error.hpp"
#include "Wire.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/XeLL.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::nand::detail {

    // One payload writer's clean byte span. `name` names the writer in a collision message and
    // must outlive the range (callers pass string literals).
    struct PayloadRange {
        std::string_view name;
        std::size_t offset;
        std::size_t length;
    };

    // Records [offset, offset + length) under `name`; an empty range is not recorded. Fails
    // OutOfRange "Payload layout range overflow for <name>" when the end overflows size_t, and
    // then records nothing.
    [[nodiscard]] Result<void> add_payload_range(std::vector<PayloadRange>& ranges,
                                                 std::string_view name, std::size_t offset,
                                                 std::size_t length);

    // Records an update slot at `base`: the CF of `cf_size` bytes when present, then the part of
    // the CG of `cg_size` bytes that resides in the slot (encrypt_all lays any tail through the
    // CF continuation table). Returns the slot's end clamped to base + slot_stride, or `base`
    // when there is no CF (`cg_size` is then ignored). Any overflow while the CF is accounted,
    // its range included, fails OutOfRange "System-update CF span exceeds the addressable payload
    // layout"; any while the CG is accounted fails with the CG text. The range overflow text of
    // add_payload_range never escapes from here.
    [[nodiscard]] Result<std::size_t>
    add_update_slot_ranges(std::vector<PayloadRange>& ranges, std::string_view cf_name,
                           std::string_view cg_name, std::size_t base, std::size_t slot_stride,
                           std::optional<std::size_t> cf_size, std::optional<std::size_t> cg_size);

    // Fails InvalidArgument "Payload layout collision: <first> overlaps <second>" for the first
    // overlapping pair in (first, second) index order, first < second. Empty ranges never
    // overlap.
    [[nodiscard]] Result<void> check_overlaps(std::span<const PayloadRange> ranges);

    inline constexpr uint32_t kKeyvaultOffset = 0x4000;
    inline constexpr uint32_t kEntryOffset = 0x8000;
    // XeLL sits at 0x70000 on every shape and is 0x40000 long. The slots follow it, rounded
    // up by the shape's erase block, or follow the chain when there is no XeLL.
    inline constexpr uint32_t kXellOffset = 0x70000;
    // A JTAG image is laid out by the loader it carries, whose neighbours sit at addresses
    // compiled into it: the slot pair at 0x70000 and 0x80000 on every shape, the core at
    // 0x90000.
    inline constexpr uint32_t kJtagSlotOffset = 0x70000;
    inline constexpr uint32_t kJtagWindowOffset = 0x90000;
    inline constexpr uint32_t kDevglSlotOffset = 0xD0000;
    inline constexpr uint32_t kSmallFsOffset = 0x10000;
    inline constexpr uint32_t kBigFsOffset = 0x20000;

    // Lays `data` at the clean `offset`, turning the driver's range sentinel into an Error
    // that names what was being laid.
    [[nodiscard]] inline Result<void> write_or_fail(Driver& driver, size_t offset,
                                                    std::span<const uint8_t> data,
                                                    std::string_view what) {
        if (!driver.write_offset(offset, data)) {
            return fail(ErrorCode::OutOfRange, "{} (0x{:X} bytes at 0x{:X}) runs past the image",
                        what, data.size(), offset);
        }
        return {};
    }

    inline constexpr uint32_t align_16(uint32_t value) noexcept {
        return (value + 0x0FU) & ~0x0FU;
    }

    inline bool checked_add(size_t left, size_t right, size_t& result) {
        if (right > std::numeric_limits<size_t>::max() - left) {
            return false;
        }
        result = left + right;
        return true;
    }

    inline bool checked_align_16(size_t value, size_t& result) {
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

    inline bool is_jtag_image(const FlashImage& image) {
        return image.build_type == BuildType::Jtag ||
               (image.payloads.patchset && image.payloads.patchset->kind == PatchSetKind::Jtag);
    }

    struct JtagExtraOffsets {
        size_t cb;
        size_t cd;
    };

    // The JTAG second CB/CD sit in the window tail, directly past the fixed-size XeLL, with
    // the CD following a 16-byte-aligned CB.
    inline JtagExtraOffsets jtag_extra_offsets(uint32_t window_base, const Payloads& payloads) {
        const size_t cb = window_base + 0x5060 + XeLL::kSize;
        if (!payloads.extra_cb) {
            return {cb, cb};
        }
        return {cb, cb + align_16(static_cast<uint32_t>(payloads.extra_cb->serialize().size()))};
    }

    inline uint32_t xell_offset(bool is_jtag_patchset, bool is_glitch_patchset,
                                const Payloads& payloads) {
        if (is_jtag_patchset) {
            return kJtagWindowOffset + 0x5060;
        }
        return is_glitch_patchset ? kXellOffset
                                  : (!payloads.rebooter ? kXellOffset : kJtagWindowOffset + 0x5060);
    }

    inline uint32_t system_update_base(uint32_t slot_base, uint32_t round, bool is_jtag_patchset,
                                       bool is_glitch_patchset, const Payloads& payloads) {
        if (!payloads.xell) {
            return slot_base;
        }
        const uint32_t offset = xell_offset(is_jtag_patchset, is_glitch_patchset, payloads);
        return offset <= slot_base
                   ? std::max<uint32_t>(
                         slot_base, round_up(offset + static_cast<uint32_t>(XeLL::kSize), round))
                   : slot_base;
    }

    // A donor header leaves an offset it does not state as 0 or as erased flash.
    inline bool header_states(uint32_t value) {
        return value != 0 && value != 0xFFFFFFFF;
    }

    // The update-slot stride a donor header states (fs_addr carries dwSysUpdateSlotSize),
    // else the small-block 0x10000.
    inline uint32_t header_slot_stride(const nand_header& header) {
        const uint32_t stated = header.fs_addr.get();
        return header_states(stated) ? stated : 0x10000;
    }

    // Where a donor header puts its first update slot (cf_offset), else the retail slot
    // offset of the shape.
    inline uint32_t donor_update_base(const nand_header& header, Driver::DriverMode mode) {
        const uint32_t stated = header.cf_offset.get();
        return header_states(stated) ? stated : retail_slot_offset(mode);
    }

    inline uint32_t slot_size(const FlashImage& image) {
        if (image.preserve_layout)
            return header_slot_stride(image.header);
        if (is_jtag_image(image)) {
            return 0x10000;
        }
        return image.flash_driver.driver_mode() == Driver::Big ? 0x20000 : 0x10000;
    }
    // Where the laid boot chain ends, counted from kEntryOffset, unchecked. CB/A and CD
    // count when they hold data; this presence rule differs on purpose from
    // checked_boot_chain_end's parsed-header rule and is the one write_to_driver lays the
    // chain by. Do not unify them: a devkit update_base follows this end, and an image
    // whose header was never parsed would move it.
    inline size_t laid_boot_chain_end(const FlashImage& image) {
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

    inline uint32_t update_base(const FlashImage& image, bool jtag, bool glitch) {
        if (image.preserve_layout && header_states(image.header.cf_offset.get()))
            return image.header.cf_offset.get();
        // A devkit image's first slot follows its chain at the next erase block: 0xD4000
        // behind the 17489 chain on small block, 0xE0000 on big block (xeBuild 1.21).
        if (image.build_type == BuildType::Devkit) {
            return round_up(static_cast<uint32_t>(laid_boot_chain_end(image)),
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

    inline bool manufacturing(const FlashImage& image) {
        return image.build_type == BuildType::Glitch2m || image.build_type == BuildType::Devgl ||
               (image.payloads.patchset && image.payloads.patchset->manufacturing);
    }
    inline size_t khv_prefix(const FlashImage& image) {
        return manufacturing(image) ? 0x60 : 0x10;
    }
    inline uint32_t fuse_offset(const FlashImage& image, uint32_t update_base, uint32_t stride,
                                uint32_t window_base) {
        return manufacturing(image) ? update_base + stride : window_base + 0x5000;
    }

    inline bool is_glitch_build(BuildType type) {
        return type == BuildType::Glitch || type == BuildType::Glitch2 ||
               type == BuildType::Glitch2m || type == BuildType::Glitch3;
    }

    // Where an image lays its update slots and payloads. Build it where it is used: every
    // field follows the image's build type, payloads and header, so a plan taken before a
    // mutation goes stale.
    struct LayoutPlan {
        Driver::DriverMode mode;
        bool big_or_emmc;
        bool glitch;
        bool jtag;
        uint32_t slot_stride;
        uint32_t update_base;
        uint32_t window_base;
        uint32_t fs_base;
        uint32_t xell_offset;
        uint32_t fuse_offset;
        size_t khv_prefix;
        bool manufacturing;
    };

    inline LayoutPlan make_plan(const FlashImage& image, bool glitch, bool jtag) {
        const auto mode = image.flash_driver.driver_mode();
        const bool big_or_emmc =
            mode == Driver::DriverMode::Big || mode == Driver::DriverMode::Emmc;
        const uint32_t slot_stride = slot_size(image);
        const uint32_t base = update_base(image, jtag, glitch);
        const uint32_t window_base = kJtagWindowOffset;
        return LayoutPlan{
            .mode = mode,
            .big_or_emmc = big_or_emmc,
            .glitch = glitch,
            .jtag = jtag,
            .slot_stride = slot_stride,
            .update_base = base,
            .window_base = window_base,
            .fs_base = big_or_emmc ? kBigFsOffset : kSmallFsOffset,
            .xell_offset = xell_offset(jtag, glitch, image.payloads),
            .fuse_offset = fuse_offset(image, base, slot_stride, window_base),
            .khv_prefix = khv_prefix(image),
            .manufacturing = manufacturing(image),
        };
    }

    // The layout the writer, the payload checks and the slot accessors share: a glitch
    // image by its build type, its patchset or a XeLL ahead of the glitch slot offset; a
    // JTAG image by its build type or its patchset.
    inline LayoutPlan plan_layout(const FlashImage& image) {
        const bool glitch =
            (image.build_type && is_glitch_build(*image.build_type)) ||
            (image.payloads.patchset && image.payloads.patchset->kind == PatchSetKind::Glitch) ||
            (image.payloads.xell &&
             image.header.cf_offset == glitch_slot_offset(image.flash_driver.driver_mode()));
        return make_plan(image, glitch, is_jtag_image(image));
    }

    // The layout encrypt_all reserves the update slots by. It differs from plan_layout on
    // purpose: the glitch test reads only the type being sealed (not the member build
    // type, the patchset or the XeLL), and the JTAG test takes the sealed type in place of
    // the member. encrypt_all can run on an image whose member build type is unset, and
    // folding the two would move update_base there.
    inline LayoutPlan plan_for_seal(const FlashImage& image, BuildType seal_type) {
        const bool jtag =
            seal_type == BuildType::Jtag ||
            (image.payloads.patchset && image.payloads.patchset->kind == PatchSetKind::Jtag);
        return make_plan(image, is_glitch_build(seal_type), jtag);
    }

    inline bool ranges_overlap(size_t first_offset, size_t first_length, size_t second_offset,
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

    inline const ParsedPatchSection* find_patch_section(const ParsedPatchSet& patchset,
                                                        PatchSectionTarget target) {
        const auto section = std::find_if(
            patchset.sections.begin(), patchset.sections.end(),
            [target](const ParsedPatchSection& candidate) { return candidate.target == target; });
        return section == patchset.sections.end() ? nullptr : &*section;
    }

    // The settings block is 0x400 bytes laid in a 0x1000 span, the rest 0xFF. Its head holds
    // the one's complement of the byte sum over [0x10, 0x10C), little-endian. Checked
    // against the settings blocks of real small-block and big-block dumps.
    inline constexpr size_t kSmcConfigLength = 0x400;
    // The settings, statistics and manufacturing blocks are each laid in 0x1000 bytes at
    // the head of their erase block; the rest of that block stays erased.
    inline constexpr size_t kSettingsSpan = 0x1000;

    inline bool smc_config_sums(std::span<const uint8_t> block) {
        if (block.size() < kSmcConfigLength) {
            return false;
        }
        uint32_t sum = 0;
        for (size_t i = 0x10; i < 0x10C; ++i) {
            sum += block[i];
        }
        const uint16_t expected = static_cast<uint16_t>(~sum);
        const auto stored = wire::read<wire::le16>(block, 0, "SMC config checksum");
        return stored && stored->get() == expected;
    }

    // Where the settings block sits: the last block before the reserved tail, which is
    // 0xF7C000 on a 16 MB image, 0x3DFC000 on a 64 MB small-block devkit image, 0x3BE0000
    // on big block and 0x2FFC000 on eMMC. The statistics and manufacturing blocks lie one
    // and two erase blocks below it.
    inline std::optional<size_t> smc_config_offset(const Driver& driver) {
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

} // namespace gxbuild3::nand::detail
