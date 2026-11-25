#pragma once

#include "gxbuild/Error.hpp"
#include "core/Wire.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/XeLL.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild::nand::detail {

    struct PayloadRange {
        std::string_view name;
        std::size_t offset;
        std::size_t length;
    };

    [[nodiscard]] Result<void> add_payload_range(std::vector<PayloadRange>& ranges,
                                                 std::string_view name, std::size_t offset,
                                                 std::size_t length);

    [[nodiscard]] Result<std::size_t>
    add_update_slot_ranges(std::vector<PayloadRange>& ranges, std::string_view cf_name,
                           std::string_view cg_name, std::size_t base, std::size_t slot_stride,
                           std::optional<std::size_t> cf_size, std::optional<std::size_t> cg_size);

    [[nodiscard]] Result<void> check_overlaps(std::span<const PayloadRange> ranges);

    inline constexpr uint32_t kSmcPayloadOffset = 0x200;
    inline constexpr uint32_t kJtagPatchSize = 0x4000;
    inline constexpr uint32_t kKeyvaultOffset = 0x4000;
    inline constexpr uint32_t kEntryOffset = 0x8000;
    inline constexpr uint32_t kXellOffset = 0x70000;
    inline constexpr uint32_t kJtagSlotOffset = 0x70000;
    inline constexpr uint32_t kJtagWindowOffset = 0x90000;
    inline constexpr uint32_t kDevglSlotOffset = 0xD0000;
    inline constexpr uint32_t kSmallFsOffset = 0x10000;
    inline constexpr uint32_t kBigFsOffset = 0x20000;

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

    inline uint32_t slot_round(Driver::DriverMode mode) {
        return mode == Driver::DriverMode::Big ? 0x20000 : 0x10000;
    }

    inline uint32_t round_up(uint32_t value, uint32_t step) {
        return (value + step - 1) / step * step;
    }

    inline uint32_t retail_slot_offset(Driver::DriverMode mode) {
        return mode == Driver::DriverMode::Big ? 0x80000 : 0x70000;
    }

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
        size_t se;
    };

    inline JtagExtraOffsets jtag_extra_offsets(uint32_t window_base, const Payloads& payloads) {
        const size_t cb = window_base + 0x5060 + XeLL::kSize;
        const size_t cd = payloads.extra_cb
                              ? cb + align_16(static_cast<uint32_t>(payloads.extra_cb->serialize().size()))
                              : cb;
        const size_t se = payloads.extra_cd
                              ? cd + align_16(static_cast<uint32_t>(payloads.extra_cd->serialize().size()))
                              : cd;
        return {cb, cd, se};
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

    inline bool header_states(uint32_t value) {
        return value != 0 && value != 0xFFFFFFFF;
    }

    inline uint32_t header_slot_stride(const nand_header& header) {
        const uint32_t stated = header.fs_addr.get();
        return header_states(stated) ? stated : 0x10000;
    }

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
    // sums the aligned sizes of every stage with non-empty data starting from 0x8000
    inline size_t laid_boot_chain_end(const FlashImage& image) {
        size_t end = kEntryOffset;
        FlashImage::for_each_present_stage(
            image, [&end](BootStageId, std::string_view, const auto& bootloader) {
                end += align_16(static_cast<uint32_t>(bootloader.serialize().size()));
            });
        return end;
    }

    inline std::optional<size_t> max_ldv_slot(const FlashImage& image) {
        std::optional<size_t> best;
        uint8_t best_ldv = 0;
        const std::array<const SystemUpdate*, 2> slots{&image.system_update_0,
                                                       &image.system_update_1};
        for (size_t index = 0; index < slots.size(); ++index) {
            const auto& cf = slots[index]->cf;
            if (!cf || cf->data.empty() || !cf->perbox) {
                continue;
            }
            if (!best || cf->perbox->lockdown_value > best_ldv) {
                best = index;
                best_ldv = cf->perbox->lockdown_value;
            }
        }
        return best;
    }

    // figures out the starting offset of the first system update slot based on build type and chain length.
    inline uint32_t update_base(const FlashImage& image, bool jtag, bool glitch) {
        if (image.preserve_layout && header_states(image.header.cf_offset.get()))
            return image.header.cf_offset.get();
        if (image.build_type == BuildType::Devkit) {
            return round_up(static_cast<uint32_t>(laid_boot_chain_end(image)),
                            static_cast<uint32_t>(image.flash_driver.block_size_clean()));
        }
        const auto mode = image.flash_driver.driver_mode();
        if (image.build_type == BuildType::Devgl) {
            return round_up(kDevglSlotOffset, slot_round(mode));
        }
        if (image.build_type == BuildType::Glitch2m && laid_boot_chain_end(image) > kXellOffset) {
            return round_up(static_cast<uint32_t>(laid_boot_chain_end(image)), slot_round(mode));
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

        [[nodiscard]] constexpr uint32_t patch_slot_offset() const noexcept {
            return update_base + slot_stride;
        }
        [[nodiscard]] constexpr uint32_t jtag_patch_offset() const noexcept {
            return window_base + 0x1000;
        }
        [[nodiscard]] constexpr size_t khv_offset() const noexcept {
            return size_t(update_base) + slot_stride + khv_prefix;
        }
        [[nodiscard]] constexpr size_t khv_capacity() const noexcept {
            return slot_stride - khv_prefix;
        }
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

    inline LayoutPlan plan_layout(const FlashImage& image) {
        const bool glitch =
            (image.build_type && is_glitch_build(*image.build_type)) ||
            (image.payloads.patchset && image.payloads.patchset->kind == PatchSetKind::Glitch) ||
            (image.payloads.xell &&
             image.header.cf_offset == glitch_slot_offset(image.flash_driver.driver_mode()));
        return make_plan(image, glitch, is_jtag_image(image));
    }

    // builds a layout plan using the explicit seal_type instead of image.build_type, which might not be set yet
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

    inline constexpr size_t kSmcConfigLength = SmcConfigBlock::kSize;
    inline constexpr size_t kSettingsSpan = StatisticsBlock::kSize;

    inline bool smc_config_sums(std::span<const uint8_t> block) {
        return SmcConfigBlock::checksum_valid(block);
    }

    // smc config sits in the last block before the reserved tail, with stats and manufacturing one and two blocks below it
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

} // namespace gxbuild::nand::detail
