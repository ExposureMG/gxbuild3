#include "nand/FlashImageLayout.hpp"

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/XeLL.hpp"

#include <algorithm>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {

    using namespace detail;

    namespace {

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

        // Where the serialized boot chain ends, counted from kEntryOffset, with CB/A and CD
        // present when their parsed header says so (see laid_boot_chain_end for the other
        // rule). Fails OutOfRange with overflow_message when an aligned size or the running
        // end overflows size_t.
        Result<size_t> checked_boot_chain_end(const FlashImage& image,
                                              std::string_view overflow_message) {
            size_t end = kEntryOffset;
            bool size_is_valid = true;
            const auto account_for = [&end, &size_is_valid](const auto& bootloader) {
                if (!size_is_valid) {
                    return;
                }
                size_t aligned_size = 0;
                if (!checked_align_16(bootloader.serialize().size(), aligned_size) ||
                    !checked_add(end, aligned_size, end)) {
                    size_is_valid = false;
                }
            };
            const auto& cb_section = image.cb_section;
            const auto& kernel_section = image.kernel_section;
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
                return fail(ErrorCode::OutOfRange, "{}", overflow_message);
            }
            return end;
        }

        // A FlashFS keeps a pointer to the driver it reads and writes; after a copy or a move it
        // must name the new object's driver, not the one it was copied or moved from.
        void rebind_filesystem(ImageState& state) {
            if (state.filesystem) {
                state.filesystem->set_driver(&state.flash_driver);
            }
        }

    } // namespace

    FlashImage::FlashImage(const FlashImage& other) : ImageState(other) {
        rebind_filesystem(*this);
    }

    FlashImage::FlashImage(FlashImage&& other) noexcept(
        std::is_nothrow_move_constructible_v<ImageState>)
        : ImageState(std::move(other)) {
        rebind_filesystem(*this);
    }

    FlashImage& FlashImage::operator=(const FlashImage& other) {
        ImageState::operator=(other);
        rebind_filesystem(*this);
        return *this;
    }

    FlashImage& FlashImage::operator=(FlashImage&& other) noexcept(
        std::is_nothrow_move_assignable_v<ImageState>) {
        ImageState::operator=(std::move(other));
        rebind_filesystem(*this);
        return *this;
    }

    bool FlashImage::devkit_chain() const {
        return cb_section.cb_or_A.header.header.magic == NANDBootloaderMagic::SB;
    }

    Result<void> FlashImage::clear_bootloader_chain() {
        if (flash_driver.block_count() == 0) {
            return fail(ErrorCode::InvalidArgument, "the NAND image has no blocks");
        }

        const auto boot_chain_end = checked_boot_chain_end(
            *this, "the donor boot chain exceeds the addressable payload layout");
        if (!boot_chain_end) {
            return std::unexpected(boot_chain_end.error());
        }
        const std::vector<uint8_t> cleared_chain(*boot_chain_end - kEntryOffset, 0);
        if (auto cleared =
                write_or_fail(flash_driver, kEntryOffset, cleared_chain, "cleared boot chain");
            !cleared) {
            return cleared;
        }

        const auto slot_mode = flash_driver.driver_mode();
        const uint32_t slot_stride = slot_size(*this);
        const uint32_t donor_patchslot_base = donor_update_base(header, slot_mode);
        const auto clear_patchslot = [&](uint32_t base_offset,
                                         const SystemUpdate& slot) -> Result<void> {
            if (!slot.cf) {
                return {};
            }
            size_t span_size = align_16(static_cast<uint32_t>(slot.cf->serialize().size()));
            if (slot.cg) {
                span_size += slot.cg_spill_blocks.empty()
                                 ? align_16(static_cast<uint32_t>(slot.cg->serialize().size()))
                                 : std::min<size_t>(align_16(slot.cg->serialize().size()),
                                                    slot_stride - span_size);
            }
            return write_or_fail(flash_driver, base_offset, std::vector<uint8_t>(span_size, 0xFF),
                                 "cleared update slot");
        };
        if (auto cleared = clear_patchslot(donor_patchslot_base, system_update_0); !cleared) {
            return cleared;
        }
        return clear_patchslot(donor_patchslot_base + slot_stride, system_update_1);
    }

    uint32_t FlashImage::patch_slot_offset() const {
        return update_slots_end() - slot_size(*this);
    }

    uint32_t FlashImage::update_slots_end() const {
        const LayoutPlan plan = plan_layout(*this);
        return plan.update_base + 2 * plan.slot_stride;
    }

    std::vector<BlockRange> FlashImage::active_payload_block_ranges() const {
        std::vector<BlockRange> ranges;
        const LayoutPlan plan = plan_layout(*this);
        const auto add_range = [&ranges, this](size_t offset, size_t length) {
            if (const auto range = flash_driver.block_range_for_byte_interval(offset, length)) {
                ranges.push_back(*range);
            }
        };

        if (payloads.payload) {
            add_range(0x200, payloads.payload->size());
        }
        if (payloads.rebooter) {
            add_range(plan.window_base, payloads.rebooter->size());
        }
        if (payloads.fuses) {
            add_range(plan.fuse_offset, payloads.fuses->size());
        }
        if (payloads.xell && !payloads.xell->data.empty()) {
            add_range(plan.xell_offset, payloads.xell->data.size());
        }
        if (plan.glitch)
            add_range(plan.update_base + plan.slot_stride, plan.slot_stride);
        if (payloads.patchset) {
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                add_range(plan.window_base + 0x1000,
                          serialize_patch_set(*payloads.patchset).size());
            }
        }
        if (plan.jtag) {
            const auto extra = jtag_extra_offsets(plan.window_base, payloads);
            if (payloads.extra_cb) {
                add_range(extra.cb, payloads.extra_cb->serialize().size());
            }
            if (payloads.extra_cd) {
                add_range(extra.cd, payloads.extra_cd->serialize().size());
            }
        }
        return ranges;
    }

    namespace detail {

        Result<void> add_payload_range(std::vector<PayloadRange>& ranges, std::string_view name,
                                       size_t offset, size_t length) {
            if (length == 0) {
                return {};
            }
            size_t end = 0;
            if (!checked_add(offset, length, end)) {
                return fail(ErrorCode::OutOfRange, "Payload layout range overflow for {}", name);
            }
            ranges.push_back(PayloadRange{name, offset, length});
            return {};
        }

        Result<size_t> add_update_slot_ranges(std::vector<PayloadRange>& ranges,
                                              std::string_view cf_name, std::string_view cg_name,
                                              size_t base, size_t slot_stride,
                                              std::optional<size_t> cf_size,
                                              std::optional<size_t> cg_size) {
            size_t end = base;
            if (!cf_size) {
                return end;
            }
            // The CF's own range overflow is reported as the CF span, as is the CG's below.
            size_t aligned_size = 0;
            if (!add_payload_range(ranges, cf_name, base, *cf_size) ||
                !checked_align_16(*cf_size, aligned_size) ||
                !checked_add(base, aligned_size, end)) {
                return fail(ErrorCode::OutOfRange,
                            "System-update CF span exceeds the addressable payload layout");
            }
            if (cg_size) {
                // Only the prefix resides in the slot; encrypt_all allocates any tail through
                // the CF continuation table for every build type.
                const size_t in_slot = std::min<size_t>(
                    *cg_size, end < base + slot_stride ? base + slot_stride - end : 0);
                if (!add_payload_range(ranges, cg_name, end, in_slot) ||
                    !checked_align_16(*cg_size, aligned_size) ||
                    !checked_add(end, aligned_size, end)) {
                    return fail(ErrorCode::OutOfRange,
                                "System-update CG span exceeds the addressable payload layout");
                }
            }
            return std::min<size_t>(end, base + slot_stride);
        }

        Result<void> check_overlaps(std::span<const PayloadRange> ranges) {
            for (size_t first = 0; first < ranges.size(); ++first) {
                for (size_t second = first + 1; second < ranges.size(); ++second) {
                    if (ranges_overlap(ranges[first].offset, ranges[first].length,
                                       ranges[second].offset, ranges[second].length)) {
                        return fail(ErrorCode::InvalidArgument,
                                    "Payload layout collision: {} overlaps {}", ranges[first].name,
                                    ranges[second].name);
                    }
                }
            }
            return {};
        }

    } // namespace detail

    namespace {

        using detail::PayloadRange;

        std::optional<size_t> serialized_size(const auto& bootloader) {
            if (!bootloader) {
                return std::nullopt;
            }
            return bootloader->serialize().size();
        }

        // Every payload writer's range in the order check_overlaps pairs them, or the first
        // failure in this precedence, which is the layout's historical one:
        //  1. the fixed payloads' range overflow, XeLL first, then the SMC payload, the
        //     rebooter, the virtual fuses and the JTAG extra CB and CD (at most one of these can
        //     overflow: each would need a length near SIZE_MAX, and two cannot coexist);
        //  2. the serialized boot chain's text, then its range overflow;
        //  3. slot 0's CF/CG span (that text replaces a CF or CG range overflow), the slot 1
        //     base, a CF0/CG0 past its stride beside a CF1, then slot 1's CF/CG span;
        //  4. the JTAG patch payload's range overflow, or the glitch KHV region size and then
        //     its range overflow.
        // Every overflow here needs a size_t wrap, so on 64-bit only the boot chain, slot and KHV
        // checks are reachable from an image; FlashImageLayout.hpp exposes the overflow steps.
        Result<std::vector<PayloadRange>> collect_payload_ranges(const FlashImage& image,
                                                                 const LayoutPlan& plan) {
            std::vector<PayloadRange> ranges;
            const auto add = [&ranges](std::string_view name, size_t offset, size_t length) {
                return detail::add_payload_range(ranges, name, offset, length);
            };
            const auto& payloads = image.payloads;

            // Keep XeLL first so a collision explains that its historically fixed placement is
            // the conflicting writer, rather than implying that the fixed JTAG payload moved.
            if (payloads.xell) {
                if (auto added = add("XeLL", plan.xell_offset, payloads.xell->data.size());
                    !added) {
                    return std::unexpected(std::move(added.error()));
                }
            }
            if (payloads.payload) {
                if (auto added = add("SMC payload", 0x200, payloads.payload->size()); !added) {
                    return std::unexpected(std::move(added.error()));
                }
            }
            if (payloads.rebooter) {
                if (auto added = add("rebooter", plan.window_base, payloads.rebooter->size());
                    !added) {
                    return std::unexpected(std::move(added.error()));
                }
            }
            if (payloads.fuses) {
                if (auto added =
                        add("virtual-fuse payload", plan.fuse_offset, payloads.fuses->size());
                    !added) {
                    return std::unexpected(std::move(added.error()));
                }
            }
            if (plan.jtag) {
                const auto extra = jtag_extra_offsets(plan.window_base, payloads);
                if (payloads.extra_cb) {
                    if (auto added =
                            add("JTAG extra CB", extra.cb, payloads.extra_cb->serialize().size());
                        !added) {
                        return std::unexpected(std::move(added.error()));
                    }
                }
                if (payloads.extra_cd) {
                    if (auto added =
                            add("JTAG extra CD", extra.cd, payloads.extra_cd->serialize().size());
                        !added) {
                        return std::unexpected(std::move(added.error()));
                    }
                }
            }

            const auto boot_chain_end = checked_boot_chain_end(
                image, "Serialized boot chain exceeds the addressable payload layout");
            if (!boot_chain_end) {
                return std::unexpected(boot_chain_end.error());
            }
            if (auto added =
                    add("serialized boot chain", kEntryOffset, *boot_chain_end - kEntryOffset);
                !added) {
                return std::unexpected(std::move(added.error()));
            }

            const auto& slot0 = image.system_update_0;
            const auto& slot1 = image.system_update_1;
            const auto slot0_end = detail::add_update_slot_ranges(
                ranges, "system-update CF0", "system-update CG0", plan.update_base,
                plan.slot_stride, serialized_size(slot0.cf), serialized_size(slot0.cg));
            if (!slot0_end) {
                return std::unexpected(slot0_end.error());
            }
            size_t slot1_base = 0;
            if (!checked_add(plan.update_base, plan.slot_stride, slot1_base)) {
                return fail(ErrorCode::OutOfRange,
                            "System-update slot base exceeds the addressable payload layout");
            }
            if (*slot0_end > slot1_base && slot1.cf) {
                return fail(ErrorCode::InvalidArgument,
                            "System-update CF0/CG0 exceeds its slot stride while CF1/CG1 is "
                            "supplied");
            }
            if (*slot0_end <= slot1_base) {
                if (auto slot1_end = detail::add_update_slot_ranges(
                        ranges, "system-update CF1", "system-update CG1", slot1_base,
                        plan.slot_stride, serialized_size(slot1.cf), serialized_size(slot1.cg));
                    !slot1_end) {
                    return std::unexpected(std::move(slot1_end.error()));
                }
            }

            if (payloads.patchset) {
                if (payloads.patchset->kind == PatchSetKind::Jtag) {
                    const auto patch_bytes = serialize_patch_set(*payloads.patchset);
                    if (auto added = add("JTAG patch payload", plan.window_base + 0x1000,
                                         patch_bytes.size());
                        !added) {
                        return std::unexpected(std::move(added.error()));
                    }
                } else if (const auto* khv =
                               find_patch_section(*payloads.patchset, PatchSectionTarget::Khv)) {
                    if (serialize_khv_payload(*khv).size() > plan.slot_stride - plan.khv_prefix)
                        return fail(ErrorCode::OutOfRange,
                                    "Glitch KHV payload exceeds its patch-slot region");
                    if (auto added = add("Glitch KHV payload", slot1_base + plan.khv_prefix,
                                         plan.slot_stride - plan.khv_prefix);
                        !added) {
                        return std::unexpected(std::move(added.error()));
                    }
                }
            }
            return ranges;
        }

    } // namespace

    Result<void> FlashImage::payload_layout() const {
        const LayoutPlan plan = plan_layout(*this);

        const bool has_cb = has_parsed_bootloader_header(
            cb_section.cb_or_A, NANDBootloaderMagic::CB, sizeof(generic_header));
        const bool has_cd = has_parsed_bootloader_header(kernel_section.cd, NANDBootloaderMagic::CD,
                                                         sizeof(cd_header));
        if (has_cb && cb_section.cb_or_A.data.empty()) {
            return fail(ErrorCode::InvalidArgument,
                        "Required CB/A bootloader has no payload and cannot be serialized");
        }
        if (has_cd && kernel_section.cd.data.empty()) {
            return fail(ErrorCode::InvalidArgument,
                        "Required CD bootloader has no payload and cannot be serialized");
        }

        if (plan.glitch && system_update_1.cf)
            return fail(ErrorCode::InvalidArgument,
                        "Glitch overlay owns the second update slot; CF1/CG1 cannot be supplied");
        for (const auto* slot : {&system_update_0, &system_update_1}) {
            if (slot->cf &&
                align_16(slot->cf->serialize().size()) + (slot->cg ? sizeof(cg_header) : 0) >
                    plan.slot_stride)
                return fail(ErrorCode::OutOfRange,
                            "CF leaves insufficient room in its update slot");
        }
        if (system_update_0.cg && !system_update_0.cf) {
            return fail(ErrorCode::InvalidArgument,
                        "System-update CG0 requires a corresponding CF0");
        }
        if (system_update_1.cg && !system_update_1.cf) {
            return fail(ErrorCode::InvalidArgument,
                        "System-update CG1 requires a corresponding CF1");
        }

        const auto ranges = collect_payload_ranges(*this, plan);
        if (!ranges) {
            return std::unexpected(ranges.error());
        }
        return detail::check_overlaps(*ranges);
    }

} // namespace gxbuild3::nand
