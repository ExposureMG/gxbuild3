#pragma once

// Internal pieces of FlashImage::payload_layout, declared here so tests can drive the
// overflow paths a real image cannot reach. Defined in FlashImage.cpp.

#include "Error.hpp"

#include <cstddef>
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

} // namespace gxbuild3::nand::detail
