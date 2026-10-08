// The payload layout's overflow steps (src/nand/FlashImageLayout.hpp, detail::add_payload_range,
// add_update_slot_ranges and check_overlaps), driven directly: a parsed or built image cannot
// reach them on 64-bit, so this pins their exact texts and their precedence (a CF or CG range
// overflow is reported as its slot's span) and the first-pair order of the collision check.

#include "nand/FlashImageLayout.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <gtest/gtest.h>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using detail::PayloadRange;
        using RangeFields = std::tuple<std::string_view, size_t, size_t>;

        // The recorded ranges as (name, offset, length), so one EXPECT prints them all.
        std::vector<RangeFields> fields_of(std::span<const PayloadRange> ranges) {
            std::vector<RangeFields> fields;
            for (const auto& range : ranges) {
                fields.emplace_back(range.name, range.offset, range.length);
            }
            return fields;
        }

        // EXPECT_ERROR_MSG compares describe(), which is the message alone only when the error
        // carries no context: the old helper's code, exact message and empty context.
        TEST(PayloadRange, OverflowsKeepTheirExactTextsAndSlotSpanPrecedence) {
            constexpr size_t kMax = std::numeric_limits<size_t>::max();
            constexpr std::string_view kCfSpan =
                "System-update CF span exceeds the addressable payload layout";
            constexpr std::string_view kCgSpan =
                "System-update CG span exceeds the addressable payload layout";

            std::vector<PayloadRange> ranges;
            EXPECT_OK(detail::add_payload_range(ranges, "empty", kMax, 0))
                << "an empty payload range is accepted and not recorded";
            EXPECT_TRUE(ranges.empty()) << "an empty payload range is accepted and not recorded";
            const auto range_overflow = detail::add_payload_range(ranges, "XeLL", kMax - 3, 8);
            EXPECT_ERROR_MSG(range_overflow, ErrorCode::OutOfRange,
                             "Payload layout range overflow for XeLL")
                << "an overflowing payload range fails with its name and is not recorded";
            EXPECT_TRUE(ranges.empty())
                << "an overflowing payload range fails with its name and is not recorded";

            ranges.clear();
            const auto cf_range = detail::add_update_slot_ranges(
                ranges, "CF0", "CG0", kMax - 4, 0x10000, size_t{0x10}, std::nullopt);
            EXPECT_ERROR_MSG(cf_range, ErrorCode::OutOfRange, kCfSpan)
                << "a CF range overflow is reported as the CF span";
            const auto cf_align = detail::add_update_slot_ranges(ranges, "CF0", "CG0", 0, 0x10000,
                                                                 kMax - 3, std::nullopt);
            EXPECT_ERROR_MSG(cf_align, ErrorCode::OutOfRange, kCfSpan)
                << "a CF that cannot be 16-aligned is reported as the CF span";
            const auto cf_end = detail::add_update_slot_ranges(ranges, "CF0", "CG0", kMax - 0x1F,
                                                               0x10000, size_t{0x11}, std::nullopt);
            EXPECT_ERROR_MSG(cf_end, ErrorCode::OutOfRange, kCfSpan)
                << "a CF whose aligned end overflows is reported as the CF span";

            ranges.clear();
            const auto cg_align = detail::add_update_slot_ranges(ranges, "CF0", "CG0", 0x1000,
                                                                 0x10000, size_t{0x20}, kMax - 3);
            EXPECT_ERROR_MSG(cg_align, ErrorCode::OutOfRange, kCgSpan)
                << "a CG that cannot be 16-aligned is reported as the CG span";
            const auto cg_end = detail::add_update_slot_ranges(ranges, "CF0", "CG0", kMax - 0x2F,
                                                               0x10, size_t{0x10}, size_t{0x20});
            EXPECT_ERROR_MSG(cg_end, ErrorCode::OutOfRange, kCgSpan)
                << "a CG whose aligned end overflows is reported as the CG span";

            ranges.clear();
            const auto no_cf = detail::add_update_slot_ranges(ranges, "CF0", "CG0", 0x70000,
                                                              0x10000, std::nullopt, size_t{0x20});
            EXPECT_OK(no_cf) << "a slot without a CF ends at its base and records nothing";
            EXPECT_EQ(no_cf.value_or(0), 0x70000u)
                << "a slot without a CF ends at its base and records nothing";
            EXPECT_TRUE(ranges.empty())
                << "a slot without a CF ends at its base and records nothing";
            const auto spilled = detail::add_update_slot_ranges(
                ranges, "CF0", "CG0", 0x70000, 0x10000, size_t{0x123}, size_t{0x20000});
            EXPECT_OK(spilled)
                << "a spilling CG records only its in-slot prefix and the slot end is clamped";
            EXPECT_EQ(spilled.value_or(0), 0x80000u)
                << "a spilling CG records only its in-slot prefix and the slot end is clamped";
            EXPECT_EQ(fields_of(ranges),
                      (std::vector<RangeFields>{{"CF0", 0x70000, 0x123},
                                                {"CG0", 0x70130, 0x10000 - 0x130}}))
                << "a spilling CG records only its in-slot prefix and the slot end is clamped";

            const std::vector<PayloadRange> overlapping{
                {"first", 0x0, 0x10}, {"second", 0x20, 0x10}, {"third", 0x8, 0x20}};
            EXPECT_ERROR_MSG(detail::check_overlaps(overlapping), ErrorCode::InvalidArgument,
                             "Payload layout collision: first overlaps third")
                << "the first overlapping pair in index order is reported";
            const std::vector<PayloadRange> disjoint{{"a", 0x0, 0x10}, {"b", 0x10, 0x10}};
            EXPECT_OK(detail::check_overlaps(disjoint)) << "touching ranges do not collide";
        }

    } // namespace
} // namespace gxbuild3::nand
