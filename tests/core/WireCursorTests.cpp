// src/Wire.hpp Cursor: takes decode, advance and borrow the caller's storage; failures are not
// sticky, never advance and report absolute offsets; a sub-cursor is based at its absolute
// offset and stops at its own end.

#include "Error.hpp"
#include "Wire.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>

namespace gxbuild3::core {
    namespace {

        using test::Bytes;

        TEST(WireCursor, TakesDecodeAdvanceAndBorrowTheCallersStorage) {
            const Bytes stream{0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03};
            wire::Cursor cursor(stream, 0x1000);
            EXPECT_EQ(cursor.offset(), 0x1000u) << "a new cursor starts at its base";
            EXPECT_EQ(cursor.remaining(), 11u) << "a new cursor starts at its base";
            EXPECT_FALSE(cursor.at_end()) << "a new cursor starts at its base";

            const auto count = cursor.take<wire::be32>("count");
            ASSERT_OK(count) << "take decodes a be32";
            EXPECT_EQ(*count, 2u) << "take decodes a be32";
            EXPECT_EQ(cursor.offset(), 0x1004u) << "take advances";
            EXPECT_EQ(cursor.remaining(), 7u) << "take advances";

            const auto words = cursor.take_bytes(4, "words");
            ASSERT_OK(words) << "take_bytes borrows the caller's storage";
            ASSERT_EQ(words->size(), 4u) << "take_bytes borrows the caller's storage";
            EXPECT_EQ((*words)[0], 0xAA) << "take_bytes borrows the caller's storage";
            EXPECT_EQ(words->data(), stream.data() + 4)
                << "take_bytes borrows the caller's storage";

            const auto tail = cursor.take<wire::be24>("tail");
            ASSERT_OK(tail) << "take decodes a be24";
            EXPECT_EQ(*tail, 0x010203u) << "take decodes a be24";
            EXPECT_TRUE(cursor.at_end()) << "the cursor reaches the end";
            EXPECT_EQ(cursor.offset(), 0x100Bu) << "the cursor reaches the end";
            EXPECT_EQ(cursor.consumed().size(), stream.size())
                << "consumed covers everything taken";
            EXPECT_EQ(cursor.consumed().data(), stream.data())
                << "consumed covers everything taken";
        }

        TEST(WireCursor, FailuresAreNotStickyDoNotAdvanceAndReportAbsoluteOffsets) {
            const Bytes stream{0x12, 0x34, 0x56};
            wire::Cursor cursor(stream, 0x200);

            EXPECT_ERROR_HAS(cursor.take<wire::be32>("KHV address"), ErrorCode::Truncated,
                             "KHV address: need 0x4 bytes at offset 0x200, 0x3 available")
                << "take reports the absolute offset";
            EXPECT_EQ(cursor.offset(), 0x200u) << "a failed take does not advance";
            EXPECT_EQ(cursor.remaining(), 3u) << "a failed take does not advance";

            const auto first = cursor.take<wire::be16>("first");
            ASSERT_OK(first) << "takes after a failure still work";
            EXPECT_EQ(*first, 0x1234) << "takes after a failure still work";

            EXPECT_ERROR_HAS(cursor.take_bytes(2, "words"), ErrorCode::Truncated,
                             "words: need 0x2 bytes at offset 0x202, 0x1 available")
                << "take_bytes reports the absolute offset";
            EXPECT_ERROR_HAS(cursor.skip(std::numeric_limits<std::size_t>::max(), "skip"),
                             ErrorCode::Truncated, "at offset 0x202, 0x1 available")
                << "skip of SIZE_MAX cannot wrap";
            EXPECT_EQ(cursor.offset(), 0x202u) << "failed take_bytes and skip do not advance";
            EXPECT_OK(cursor.skip(1, "last")) << "skip to the end";
            EXPECT_TRUE(cursor.at_end()) << "skip to the end";
            EXPECT_OK(cursor.skip(0, "nothing")) << "skip 0 at the end succeeds";
            EXPECT_OK(cursor.take_bytes(0, "nothing")) << "take_bytes 0 at the end succeeds";
            EXPECT_EQ(cursor.consumed().size(), 3u) << "consumed after skip";
        }

        TEST(WireCursor, SubIsBasedAtItsAbsoluteOffsetAndAdvancesTheParent) {
            const Bytes stream{0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99};
            wire::Cursor parent(stream, 0x40);
            EXPECT_OK(parent.skip(2, "lead")) << "skip the lead";

            auto sub = parent.sub(5, "section");
            EXPECT_EQ(parent.offset(), 0x47u) << "sub advances the parent";
            EXPECT_EQ(parent.remaining(), 1u) << "sub advances the parent";
            ASSERT_OK(sub) << "sub succeeds";
            EXPECT_EQ(sub->offset(), 0x42u) << "sub is based at its absolute offset";
            EXPECT_EQ(sub->remaining(), 5u) << "sub is based at its absolute offset";
            const auto word = sub->take<wire::be32>("word");
            ASSERT_OK(word) << "sub reads its own bytes";
            EXPECT_EQ(*word, 0xAABBCCDDu) << "sub reads its own bytes";
            EXPECT_ERROR_HAS(sub->take<wire::be16>("half"), ErrorCode::Truncated,
                             "half: need 0x2 bytes at offset 0x46, 0x1 available")
                << "sub reports absolute offsets and stops at its own end";

            EXPECT_ERROR_HAS(parent.sub(2, "next"), ErrorCode::Truncated,
                             "next: need 0x2 bytes at offset 0x47, 0x1 available")
                << "sub past the end";
            EXPECT_EQ(parent.offset(), 0x47u) << "a failed sub does not advance the parent";
        }

    } // namespace
} // namespace gxbuild3::core
