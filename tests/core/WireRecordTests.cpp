// src/Wire.hpp record codecs: read, read_head, write, patch, append, bytes_of and as_u8 over the
// sample record (core/WireSample.hpp), including the bounds checks that cannot wrap and leave
// the buffer untouched on failure.

#include "Error.hpp"
#include "Wire.hpp"
#include "core/WireSample.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <span>
#include <string_view>

namespace gxbuild3::core {
    namespace {

        using test::Bytes;

        // `lead` bytes of `fill`, then the sample image, then `trail` bytes of `fill`.
        Bytes sample_at(std::size_t lead, std::uint8_t fill, std::size_t trail = 0) {
            Bytes out(lead + kSampleImage.size() + trail, fill);
            std::copy(kSampleImage.begin(), kSampleImage.end(),
                      out.begin() + static_cast<std::ptrdiff_t>(lead));
            return out;
        }

        TEST(WireRecord, ReadDecodesEveryFieldAndEncodeReproducesTheBytes) {
            const Bytes buffer = sample_at(0x10, 0xEE);

            const auto record = wire::read<sample_record>(buffer, 0x10, "sample");
            ASSERT_OK(record) << "read succeeds when the record ends at the buffer end";
            EXPECT_EQ(record->magic, 0x4342) << "read be16 fields";
            EXPECT_EQ(record->version, 0x1F42) << "read be16 fields";
            EXPECT_EQ(record->count, 0x11223344u) << "read le32 field";
            EXPECT_EQ(record->stamp, 0x0102030405060708ULL) << "read be64 field";
            EXPECT_EQ(record->block, 0xABCDEFu) << "read 24-bit fields";
            EXPECT_EQ(record->hash_block, 0x123456u) << "read 24-bit fields";
            EXPECT_EQ(record->flags, 0x5A) << "read byte fields";
            EXPECT_EQ(record->tag[3], '!') << "read byte fields";
            EXPECT_EQ(std::string_view(record->name), "wire") << "read char array";
            EXPECT_BYTES_EQ(kSampleImage, wire::encode(*record))
                << "encode reproduces the read bytes";

            const auto view = wire::bytes_of(*record);
            EXPECT_BYTES_EQ(kSampleImage, view) << "bytes_of views the on-disk image";
        }

        TEST(WireRecord, ReadFailsTruncatedWithoutWrappingAndReadsTheLastBytes) {
            const Bytes buffer(0x30, 0);
            EXPECT_ERROR_HAS(wire::read<sample_record>(buffer, 0x11, "sample"),
                             ErrorCode::Truncated,
                             "sample: need 0x20 bytes at offset 0x11, 0x1f available")
                << "read one byte short";
            EXPECT_ERROR_HAS(wire::read<sample_record>(buffer, 0x40, "sample"),
                             ErrorCode::Truncated, "need 0x20 bytes at offset 0x40, 0x0 available")
                << "read past the end";
            EXPECT_ERROR_HAS(
                wire::read<wire::be32>(buffer, std::numeric_limits<std::size_t>::max(), "word"),
                ErrorCode::Truncated, "word: need 0x4 bytes")
                << "read at SIZE_MAX cannot wrap";
            EXPECT_ERROR_HAS(wire::read<wire::be16>(std::span<const std::uint8_t>{}, 0, "empty"),
                             ErrorCode::Truncated, "at offset 0x0, 0x0 available")
                << "read from empty";
            EXPECT_OK(wire::read<wire::be16>(buffer, 0x2E, "tail")) << "read the last two bytes";
        }

        TEST(WireRecord, ReadHeadDecodesTheRecordAndBorrowsTheRest) {
            Bytes buffer = sample_at(0, 0, 2);
            buffer[0x20] = 0x99;
            buffer[0x21] = 0x98;
            const auto head = wire::read_head<sample_record>(buffer, "sample");
            EXPECT_ERROR_HAS(
                wire::read_head<sample_record>(std::span(buffer).first(0x1F), "sample"),
                ErrorCode::Truncated, "need 0x20 bytes at offset 0x0, 0x1f available")
                << "read_head on a short span";
            ASSERT_OK(head) << "read_head succeeds";
            EXPECT_EQ(head->value.magic, 0x4342) << "read_head decodes the record";
            ASSERT_EQ(head->rest.size(), 2u) << "read_head rest borrows the bytes after the record";
            EXPECT_EQ(head->rest[0], 0x99) << "read_head rest borrows the bytes after the record";
            EXPECT_EQ(head->rest.data(), buffer.data() + 0x20)
                << "read_head rest borrows the bytes after the record";
        }

        TEST(WireRecord, WriteStoresTheImageAndAFailedWriteLeavesTheBufferUntouched) {
            Bytes buffer(0x24, 0xCC);
            EXPECT_OK(wire::write(std::span(buffer), 0x04, make_sample(), "sample"))
                << "write succeeds when the record ends at the buffer end";
            EXPECT_BYTES_EQ(kSampleImage, std::span(buffer).subspan(4))
                << "write stores the on-disk image";
            EXPECT_EQ(buffer[3], 0xCC) << "write leaves the bytes before it alone";

            const Bytes before = buffer;
            EXPECT_ERROR_HAS(wire::write(std::span(buffer), 0x05, make_sample(), "sample"),
                             ErrorCode::OutOfRange,
                             "sample: cannot write 0x20 bytes at offset 0x5, 0x1f")
                << "write one byte short";
            EXPECT_ERROR_HAS(wire::write(std::span(buffer), std::numeric_limits<std::size_t>::max(),
                                         wire::be16{1}, "word"),
                             ErrorCode::OutOfRange, "word: cannot write 0x2 bytes")
                << "write at SIZE_MAX cannot wrap";
            EXPECT_BYTES_EQ(before, buffer) << "a failed write leaves the buffer untouched";
        }

        TEST(WireRecord, PatchRewritesOnlyTheEditedFieldAndSkipsTheEditWhenTheRecordDoesNotFit) {
            Bytes buffer = sample_at(0x10, 0);
            const auto patched = wire::patch<sample_record>(
                buffer, 0x10, "sample", [](sample_record& r) { r.count = 0xA0B0C0D0; });
            EXPECT_OK(patched) << "patch succeeds";
            Bytes expected = sample_at(0x10, 0);
            expected[0x14] = 0xD0;
            expected[0x15] = 0xC0;
            expected[0x16] = 0xB0;
            expected[0x17] = 0xA0;
            EXPECT_BYTES_EQ(expected, buffer) << "patch rewrites only the edited field";

            bool called = false;
            const auto past_the_end = wire::patch<sample_record>(
                buffer, 0x11, "sample", [&called](sample_record&) { called = true; });
            EXPECT_ERROR_HAS(past_the_end, ErrorCode::Truncated,
                             "sample: need 0x20 bytes at offset 0x11")
                << "patch past the end";
            EXPECT_FALSE(called) << "patch does not call edit when the record does not fit";
            EXPECT_BYTES_EQ(expected, buffer) << "a failed patch leaves the buffer untouched";
        }

        TEST(WireRecord, AppendAddsTheOnDiskImagesInOrder) {
            Bytes out{0x01};
            wire::append(out, wire::be32{0x0A0B0C0D});
            wire::append(out, wire::le16{0x0102});
            wire::append(out, make_sample());
            Bytes expected = sample_at(7, 0);
            const std::array<std::uint8_t, 7> lead{0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x02, 0x01};
            std::copy(lead.begin(), lead.end(), expected.begin());
            EXPECT_BYTES_EQ(expected, out) << "append adds the on-disk images in order";
        }

        TEST(WireRecord, AsU8ViewsByteStorageAndFeedsRead) {
            const std::array<std::byte, 4> storage{std::byte{0xDE}, std::byte{0xAD},
                                                   std::byte{0xBE}, std::byte{0xEF}};
            const auto view = wire::as_u8(storage);
            EXPECT_EQ(view.size(), 4u) << "as_u8 views the same storage";
            EXPECT_EQ(view.data(), reinterpret_cast<const std::uint8_t*>(&storage))
                << "as_u8 views the same storage";
            const auto word = wire::read<wire::be32>(view, 0, "word");
            ASSERT_OK(word) << "as_u8 feeds wire::read";
            EXPECT_EQ(*word, 0xDEADBEEFu) << "as_u8 feeds wire::read";
            const auto host = std::bit_cast<std::uint32_t>(storage);
            const std::uint32_t big_endian =
                std::endian::native == std::endian::big ? host : std::byteswap(host);
            EXPECT_EQ(*word, big_endian)
                << "wire::read agrees with a std::byteswap of the host word";
        }

    } // namespace
} // namespace gxbuild3::core
