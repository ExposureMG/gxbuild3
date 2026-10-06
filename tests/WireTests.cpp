// Tests for src/Wire.hpp: endian field types, record codecs, the stream Cursor, the compile-time
// rejections the convention relies on, and formatting through std::format and spdlog (Log.hpp).

#include "Endian.hpp"
#include "Error.hpp"
#include "Wire.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iostream>
#include <limits>
#include <memory>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

    namespace wire = gxbuild3::wire;
    using gxbuild3::ErrorCode;
    using gxbuild3::Result;

    using Bytes = std::vector<std::uint8_t>;

    // ---- A sample record -----------------------------------------------------------------------

    struct sample_record {
        wire::be16 magic;
        wire::be16 version;
        wire::le32 count;
        std::uint8_t tag[4];
        wire::be64 stamp;
        wire::be24 block;
        std::uint8_t flags;
        wire::le24 hash_block;
        char name[5];
    };
    static_assert(wire::WireLayout<sample_record>);
    static_assert(sizeof(sample_record) == 0x20);
    static_assert(offsetof(sample_record, version) == 0x02);
    static_assert(offsetof(sample_record, count) == 0x04);
    static_assert(offsetof(sample_record, tag) == 0x08);
    static_assert(offsetof(sample_record, stamp) == 0x0C);
    static_assert(offsetof(sample_record, block) == 0x14);
    static_assert(offsetof(sample_record, flags) == 0x17);
    static_assert(offsetof(sample_record, hash_block) == 0x18);
    static_assert(offsetof(sample_record, name) == 0x1B);

    constexpr sample_record make_sample() {
        sample_record r{};
        r.magic = 0x4342;
        r.version = 0x1F42;
        r.count = 0x11223344;
        r.tag[0] = 't';
        r.tag[1] = 'a';
        r.tag[2] = 'g';
        r.tag[3] = '!';
        r.stamp = 0x0102030405060708ULL;
        r.block = 0xABCDEF;
        r.flags = 0x5A;
        r.hash_block = 0x123456;
        r.name[0] = 'w';
        r.name[1] = 'i';
        r.name[2] = 'r';
        r.name[3] = 'e';
        r.name[4] = '\0';
        return r;
    }

    constexpr std::array<std::uint8_t, 0x20> kSampleImage = {
        0x43, 0x42, 0x1F, 0x42,                         // magic, version (big)
        0x44, 0x33, 0x22, 0x11,                         // count (little)
        't',  'a',  'g',  '!',                          // tag
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // stamp (big)
        0xAB, 0xCD, 0xEF,                               // block (be24)
        0x5A,                                           // flags
        0x56, 0x34, 0x12,                               // hash_block (le24)
        'w',  'i',  'r',  'e',  0x00,                   // name
    };

    // ---- Compile-time checks: constexpr round trips and encode ---------------------------------

    static_assert(wire::encode(wire::be16{0x1234}) == std::array<std::uint8_t, 2>{0x12, 0x34});
    static_assert(wire::encode(wire::le16{0x1234}) == std::array<std::uint8_t, 2>{0x34, 0x12});
    static_assert(wire::encode(wire::be32{0x11223344}) ==
                  std::array<std::uint8_t, 4>{0x11, 0x22, 0x33, 0x44});
    static_assert(wire::encode(wire::le32{0x11223344}) ==
                  std::array<std::uint8_t, 4>{0x44, 0x33, 0x22, 0x11});
    static_assert(wire::encode(wire::be64{0x0102030405060708ULL}) ==
                  std::array<std::uint8_t, 8>{1, 2, 3, 4, 5, 6, 7, 8});
    static_assert(wire::encode(wire::le64{0x0102030405060708ULL}) ==
                  std::array<std::uint8_t, 8>{8, 7, 6, 5, 4, 3, 2, 1});
    static_assert(wire::encode(wire::be24{0xABCDEF}) ==
                  std::array<std::uint8_t, 3>{0xAB, 0xCD, 0xEF});
    static_assert(wire::encode(wire::le24{0xABCDEF}) ==
                  std::array<std::uint8_t, 3>{0xEF, 0xCD, 0xAB});
    static_assert(wire::be24{0xFF123456}.get() == 0x123456, "be24 keeps the low 24 bits");
    static_assert(wire::encode(make_sample()) == kSampleImage);

    template <class W> constexpr bool round_trips(typename W::value_type value) {
        W field{};
        field = value;
        const W copy = std::bit_cast<W>(wire::encode(field));
        return copy.get() == value && static_cast<typename W::value_type>(copy) == value &&
               W{value}.raw() == field.raw();
    }
    static_assert(round_trips<wire::be16>(0xFEDC) && round_trips<wire::le16>(0xFEDC));
    static_assert(round_trips<wire::be32>(0xDEADBEEF) && round_trips<wire::le32>(0xDEADBEEF));
    static_assert(round_trips<wire::be64>(0xFEDCBA9876543210ULL) &&
                  round_trips<wire::le64>(0xFEDCBA9876543210ULL));
    static_assert(round_trips<wire::be24>(0xFEDCBA) && round_trips<wire::le24>(0xFEDCBA));
    static_assert(wire::be32{}.get() == 0, "value-initialised fields are zero");

    // ---- Compile-time checks: what the convention accepts --------------------------------------

    enum Magic : std::uint16_t {
        MagicCB = 0x4342,
        MagicCD = 0x4344,
    };

    constexpr int classify(const sample_record& r) {
        switch (r.magic) {
            case MagicCB:
                return 2;
            case MagicCD:
                return 4;
            default:
                return 0;
        }
    }
    static_assert(classify(make_sample()) == 2, "switch reads the host value");
    static_assert(make_sample().magic == MagicCB && make_sample().magic != 0x4344);
    static_assert((make_sample().version & 0x1000) != 0, "bitwise and on a field");
    static_assert(std::uint64_t{make_sample().count} + 0xF == 0x11223353ULL);
    static_assert((make_sample().magic ? make_sample().magic : 0xFF4F) == 0x4342,
                  "the conditional operator with a literal is unambiguous");
    static_assert(make_sample().count < make_sample().stamp, "mixed-width comparison");
    static_assert(std::max(make_sample().count.get(), 5u) == 0x11223344, "get() for std::max");
    static_assert(std::format_string<wire::be16>("{:04X}").get() == "{:04X}");

    // ---- Compile-time checks: what the convention rejects --------------------------------------

    template <class V>
    concept CanBswap16 = requires(V v) { gxbuild3::bswap16(v); };
    template <class V>
    concept CanBswap32 = requires(V v) { gxbuild3::bswap32(v); };
    template <class V>
    concept CanBswap64 = requires(V v) { gxbuild3::bswap64(v); };
    template <class V>
    concept CanStdByteswap = requires(V v) { std::byteswap(v); };
    template <class V>
    concept CanCompoundAssign = requires(V& v) { v += 4u; };
    template <class V>
    concept CanStdMaxWithUnsigned = requires(V v) { std::max(v, 5u); };

    // The legacy helpers still take host integers.
    static_assert(CanBswap16<std::uint16_t> && CanBswap32<std::uint32_t> &&
                  CanBswap64<std::uint64_t>);
    // A manual swap on a wire field does not compile: the deleted overloads win.
    static_assert(!CanBswap16<wire::be16> && !CanBswap16<wire::le16>);
    static_assert(!CanBswap32<wire::be32> && !CanBswap32<wire::le32>);
    static_assert(!CanBswap64<wire::be64> && !CanBswap64<wire::le64>);
    static_assert(!CanBswap32<wire::be24> && !CanBswap32<wire::le24>);
    static_assert(!CanStdByteswap<wire::be16> && !CanStdByteswap<wire::be32> &&
                  !CanStdByteswap<wire::be64>);
    // No compound assignment, no implicit construction, no pointer pun, no deduced std::max.
    static_assert(!CanCompoundAssign<wire::be32> && !CanCompoundAssign<wire::be24>);
    static_assert(!std::is_convertible_v<std::uint32_t, wire::be32>, "be32 v = 5u is rejected");
    static_assert(std::is_constructible_v<wire::be32, std::uint32_t>, "be32{5u} is fine");
    static_assert(!std::is_convertible_v<wire::be32*, std::uint32_t*>);
    static_assert(!CanStdMaxWithUnsigned<wire::be32>);
    static_assert(!wire::WireLayout<std::uint32_t>, "a host integer is not a wire field");

    // ---- Runtime helpers -----------------------------------------------------------------------

    int failures = 0;

    void check(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            ++failures;
        }
    }

    bool contains(std::string_view text, std::string_view needle) {
        return text.find(needle) != std::string_view::npos;
    }

    template <class T>
    void check_error(const Result<T>& result, ErrorCode code, std::string_view needle,
                     std::string_view message) {
        if (result) {
            check(false, std::format("{}: expected an error", message));
            return;
        }
        check(result.error().code == code, std::format("{}: wrong code '{}'", message,
                                                       gxbuild3::to_string(result.error().code)));
        check(contains(result.error().message, needle),
              std::format("{}: message '{}' lacks '{}'", message, result.error().message, needle));
    }

    // `lead` bytes of `fill`, then the sample image, then `trail` bytes of `fill`.
    Bytes sample_at(std::size_t lead, std::uint8_t fill, std::size_t trail = 0) {
        Bytes out(lead + kSampleImage.size() + trail, fill);
        std::copy(kSampleImage.begin(), kSampleImage.end(),
                  out.begin() + static_cast<std::ptrdiff_t>(lead));
        return out;
    }

    // ---- Records -------------------------------------------------------------------------------

    void test_read_round_trip() {
        const Bytes buffer = sample_at(0x10, 0xEE);

        const auto record = wire::read<sample_record>(buffer, 0x10, "sample");
        check(record.has_value(), "read succeeds when the record ends at the buffer end");
        if (!record) {
            return;
        }
        check(record->magic == 0x4342 && record->version == 0x1F42, "read be16 fields");
        check(record->count == 0x11223344, "read le32 field");
        check(record->stamp == 0x0102030405060708ULL, "read be64 field");
        check(record->block == 0xABCDEF && record->hash_block == 0x123456, "read 24-bit fields");
        check(record->flags == 0x5A && record->tag[3] == '!', "read byte fields");
        check(std::string_view(record->name) == "wire", "read char array");
        check(wire::encode(*record) == kSampleImage, "encode reproduces the read bytes");

        const auto view = wire::bytes_of(*record);
        check(std::equal(view.begin(), view.end(), kSampleImage.begin(), kSampleImage.end()),
              "bytes_of views the on-disk image");
    }

    void test_read_truncated() {
        const Bytes buffer(0x30, 0);
        check_error(wire::read<sample_record>(buffer, 0x11, "sample"), ErrorCode::Truncated,
                    "sample: need 0x20 bytes at offset 0x11, 0x1f available",
                    "read one byte short");
        check_error(wire::read<sample_record>(buffer, 0x40, "sample"), ErrorCode::Truncated,
                    "need 0x20 bytes at offset 0x40, 0x0 available", "read past the end");
        check_error(wire::read<wire::be32>(buffer, std::numeric_limits<std::size_t>::max(), "word"),
                    ErrorCode::Truncated, "word: need 0x4 bytes", "read at SIZE_MAX cannot wrap");
        check_error(wire::read<wire::be16>(std::span<const std::uint8_t>{}, 0, "empty"),
                    ErrorCode::Truncated, "at offset 0x0, 0x0 available", "read from empty");
        check(wire::read<wire::be16>(buffer, 0x2E, "tail").has_value(), "read the last two bytes");
    }

    void test_read_head() {
        Bytes buffer = sample_at(0, 0, 2);
        buffer[0x20] = 0x99;
        buffer[0x21] = 0x98;
        const auto head = wire::read_head<sample_record>(buffer, "sample");
        check(head.has_value(), "read_head succeeds");
        if (head) {
            check(head->value.magic == 0x4342, "read_head decodes the record");
            check(head->rest.size() == 2 && head->rest[0] == 0x99 &&
                      head->rest.data() == buffer.data() + 0x20,
                  "read_head rest borrows the bytes after the record");
        }
        check_error(wire::read_head<sample_record>(std::span(buffer).first(0x1F), "sample"),
                    ErrorCode::Truncated, "need 0x20 bytes at offset 0x0, 0x1f available",
                    "read_head on a short span");
    }

    void test_write() {
        Bytes buffer(0x24, 0xCC);
        check(wire::write(std::span(buffer), 0x04, make_sample(), "sample").has_value(),
              "write succeeds when the record ends at the buffer end");
        check(std::equal(buffer.begin() + 4, buffer.end(), kSampleImage.begin()),
              "write stores the on-disk image");
        check(buffer[3] == 0xCC, "write leaves the bytes before it alone");

        const Bytes before = buffer;
        check_error(wire::write(std::span(buffer), 0x05, make_sample(), "sample"),
                    ErrorCode::OutOfRange, "sample: cannot write 0x20 bytes at offset 0x5, 0x1f",
                    "write one byte short");
        check_error(wire::write(std::span(buffer), std::numeric_limits<std::size_t>::max(),
                                wire::be16{1}, "word"),
                    ErrorCode::OutOfRange, "word: cannot write 0x2 bytes",
                    "write at SIZE_MAX cannot wrap");
        check(buffer == before, "a failed write leaves the buffer untouched");
    }

    void test_patch() {
        Bytes buffer = sample_at(0x10, 0);
        const auto patched = wire::patch<sample_record>(
            buffer, 0x10, "sample", [](sample_record& r) { r.count = 0xA0B0C0D0; });
        check(patched.has_value(), "patch succeeds");
        Bytes expected = sample_at(0x10, 0);
        expected[0x14] = 0xD0;
        expected[0x15] = 0xC0;
        expected[0x16] = 0xB0;
        expected[0x17] = 0xA0;
        check(buffer == expected, "patch rewrites only the edited field");

        bool called = false;
        check_error(wire::patch<sample_record>(buffer, 0x11, "sample",
                                               [&called](sample_record&) { called = true; }),
                    ErrorCode::Truncated, "sample: need 0x20 bytes at offset 0x11",
                    "patch past the end");
        check(!called, "patch does not call edit when the record does not fit");
        check(buffer == expected, "a failed patch leaves the buffer untouched");
    }

    void test_append() {
        Bytes out{0x01};
        wire::append(out, wire::be32{0x0A0B0C0D});
        wire::append(out, wire::le16{0x0102});
        wire::append(out, make_sample());
        Bytes expected = sample_at(7, 0);
        const std::array<std::uint8_t, 7> lead{0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x02, 0x01};
        std::copy(lead.begin(), lead.end(), expected.begin());
        check(out == expected, "append adds the on-disk images in order");
    }

    void test_as_u8() {
        const std::array<std::byte, 4> storage{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                                               std::byte{0xEF}};
        const auto view = wire::as_u8(storage);
        check(view.size() == 4 && view.data() == reinterpret_cast<const std::uint8_t*>(&storage),
              "as_u8 views the same storage");
        const auto word = wire::read<wire::be32>(view, 0, "word");
        check(word.has_value() && *word == 0xDEADBEEF, "as_u8 feeds wire::read");
        check(word.has_value() && *word == gxbuild3::read_be32(storage.data()),
              "wire::read agrees with the legacy read_be32");
    }

    // ---- Cursor --------------------------------------------------------------------------------

    void test_cursor_takes() {
        const Bytes stream{0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03};
        wire::Cursor cursor(stream, 0x1000);
        check(cursor.offset() == 0x1000 && cursor.remaining() == 11 && !cursor.at_end(),
              "a new cursor starts at its base");

        const auto count = cursor.take<wire::be32>("count");
        check(count.has_value() && *count == 2, "take decodes a be32");
        check(cursor.offset() == 0x1004 && cursor.remaining() == 7, "take advances");

        const auto words = cursor.take_bytes(4, "words");
        check(words.has_value() && words->size() == 4 && (*words)[0] == 0xAA &&
                  words->data() == stream.data() + 4,
              "take_bytes borrows the caller's storage");

        const auto tail = cursor.take<wire::be24>("tail");
        check(tail.has_value() && *tail == 0x010203, "take decodes a be24");
        check(cursor.at_end() && cursor.offset() == 0x100B, "the cursor reaches the end");
        check(cursor.consumed().size() == stream.size() &&
                  cursor.consumed().data() == stream.data(),
              "consumed covers everything taken");
    }

    void test_cursor_failures_are_not_sticky() {
        const Bytes stream{0x12, 0x34, 0x56};
        wire::Cursor cursor(stream, 0x200);

        check_error(cursor.take<wire::be32>("KHV address"), ErrorCode::Truncated,
                    "KHV address: need 0x4 bytes at offset 0x200, 0x3 available",
                    "take reports the absolute offset");
        check(cursor.offset() == 0x200 && cursor.remaining() == 3,
              "a failed take does not advance");

        const auto first = cursor.take<wire::be16>("first");
        check(first.has_value() && *first == 0x1234, "takes after a failure still work");

        check_error(cursor.take_bytes(2, "words"), ErrorCode::Truncated,
                    "words: need 0x2 bytes at offset 0x202, 0x1 available",
                    "take_bytes reports the absolute offset");
        check_error(cursor.skip(std::numeric_limits<std::size_t>::max(), "skip"),
                    ErrorCode::Truncated, "at offset 0x202, 0x1 available",
                    "skip of SIZE_MAX cannot wrap");
        check(cursor.offset() == 0x202, "failed take_bytes and skip do not advance");
        check(cursor.skip(1, "last").has_value() && cursor.at_end(), "skip to the end");
        check(cursor.skip(0, "nothing").has_value(), "skip 0 at the end succeeds");
        check(cursor.take_bytes(0, "nothing").has_value(), "take_bytes 0 at the end succeeds");
        check(cursor.consumed().size() == 3, "consumed after skip");
    }

    void test_cursor_sub() {
        const Bytes stream{0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99};
        wire::Cursor parent(stream, 0x40);
        check(parent.skip(2, "lead").has_value(), "skip the lead");

        auto sub = parent.sub(5, "section");
        check(sub.has_value(), "sub succeeds");
        check(parent.offset() == 0x47 && parent.remaining() == 1, "sub advances the parent");
        if (!sub) {
            return;
        }
        check(sub->offset() == 0x42 && sub->remaining() == 5,
              "sub is based at its absolute offset");
        const auto word = sub->take<wire::be32>("word");
        check(word.has_value() && *word == 0xAABBCCDD, "sub reads its own bytes");
        check_error(sub->take<wire::be16>("half"), ErrorCode::Truncated,
                    "half: need 0x2 bytes at offset 0x46, 0x1 available",
                    "sub reports absolute offsets and stops at its own end");

        check_error(parent.sub(2, "next"), ErrorCode::Truncated,
                    "next: need 0x2 bytes at offset 0x47, 0x1 available", "sub past the end");
        check(parent.offset() == 0x47, "a failed sub does not advance the parent");
    }

    // ---- Formatting ----------------------------------------------------------------------------

    void test_std_format() {
        const auto r = make_sample();
        check(std::format("{:04X} {:#x} {}", r.magic, r.count, r.block) ==
                  "4342 0x11223344 11259375",
              "std::format reads the host value");
        const Result<void> failed =
            gxbuild3::fail(ErrorCode::Malformed, "bad magic {:04X} at {:#x}", r.magic, r.stamp);
        check(!failed && failed.error().message == "bad magic 4342 at 0x102030405060708",
              "fail() formats wire fields");
    }

    // Formats wire fields through gxbuild3::Log (spdlog with its bundled fmt) without .get():
    // fmt picks up wire::format_as by ADL.
    void test_spdlog_format_as() {
        gxbuild3::Log::Init();
        std::ostringstream captured;
        const auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(captured);
        sink->set_pattern("%v");
        const auto logger = spdlog::get("GxBuild3");
        check(logger != nullptr, "Log::Init registers the GxBuild3 logger");
        if (!logger) {
            return;
        }
        logger->sinks().clear();
        logger->sinks().push_back(sink);

        const auto r = make_sample();
        gxbuild3::Log::Info("magic {:04X} version {} count {:#x} block {:06X} stamp {:#x}", r.magic,
                            r.version, r.count, r.block, r.stamp);
        logger->flush();
        gxbuild3::Log::Shutdown();

        check(
            captured.str() ==
                "magic 4342 version 8002 count 0x11223344 block ABCDEF stamp 0x102030405060708\n",
            std::format("Log::Info formats wire fields without .get(), got '{}'", captured.str()));
    }

} // namespace

int main() {
    test_read_round_trip();
    test_read_truncated();
    test_read_head();
    test_write();
    test_patch();
    test_append();
    test_as_u8();
    test_cursor_takes();
    test_cursor_failures_are_not_sticky();
    test_cursor_sub();
    test_std_format();
    test_spdlog_format_as();
    if (failures != 0) {
        std::cerr << failures << " wire check(s) failed\n";
        return 1;
    }
    std::cout << "Wire tests passed (spdlog formats be16/be32/be64/be24 via format_as)\n";
    return 0;
}
