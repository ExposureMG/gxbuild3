// Compile-time pins of src/Wire.hpp: the sample record's on-disk layout, constexpr encode and
// round trips of every field type, what the convention accepts (switch, comparisons, bitwise
// and arithmetic on host values) and what it rejects (manual swaps through the deleted
// overloads, std::byteswap, compound assignment, implicit construction, deduced std::max).
// The requires-expressions stay fully qualified (gxbuild3::bswap16 and so on), so a negative
// concept cannot flip through name lookup in this namespace. One run-time case gives the pins
// a listed test name.

#include "Wire.hpp"
#include "core/WireSample.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <type_traits>

namespace gxbuild3::core {
    namespace {

        // ---- The sample record's layout ----------------------------------------------------

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

        // ---- Compile-time checks: constexpr round trips and encode -------------------------

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

        // ---- Compile-time checks: what the convention accepts ------------------------------

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

        // ---- Compile-time checks: what the convention rejects ------------------------------

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

        // Endian.hpp is gone: no host-integer bswap helper is left; std::byteswap is the host
        // swap.
        static_assert(!CanBswap16<std::uint16_t> && !CanBswap32<std::uint32_t> &&
                      !CanBswap64<std::uint64_t>);
        static_assert(CanStdByteswap<std::uint16_t> && CanStdByteswap<std::uint32_t> &&
                      CanStdByteswap<std::uint64_t>);
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

        // ---- Run time ----------------------------------------------------------------------

        TEST(WireLayoutPins, SampleRecordEncodesToTheSampleImageAtRunTime) {
            const sample_record sample = make_sample();
            EXPECT_BYTES_EQ(kSampleImage, wire::encode(sample))
                << "encode(make_sample()) reproduces kSampleImage outside constant evaluation";
        }

    } // namespace
} // namespace gxbuild3::core
