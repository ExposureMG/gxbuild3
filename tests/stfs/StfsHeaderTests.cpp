// src/stfs/HeaderParser.hpp: parse_header and read_header_from_file need the whole 0x22C-byte
// header, a CON header's ConSignature fields come from their spec offsets, and
// StfsContainer::open refuses an absurd header_size.

#include "PirsPackage.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <variant>

namespace gxbuild3::stfs {
    namespace {

        using pirs::Bytes;
        using pirs::make_package;
        using pirs::pattern;
        using pirs::put_be;

        TEST(StfsHeader, ParseHeaderRejectsA0x1B0ByteBufferAndParsesA0x22CByteHeader) {
            Bytes data(0x1B0, std::byte{0});
            for (std::size_t i = 0; i < 4; ++i) {
                data[i] = static_cast<std::byte>("PIRS"[i]);
            }
            EXPECT_ERROR(parse_header(data), ErrorCode::Truncated)
                << "a 0x1B0-byte PIRS header must be rejected, not over-read";

            data.resize(0x22C);
            const auto header = parse_header(data);
            ASSERT_OK(header) << "a full 0x22C-byte header parses";
            EXPECT_EQ(header->magic, Magic::PIRS) << "a full 0x22C-byte header parses";
        }

        // A synthetic CON header whose bytes are all distinct-ish: every ConSignature field must
        // come from its spec offset (0x004 + the con_signature_disk offset) in on-disk order.
        TEST(StfsHeader, ConSignatureFieldsDecodeFromTheirSpecOffsets) {
            Bytes data(0x22C);
            for (std::size_t i = 0; i < data.size(); ++i) {
                data[i] = static_cast<std::byte>((i * 7 + 3) & 0xFF);
            }
            for (std::size_t i = 0; i < 4; ++i) {
                data[i] = static_cast<std::byte>("CON "[i]);
            }

            const auto header = parse_header(data);
            ASSERT_OK(header) << "a CON header parses";
            EXPECT_EQ(header->magic, Magic::CON) << "a CON header parses";
            const auto* con = std::get_if<ConSignature>(&header->signature);
            ASSERT_NE(con, nullptr) << "a CON header carries a ConSignature";

            const auto matches = [&data](const auto& field, std::size_t offset) {
                const auto* bytes = reinterpret_cast<const std::byte*>(field.data());
                return std::equal(bytes, bytes + field.size(), data.begin() + offset);
            };
            const auto byte_at = [&data](std::size_t offset) {
                return std::to_integer<std::uint32_t>(data[offset]);
            };

            EXPECT_EQ(con->public_key_certificate_size, (byte_at(0x004) << 8) | byte_at(0x005))
                << "public_key_certificate_size is big-endian at 0x004";
            EXPECT_TRUE(matches(con->certificate_owner_console_id, 0x006)) << "console id at 0x006";
            EXPECT_TRUE(matches(con->certificate_owner_console_part_number, 0x00B))
                << "console part number at 0x00B";
            EXPECT_EQ(con->certificate_owner_console_type, byte_at(0x01F))
                << "console type at 0x01F";
            EXPECT_TRUE(matches(con->certificate_date_of_generation, 0x020)) << "date at 0x020";
            EXPECT_TRUE(matches(con->public_exponent, 0x028)) << "public exponent at 0x028";
            EXPECT_TRUE(matches(con->public_modulus, 0x02C)) << "public modulus at 0x02C";
            EXPECT_TRUE(matches(con->certificate_signature, 0x0AC))
                << "certificate signature at 0x0AC";
            EXPECT_TRUE(matches(con->signature, 0x1AC)) << "signature at 0x1AC";
        }

        TEST(StfsHeader, ReadHeaderFromFileRequiresTheFullHeader) {
            const test::ScratchDir dir;
            Bytes data(0x1B0, std::byte{0});
            for (std::size_t i = 0; i < 4; ++i) {
                data[i] = static_cast<std::byte>("PIRS"[i]);
            }
            ASSERT_OK(test::write_file(dir.path() / "short", pirs::as_u8(data)))
                << "fixture file must be writable";
            EXPECT_ERROR(read_header_from_file(dir.path() / "short"), ErrorCode::Truncated)
                << "a short header file must be rejected";

            ASSERT_OK(test::write_file(dir.path() / "full",
                                       pirs::as_u8(make_package({{"a.bin", pattern(10, 1)}}))))
                << "fixture file must be writable";
            const auto header = read_header_from_file(dir.path() / "full");
            ASSERT_OK(header) << "a full package header reads from file";
            EXPECT_EQ(header->magic, Magic::PIRS) << "a full package header reads from file";
        }

        // The three sizes are also rows of Row/StfsErrorCode (OpenHeaderSize*); here they stay
        // one case, each under its own trace.
        TEST(StfsHeader, OutOfRangeHeaderSizeIsRejected) {
            for (const std::uint32_t header_size : {0x100u, 0x100000u, 0xFFFFF000u}) {
                SCOPED_TRACE(std::format("header_size 0x{:X}", header_size));
                auto bytes = make_package({{"a.bin", pattern(10, 1)}});
                put_be(bytes, 0x340, header_size, 4);
                EXPECT_ERROR(StfsContainer::open(bytes), ErrorCode::Malformed)
                    << "an absurd header_size is rejected";
            }
        }

    } // namespace
} // namespace gxbuild3::stfs
