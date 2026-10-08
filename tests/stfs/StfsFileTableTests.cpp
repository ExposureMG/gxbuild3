// src/stfs/FileTableParser.hpp through StfsContainer::open: the volume descriptor's file table
// block count and block_separation bit 0, the file table chain length, and the name rules of a
// file-table entry (name_length within the 0x28-byte field, a nameless entry ends the listing,
// NUL padding trimmed, no empty or separated names, system update names accepted).

#include "PirsPackage.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::stfs {
    namespace {

        using pirs::entry_offset;
        using pirs::kVolumeDescriptor;
        using pirs::make_package;
        using pirs::pattern;
        using pirs::put_le;

        TEST(StfsFileTable, ZeroOrNegativeBlockCountIsRejected) {
            auto empty = make_package({{"a.bin", pattern(10, 1)}});
            put_le(empty, kVolumeDescriptor + 0x03, 0, 2);
            EXPECT_ERROR(StfsContainer::open(empty), ErrorCode::Malformed)
                << "StfsContainer rejects a zero file table block count";

            auto negative = make_package({{"a.bin", pattern(10, 1)}});
            put_le(negative, kVolumeDescriptor + 0x03, 0x8000, 2);
            EXPECT_ERROR(StfsContainer::open(negative), ErrorCode::Malformed)
                << "StfsContainer rejects a negative file table block count";
        }

        TEST(StfsFileTable, ChainShorterThanItsBlockCountIsRejected) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            put_le(bytes, kVolumeDescriptor + 0x03, 2, 2); // claims two blocks, chain has one
            EXPECT_ERROR(StfsContainer::open(bytes), ErrorCode::Truncated)
                << "a file table chain shorter than its block count is rejected";
        }

        TEST(StfsFileTable, WritableLayoutIsRejectedAndOtherBlockSeparationBitsDoNotMatter) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            bytes[kVolumeDescriptor + 0x02] = std::byte{0x00}; // block_separation bit 0 clear
            EXPECT_ERROR(StfsContainer::open(bytes), ErrorCode::Unsupported)
                << "StfsContainer rejects block_separation bit 0 clear";

            bytes[kVolumeDescriptor + 0x02] = std::byte{0x03};
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "other block_separation bits do not matter";
            EXPECT_EQ(container->entries().size(), 1u)
                << "other block_separation bits do not matter";
        }

        TEST(StfsFileTable, NameLengthBeyondTheFieldIsRejectedAnd0x28IsAccepted) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            bytes[entry_offset(0) + 0x28] = std::byte{0x40 | 0x29};
            EXPECT_ERROR(StfsContainer::open(bytes), ErrorCode::Malformed)
                << "name_length 0x29 is rejected";
            bytes[entry_offset(0) + 0x28] = std::byte{0x40 | 0x3F};
            EXPECT_ERROR(StfsContainer::open(bytes), ErrorCode::Malformed)
                << "name_length 0x3F is rejected";

            const std::string longest(0x28, 'n');
            const auto full_bytes = make_package({{longest, pattern(10, 1)}});
            const auto full = StfsContainer::open(full_bytes);
            ASSERT_OK(full) << "a 40-byte name is accepted";
            EXPECT_EQ(full->entries().at(0).name, longest) << "a 40-byte name is accepted";
        }

        TEST(StfsFileTable, NamelessEntryEndsTheListing) {
            auto bytes = make_package(
                {{"a.bin", pattern(10, 1)}, {"b.bin", pattern(10, 2)}, {"c.bin", pattern(10, 3)}});
            bytes[entry_offset(1) + 0x28] = std::byte{0x40}; // name_length 0, other bytes set
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "an entry without a name length ends the listing";
            ASSERT_EQ(container->entries().size(), 1u)
                << "an entry without a name length ends the listing";
            EXPECT_EQ(container->entries().at(0).name, "a.bin")
                << "an entry without a name length ends the listing";
        }

        TEST(StfsFileTable, NamesTrimNulPaddingAndRejectEmptyOrSeparatedNames) {
            auto padded = make_package({{"a.bin", pattern(10, 1)}});
            padded[entry_offset(0) + 0x28] = std::byte{0x40 | 0x08}; // "a.bin\0\0\0"
            const auto padded_container = StfsContainer::open(padded);
            EXPECT_OK(padded_container) << "NUL padding inside name_length is trimmed";
            if (padded_container) {
                EXPECT_EQ(padded_container->entries().at(0).name, "a.bin")
                    << "NUL padding inside name_length is trimmed";
            }

            auto empty = make_package({{"a.bin", pattern(10, 1)}});
            empty[entry_offset(0)] = std::byte{0};
            EXPECT_ERROR(StfsContainer::open(empty), ErrorCode::Malformed)
                << "a name that starts with NUL is rejected";

            for (const auto* name : {"a/b", "a\\b"}) {
                SCOPED_TRACE(name);
                const auto bytes = make_package({{name, pattern(10, 1)}});
                EXPECT_ERROR(StfsContainer::open(bytes), ErrorCode::Malformed)
                    << "a name with a path separator is rejected";
            }

            const auto plain_bytes = make_package({{"$flash_dash.xex", pattern(10, 1)},
                                                   {"$flash_SegoeXbox-Light.xtt", pattern(10, 2)}});
            const auto plain = StfsContainer::open(plain_bytes);
            ASSERT_OK(plain) << "system update names are accepted";
            ASSERT_EQ(plain->entries().size(), 2u) << "system update names are accepted";
            EXPECT_EQ(plain->entries().at(1).name, "$flash_SegoeXbox-Light.xtt")
                << "system update names are accepted";
        }

    } // namespace
} // namespace gxbuild3::stfs
