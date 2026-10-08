// src/stfs/FileExtractor.hpp and BlockParser.hpp: a chained file follows its hash chain and is
// cut at file_size, a short chain is Truncated, a zero-size file walks nothing, consecutive files
// ignore the chain but stay bounded, block offsets are 64-bit, a bad hash status prints in hex,
// the file table itself follows the hash chain, and block 0 starts at the header size rounded up
// to the next 0x1000 boundary.

#include "PirsPackage.hpp"
#include "stfs/BlockParser.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::stfs {
    namespace {

        using pirs::Bytes;
        using pirs::data_offset;
        using pirs::entry_offset;
        using pirs::hash_offset;
        using pirs::make_package;
        using pirs::pattern;
        using pirs::put_be;
        using pirs::put_le;
        using pirs::seal;
        using Verify = StfsContainer::Verify;

        TEST(StfsChain, TruncatedChainFailsInsteadOfReturningAShortBuffer) {
            // A chained (non-consecutive) two-block file whose chain ends after the first block.
            auto bytes = make_package({{"a.bin", pattern(0x1800, 1), false}});
            put_be(bytes, hash_offset(1) + 0x15, 0xFFFFFF, 3);
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a package with a truncated chain opens";
            EXPECT_ERROR(container->extract(container->entries().at(0)), ErrorCode::Truncated)
                << "a chain shorter than file_size must fail, not return a short buffer";
        }

        TEST(StfsChain, LongerChainIsCutAtFileSize) {
            // The chain may be longer than needed; extraction stops at file_size.
            const auto data = pattern(0x1800, 4);
            auto bytes = make_package({{"a.bin", data, false}, {"b.bin", pattern(0x10, 5), false}});
            put_be(bytes, hash_offset(2) + 0x15, 3, 3); // a.bin's last block links on into b.bin
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a package with a longer chain opens";
            const auto extracted = container->extract(container->entries().at(0));
            ASSERT_OK(extracted) << "a longer chain yields exactly file_size bytes";
            EXPECT_BYTES_EQ(data, *extracted) << "a longer chain yields exactly file_size bytes";
        }

        TEST(StfsChain, ZeroSizeFileSkipsItsChain) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}, {"empty.bin", {}}});
            put_le(bytes, entry_offset(1) + 0x2F, 3000, 3); // starting block far out of range
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a package with an empty file opens";
            const auto extracted = container->extract(container->entries().at(1));
            ASSERT_OK(extracted) << "a zero-size file returns no bytes without walking its chain";
            EXPECT_TRUE(extracted->empty())
                << "a zero-size file returns no bytes without walking its chain";
        }

        TEST(StfsChain, BlockOffsetsAre64Bit) {
            EXPECT_EQ(block_to_offset(0, 0xAD0E).value_or(0), 0xB000u)
                << "0xAD0E rounds up to 0xB000";
            EXPECT_EQ(block_to_offset(0, 0x971A).value_or(0), 0xA000u)
                << "0x971A rounds up to 0xA000";
            EXPECT_EQ(block_to_offset(2, 0x1F000).value_or(0), 0x21000u)
                << "header sizes above 0xFFFF are kept";
            EXPECT_EQ(block_to_offset(0xFFFFFF, 0xAD0E).value_or(0), 0xB000 + 0xFFFFFF000ull)
                << "the largest block number does not wrap";
            EXPECT_ERROR(block_to_offset(0x1000000, 0xAD0E), ErrorCode::OutOfRange)
                << "block numbers above 24 bits are rejected";
        }

        TEST(StfsChain, InvalidHashStatusIsMalformedAndPrintedInHex) {
            auto bytes = make_package({{"a.bin", pattern(10, 1), false}});
            bytes[hash_offset(1) + 0x14] = std::byte{0xAB};
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a package with a bad hash status opens";
            const auto extracted = container->extract(container->entries().at(0));
            EXPECT_ERROR(extracted, ErrorCode::Malformed)
                << "an invalid hash entry status is malformed";
            EXPECT_ERROR_HAS(extracted, ErrorCode::Malformed, "(0xAB)")
                << "the hash entry status is printed in hex";
        }

        TEST(StfsChain, ConsecutiveFileIgnoresTheHashChain) {
            const auto data = pattern(0x2800, 6);
            auto consecutive = make_package({{"a.bin", data, true}});
            auto chained = make_package({{"a.bin", data, false}});
            for (auto* bytes : {&consecutive, &chained}) {
                for (std::uint32_t block = 1; block <= 3; ++block) {
                    put_be(*bytes, hash_offset(block) + 0x15, 0xFFFFFF, 3); // break the chain
                }
                seal(*bytes);
            }

            const auto container = StfsContainer::open(consecutive);
            ASSERT_OK(container) << "a consecutive package opens";
            const auto unverified = container->extract(container->entries().at(0));
            EXPECT_OK(unverified)
                << "a consecutive file is read from starting_block without its chain";
            EXPECT_BYTES_EQ(data, unverified.value_or(Bytes{}))
                << "a consecutive file is read from starting_block without its chain";
            const auto verified = container->extract(container->entries().at(0), Verify::Yes);
            EXPECT_OK(verified) << "a consecutive file still verifies block by block";
            EXPECT_BYTES_EQ(data, verified.value_or(Bytes{}))
                << "a consecutive file still verifies block by block";

            const auto chained_container = StfsContainer::open(chained);
            ASSERT_OK(chained_container) << "a chained package opens";
            EXPECT_ERROR(chained_container->extract(chained_container->entries().at(0)),
                         ErrorCode::Truncated)
                << "a non-consecutive file still follows (and trusts) its chain";
        }

        TEST(StfsChain, ConsecutiveFileStaysInsideItsAllocationAndThePackage) {
            auto short_allocation = make_package({{"a.bin", pattern(0x2800, 6), true}});
            put_le(short_allocation, entry_offset(0) + 0x29, 2, 3); // 2 blocks for 0x2800 bytes
            const auto container = StfsContainer::open(short_allocation);
            ASSERT_OK(container) << "a short allocation opens";
            EXPECT_ERROR(container->extract(container->entries().at(0)), ErrorCode::Malformed)
                << "blocks_allocated too small for file_size is rejected";

            auto past_end = make_package({{"a.bin", pattern(0x2800, 6), true}});
            put_le(past_end, entry_offset(0) + 0x2F, 0xFFFFFE, 3);
            const auto past_end_container = StfsContainer::open(past_end);
            ASSERT_OK(past_end_container) << "a starting block near the end opens";
            EXPECT_ERROR(past_end_container->extract(past_end_container->entries().at(0)),
                         ErrorCode::OutOfRange)
                << "consecutive blocks past the last block number are rejected";

            auto huge = make_package({{"a.bin", pattern(0x10, 6), true}});
            put_le(huge, entry_offset(0) + 0x29, 0xFFFFFF, 3);
            put_be(huge, entry_offset(0) + 0x34, 0xFFFFFFFF, 4);
            const auto huge_container = StfsContainer::open(huge);
            ASSERT_OK(huge_container) << "a huge consecutive file entry opens";
            EXPECT_ERROR(huge_container->extract(huge_container->entries().at(0)),
                         ErrorCode::OutOfRange)
                << "a consecutive file larger than the package is rejected";
        }

        TEST(StfsChain, FileTableFollowsTheHashChain) {
            // Logical block 0 is the first table block; a.bin lives in block 1 and the second
            // table block is block 2, linked 0 -> 2 through the hash chain.
            const auto data = pattern(10, 1);
            auto bytes = make_package({{"a.bin", data}, {"spare", pattern(pirs::kBlockSize, 2)}});
            for (std::size_t i = 1; i < 64; ++i) {
                pirs::write_entry(bytes, entry_offset(i), "e" + std::to_string(i), 0x40, 0, 0, 0);
            }
            std::fill_n(bytes.begin() + static_cast<std::ptrdiff_t>(data_offset(2)),
                        pirs::kBlockSize, std::byte{0});
            pirs::write_entry(bytes, data_offset(2), "second.bin", 0x40, 1, 1, 10);
            put_le(bytes, pirs::kVolumeDescriptor + 0x03, 2, 2);
            put_be(bytes, hash_offset(0) + 0x15, 2, 3);
            seal(bytes);

            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a package with a two-block file table opens";
            ASSERT_EQ(container->entries().size(), 65u)
                << "StfsContainer reads the file table through its hash chain";
            EXPECT_EQ(container->entries().back().name, "second.bin")
                << "StfsContainer reads the file table through its hash chain";
            const auto verified = container->extract(container->entries().back(), Verify::Yes);
            EXPECT_OK(verified) << "an entry from the second table block extracts";
            EXPECT_BYTES_EQ(data, verified.value_or(Bytes{}))
                << "an entry from the second table block extracts";
            const auto by_name = container->extract_file_by_name("second.bin");
            EXPECT_OK(by_name)
                << "StfsContainer finds the entry from the second table block by name";
            EXPECT_BYTES_EQ(data, by_name.value_or(Bytes{}))
                << "StfsContainer finds the entry from the second table block by name";
        }

        // block_to_offset rounds the header size up to the next 0x1000 boundary and leaves an
        // aligned one alone, so a package declaring the real-world 0x971A (or 0x9001) lays out
        // exactly like the synthetic 0xA000 one, while header_size() keeps the declared value.
        TEST(StfsChain, HeaderSizeRoundsUpToTheNextBlockBoundary) {
            EXPECT_EQ(block_to_offset(0, 0xA000).value_or(0), 0xA000u) << "aligned stays";
            EXPECT_EQ(block_to_offset(0, 0xA001).value_or(0), 0xB000u) << "one past rounds up";
            EXPECT_EQ(block_to_offset(0, 0x9001).value_or(0), 0xA000u) << "0x9001 rounds up";
            EXPECT_EQ(block_to_offset(3, 0x971A).value_or(0), 0xD000u)
                << "block N is the rounded base plus N blocks";

            const auto data = pattern(0x1800, 7);
            auto bytes = make_package({{"a.bin", data, false}});
            put_be(bytes, 0x340, 0x971A, 4);
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a package declaring header size 0x971A opens";
            EXPECT_EQ(container->header_size(), 0x971Au) << "the declared size is kept";
            const auto extracted = container->extract(container->entries().at(0), Verify::Yes);
            ASSERT_OK(extracted) << "the chain and hashes resolve against the rounded base";
            EXPECT_BYTES_EQ(data, *extracted)
                << "the chain and hashes resolve against the rounded base";
        }

    } // namespace
} // namespace gxbuild3::stfs
