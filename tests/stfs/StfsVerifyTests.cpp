// src/stfs/HashVerifier.hpp and FileExtractor.hpp: verified extraction needs total_blocks, and a
// corrupted data block or hash table fails the hash (a block outside the package is OutOfRange)
// while unverified extraction ignores it.

#include "PirsPackage.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/HashVerifier.hpp"
#include "stfs/MetadataParser.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <gtest/gtest.h>
#include <variant>

namespace gxbuild3::stfs {
    namespace {

        using pirs::Bytes;
        using pirs::data_offset;
        using pirs::hash_offset;
        using pirs::make_package;
        using pirs::pattern;
        using Verify = StfsContainer::Verify;

        TEST(StfsVerify, VerificationRequiresTotalBlocks) {
            const auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "the package opens";
            const auto& entry = container->entries().at(0);
            const auto meta = parse_metadata(bytes);
            ASSERT_OK(meta) << "parse_metadata accepts the package";
            const auto* vd = std::get_if<StfsVolumeDescriptor>(&meta->volume_descriptor);
            ASSERT_NE(vd, nullptr) << "synthetic package has an STFS descriptor";

            EXPECT_ERROR(
                extract_file(bytes, entry, Magic::PIRS, 0xA000, true, &vd->top_hash_table_hash, 0),
                ErrorCode::InvalidArgument)
                << "extract_file with verify and total_blocks 0 fails";
            const test::ScratchDir dir;
            EXPECT_ERROR(extract_file_to_disk(bytes, entry, Magic::PIRS, 0xA000, dir.path() / "a",
                                              true, &vd->top_hash_table_hash, 0),
                         ErrorCode::InvalidArgument)
                << "extract_file_to_disk with verify and total_blocks 0 fails";

            const auto verified =
                extract_file(bytes, entry, Magic::PIRS, 0xA000, true, &vd->top_hash_table_hash, 2);
            ASSERT_OK(verified) << "verification passes with total_blocks set";
            EXPECT_BYTES_EQ(pattern(10, 1), *verified)
                << "verification passes with total_blocks set";
        }

        TEST(StfsVerify, CorruptedDataBlockOrHashTableFailsTheHash) {
            auto data_corrupt = make_package({{"a.bin", pattern(10, 1)}});
            data_corrupt[data_offset(1) + 0x800] ^= std::byte{0x01}; // past file_size, hashed
            const auto container = StfsContainer::open(data_corrupt);
            ASSERT_OK(container) << "the corrupted package opens";
            const auto unverified = container->extract(container->entries().at(0));
            EXPECT_OK(unverified) << "unverified extraction ignores the hash";
            EXPECT_BYTES_EQ(pattern(10, 1), unverified.value_or(Bytes{}))
                << "unverified extraction ignores the hash";
            EXPECT_ERROR(container->extract(container->entries().at(0), Verify::Yes),
                         ErrorCode::HashMismatch)
                << "a corrupted data block fails verification";
            const auto meta = parse_metadata(data_corrupt);
            ASSERT_OK(meta) << "parse_metadata accepts the corrupted package";
            const auto* vd = std::get_if<StfsVolumeDescriptor>(&meta->volume_descriptor);
            ASSERT_NE(vd, nullptr) << "synthetic package has an STFS descriptor";
            EXPECT_ERROR(verify_data_block(data_corrupt, 1, 0xA000, vd->top_hash_table_hash, 2),
                         ErrorCode::HashMismatch)
                << "a corrupted data block is a hash mismatch";
            EXPECT_ERROR(verify_data_block(data_corrupt, 0x100, 0xA000, vd->top_hash_table_hash, 2),
                         ErrorCode::OutOfRange)
                << "a block outside the package is out of range, not a hash mismatch";

            auto table_corrupt = make_package({{"a.bin", pattern(10, 1)}});
            table_corrupt[hash_offset(5) + 0x3] ^= std::byte{0x01}; // unused hash slot
            const auto table_container = StfsContainer::open(table_corrupt);
            ASSERT_OK(table_container) << "the package with a corrupted hash table opens";
            EXPECT_ERROR(table_container->extract(table_container->entries().at(0), Verify::Yes),
                         ErrorCode::HashMismatch)
                << "a corrupted hash table fails the top hash";
        }

    } // namespace
} // namespace gxbuild3::stfs
