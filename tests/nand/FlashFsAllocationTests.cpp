// FlashFS chain allocation (src/nand/objects/FlashFileSystem.hpp): the block count a size needs
// at its boundaries, and a SIZE_MAX allocation refused without touching the blockmap.

#include "nand/objects/FlashFileSystem.hpp"
#include "support/Expect.hpp"
#include "support/FlashFsAccess.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <optional>

namespace gxbuild3::nand {
    namespace {

        TEST(FlashFsAllocation, FlashFilesystemBlockCountHandlesBoundaries) {
            constexpr size_t block_size = kCleanBlockSize;
            const auto max_blocks = FlashFileSystemTestAccess::checked_block_count(
                std::numeric_limits<size_t>::max(), block_size);
            EXPECT_TRUE(max_blocks.has_value())
                << "FlashFS SIZE_MAX allocation must not wrap into one block";
            EXPECT_NE(max_blocks.value_or(1), 1u)
                << "FlashFS SIZE_MAX allocation must not wrap into one block";
            EXPECT_EQ(FlashFileSystemTestAccess::checked_block_count(0, block_size),
                      std::optional<size_t>{1})
                << "FlashFS zero-length allocation must use one block";
            EXPECT_EQ(FlashFileSystemTestAccess::checked_block_count(block_size * 2, block_size),
                      std::optional<size_t>{2})
                << "FlashFS exact multiples must use the exact block count";
            EXPECT_EQ(
                FlashFileSystemTestAccess::checked_block_count(block_size * 2 + 1, block_size),
                std::optional<size_t>{3})
                << "FlashFS one-over multiples must round up one block";
            EXPECT_FALSE(FlashFileSystemTestAccess::checked_block_count(1, 0).has_value())
                << "FlashFS must reject a zero clean block size";
        }

        TEST(FlashFsAllocation, FlashFilesystemSizeMaxAllocationIsRejectedWithoutMutation) {
            FlashFileSystem filesystem{};
            ASSERT_OK(filesystem.format(0x400))
                << "FlashFS must format before allocation guard test";
            const auto before = filesystem.blockmap();
            std::optional<uint16_t> result;
            ASSERT_NO_THROW(result = filesystem.allocate_chain(std::numeric_limits<size_t>::max()))
                << "FlashFS SIZE_MAX allocation must not throw";
            EXPECT_FALSE(result.has_value()) << "FlashFS SIZE_MAX allocation must return nullopt";
            EXPECT_EQ(filesystem.blockmap(), before)
                << "FlashFS SIZE_MAX allocation must not mutate the blockmap";
        }

    } // namespace
} // namespace gxbuild3::nand
