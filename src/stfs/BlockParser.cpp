#include "stfs/BlockParser.hpp"

#include "stfs/Commons.hpp"
#include "stfs/Layout.hpp"

namespace gxbuild3::stfs {

    namespace {

        constexpr std::uint64_t kStfsBlockStep0 = 0xAB;
        constexpr std::uint64_t kStfsBlockStep1 = 0x718F;
        constexpr std::uint64_t kBlocksPerHashTable = 1;

    } // namespace

    Result<std::uint64_t> block_to_offset(std::uint32_t block, std::uint32_t header_size) {
        if (block > kMaxBlockNumber) {
            return fail(ErrorCode::OutOfRange, "block number 0x{:X} is out of range", block);
        }
        // Block 0 starts at the header size rounded up to the next 4 KiB boundary.
        constexpr std::uint64_t block_size = kBlockSize;
        const std::uint64_t first_block =
            (static_cast<std::uint64_t>(header_size) + block_size - 1) & ~(block_size - 1);
        return first_block + static_cast<std::uint64_t>(block) * block_size;
    }

    Result<std::uint32_t> compute_level_n_hash_block_number(std::uint32_t block, int level) {
        constexpr std::uint32_t per_level0 = kDataBlocksPerHashLevel[0];
        constexpr std::uint32_t per_level1 = kDataBlocksPerHashLevel[1];
        std::uint64_t blockNum64 = block;
        std::uint64_t num = 0;

        if (level == 0) {
            num = (blockNum64 / per_level0) * kStfsBlockStep0;
            if (blockNum64 / per_level0 == 0) {
                return static_cast<std::uint32_t>(num);
            }
            num = num + ((blockNum64 / per_level1) + 1) * kBlocksPerHashTable;
            if (blockNum64 / per_level1 == 0) {
                return static_cast<std::uint32_t>(num);
            }
        } else if (level == 1) {
            num = (blockNum64 / per_level1) * kStfsBlockStep1;
            if (blockNum64 / per_level1 == 0) {
                return static_cast<std::uint32_t>(num) +
                       static_cast<std::uint32_t>(kStfsBlockStep0);
            }
        } else if (level == 2) {
            return static_cast<std::uint32_t>(kStfsBlockStep1);
        } else {
            return fail(ErrorCode::InvalidArgument, "invalid hash table level {}", level);
        }

        return static_cast<std::uint32_t>(num) + static_cast<std::uint32_t>(kBlocksPerHashTable);
    }

    std::uint32_t compute_data_block_number(std::uint32_t block) {
        constexpr std::uint32_t per_level0 = kDataBlocksPerHashLevel[0];
        constexpr std::uint32_t per_level1 = kDataBlocksPerHashLevel[1];
        constexpr std::uint32_t per_level2 = kDataBlocksPerHashLevel[2];
        std::uint64_t base = (block + per_level0) / per_level0;
        std::uint64_t result = base + block;

        if (block >= per_level0) {
            base = (block + per_level1) / per_level1;
            result += base;

            if (block >= per_level1) {
                base = (block + per_level2) / per_level2;
                result += base;
            }
        }

        return static_cast<std::uint32_t>(result);
    }

    Result<std::uint64_t> hash_entry_offset(std::uint32_t block, int level,
                                            std::uint32_t header_size) {
        const auto table_block = compute_level_n_hash_block_number(block, level);
        if (!table_block) {
            return std::unexpected(table_block.error());
        }
        const auto table_offset = block_to_offset(*table_block, header_size);
        if (!table_offset) {
            return std::unexpected(table_offset.error());
        }
        // compute_level_n_hash_block_number has rejected any level other than 0, 1 or 2.
        std::uint32_t record = block;
        if (level > 0) {
            record /= kDataBlocksPerHashLevel[static_cast<std::size_t>(level - 1)];
        }
        record %= kDataBlocksPerHashLevel[0];
        return *table_offset + std::uint64_t{record} * kHashEntrySize;
    }

} // namespace gxbuild3::stfs
