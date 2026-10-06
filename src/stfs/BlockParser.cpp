#include "stfs/BlockParser.hpp"

#include "stfs/Commons.hpp"

namespace gxbuild3::stfs {

    namespace {

        constexpr std::uint64_t kStfsBlockStep0 = 0xAB;
        constexpr std::uint64_t kStfsBlockStep1 = 0x718F;
        constexpr std::uint64_t kBlocksPerHashTable = 1;

    } // namespace

    Result<std::uint64_t> block_to_offset(std::uint32_t block, std::uint32_t header_size) {
        if (block > 0xFFFFFF) {
            return fail(ErrorCode::OutOfRange, "block number 0x{:X} is out of range", block);
        }
        // Block 0 starts at the header size rounded up to the next 4 KiB boundary.
        const std::uint64_t first_block =
            (static_cast<std::uint64_t>(header_size) + 0xFFF) & ~std::uint64_t{0xFFF};
        return first_block + (static_cast<std::uint64_t>(block) << 12);
    }

    Result<std::uint32_t> compute_level_n_hash_block_number(std::uint32_t block, int level) {
        std::uint64_t blockNum64 = block;
        std::uint64_t num = 0;

        if (level == 0) {
            num = (blockNum64 / 0xAA) * kStfsBlockStep0;
            if (blockNum64 / 0xAA == 0) {
                return static_cast<std::uint32_t>(num);
            }
            num = num + ((blockNum64 / 0x70E4) + 1) * kBlocksPerHashTable;
            if (blockNum64 / 0x70E4 == 0) {
                return static_cast<std::uint32_t>(num);
            }
        } else if (level == 1) {
            num = (blockNum64 / 0x70E4) * kStfsBlockStep1;
            if (blockNum64 / 0x70E4 == 0) {
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
        std::uint64_t base = (block + 0xAA) / 0xAA;
        std::uint64_t result = base + block;

        if (block >= 0xAA) {
            base = (block + 0x70E4) / 0x70E4;
            result += base;

            if (block >= 0x70E4) {
                base = (block + 0x4AF768) / 0x4AF768;
                result += base;
            }
        }

        return static_cast<std::uint32_t>(result);
    }

} // namespace gxbuild3::stfs