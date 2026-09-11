#include <BlockParser.hpp>
#include <Commons.hpp>
#include <stdexcept>

namespace stfs {

    namespace {

        constexpr std::uint64_t kStfsBlockStep0 = 0xAB;
        constexpr std::uint64_t kStfsBlockStep1 = 0x718F;
        constexpr std::uint64_t kBlocksPerHashTable = 1;

    } // namespace

    std::uint32_t blockToOffset(std::uint32_t block, std::uint32_t header_size) {
        if (block > 0xFFFFFF) {
            throw std::runtime_error("Block number out of range");
        }
        return ((header_size + 0xFFF) & 0xF000) + (block << 12);
    }

    std::uint32_t computeLevelNHashBlockNumber(std::uint32_t block, int level) {
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
            throw std::runtime_error("Invalid hash table level");
        }

        return static_cast<std::uint32_t>(num) + static_cast<std::uint32_t>(kBlocksPerHashTable);
    }

    std::uint32_t computeDataBlockNumber(std::uint32_t block) {
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

} // namespace stfs