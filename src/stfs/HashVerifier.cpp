#include "stfs/HashVerifier.hpp"

#include "excrypt.h"
#include "stfs/BlockParser.hpp"
#include "stfs/Commons.hpp"

#include <array>
#include <cstring>
#include <stdexcept>

namespace gxbuild3::stfs {

    namespace {

        using Digest = std::array<std::byte, 0x14>;

        constexpr std::size_t kHashEntrySize = 0x18;
        constexpr std::size_t kBlockSize = 0x1000;
        constexpr std::array<std::uint32_t, 3> kDataBlocksPerHashLevel = {0xAA, 0x70E4, 0x4AF768};

        // True when the 4 KiB block at `offset` is inside the package and hashes to `expected`.
        bool blockHashMatches(std::span<const std::byte> package, std::uint64_t offset,
                              const Digest& expected) {
            if (offset + kBlockSize > package.size()) {
                return false;
            }

            std::array<std::uint8_t, 0x14> digest{};
            ExCryptSha(reinterpret_cast<const std::uint8_t*>(package.data() + offset),
                       static_cast<std::uint32_t>(kBlockSize), nullptr, 0, nullptr, 0,
                       digest.data(), static_cast<std::uint32_t>(digest.size()));
            return std::memcmp(digest.data(), expected.data(), digest.size()) == 0;
        }

        // The hash stored for `block_number` in its level-N hash table.
        Digest readLevelHash(std::span<const std::byte> package, std::uint32_t block_number,
                             int level, std::uint32_t header_size) {
            std::uint32_t record = block_number;
            if (level > 0) {
                record /= kDataBlocksPerHashLevel[level - 1];
            }
            record %= kDataBlocksPerHashLevel[0];

            const std::uint32_t backing_block = computeLevelNHashBlockNumber(block_number, level);
            const std::uint64_t hash_offset =
                blockToOffset(backing_block, header_size) + std::uint64_t{record} * kHashEntrySize;

            if (hash_offset + kHashEntrySize > package.size()) {
                throw std::runtime_error("Hash entry offset out of bounds");
            }

            Digest hash;
            std::memcpy(hash.data(), package.data() + hash_offset, hash.size());
            return hash;
        }

    } // namespace

    bool verifyDataBlock(std::span<const std::byte> package, std::uint32_t block,
                         std::uint32_t header_size, const std::array<std::byte, 0x14>& top_hash,
                         std::uint32_t total_blocks) {
        if (total_blocks == 0) {
            throw std::runtime_error("total_blocks required for hash verification");
        }

        // The top hash covers the highest hash table level the package needs.
        Digest expected = top_hash;
        const int top_level = total_blocks > kDataBlocksPerHashLevel[1]   ? 2
                              : total_blocks > kDataBlocksPerHashLevel[0] ? 1
                                                                          : 0;

        for (int level = top_level; level >= 0; --level) {
            const auto table = computeLevelNHashBlockNumber(block, level);
            if (!blockHashMatches(package, blockToOffset(table, header_size), expected)) {
                return false;
            }
            expected = readLevelHash(package, block, level, header_size);
        }

        const auto data_block = computeDataBlockNumber(block);
        return blockHashMatches(package, blockToOffset(data_block, header_size), expected);
    }

} // namespace gxbuild3::stfs
