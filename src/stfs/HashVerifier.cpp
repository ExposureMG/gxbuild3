#include "stfs/HashVerifier.hpp"

#include "excrypt.h"
#include "stfs/BlockParser.hpp"
#include "stfs/Commons.hpp"

#include <array>
#include <cstring>
#include <format>
#include <string_view>

namespace gxbuild3::stfs {

    namespace {

        using Digest = std::array<std::byte, 0x14>;

        constexpr std::size_t kHashEntrySize = 0x18;
        constexpr std::size_t kBlockSize = 0x1000;
        constexpr std::array<std::uint32_t, 3> kDataBlocksPerHashLevel = {0xAA, 0x70E4, 0x4AF768};

        // Checks that the 4 KiB block at `offset` is inside the package and hashes to `expected`.
        [[nodiscard]] Result<void> check_block_hash(std::span<const std::byte> package,
                                                    std::uint64_t offset, const Digest& expected,
                                                    std::string_view what) {
            if (offset + kBlockSize > package.size()) {
                return fail(ErrorCode::OutOfRange, "{} at 0x{:X} is outside the package", what,
                            offset);
            }

            std::array<std::uint8_t, 0x14> digest{};
            ExCryptSha(reinterpret_cast<const std::uint8_t*>(package.data() + offset),
                       static_cast<std::uint32_t>(kBlockSize), nullptr, 0, nullptr, 0,
                       digest.data(), static_cast<std::uint32_t>(digest.size()));
            if (std::memcmp(digest.data(), expected.data(), digest.size()) != 0) {
                return fail(ErrorCode::HashMismatch, "{} at 0x{:X} does not match its hash", what,
                            offset);
            }
            return {};
        }

        // The hash stored for `block_number` in its level-N hash table.
        [[nodiscard]] Result<Digest> read_level_hash(std::span<const std::byte> package,
                                                     std::uint32_t block_number, int level,
                                                     std::uint32_t header_size) {
            std::uint32_t record = block_number;
            if (level > 0) {
                record /= kDataBlocksPerHashLevel[level - 1];
            }
            record %= kDataBlocksPerHashLevel[0];

            const auto backing_block = compute_level_n_hash_block_number(block_number, level);
            if (!backing_block) {
                return std::unexpected(backing_block.error());
            }
            const auto table_offset = block_to_offset(*backing_block, header_size);
            if (!table_offset) {
                return std::unexpected(table_offset.error());
            }
            const std::uint64_t hash_offset =
                *table_offset + std::uint64_t{record} * kHashEntrySize;

            if (hash_offset + kHashEntrySize > package.size()) {
                return fail(ErrorCode::OutOfRange, "hash entry at 0x{:X} is outside the package",
                            hash_offset);
            }

            Digest hash;
            std::memcpy(hash.data(), package.data() + hash_offset, hash.size());
            return hash;
        }

    } // namespace

    Result<void> verify_data_block(std::span<const std::byte> package, std::uint32_t block,
                                   std::uint32_t header_size,
                                   const std::array<std::byte, 0x14>& top_hash,
                                   std::uint32_t total_blocks) {
        if (total_blocks == 0) {
            return fail(ErrorCode::InvalidArgument, "total_blocks required for hash verification");
        }

        // The top hash covers the highest hash table level the package needs.
        Digest expected = top_hash;
        const int top_level = total_blocks > kDataBlocksPerHashLevel[1]   ? 2
                              : total_blocks > kDataBlocksPerHashLevel[0] ? 1
                                                                          : 0;

        for (int level = top_level; level >= 0; --level) {
            const auto table = compute_level_n_hash_block_number(block, level);
            if (!table) {
                return std::unexpected(table.error());
            }
            const auto table_offset = block_to_offset(*table, header_size);
            if (!table_offset) {
                return std::unexpected(table_offset.error());
            }
            auto checked = check_block_hash(package, *table_offset, expected,
                                            std::format("level-{} hash table", level));
            if (!checked) {
                return checked;
            }
            auto level_hash = read_level_hash(package, block, level, header_size);
            if (!level_hash) {
                return std::unexpected(std::move(level_hash.error()));
            }
            expected = *level_hash;
        }

        const auto data_offset = block_to_offset(compute_data_block_number(block), header_size);
        if (!data_offset) {
            return std::unexpected(data_offset.error());
        }
        return check_block_hash(package, *data_offset, expected, "data block");
    }

} // namespace gxbuild3::stfs
