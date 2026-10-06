#include "stfs/HashVerifier.hpp"

#include "Wire.hpp"
#include "excrypt.h"
#include "stfs/BlockParser.hpp"
#include "stfs/Commons.hpp"
#include "stfs/Layout.hpp"

#include <array>
#include <bit>
#include <cstring>
#include <format>
#include <string_view>

namespace gxbuild3::stfs {

    namespace {

        using Digest = std::array<std::byte, 0x14>;

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
            const auto entry_offset = hash_entry_offset(block_number, level, header_size);
            if (!entry_offset) {
                return std::unexpected(entry_offset.error());
            }
            const std::uint64_t hash_offset = *entry_offset;

            if (hash_offset + kHashEntrySize > package.size()) {
                return fail(ErrorCode::OutOfRange, "hash entry at 0x{:X} is outside the package",
                            hash_offset);
            }

            const auto record = wire::read<stfs_hash_entry>(
                wire::as_u8(package), static_cast<std::size_t>(hash_offset), "STFS hash entry");
            if (!record) {
                return std::unexpected(record.error());
            }
            return std::bit_cast<Digest>(record->sha1);
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
