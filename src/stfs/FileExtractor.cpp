#include "stfs/FileExtractor.hpp"

#include "ContainerDetail.hpp"
#include "Endian.hpp"
#include "stfs/BlockParser.hpp"
#include "stfs/Commons.hpp"
#include "stfs/HashVerifier.hpp"
#include "stfs/Layout.hpp"

#include <algorithm>
#include <format>
#include <utility>

namespace gxbuild3::stfs {

    namespace {

        struct HashEntry {
            std::uint32_t next_block;
            std::uint8_t status;
        };

        // The level-0 hash entry of `data_block`, which holds its status and the next block.
        [[nodiscard]] Result<HashEntry> read_hash_entry(std::span<const std::byte> package,
                                                        std::uint32_t data_block,
                                                        std::uint32_t header_size) {
            const auto entry_offset = hash_entry_offset(data_block, 0, header_size);
            if (!entry_offset) {
                return std::unexpected(entry_offset.error());
            }
            const std::uint64_t offset = *entry_offset;

            if (offset + kHashEntrySize > package.size()) {
                return fail(ErrorCode::OutOfRange,
                            "hash entry for block {} at 0x{:X} is outside the package", data_block,
                            offset);
            }

            const auto* ptr = package.data() + offset;

            HashEntry entry;
            entry.status = static_cast<std::uint8_t>(ptr[0x14]);
            entry.next_block = read_be24(ptr + 0x15);

            constexpr std::uint8_t kStatusUsed = 0x80;
            constexpr std::uint8_t kStatusNewlyAllocated = 0xC0;

            if (entry.status != kStatusUsed && entry.status != kStatusNewlyAllocated) {
                return fail(ErrorCode::Malformed,
                            "block {} has invalid hash entry status (0x{:02X}) - expected used or "
                            "newly allocated",
                            data_block, entry.status);
            }

            return entry;
        }

    } // namespace

    Result<std::vector<std::uint32_t>> follow_block_chain(std::span<const std::byte> package,
                                                          std::uint32_t starting_block,
                                                          std::uint32_t header_size) {
        std::vector<std::uint32_t> chain;
        std::uint32_t current_block = starting_block;

        std::uint32_t max_steps = static_cast<std::uint32_t>(package.size() / kBlockSize) + 1;
        std::uint32_t steps = 0;

        while (current_block != kChainTerminator) {
            if (steps >= max_steps) {
                return fail(ErrorCode::Malformed,
                            "block chain from block {} exceeds the maximum possible length",
                            starting_block);
            }

            chain.push_back(current_block);

            const auto hash_entry = read_hash_entry(package, current_block, header_size);
            if (!hash_entry) {
                return std::unexpected(hash_entry.error());
            }

            current_block = hash_entry->next_block;
            ++steps;
        }

        return chain;
    }

    namespace {

        // Logical blocks holding a non-empty file. Files flagged as consecutive occupy
        // starting_block onwards and need not have a usable hash chain; others follow the chain.
        [[nodiscard]] Result<std::vector<std::uint32_t>>
        file_blocks(std::span<const std::byte> package, const FileEntry& entry,
                    std::uint32_t header_size) {
            if (!entry.is_consecutive_blocks()) {
                return follow_block_chain(package, entry.starting_block, header_size);
            }

            if (std::uint64_t{entry.blocks_allocated} * kBlockSize < entry.file_size) {
                return fail(ErrorCode::Malformed,
                            "file {} allocates fewer blocks than its size needs", entry.name);
            }

            const std::uint64_t needed =
                (std::uint64_t{entry.file_size} + kBlockSize - 1) / kBlockSize;
            if (needed > package.size() / kBlockSize ||
                std::uint64_t{entry.starting_block} + needed - 1 > kChainTerminator - 1) {
                return fail(ErrorCode::OutOfRange,
                            "consecutive blocks of {} run past the end of the package", entry.name);
            }

            std::vector<std::uint32_t> blocks(static_cast<std::size_t>(needed));
            for (std::size_t i = 0; i < blocks.size(); ++i) {
                blocks[i] = entry.starting_block + static_cast<std::uint32_t>(i);
            }
            return blocks;
        }

    } // namespace

    Result<std::vector<std::byte>> extract_file(std::span<const std::byte> package,
                                                const FileEntry& entry, Magic magic,
                                                std::uint32_t header_size, bool verify,
                                                const std::array<std::byte, 0x14>* top_hash,
                                                std::uint32_t total_blocks) {
        if (magic == Magic::CON) {
            return fail(ErrorCode::Unsupported, "CON packages are not yet supported");
        }

        if (verify && top_hash == nullptr) {
            return fail(ErrorCode::InvalidArgument,
                        "verification requested but no top_hash provided");
        }
        if (verify && total_blocks == 0) {
            return fail(ErrorCode::InvalidArgument, "total_blocks required for hash verification");
        }

        if (entry.file_size == 0) {
            return std::vector<std::byte>{};
        }

        const auto chain = file_blocks(package, entry, header_size);
        if (!chain) {
            return std::unexpected(chain.error());
        }

        std::vector<std::byte> result;
        result.reserve(std::min<std::size_t>(entry.file_size, chain->size() * kBlockSize));

        for (std::uint32_t logical_block : *chain) {
            if (verify) {
                auto verified =
                    verify_data_block(package, logical_block, header_size, *top_hash, total_blocks);
                if (!verified) {
                    return std::unexpected(
                        std::move(verified.error())
                            .add_context(std::format("verifying block {} in file {}", logical_block,
                                                     entry.name)));
                }
            }

            std::uint32_t data_block = compute_data_block_number(logical_block);
            const auto block_offset = block_to_offset(data_block, header_size);
            if (!block_offset) {
                return std::unexpected(block_offset.error());
            }
            const std::uint64_t offset = *block_offset;

            if (offset + kBlockSize > package.size()) {
                return fail(ErrorCode::OutOfRange,
                            "data block {} of {} at 0x{:X} is outside the package", data_block,
                            entry.name, offset);
            }

            const auto* block_ptr = package.data() + offset;
            std::size_t remaining = entry.file_size - result.size();
            std::size_t copy_size = remaining < kBlockSize ? remaining : kBlockSize;

            result.insert(result.end(), block_ptr, block_ptr + copy_size);

            if (result.size() >= entry.file_size) {
                break;
            }
        }

        if (result.size() < entry.file_size) {
            return fail(ErrorCode::Truncated, "blocks of {} end after {} of {} bytes", entry.name,
                        result.size(), entry.file_size);
        }

        return result;
    }

    Result<void> extract_file_to_disk(std::span<const std::byte> package, const FileEntry& entry,
                                      Magic magic, std::uint32_t header_size,
                                      const std::filesystem::path& output_path, bool verify,
                                      const std::array<std::byte, 0x14>* top_hash,
                                      std::uint32_t total_blocks) {
        const auto data =
            extract_file(package, entry, magic, header_size, verify, top_hash, total_blocks);
        if (!data) {
            return std::unexpected(data.error());
        }
        return detail::write_file(output_path, *data);
    }

} // namespace gxbuild3::stfs