#include "stfs/FileExtractor.hpp"

#include "Endian.hpp"
#include "PackageCommon.hpp"
#include "stfs/BlockParser.hpp"
#include "stfs/Commons.hpp"
#include "stfs/HashVerifier.hpp"

#include <algorithm>
#include <format>
#include <stdexcept>

namespace gxbuild3::stfs {

    namespace {

        constexpr std::size_t kBlockSize = 0x1000;
        constexpr std::size_t kHashEntrySize = 0x18;
        constexpr std::uint32_t kChainTerminator = 0xFFFFFF;

        struct HashEntry {
            std::uint32_t next_block;
            std::uint8_t status;
        };

        HashEntry readHashEntry(std::span<const std::byte> package, std::uint32_t hash_block,
                                std::uint32_t data_block, std::uint32_t header_size) {
            std::uint32_t entry_index = data_block % 0xAA;
            const std::uint64_t offset = blockToOffset(hash_block, header_size) +
                                         std::uint64_t{entry_index} * kHashEntrySize;

            if (offset + kHashEntrySize > package.size()) {
                throw std::runtime_error("Hash entry offset out of bounds");
            }

            const auto* ptr = package.data() + offset;

            HashEntry entry;
            entry.status = static_cast<std::uint8_t>(ptr[0x14]);
            entry.next_block = readUInt24BE(ptr + 0x15);

            constexpr std::uint8_t kStatusUsed = 0x80;
            constexpr std::uint8_t kStatusNewlyAllocated = 0xC0;

            if (entry.status != kStatusUsed && entry.status != kStatusNewlyAllocated) {
                throw std::runtime_error(
                    std::format("Block {} has invalid hash entry status (0x{:02X}) - expected used "
                                "or newly allocated",
                                data_block, entry.status));
            }

            return entry;
        }

    } // namespace

    std::vector<std::uint32_t> followBlockChain(std::span<const std::byte> package,
                                                std::uint32_t starting_block,
                                                std::uint32_t header_size) {
        std::vector<std::uint32_t> chain;
        std::uint32_t current_block = starting_block;

        std::uint32_t max_steps = static_cast<std::uint32_t>(package.size() / kBlockSize) + 1;
        std::uint32_t steps = 0;

        while (current_block != kChainTerminator) {
            if (steps >= max_steps) {
                throw std::runtime_error("Block chain exceeded maximum possible length");
            }

            chain.push_back(current_block);

            std::uint32_t hash_block = computeLevelNHashBlockNumber(current_block, 0);
            HashEntry hash_entry = readHashEntry(package, hash_block, current_block, header_size);

            current_block = hash_entry.next_block;
            ++steps;
        }

        return chain;
    }

    namespace {

        // Logical blocks holding a non-empty file. Files flagged as consecutive occupy
        // starting_block onwards and need not have a usable hash chain; others follow the chain.
        std::vector<std::uint32_t> fileBlocks(std::span<const std::byte> package,
                                              const FileEntry& entry, std::uint32_t header_size) {
            if (!entry.isConsecutiveBlocks()) {
                return followBlockChain(package, entry.starting_block, header_size);
            }

            if (std::uint64_t{entry.blocks_allocated} * kBlockSize < entry.file_size) {
                throw std::runtime_error("File " + entry.name +
                                         " allocates fewer blocks than its size needs");
            }

            const std::uint64_t needed =
                (std::uint64_t{entry.file_size} + kBlockSize - 1) / kBlockSize;
            if (needed > package.size() / kBlockSize ||
                std::uint64_t{entry.starting_block} + needed - 1 > kChainTerminator - 1) {
                throw std::runtime_error("Consecutive blocks of " + entry.name +
                                         " run past the end of the package");
            }

            std::vector<std::uint32_t> blocks(static_cast<std::size_t>(needed));
            for (std::size_t i = 0; i < blocks.size(); ++i) {
                blocks[i] = entry.starting_block + static_cast<std::uint32_t>(i);
            }
            return blocks;
        }

    } // namespace

    std::vector<std::byte> extractFile(std::span<const std::byte> package, const FileEntry& entry,
                                       Magic magic, std::uint32_t header_size, bool verify,
                                       const std::array<std::byte, 0x14>* top_hash,
                                       std::uint32_t total_blocks) {
        if (magic == Magic::CON) {
            throw std::runtime_error("CON packages are not yet supported");
        }

        if (verify && top_hash == nullptr) {
            throw std::runtime_error("Verification requested but no top_hash provided");
        }
        if (verify && total_blocks == 0) {
            throw std::runtime_error("total_blocks required for hash verification");
        }

        if (entry.file_size == 0) {
            return {};
        }

        const auto chain = fileBlocks(package, entry, header_size);

        std::vector<std::byte> result;
        result.reserve(std::min<std::size_t>(entry.file_size, chain.size() * kBlockSize));

        for (std::uint32_t logical_block : chain) {
            if (verify &&
                !verifyDataBlock(package, logical_block, header_size, *top_hash, total_blocks)) {
                throw std::runtime_error("Hash verification failed for block " +
                                         std::to_string(logical_block) + " in file " + entry.name);
            }

            std::uint32_t data_block = computeDataBlockNumber(logical_block);
            const std::uint64_t offset = blockToOffset(data_block, header_size);

            if (offset + kBlockSize > package.size()) {
                throw std::runtime_error("Data block offset out of bounds");
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
            throw std::runtime_error("Blocks of " + entry.name + " end after " +
                                     std::to_string(result.size()) + " of " +
                                     std::to_string(entry.file_size) + " bytes");
        }

        return result;
    }

    void extractFileToDisk(std::span<const std::byte> package, const FileEntry& entry, Magic magic,
                           std::uint32_t header_size, const std::filesystem::path& output_path,
                           bool verify, const std::array<std::byte, 0x14>* top_hash,
                           std::uint32_t total_blocks) {
        const auto data =
            extractFile(package, entry, magic, header_size, verify, top_hash, total_blocks);
        detail::writeFile(output_path, data);
    }

} // namespace gxbuild3::stfs