#include <BlockParser.hpp>
#include <Commons.hpp>
#include <Endian.hpp>
#include <FileExtractor.hpp>
#include <HashVerifier.hpp>
#include <fstream>
#include <stdexcept>

namespace stfs {

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
            std::uint32_t offset =
                blockToOffset(hash_block, header_size) + entry_index * kHashEntrySize;

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
                throw std::runtime_error("Block " + std::to_string(data_block) +
                                         " has invalid hash entry status (0x" +
                                         std::to_string(static_cast<int>(entry.status)) +
                                         ") — expected used or newly allocated");
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

        auto chain = followBlockChain(package, entry.starting_block, header_size);

        std::vector<std::byte> result;
        result.reserve(entry.file_size);

        for (std::uint32_t logical_block : chain) {
            if (verify &&
                !verifyDataBlock(package, logical_block, header_size, *top_hash, total_blocks)) {
                throw std::runtime_error("Hash verification failed for block " +
                                         std::to_string(logical_block) + " in file " + entry.name);
            }

            std::uint32_t data_block = computeDataBlockNumber(logical_block);
            std::uint32_t offset = blockToOffset(data_block, header_size);

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

        return result;
    }

    void extractFileToDisk(std::span<const std::byte> package, const FileEntry& entry, Magic magic,
                           std::uint32_t header_size, const std::filesystem::path& output_path,
                           bool verify, const std::array<std::byte, 0x14>* top_hash,
                           std::uint32_t total_blocks) {
        auto data = extractFile(package, entry, magic, header_size, verify, top_hash, total_blocks);

        std::ofstream out(output_path, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Cannot open output file: " + output_path.string());
        }

        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.data() != nullptr ? data.size() : 0));
    }

} // namespace stfs