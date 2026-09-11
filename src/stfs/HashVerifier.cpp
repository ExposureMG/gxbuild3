#include <BlockParser.hpp>
#include <Commons.hpp>
#include <HashVerifier.hpp>
#include <SHA1.hpp>
#include <array>
#include <cstring>
#include <stdexcept>

namespace stfs {

    namespace {

        constexpr std::size_t kHashEntrySize = 0x18;
        constexpr std::size_t kBlockSize = 0x1000;
        constexpr std::array<std::uint32_t, 3> kDataBlocksPerHashLevel = {0xAA, 0x70E4, 0x4AF768};

        std::array<std::byte, 0x14> sha1(std::span<const std::byte> data) {
            SHA1 checksum;
            checksum.update(std::string(reinterpret_cast<const char*>(data.data()), data.size()));
            std::string hex = checksum.final();

            std::array<std::byte, 0x14> out;
            for (std::size_t i = 0; i < 0x14; ++i) {
                std::string byte_str = hex.substr(i * 2, 2);
                out[i] = static_cast<std::byte>(std::stoul(byte_str, nullptr, 16));
            }
            return out;
        }

        struct LevelEntry {
            std::array<std::byte, 0x14> hash;
            std::uint8_t status;
            std::uint32_t next_block;
        };

        LevelEntry readLevelEntry(std::span<const std::byte> package, std::uint32_t block_number,
                                  int level, std::uint32_t header_size) {
            std::uint32_t record = block_number;
            if (level > 0) {
                record /= kDataBlocksPerHashLevel[level - 1];
            }
            record %= kDataBlocksPerHashLevel[0];

            std::uint32_t backing_block = computeLevelNHashBlockNumber(block_number, level);
            std::size_t hash_offset =
                blockToOffset(backing_block, header_size) + record * kHashEntrySize;

            if (hash_offset + kHashEntrySize > package.size()) {
                throw std::runtime_error("Hash entry offset out of bounds");
            }

            const auto* ptr = package.data() + hash_offset;

            LevelEntry entry;
            std::memcpy(entry.hash.data(), ptr, 0x14);
            entry.status = static_cast<std::uint8_t>(ptr[0x14]);
            entry.next_block = (static_cast<std::uint32_t>(ptr[0x15]) << 16) |
                               (static_cast<std::uint32_t>(ptr[0x16]) << 8) |
                               static_cast<std::uint32_t>(ptr[0x17]);

            return entry;
        }

        bool hashesEqual(const std::array<std::byte, 0x14>& a,
                         const std::array<std::byte, 0x14>& b) {
            return std::memcmp(a.data(), b.data(), 0x14) == 0;
        }

    } // namespace

    bool verifyDataBlock(std::span<const std::byte> package, std::uint32_t block,
                         std::uint32_t header_size, const std::array<std::byte, 0x14>& top_hash,
                         std::uint32_t total_blocks) {
        std::array<std::byte, 0x14> expected = top_hash;

        bool has_l2 = total_blocks > kDataBlocksPerHashLevel[1];
        bool has_l1 = total_blocks > kDataBlocksPerHashLevel[0];

        if (has_l2) {
            std::uint32_t l2_backing = computeLevelNHashBlockNumber(block, 2);
            std::size_t l2_offset = blockToOffset(l2_backing, header_size);
            if (l2_offset + kBlockSize > package.size())
                return false;
            std::span<const std::byte> l2_block(package.data() + l2_offset, kBlockSize);
            if (!hashesEqual(sha1(l2_block), expected))
                return false;
            expected = readLevelEntry(package, block, 2, header_size).hash;
        }

        if (has_l1) {
            std::uint32_t l1_backing = computeLevelNHashBlockNumber(block, 1);
            std::size_t l1_offset = blockToOffset(l1_backing, header_size);
            if (l1_offset + kBlockSize > package.size())
                return false;
            std::span<const std::byte> l1_block(package.data() + l1_offset, kBlockSize);
            if (!hashesEqual(sha1(l1_block), expected))
                return false;
            expected = readLevelEntry(package, block, 1, header_size).hash;
        }

        std::uint32_t l0_backing = computeLevelNHashBlockNumber(block, 0);
        std::size_t l0_offset = blockToOffset(l0_backing, header_size);
        if (l0_offset + kBlockSize > package.size())
            return false;
        std::span<const std::byte> l0_block(package.data() + l0_offset, kBlockSize);
        if (!hashesEqual(sha1(l0_block), expected))
            return false;
        LevelEntry l0_entry = readLevelEntry(package, block, 0, header_size);

        std::uint32_t data_phys = computeDataBlockNumber(block);
        std::size_t data_offset = blockToOffset(data_phys, header_size);
        if (data_offset + kBlockSize > package.size())
            return false;
        std::span<const std::byte> data_block(package.data() + data_offset, kBlockSize);

        return hashesEqual(sha1(data_block), l0_entry.hash);
    }

} // namespace stfs