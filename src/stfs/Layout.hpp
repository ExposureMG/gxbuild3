#pragma once

#include "Error.hpp"
#include "Wire.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace gxbuild3::stfs {

    // STFS geometry. Blocks are 4 KiB; block numbers are 24 bits wide.
    inline constexpr std::size_t kBlockSize = 0x1000;
    inline constexpr std::uint32_t kMaxBlockNumber = 0xFFFFFF;

    // The next-block field of the last hash entry in a chain.
    inline constexpr std::uint32_t kChainTerminator = kMaxBlockNumber;

    // A hash table block holds 0xAA entries of 0x18 bytes (SHA-1, status, next block).
    inline constexpr std::size_t kHashEntrySize = 0x18;

    // Data blocks covered by one hash table at level 0, 1 and 2.
    inline constexpr std::array<std::uint32_t, 3> kDataBlocksPerHashLevel = {0xAA, 0x70E4,
                                                                             0x4AF768};

    // CON signatures end at 0x22C (0x1AC + 0x80); LIVE/PIRS signatures end at 0x22C as well
    // (0x004 + 0x100 + 0x128). Every header variant needs this many bytes.
    inline constexpr std::size_t kHeaderRegionSize = 0x22C;

    // Bytes of the v1 metadata parsed by parse_metadata; every header holds at least this much.
    inline constexpr std::uint32_t kMinMetadataSize = 0x971A;

    // One 0x40-byte file table entry as the container stores it. Block counts and the starting
    // block are 24-bit little-endian; the rest is big-endian. The name is not NUL-terminated and
    // its length is the low six bits of flags.
    struct stfs_file_table_entry {
        char name[0x28];
        std::uint8_t flags;
        wire::le24 blocks_allocated;
        wire::le24 blocks_allocated_copy;
        wire::le24 starting_block;
        wire::be16 path_indicator;
        wire::be32 file_size;
        wire::be32 update_timestamp;
        wire::be32 access_timestamp;
    };
    static_assert(wire::WireLayout<stfs_file_table_entry>);
    static_assert(sizeof(stfs_file_table_entry) == 0x40);
    static_assert(offsetof(stfs_file_table_entry, flags) == 0x28);
    static_assert(offsetof(stfs_file_table_entry, blocks_allocated) == 0x29);
    static_assert(offsetof(stfs_file_table_entry, blocks_allocated_copy) == 0x2C);
    static_assert(offsetof(stfs_file_table_entry, starting_block) == 0x2F);
    static_assert(offsetof(stfs_file_table_entry, path_indicator) == 0x32);
    static_assert(offsetof(stfs_file_table_entry, file_size) == 0x34);
    static_assert(offsetof(stfs_file_table_entry, update_timestamp) == 0x38);
    static_assert(offsetof(stfs_file_table_entry, access_timestamp) == 0x3C);

    // Byte offset of the level-`level` hash entry for logical block `block`: the entry's index in
    // the hash table block that covers it, scaled by kHashEntrySize, added to that table block's
    // offset. Fails like compute_level_n_hash_block_number and block_to_offset.
    [[nodiscard]] Result<std::uint64_t> hash_entry_offset(std::uint32_t block, int level,
                                                          std::uint32_t header_size);

} // namespace gxbuild3::stfs
