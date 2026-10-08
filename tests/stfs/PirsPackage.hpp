#pragma once

// The synthetic read-only PIRS packages of the src/stfs tests (gxbuild3_stfs_tests), kept
// area-local: its fill pattern (byte i = (i * 7 + seed) & 0xFF) is a third formula, neither
// test::flashfs_pattern nor test::image_pattern, and utils' make_simple_package is a separate
// builder.
//
// Layout (block_separation bit 0 set):
//   header_size 0xA000, one level-0 hash table at 0xA000,
//   logical block N stored at 0xB000 + N * 0x1000.
// Logical block 0 holds the file table; files follow in consecutive blocks.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::stfs::pirs {

    using Bytes = std::vector<std::byte>;

    inline constexpr std::size_t kBlockSize = 0x1000;
    inline constexpr std::size_t kHeaderSize = 0xA000;
    inline constexpr std::size_t kHashTable = 0xA000;
    inline constexpr std::size_t kVolumeDescriptor = 0x379;

    [[nodiscard]] constexpr std::size_t data_offset(std::uint32_t logical) {
        return kHashTable + (logical + 1) * kBlockSize;
    }
    [[nodiscard]] constexpr std::size_t hash_offset(std::uint32_t logical) {
        return kHashTable + logical * 0x18;
    }
    [[nodiscard]] constexpr std::size_t entry_offset(std::size_t index) {
        return data_offset(0) + index * 0x40;
    }

    // Big- and little-endian fields of `width` bytes; bytes.at() throws past the end.
    void put_be(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width);
    void put_le(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width);

    // The volume descriptor's total allocated block count (big-endian at 0x395).
    [[nodiscard]] std::uint32_t total_blocks(const Bytes& package);

    // Recomputes the level-0 data hashes and the top hash so verification passes.
    void seal(Bytes& package);

    struct SynthFile {
        std::string name;
        Bytes data;
        bool consecutive = true;
        std::int16_t parent = -1;
        bool directory = false;
    };

    // One file-table block, then each file in consecutive blocks with its hash chain, sealed.
    // Records a test failure and returns an empty package when the files do not fit (at most 64
    // entries, names of at most 0x28 bytes, at most 0xAA blocks in all).
    [[nodiscard]] Bytes make_package(const std::vector<SynthFile>& files);

    // Overwrites the 0x40-byte file-table entry at `offset` (parent 0xFFFF).
    void write_entry(Bytes& bytes, std::size_t offset, std::string_view name, std::uint8_t flags,
                     std::uint32_t blocks, std::uint32_t start, std::uint32_t size);

    // byte i = (i * 7 + seed) & 0xFF.
    [[nodiscard]] Bytes pattern(std::size_t size, std::uint8_t seed);

    // The same bytes viewed as uint8_t, for test::write_file.
    [[nodiscard]] std::span<const std::uint8_t> as_u8(const Bytes& bytes);

} // namespace gxbuild3::stfs::pirs
