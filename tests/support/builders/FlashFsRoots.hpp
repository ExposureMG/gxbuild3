#pragma once

// Hand-built FlashFS roots, shared by the nand FlashFS unit tests and the flashfs_roots golden:
// big-endian table and directory fields, where a cluster's link and a directory slot sit in a
// root, a small-block root with four one-cluster files, and the load pin that writes a root, loads
// it and records the outcome as a golden line. Moved verbatim from tests/FlashFileSystemTests.cpp;
// tests/golden/flashfs_roots.txt depends on their bytes and text. No GoogleTest here.

#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/objects/FlashFileSystem.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::test::flashfs {

    // Big-endian 16- and 32-bit fields; the offset is not checked.
    void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value);
    void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value);

    // Where a cluster's link sits in the root's table: 256 links per 1 KiB.
    [[nodiscard]] size_t map_offset(size_t cluster);

    // Where a directory slot sits in the root: 16 entries of 32 bytes per directory page, the
    // directory pages alternating with the table pages.
    [[nodiscard]] size_t slot_offset(size_t slot);

    // Writes a directory entry: the name (zero-padded, not terminated when it fills all 22
    // bytes), its block relative to the filesystem's base, its length and the stamp 0x5D444AC2.
    void put_entry(std::vector<uint8_t>& root, size_t slot, std::string_view name,
                   uint16_t relative_block, uint32_t length);

    // A small-block root at block 0x3E0 with every cluster Free and four one-cluster files at
    // 0x60..0x63.
    [[nodiscard]] std::vector<uint8_t> small_root();

    // "ok" or "err=<code>".
    [[nodiscard]] std::string outcome(const Result<>& result);

    // Writes `root` at `root_block`, loads it into `fs` (the result into `result`) and returns the
    // golden line "[load <name>] <outcome>[ entries=<name>@0x<block>,...]".
    [[nodiscard]] std::string load_pin(const char* name, nand::Driver& driver,
                                       const std::vector<uint8_t>& root, uint16_t root_block,
                                       nand::FlashFileSystem& fs, Result<>& result);

    // The name in a directory slot, up to its terminator or 22 characters.
    [[nodiscard]] std::string slot_name(const std::vector<uint8_t>& root, size_t slot);

} // namespace gxbuild3::test::flashfs
