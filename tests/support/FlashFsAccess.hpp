#pragma once

// The one test-side definition of nand::FlashFileSystemTestAccess, the friend that
// src/nand/objects/FlashFileSystem.hpp declares. Every test TU that needs FlashFileSystem's
// private members includes this header, so the struct has a single definition in any binary.

#include "nand/objects/FlashFileSystem.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace gxbuild3::nand {

    struct FlashFileSystemTestAccess {
        // The block count FlashFileSystem allocates for bytes_needed, or nullopt on overflow.
        static std::optional<size_t> checked_block_count(size_t bytes_needed,
                                                         size_t clean_block_size) {
            return FlashFileSystem::checked_block_count(bytes_needed, clean_block_size);
        }

        // The goldens need a chain link carrying the 0x8000 bit, which only load() produces
        // through the public API.
        static std::vector<uint16_t>& blockmap(FlashFileSystem& fs) { return fs.m_blockmap; }
    };

} // namespace gxbuild3::nand
