#pragma once

// Synthetic patch files shared by the orchestration and resolver tests and the run_build and
// resolver goldens. Moved verbatim from tests/BuildRunnerTests.cpp and
// tests/BuildInputResolverTests.cpp; the goldens depend on their bytes. Big-endian words come
// from append_be32 (support/Bytes.hpp). No GoogleTest here.

#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild3::test {

    using Bytes = std::vector<uint8_t>;

    // A glitch patch file: section one patches one word at first_address (CB, or CB_B for
    // glitch2 and up), section two one word at cd_address (CD), each closed by 0xFFFFFFFF;
    // the KHV bytes follow.
    [[nodiscard]] Bytes glitch_patchset(uint32_t first_address, uint32_t first_word,
                                        uint32_t cd_address, uint32_t cd_word,
                                        std::span<const uint8_t> khv);

    // glitch_patchset(0x20, 0x11223344, 0x30, 0x55667788, {marker}): the resolver's stand-in
    // patch file.
    [[nodiscard]] Bytes valid_glitch_patchset(uint8_t marker = 0xA0);

    // A JTAG patch file: three four-byte sections (0x10, 0x11, 0x12 bytes), each closed by
    // 0xFFFFFFFF, then section four as given.
    [[nodiscard]] Bytes jtag_patchset(std::span<const uint8_t> section4);

    // One glitch patch file section of a single entry, then the delimiter.
    void append_patch_entry(Bytes& bytes, uint32_t address, uint32_t word);

} // namespace gxbuild3::test
