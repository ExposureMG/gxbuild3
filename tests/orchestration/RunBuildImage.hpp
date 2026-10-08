#pragma once

// Reads of a run_build image shared by the orchestration tests: the image read and parsed as a
// FlashImage, the logical bytes at an offset (through FlashImage's driver, so spare bytes and
// bad-block remaps are hidden), and the two size checks the patch tests make of a patched stage.
// The old tests/BuildRunnerTests.cpp helpers, same behaviour.

#include "nand/FlashImage.hpp"
#include "support/Bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace gxbuild3::orchestration {

    // The image read and parsed as a FlashImage, or nullopt when it does not read or parse.
    [[nodiscard]] std::optional<nand::FlashImage> parse_image(std::span<const uint8_t> bytes);

    // `length` logical bytes at `offset` of the image, or nullopt when the image does not read or
    // parse as a FlashImage. A read past the image's end is shorter than `length`.
    [[nodiscard]] std::optional<test::Bytes> read_logical(std::span<const uint8_t> image,
                                                          size_t offset, size_t length);

    // value rounded up to a multiple of 0x10.
    [[nodiscard]] uint32_t align_16(uint32_t value);

    // Whether bytes[begin, end) are all zero; false when end is past the span.
    [[nodiscard]] bool zero_between(std::span<const uint8_t> bytes, size_t begin, size_t end);

} // namespace gxbuild3::orchestration
