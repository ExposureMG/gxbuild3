#include "orchestration/RunBuildImage.hpp"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace gxbuild3::orchestration {

    std::optional<nand::FlashImage> parse_image(std::span<const uint8_t> bytes) {
        auto image = nand::FlashImage::read(test::Bytes(bytes.begin(), bytes.end()));
        if (!image || !image->parse()) {
            return std::nullopt;
        }
        return image;
    }

    std::optional<test::Bytes> read_logical(std::span<const uint8_t> image, size_t offset,
                                            size_t length) {
        auto parsed = nand::FlashImage::read(test::Bytes(image.begin(), image.end()));
        if (!parsed || !parsed->parse()) {
            return std::nullopt;
        }
        const auto bytes = std::as_const(parsed->flash_driver).read_offset(offset, length);
        return test::Bytes(bytes.begin(), bytes.end());
    }

    uint32_t align_16(uint32_t value) {
        return (value + 0x0F) & ~uint32_t{0x0F};
    }

    bool zero_between(std::span<const uint8_t> bytes, size_t begin, size_t end) {
        return end <= bytes.size() &&
               std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                           bytes.begin() + static_cast<std::ptrdiff_t>(end),
                           [](uint8_t byte) { return byte == 0; });
    }

} // namespace gxbuild3::orchestration
