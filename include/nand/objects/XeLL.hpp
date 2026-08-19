#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace gxbuild3::NAND {

    struct XeLLMetadata {
        std::string version;
        std::string author;
        std::string date;
    };

    struct XeLL {
        static constexpr size_t kSize = 256 * 1024;

        XeLLMetadata metadata;
        std::vector<uint8_t> data;

        static std::optional<XeLL> parse(std::span<const uint8_t> bytes);
        static std::optional<XeLL> parse(const std::vector<uint8_t>& bytes);
    };

} // namespace gxbuild3::NAND
