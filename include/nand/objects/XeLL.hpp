#pragma once

#include "gxbuild/Error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gxbuild::nand {

    struct XeLLMetadata {
        std::string version;
        std::string author;
        std::string date;
    };

    struct XeLL {
        static constexpr size_t kSize = 256 * 1024;

        XeLLMetadata metadata;
        std::vector<uint8_t> data;

        [[nodiscard]] static Result<XeLL> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<XeLL> parse(const std::vector<uint8_t>& bytes);
    };

} // namespace gxbuild::nand
