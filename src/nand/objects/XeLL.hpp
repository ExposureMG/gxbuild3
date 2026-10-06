#pragma once

#include "Error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gxbuild3::nand {

    struct XeLLMetadata {
        std::string version;
        std::string author;
        std::string date;
    };

    struct XeLL {
        static constexpr size_t kSize = 256 * 1024;

        XeLLMetadata metadata;
        std::vector<uint8_t> data;

        // Refuses an image that is not exactly kSize bytes (Truncated / OutOfRange) or that
        // starts with neither the PPC exception vectors nor an ELF header (Malformed).
        [[nodiscard]] static Result<XeLL> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<XeLL> parse(const std::vector<uint8_t>& bytes);
    };

} // namespace gxbuild3::nand
