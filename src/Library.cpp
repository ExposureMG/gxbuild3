#include "Library.hpp"

namespace GxBuild {

    std::optional<std::vector<uint8_t>> RunBuild(const Input& input) {
        return ::RunBuild(input);
    }

    std::optional<InputMetadata> ExtractMetadata(
        std::span<const uint8_t> nand_image,
        std::span<const uint8_t> cpu_key
    ) {
        return ::ExtractMetadata(nand_image, cpu_key);
    }

    std::optional<InputMetadata> ExtractMetadata(
        const std::vector<uint8_t>& nand_image,
        const std::vector<uint8_t>& cpu_key
    ) {
        return ::ExtractMetadata(nand_image, cpu_key);
    }

} // namespace GxBuild
