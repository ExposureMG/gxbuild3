#include "Library.hpp"

namespace GxBuild {

    BuildResult RunBuild(const Input& input) {
        return ::RunBuild(input);
    }

    std::optional<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image) {
        return ::ExtractSomeInfo(nand_image);
    }

    std::optional<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image) {
        return ::ExtractSomeInfo(nand_image);
    }

    std::optional<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                                 std::span<const uint8_t> cpu_key) {
        return ::ExtractMetadata(nand_image, cpu_key);
    }

    std::optional<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                                 const std::vector<uint8_t>& cpu_key) {
        return ::ExtractMetadata(nand_image, cpu_key);
    }

    std::optional<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                              std::span<const uint8_t> cpu_key) {
        return ::ExtractAllInfo(nand_image, cpu_key);
    }

    std::optional<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                              const std::vector<uint8_t>& cpu_key) {
        return ::ExtractAllInfo(nand_image, cpu_key);
    }

    std::optional<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                    std::span<const uint8_t> cpu_key) {
        return ::ExtractAll(nand_image, cpu_key);
    }

    std::optional<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                    const std::vector<uint8_t>& cpu_key) {
        return ::ExtractAll(nand_image, cpu_key);
    }

} // namespace GxBuild
