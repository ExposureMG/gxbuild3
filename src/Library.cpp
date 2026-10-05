#include "Library.hpp"

#include "BuildRunner.hpp"

namespace GxBuild {

    BuildResult RunBuild(const Input& input) {
        return gxbuild3::run_build(input);
    }

    std::optional<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image) {
        return gxbuild3::extract_some_info(nand_image);
    }

    std::optional<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image) {
        return gxbuild3::extract_some_info(nand_image);
    }

    std::optional<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                                 std::span<const uint8_t> cpu_key) {
        return gxbuild3::extract_metadata(nand_image, cpu_key);
    }

    std::optional<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                                 const std::vector<uint8_t>& cpu_key) {
        return gxbuild3::extract_metadata(nand_image, cpu_key);
    }

    std::optional<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                              std::span<const uint8_t> cpu_key) {
        return gxbuild3::extract_all_info(nand_image, cpu_key);
    }

    std::optional<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                              const std::vector<uint8_t>& cpu_key) {
        return gxbuild3::extract_all_info(nand_image, cpu_key);
    }

    std::optional<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                    std::span<const uint8_t> cpu_key) {
        return gxbuild3::extract_all(nand_image, cpu_key);
    }

    std::optional<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                    const std::vector<uint8_t>& cpu_key) {
        return gxbuild3::extract_all(nand_image, cpu_key);
    }

} // namespace GxBuild
