#pragma once

#include "gxbuild/Error.hpp"
#include "gxbuild/Types.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild {

    [[nodiscard]] Result<std::vector<uint8_t>> RunBuild(const Input& input);

    [[nodiscard]] Result<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image);
    [[nodiscard]] Result<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image);

    [[nodiscard]] Result<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                                        std::span<const uint8_t> cpu_key);
    [[nodiscard]] Result<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                                        const std::vector<uint8_t>& cpu_key);

    [[nodiscard]] Result<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                                       std::span<const uint8_t> cpu_key);
    [[nodiscard]] Result<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                                       const std::vector<uint8_t>& cpu_key);

    [[nodiscard]] Result<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                           std::span<const uint8_t> cpu_key);
    [[nodiscard]] Result<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                           const std::vector<uint8_t>& cpu_key);

} // namespace gxbuild
