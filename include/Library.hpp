#pragma once

#include "GxBuildTypes.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace GxBuild {

    [[nodiscard]] BuildResult RunBuild(const Input& input);

    [[nodiscard]] std::optional<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image);

    [[nodiscard]] std::optional<AllNandInfo>
    ExtractSomeInfo(const std::vector<uint8_t>& nand_image);

    [[nodiscard]] std::optional<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                                               std::span<const uint8_t> cpu_key);

    [[nodiscard]] std::optional<InputMetadata>
    ExtractMetadata(const std::vector<uint8_t>& nand_image, const std::vector<uint8_t>& cpu_key);

    [[nodiscard]] std::optional<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                                            std::span<const uint8_t> cpu_key);

    [[nodiscard]] std::optional<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                                            const std::vector<uint8_t>& cpu_key);

    [[nodiscard]] std::optional<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                                  std::span<const uint8_t> cpu_key);

    [[nodiscard]] std::optional<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                                  const std::vector<uint8_t>& cpu_key);

} // namespace GxBuild
