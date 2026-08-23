#pragma once

#include "Args.hpp"
#include "BuildRunner.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace GxBuild {

    std::optional<std::vector<uint8_t>> RunBuild(const Input& input);

    std::optional<InputMetadata> ExtractMetadata(
        std::span<const uint8_t> nand_image,
        std::span<const uint8_t> cpu_key
    );

    std::optional<InputMetadata> ExtractMetadata(
        const std::vector<uint8_t>& nand_image,
        const std::vector<uint8_t>& cpu_key
    );

    std::optional<AllNandInfo> ExtractAllInfo(
        std::span<const uint8_t> nand_image,
        std::span<const uint8_t> cpu_key
    );

    std::optional<AllNandInfo> ExtractAllInfo(
        const std::vector<uint8_t>& nand_image,
        const std::vector<uint8_t>& cpu_key
    );

    std::optional<Input> ExtractAll(
        std::span<const uint8_t> nand_image,
        std::span<const uint8_t> cpu_key
    );

    std::optional<Input> ExtractAll(
        const std::vector<uint8_t>& nand_image,
        const std::vector<uint8_t>& cpu_key
    );

} // namespace GxBuild
