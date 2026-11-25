#pragma once

#include "core/Args.hpp"
#include "gxbuild/Error.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild {

    [[nodiscard]] Result<AllNandInfo> extract_some_info(std::span<const uint8_t> nand_image);

    [[nodiscard]] Result<AllNandInfo> extract_some_info(const std::vector<uint8_t>& nand_image);

    [[nodiscard]] Result<InputMetadata> extract_metadata(std::span<const uint8_t> nand_image,
                                                         std::span<const uint8_t> cpu_key);

    [[nodiscard]] Result<InputMetadata> extract_metadata(const std::vector<uint8_t>& nand_image,
                                                         const std::vector<uint8_t>& cpu_key);

    [[nodiscard]] Result<AllNandInfo> extract_all_info(std::span<const uint8_t> nand_image,
                                                       std::span<const uint8_t> cpu_key);

    [[nodiscard]] Result<AllNandInfo> extract_all_info(const std::vector<uint8_t>& nand_image,
                                                       const std::vector<uint8_t>& cpu_key);

    [[nodiscard]] Result<Input> extract_all(std::span<const uint8_t> nand_image,
                                            std::span<const uint8_t> cpu_key);

    [[nodiscard]] Result<Input> extract_all(const std::vector<uint8_t>& nand_image,
                                            const std::vector<uint8_t>& cpu_key);

} // namespace gxbuild
