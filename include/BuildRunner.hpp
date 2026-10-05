#pragma once

#include "Args.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

enum class BuildErrorCode {
    InvalidInput,
    InvalidDonor,
    InvalidSmc,
    InvalidKeyvault,
    InvalidBootloader,
    PatchFailure,
    EncryptionFailure,
    SerializationFailure,
};

struct BuildError {
    BuildErrorCode code;
    std::string message;
};

using BuildResult = std::expected<std::vector<uint8_t>, BuildError>;

namespace gxbuild3 {

    BuildResult run_build(const Input& input);

    std::optional<AllNandInfo> extract_some_info(std::span<const uint8_t> nand_image);

    std::optional<AllNandInfo> extract_some_info(const std::vector<uint8_t>& nand_image);

    std::optional<InputMetadata> extract_metadata(std::span<const uint8_t> nand_image,
                                                  std::span<const uint8_t> cpu_key);

    std::optional<InputMetadata> extract_metadata(const std::vector<uint8_t>& nand_image,
                                                  const std::vector<uint8_t>& cpu_key);

    std::optional<AllNandInfo> extract_all_info(std::span<const uint8_t> nand_image,
                                                std::span<const uint8_t> cpu_key);

    std::optional<AllNandInfo> extract_all_info(const std::vector<uint8_t>& nand_image,
                                                const std::vector<uint8_t>& cpu_key);

    std::optional<Input> extract_all(std::span<const uint8_t> nand_image,
                                     std::span<const uint8_t> cpu_key);

    std::optional<Input> extract_all(const std::vector<uint8_t>& nand_image,
                                     const std::vector<uint8_t>& cpu_key);

} // namespace gxbuild3
