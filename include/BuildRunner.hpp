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

BuildResult RunBuild(const Input& input);

std::optional<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image);

std::optional<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image);

std::optional<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                             std::span<const uint8_t> cpu_key);

std::optional<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                             const std::vector<uint8_t>& cpu_key);

std::optional<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                          std::span<const uint8_t> cpu_key);

std::optional<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                          const std::vector<uint8_t>& cpu_key);

std::optional<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                std::span<const uint8_t> cpu_key);

std::optional<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                const std::vector<uint8_t>& cpu_key);
