#pragma once

#include "patchers/BinaryParser.hpp"
#include "patchers/Patcher.hpp"
#include "patchers/Signature.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace GxBuild {

    struct BuildOptions {
        std::optional<std::vector<uint8_t>> cpu_key;
        std::optional<std::vector<uint8_t>> bl_key;
        std::optional<std::filesystem::path> data_dir;
        std::optional<std::filesystem::path> common_dir;
        std::optional<std::filesystem::path> fw_dir;
        std::optional<std::filesystem::path> source_nand_path;
        std::optional<std::vector<uint8_t>> source_nand_bytes;
        std::optional<std::filesystem::path> custom_kv_path;
        std::optional<std::filesystem::path> custom_smc_path;
        std::optional<std::filesystem::path> custom_smc_config_path;
        // Explicit xboxupd.bin path. When set, takes priority over auto-discovery.
        // Used as the source for CF+CG when individual bl files are absent.
        std::optional<std::filesystem::path> xboxupd_path;
        // PIRS/STFS addon packages. Each is extracted in-memory and used as a
        // fallback source for both xboxupd.bin (→ CF/CG) and flashfs payload files.
        std::vector<std::filesystem::path> addon_stfs_paths;
        // Key-value options (e.g. {{"nofcrt", ""}, {"cputemp", "65"}})
        std::vector<std::pair<std::string, std::string>> options;
        // Additional raw patch filenames / paths
        std::vector<std::string> raw_patches;
    };

    // Builds a NAND image directly in C++ memory from a native xeBuild INI string
    std::expected<std::vector<uint8_t>, std::string>
    BuildNandFromXeBuildIni(std::string_view ini_string, std::string_view image_type,
                            std::string_view console_model, const BuildOptions& options,
                            const std::function<void(const std::string&)>& log_callback = nullptr);

    // --- Standalone Patcher API Exposed via gxbuild3_lib ---

    namespace Patcher {

        // 1. Raw Byte Patching: Copy raw payload buffer into target data buffer at offset
        bool ApplyRawPatch(std::span<uint8_t> targetData, uint32_t offset,
                           std::span<const uint8_t> payload);

        // 2. XePatch Words Patching: Write array of 32-bit big-endian words to address
        bool ApplyXePatchWords(std::span<uint8_t> targetData, uint32_t address, uint32_t wordCount,
                               const uint32_t* patchWords);

        // 3. XePatch Entry & Section Patching
        bool ApplyXePatchEntry(std::span<uint8_t> targetData, const XePatchEntry& entry);
        bool ApplyXePatchSection(std::span<uint8_t> targetData, const XePatchSection& section);

        // 4. Pattern / Signature Search & Replace (e.g. SMC autopatcher)
        uint32_t ApplySignaturePatch(std::span<uint8_t> targetData,
                                     const std::string& searchPatternStr,
                                     const std::string& replacePatternStr);

        // 5. Binary Patch Parser & Serializer API
        bool ParsePatchFile(const std::string& filePath, std::vector<XePatchSection>& outSections);
        bool ParsePatchSet(const std::string& filePath, BuildType buildType,
                           ParsedPatchSet& outPatchSet);
        std::vector<uint8_t> SerializePatchSet(const ParsedPatchSet& patchSet);

    } // namespace Patcher

} // namespace GxBuild
