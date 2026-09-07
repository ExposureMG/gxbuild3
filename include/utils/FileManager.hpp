#pragma once

#include "Args.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace gxbuild3::utils {

    struct ScanOptions {
        // Do not discover or open system-update STFS packages.
        bool nosu = false;
        // Exclude security contents from STFS extraction, but still use loose files.
        bool nosusecurity = false;
    };

    enum class AssetSource {
        Loose,
        Stfs,
        Xboxupd
    };
    enum class AssetKind {
        Regular,
        Bootloader
    };

    struct ResolvedFile {
        std::string requested_name;
        std::filesystem::path source_path;
        std::vector<uint8_t> data;
        size_t root_index{0};
        AssetSource source{AssetSource::Loose};
    };

    enum class FileLookupErrorCode {
        InspectionFailed,
        ReadFailed,
    };

    struct FileLookupError {
        FileLookupErrorCode code;
        std::string message;
        std::filesystem::path source_path;
        std::filesystem::path root_path;
        size_t root_index{0};
        AssetSource source{AssetSource::Loose};
    };

    using FileLookupResult = std::expected<std::optional<ResolvedFile>, FileLookupError>;

    struct IniFilesResult {
        InputBootloaders bootloaders;
        std::vector<std::pair<std::string, std::vector<uint8_t>>> flashfs_sec;
    };

    // Search roots are ordered from highest to lowest priority. Within a root,
    // loose files win over STFS entries, then derived CF/CG parts. Payloads are
    // unique by lowercase basename; bootloader chain slots remain independent.
    std::optional<IniFilesResult>
    ReadIniFiles(const std::filesystem::path& ini_path, std::string_view target_section,
                 const std::vector<std::filesystem::path>& search_paths, ScanOptions options = {});

    // Convenience wrapper: fw_dir (or mydata), version, then common.
    std::optional<IniFilesResult> ReadIniFiles(std::string_view version, std::string_view type,
                                               std::string_view target_section,
                                               const std::filesystem::path& fw_dir = {},
                                               ScanOptions options = {});

    // Same priority rules. STFS matches return the package path. Keys are
    // lowercase basenames. Throws if any unique requested file is unavailable.
    // Without an INI, nosusecurity excludes crl/dae/odd/extended/fcrt/secdata.bin.
    std::unordered_map<std::string, std::filesystem::path>
    FindFiles(const std::vector<std::string>& filenames,
              const std::vector<std::filesystem::path>& search_paths, ScanOptions options = {});

    // Returns bytes and provenance for an optional asset using the same lookup
    // priority as FindFiles and ReadIniFiles.
    std::optional<ResolvedFile> FindFileData(std::string_view filename,
                                             const std::vector<std::filesystem::path>& search_paths,
                                             ScanOptions options = {},
                                             AssetKind kind = AssetKind::Regular);

    // Detailed counterpart for callers that must distinguish absence from a failure to inspect or
    // read the highest-priority candidate. Errors retain candidate and source-root provenance.
    FileLookupResult FindFileDataDetailed(std::string_view filename,
                                          const std::vector<std::filesystem::path>& search_paths,
                                          ScanOptions options = {},
                                          AssetKind kind = AssetKind::Regular);

} // namespace gxbuild3::utils

namespace FileManager {
    using namespace gxbuild3::utils;
}
