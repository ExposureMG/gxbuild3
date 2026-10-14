#pragma once

#include "Args.hpp"
#include "Error.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::utils {

    struct InMemoryStfsPackage {
        std::string name;
        std::vector<uint8_t> data;
    };

    struct ScanOptions {
        // Do not discover or open system-update STFS packages.
        bool nosu = false;
        // Exclude security contents from STFS extraction, but still use loose files.
        bool nosusecurity = false;
        // In-memory STFS packages (queried without requiring a filesystem path).
        std::vector<InMemoryStfsPackage> in_memory_stfs{};
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

    // A failed lookup: the Error and the candidate and source root it concerns. For an
    // in-memory package, source_path and root_path are empty and root_index counts the
    // in-memory packages, as ResolvedFile::root_index does.
    struct FileLookupError : Error {
        std::filesystem::path source_path;
        std::filesystem::path root_path;
        size_t root_index{0};
        AssetSource source{AssetSource::Loose};
    };

    // An error means the lookup failed; an empty optional means no root has the asset.
    using FileLookupResult = std::expected<std::optional<ResolvedFile>, FileLookupError>;

    struct IniFilesResult {
        InputBootloaders bootloaders;
        std::vector<std::pair<std::string, std::vector<uint8_t>>> flashfs_sec;
        std::vector<InputRawPatch> raw_patches;
    };

    // The name a release INI entry is looked up under. xeBuild reads "..\data\x.bin" from
    // the release directory, so its leading ".." components are dropped and the rest is
    // found in the source roots, one of which holds the release directory.
    std::string ini_asset_name(std::string_view entry);

    // Whether an INI entry names a file outside its release (a leading ".."). xeBuild goes
    // without such a file when it is missing ("could not read file ..., skipping").
    bool ini_asset_is_outside(std::string_view entry);

    // Search roots are ordered from highest to lowest priority. Within a root,
    // loose files win over STFS entries, then derived CF/CG parts. Payloads are
    // unique by lowercase basename; bootloader chain slots remain independent.
    // A source that cannot be inspected or read is skipped with a warning (xeBuild
    // parity); an asset that escapes its source root fails the whole INI.
    [[nodiscard]] Result<IniFilesResult>
    read_ini_files(const std::filesystem::path& ini_path, std::string_view target_section,
                   const std::vector<std::filesystem::path>& search_paths, ScanOptions options = {},
                   BuildType build_type = BuildType::Retail);

    // Convenience wrapper: fw_dir (or mydata), version, then common.
    [[nodiscard]] Result<IniFilesResult>
    read_ini_files(std::string_view version, std::string_view type, std::string_view target_section,
                   const std::filesystem::path& fw_dir = {}, ScanOptions options = {},
                   BuildType build_type = BuildType::Retail);

    // Returns bytes and provenance for an asset, using the same lookup priority as
    // read_ini_files. Without an INI, nosusecurity excludes
    // crl/dae/odd/extended/fcrt/secdata.bin from STFS. Unlike read_ini_files, the
    // highest-priority source that cannot be inspected or read fails the lookup instead
    // of being skipped; the error retains candidate and source-root provenance.
    [[nodiscard]] FileLookupResult
    find_file_data_detailed(std::string_view filename,
                            const std::vector<std::filesystem::path>& search_paths,
                            ScanOptions options = {}, AssetKind kind = AssetKind::Regular);

    // Clears cached STFS containers, directory listings, and derived bootloader parts.
    void clear_stfs_cache();

} // namespace gxbuild3::utils
