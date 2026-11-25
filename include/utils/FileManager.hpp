#pragma once

#include "core/Args.hpp"
#include "gxbuild/Error.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild::utils {

    struct StfsCacheAccess;

    class StfsCache {
      public:
        StfsCache();
        ~StfsCache();
        StfsCache(const StfsCache&) = delete;
        StfsCache& operator=(const StfsCache&) = delete;
        StfsCache(StfsCache&&) noexcept;
        StfsCache& operator=(StfsCache&&) noexcept;

        void clear();

      private:
        friend struct StfsCacheAccess;
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

    struct InMemoryStfsPackage {
        std::string name;
        std::vector<uint8_t> data;
    };

    struct ScanOptions {
        bool nosu = false;
        bool nosusecurity = false;
        std::vector<InMemoryStfsPackage> in_memory_stfs{};
        StfsCache* stfs_cache = nullptr;
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

    struct IniFilesResult {
        InputBootloaders bootloaders;
        std::vector<std::pair<std::string, std::vector<uint8_t>>> flashfs_sec;
        std::vector<InputRawPatch> raw_patches;
    };

    std::string ini_asset_name(std::string_view entry);

    bool ini_asset_is_outside(std::string_view entry);

    [[nodiscard]] Result<IniFilesResult>
    read_ini_files(const std::filesystem::path& ini_path, std::string_view target_section,
                   const std::vector<std::filesystem::path>& search_paths, ScanOptions options = {},
                   BuildType build_type = BuildType::Retail);

    [[nodiscard]] Result<IniFilesResult>
    read_ini_files(std::string_view version, std::string_view type, std::string_view target_section,
                   const std::filesystem::path& fw_dir = {}, ScanOptions options = {},
                   BuildType build_type = BuildType::Retail);

    [[nodiscard]] Result<std::optional<ResolvedFile>>
    find_file_data_detailed(std::string_view filename,
                            const std::vector<std::filesystem::path>& search_paths,
                            ScanOptions options = {}, AssetKind kind = AssetKind::Regular);

} // namespace gxbuild::utils
