#include "utils/FileManager.hpp"

#include "ini/IniParser.hpp"
#include "nand/objects/Xboxupd.hpp"
#include "stfs/StfsContainer.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>

namespace gxbuild3::utils {
    namespace {

        std::string normalize_file_key(std::string key) {
            std::replace(key.begin(), key.end(), '\\', '/');
            if (auto pos = key.rfind('/'); pos != std::string::npos)
                key.erase(0, pos + 1);
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return key;
        }

        std::filesystem::path entry_to_lookup_path(std::string_view name) {
            std::string normalized{name};
            std::replace(normalized.begin(), normalized.end(), '\\', '/');
            return std::filesystem::path(normalized);
        }

        bool safe_asset_name(std::string_view name) {
            const auto path = entry_to_lookup_path(name);
            if (path.empty() || path.has_root_path() || name.find(':') != std::string_view::npos ||
                name.find('\0') != std::string_view::npos)
                return false;
            return std::none_of(path.begin(), path.end(),
                                [](const auto& component) { return component == ".."; });
        }

        bool contained_asset_path(const std::filesystem::path& root,
                                  const std::filesystem::path& relative) {
            std::error_code error;
            const auto canonical_root = std::filesystem::weakly_canonical(root, error);
            if (error)
                return false;
            const auto canonical_candidate =
                std::filesystem::weakly_canonical(root / relative, error);
            if (error)
                return false;
            const auto within = canonical_candidate.lexically_relative(canonical_root);
            return !within.empty() && !within.has_root_path() &&
                   std::none_of(within.begin(), within.end(),
                                [](const auto& component) { return component == ".."; });
        }

        std::vector<uint8_t> to_u8(std::span<const std::byte> data) {
            std::vector<uint8_t> result;
            result.reserve(data.size());
            for (const auto byte : data) {
                result.push_back(std::to_integer<uint8_t>(byte));
            }
            return result;
        }

        std::vector<std::string> security_file_names() {
            return {"crl.bin", "dae.bin", "odd.bin", "extended.bin", "fcrt.bin", "secdata.bin"};
        }

        std::optional<std::filesystem::path> find_stfs_file(const std::filesystem::path& dir) {
            std::optional<std::filesystem::path> result;
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                const auto candidate = entry.path();
                if (entry.is_regular_file() && !candidate.has_extension() &&
                    normalize_file_key(candidate.filename().string()).starts_with("su")) {
                    // Preserve one package per directory, with a deterministic tie-break.
                    if (!result || candidate < *result)
                        result = candidate;
                }
            }
            return result;
        }

        struct StfsAssets {
            std::filesystem::path path;
            Stfs::ExtractedFiles files;
        };

        std::optional<StfsAssets>
        load_stfs_from_dir(const std::filesystem::path& dir,
                           const std::vector<std::string>& excluded_names) {
            try {
                const auto path = find_stfs_file(dir);
                if (!path)
                    return std::nullopt;
                const auto data = read_file(*path);
                if (!data)
                    return std::nullopt;
                StfsAssets assets{*path, {}};
                const Stfs::StfsContainer container(std::as_bytes(std::span(*data)));
                assets.files = container.extractToMemory(excluded_names);
                Log::Info("Loaded {} files from STFS '{}'", assets.files.size(), path->string());
                return assets;
            } catch (const std::exception& e) {
                Log::Warn("Failed to extract STFS assets in '{}': {}", dir.string(), e.what());
                return std::nullopt;
            } catch (...) {
                Log::Warn("Failed to extract STFS assets in '{}'", dir.string());
                return std::nullopt;
            }
        }

        // Lower ranks win: root index first, then loose / STFS / derived parts.
        using SourceRank = std::pair<size_t, unsigned>;

        struct LocatedFile {
            std::filesystem::path path;
            std::vector<uint8_t> data;
            size_t root_index;
            AssetSource source;
            SourceRank rank;
        };

        class AssetSearch {
          public:
            AssetSearch(const std::vector<std::filesystem::path>& roots, ScanOptions options,
                        std::vector<std::string> security_names = security_file_names())
                : options_(options), excluded_(options.nosusecurity ? std::move(security_names)
                                                                    : std::vector<std::string>{}) {
                for (const auto& root : roots)
                    roots_.push_back({root, false, {}});
            }

            std::optional<LocatedFile>
            find(std::string_view name, AssetKind kind = AssetKind::Regular, bool contents = true) {
                if (!safe_asset_name(name))
                    return std::nullopt;
                const auto relative = entry_to_lookup_path(name);
                const auto key = normalize_file_key(std::string(name));
                for (size_t index = 0; index < roots_.size(); ++index) {
                    auto& root = roots_[index];
                    if (root.path.empty() || !std::filesystem::is_directory(root.path))
                        continue;
                    if (!contained_asset_path(root.path, relative)) {
                        invalid_path_ = true;
                        return std::nullopt;
                    }
                    const auto candidate = root.path / relative;
                    if (std::filesystem::is_regular_file(candidate)) {
                        if (!contents)
                            return LocatedFile{
                                candidate, {}, index, AssetSource::Loose, {index, 0}};
                        if (auto data = read_file(candidate))
                            return LocatedFile{
                                candidate, std::move(*data), index, AssetSource::Loose, {index, 0}};
                    }
                    if (options_.nosu ||
                        std::find(excluded_.begin(), excluded_.end(), key) != excluded_.end())
                        continue;
                    if (!root.loaded) {
                        root.loaded = true;
                        root.stfs = load_stfs_from_dir(root.path, excluded_);
                    }
                    if (!root.stfs)
                        continue;
                    auto& stfs = *root.stfs;
                    auto it = stfs.files.find(key);
                    // FindFiles historically also accepts a filename's bare stem.
                    if (it == stfs.files.end() && !contents) {
                        const auto stem = std::filesystem::path(key).stem().string();
                        if (std::find(excluded_.begin(), excluded_.end(), stem) == excluded_.end())
                            it = stfs.files.find(stem);
                    }
                    if (it != stfs.files.end()) {
                        std::vector<uint8_t> data;
                        if (contents) {
                            data.reserve(it->second.size());
                            for (auto byte : it->second)
                                data.push_back(std::to_integer<uint8_t>(byte));
                        }
                        return LocatedFile{
                            stfs.path, std::move(data), index, AssetSource::Stfs, {index, 1}};
                    }
                    if (kind == AssetKind::Bootloader) {
                        const auto stem = std::filesystem::path(key).stem().string();
                        const bool wants_xboxupd_part = key.starts_with("cf") ||
                                                        key.starts_with("cg") || stem == "6bl" ||
                                                        stem == "7bl";
                        const auto xboxupd = stfs.files.find("xboxupd.bin");
                        if (wants_xboxupd_part && xboxupd != stfs.files.end()) {
                            try {
                                const auto parts =
                                    bootloaders::split_xboxupd_raw(std::span(xboxupd->second));
                                const std::vector<uint8_t>* part = nullptr;
                                if (key.starts_with("cf") || stem == "6bl")
                                    part = &parts.cf_raw;
                                else if (key.starts_with("cg") || stem == "7bl")
                                    part = &parts.cg_raw;
                                if (part && !part->empty())
                                    return LocatedFile{stfs.path,
                                                       contents ? *part : std::vector<uint8_t>{},
                                                       index,
                                                       AssetSource::Xboxupd,
                                                       {index, 2}};
                            } catch (const std::exception& e) {
                                Log::Warn("Failed to split xboxupd.bin from STFS '{}': {}",
                                          stfs.path.string(), e.what());
                            } catch (...) {
                                Log::Warn("Failed to split xboxupd.bin from STFS '{}'",
                                          stfs.path.string());
                            }
                        }
                    }
                }
                return std::nullopt;
            }

            bool invalid_path() const { return invalid_path_; }

          private:
            struct Root {
                std::filesystem::path path;
                bool loaded;
                std::optional<StfsAssets> stfs;
            };
            ScanOptions options_;
            std::vector<std::string> excluded_;
            std::vector<Root> roots_;
            bool invalid_path_ = false;
        };

    } // namespace

    std::unordered_map<std::string, std::filesystem::path>
    FindFiles(const std::vector<std::string>& filenames,
              const std::vector<std::filesystem::path>& search_paths, ScanOptions options) {
        AssetSearch search(search_paths, options);
        std::unordered_map<std::string, LocatedFile> winners;
        for (const auto& name : filenames) {
            const auto key = normalize_file_key(name);
            if (auto candidate = search.find(name, AssetKind::Bootloader, false)) {
                const auto it = winners.find(key);
                if (it == winners.end() || candidate->rank < it->second.rank)
                    winners.insert_or_assign(key, std::move(*candidate));
            }
        }

        std::string missing;
        for (const auto& name : filenames) {
            if (!winners.contains(normalize_file_key(name))) {
                if (!missing.empty())
                    missing += ", ";
                missing += name;
            }
        }
        if (!missing.empty())
            throw std::runtime_error("FindFiles: could not locate required file(s): " + missing);

        std::unordered_map<std::string, std::filesystem::path> result;
        for (auto& [key, winner] : winners)
            result.emplace(key, std::move(winner.path));
        return result;
    }

    std::optional<ResolvedFile> FindFileData(std::string_view filename,
                                             const std::vector<std::filesystem::path>& search_paths,
                                             ScanOptions options, AssetKind kind) {
        if (!safe_asset_name(filename))
            return std::nullopt;
        const auto relative = entry_to_lookup_path(filename);
        const auto key = normalize_file_key(std::string(filename));
        const auto security_names = security_file_names();
        const auto excluded =
            options.nosusecurity &&
            std::find(security_names.begin(), security_names.end(), key) != security_names.end();

        for (size_t root_index = 0; root_index < search_paths.size(); ++root_index) {
            const auto& root = search_paths[root_index];
            std::error_code status_error;
            if (root.empty() || !std::filesystem::is_directory(root, status_error)) {
                continue;
            }

            if (!contained_asset_path(root, relative))
                return std::nullopt;
            const auto candidate = root / relative;
            status_error.clear();
            if (std::filesystem::is_regular_file(candidate, status_error)) {
                if (auto data = read_file(candidate)) {
                    return ResolvedFile{std::string(filename), candidate, std::move(*data),
                                        root_index, AssetSource::Loose};
                }
            }
            if (options.nosu || excluded) {
                continue;
            }

            try {
                const auto package = find_stfs_file(root);
                if (!package) {
                    continue;
                }
                const auto package_data = read_file(*package);
                if (!package_data) {
                    continue;
                }
                const Stfs::StfsContainer container(std::as_bytes(std::span(*package_data)));
                if (container.containsFileByName(key)) {
                    try {
                        const auto data = container.extractFileByName(key);
                        return ResolvedFile{std::string(filename), *package, to_u8(data),
                                            root_index, AssetSource::Stfs};
                    } catch (const std::exception& exception) {
                        Log::Warn("Failed to extract '{}' from STFS '{}': {}", filename,
                                  package->string(), exception.what());
                        continue;
                    } catch (...) {
                        Log::Warn("Failed to extract '{}' from STFS '{}'", filename,
                                  package->string());
                        continue;
                    }
                }

                const auto stem = std::filesystem::path(key).stem().string();
                const bool wants_xboxupd_part = key.starts_with("cf") || key.starts_with("cg") ||
                                                stem == "6bl" || stem == "7bl";
                if (kind != AssetKind::Bootloader || !wants_xboxupd_part ||
                    !container.containsFileByName("xboxupd.bin")) {
                    continue;
                }
                try {
                    const auto xboxupd = container.extractFileByName("xboxupd.bin");
                    const auto parts = bootloaders::split_xboxupd_raw(std::span(xboxupd));
                    const std::vector<uint8_t>* part = nullptr;
                    if (key.starts_with("cf") || stem == "6bl") {
                        part = &parts.cf_raw;
                    } else if (key.starts_with("cg") || stem == "7bl") {
                        part = &parts.cg_raw;
                    }
                    if (part && !part->empty()) {
                        return ResolvedFile{std::string(filename), *package, *part, root_index,
                                            AssetSource::Xboxupd};
                    }
                } catch (const std::exception& exception) {
                    Log::Warn("Failed to derive '{}' from xboxupd.bin in STFS '{}': {}", filename,
                              package->string(), exception.what());
                } catch (...) {
                    Log::Warn("Failed to derive '{}' from xboxupd.bin in STFS '{}'", filename,
                              package->string());
                }
            } catch (const std::exception& exception) {
                Log::Warn("Failed to inspect STFS assets in '{}': {}", root.string(),
                          exception.what());
            } catch (...) {
                Log::Warn("Failed to inspect STFS assets in '{}'", root.string());
            }
        }
        return std::nullopt;
    }

    FileLookupResult FindFileDataDetailed(std::string_view filename,
                                          const std::vector<std::filesystem::path>& search_paths,
                                          ScanOptions options, AssetKind kind) {
        if (!safe_asset_name(filename)) {
            return std::unexpected(FileLookupError{
                .code = FileLookupErrorCode::InspectionFailed,
                .message = "Asset name must be a confined relative path",
                .source_path = entry_to_lookup_path(filename),
                .root_path = {}});
        }
        const auto relative = entry_to_lookup_path(filename);
        const auto key = normalize_file_key(std::string(filename));
        const auto security_names = security_file_names();
        const bool excluded =
            options.nosusecurity &&
            std::find(security_names.begin(), security_names.end(), key) != security_names.end();
        for (size_t root_index = 0; root_index < search_paths.size(); ++root_index) {
            const auto& root = search_paths[root_index];
            try {
                std::error_code status_error;
                const auto root_status = std::filesystem::status(root, status_error);
                if (status_error && root_status.type() != std::filesystem::file_type::not_found) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Could not inspect source root: " + status_error.message(),
                        .source_path = root,
                        .root_path = root,
                        .root_index = root_index,
                        .source = AssetSource::Loose});
                }
                if (root_status.type() == std::filesystem::file_type::not_found ||
                    !std::filesystem::is_directory(root_status)) {
                    continue;
                }

                const auto candidate = root / relative;
                if (!contained_asset_path(root, relative)) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Asset path escapes its source root or cannot be inspected",
                        .source_path = candidate,
                        .root_path = root,
                        .root_index = root_index,
                        .source = AssetSource::Loose});
                }
                status_error.clear();
                const auto candidate_status = std::filesystem::status(candidate, status_error);
                if (status_error &&
                    candidate_status.type() != std::filesystem::file_type::not_found) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Could not inspect loose candidate: " + status_error.message(),
                        .source_path = candidate,
                        .root_path = root,
                        .root_index = root_index,
                        .source = AssetSource::Loose});
                }
                if (candidate_status.type() != std::filesystem::file_type::not_found &&
                    std::filesystem::exists(candidate_status)) {
                    if (!std::filesystem::is_regular_file(candidate_status)) {
                        return std::unexpected(
                            FileLookupError{.code = FileLookupErrorCode::InspectionFailed,
                                            .message = "Loose candidate is not a regular file",
                                            .source_path = candidate,
                                            .root_path = root,
                                            .root_index = root_index,
                                            .source = AssetSource::Loose});
                    }
                    auto data = read_file(candidate);
                    if (!data) {
                        return std::unexpected(
                            FileLookupError{.code = FileLookupErrorCode::ReadFailed,
                                            .message = "Could not read loose candidate",
                                            .source_path = candidate,
                                            .root_path = root,
                                            .root_index = root_index,
                                            .source = AssetSource::Loose});
                    }
                    return std::optional<ResolvedFile>{
                        ResolvedFile{std::string(filename), candidate, std::move(*data), root_index,
                                     AssetSource::Loose}};
                }

                if (options.nosu || excluded) {
                    continue;
                }

                const auto package = find_stfs_file(root);
                if (!package) {
                    continue;
                }
                const auto package_data = read_file(*package);
                if (!package_data) {
                    return std::unexpected(FileLookupError{.code = FileLookupErrorCode::ReadFailed,
                                                           .message = "Could not read STFS package",
                                                           .source_path = *package,
                                                           .root_path = root,
                                                           .root_index = root_index,
                                                           .source = AssetSource::Stfs});
                }

                std::unique_ptr<Stfs::StfsContainer> container;
                try {
                    container = std::make_unique<Stfs::StfsContainer>(
                        std::as_bytes(std::span(*package_data)));
                } catch (const std::exception& exception) {
                    return std::unexpected(
                        FileLookupError{.code = FileLookupErrorCode::InspectionFailed,
                                        .message = "Could not inspect STFS package: " +
                                                   std::string(exception.what()),
                                        .source_path = *package,
                                        .root_path = root,
                                        .root_index = root_index,
                                        .source = AssetSource::Stfs});
                } catch (...) {
                    return std::unexpected(
                        FileLookupError{.code = FileLookupErrorCode::InspectionFailed,
                                        .message = "Could not inspect STFS package",
                                        .source_path = *package,
                                        .root_path = root,
                                        .root_index = root_index,
                                        .source = AssetSource::Stfs});
                }
                if (container->containsFileByName(key)) {
                    try {
                        const auto data = container->extractFileByName(key);
                        return std::optional<ResolvedFile>{
                            ResolvedFile{std::string(filename), *package, to_u8(data), root_index,
                                         AssetSource::Stfs}};
                    } catch (const std::exception& exception) {
                        return std::unexpected(
                            FileLookupError{.code = FileLookupErrorCode::InspectionFailed,
                                            .message = "Could not extract requested STFS entry: " +
                                                       std::string(exception.what()),
                                            .source_path = *package,
                                            .root_path = root,
                                            .root_index = root_index,
                                            .source = AssetSource::Stfs});
                    } catch (...) {
                        return std::unexpected(
                            FileLookupError{.code = FileLookupErrorCode::InspectionFailed,
                                            .message = "Could not extract requested STFS entry",
                                            .source_path = *package,
                                            .root_path = root,
                                            .root_index = root_index,
                                            .source = AssetSource::Stfs});
                    }
                }

                const auto stem = std::filesystem::path(key).stem().string();
                const bool wants_xboxupd_part = key.starts_with("cf") || key.starts_with("cg") ||
                                                stem == "6bl" || stem == "7bl";
                if (kind != AssetKind::Bootloader || !wants_xboxupd_part ||
                    !container->containsFileByName("xboxupd.bin")) {
                    continue;
                }
                try {
                    const auto xboxupd = container->extractFileByName("xboxupd.bin");
                    const auto parts = bootloaders::split_xboxupd_raw(std::span(xboxupd));
                    const std::vector<uint8_t>* part = nullptr;
                    if (key.starts_with("cf") || stem == "6bl") {
                        part = &parts.cf_raw;
                    } else if (key.starts_with("cg") || stem == "7bl") {
                        part = &parts.cg_raw;
                    }
                    if (part && !part->empty()) {
                        return std::optional<ResolvedFile>{ResolvedFile{std::string(filename),
                                                                        *package, *part, root_index,
                                                                        AssetSource::Xboxupd}};
                    }
                } catch (const std::exception& exception) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Could not derive requested bootloader from xboxupd.bin: " +
                                   std::string(exception.what()),
                        .source_path = *package,
                        .root_path = root,
                        .root_index = root_index,
                        .source = AssetSource::Xboxupd});
                } catch (...) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Could not derive requested bootloader from xboxupd.bin",
                        .source_path = *package,
                        .root_path = root,
                        .root_index = root_index,
                        .source = AssetSource::Xboxupd});
                }
            } catch (const std::exception& exception) {
                return std::unexpected(FileLookupError{
                    .code = FileLookupErrorCode::InspectionFailed,
                    .message = "Could not inspect source root: " + std::string(exception.what()),
                    .source_path = root,
                    .root_path = root,
                    .root_index = root_index,
                    .source = AssetSource::Loose});
            } catch (...) {
                return std::unexpected(
                    FileLookupError{.code = FileLookupErrorCode::InspectionFailed,
                                    .message = "Could not inspect source root",
                                    .source_path = root,
                                    .root_path = root,
                                    .root_index = root_index,
                                    .source = AssetSource::Loose});
            }
        }
        return std::optional<ResolvedFile>{};
    }

    std::optional<IniFilesResult> ReadIniFiles(std::string_view version, std::string_view type,
                                               std::string_view target_section,
                                               const std::filesystem::path& fw_dir,
                                               ScanOptions options) {
        const auto cwd = std::filesystem::current_path();
        const auto version_dir = cwd / version;
        return ReadIniFiles(version_dir / ("_" + std::string(type) + ".ini"), target_section,
                            {fw_dir.empty() ? cwd / "mydata" : fw_dir, version_dir, cwd / "common"},
                            options);
    }

    std::optional<IniFilesResult>
    ReadIniFiles(const std::filesystem::path& ini_path, std::string_view target_section,
                 const std::vector<std::filesystem::path>& search_paths, ScanOptions options) {
        auto doc_res = Ini::ParseFile(ini_path);
        if (!doc_res) {
            Log::Error("Could not parse INI file at '{}'", ini_path.string());
            return std::nullopt;
        }
        const auto& doc = *doc_res;
        const Ini::Section* bl_sec = doc.get(target_section);
        if (!bl_sec) {
            std::string alt{target_section};
            if (const auto pos = alt.find('_'); pos != std::string::npos) {
                const auto base = alt.substr(0, pos);
                if (!base.ends_with("bl"))
                    bl_sec = doc.get(base + "bl" + alt.substr(pos));
            } else if (!alt.ends_with("bl")) {
                bl_sec = doc.get(alt + "bl");
            }
        }
        if (!bl_sec) {
            Log::Error("Bootloader section '[{}]' not found in INI configuration", target_section);
            return std::nullopt;
        }

        // Validate all names before loading anything, including optional payloads.
        // An unsafe name must never become a basename-only STFS lookup.
        for (const auto* section : {bl_sec, doc.get("security"), doc.get("flashfs")}) {
            if (!section)
                continue;
            for (const auto& entry : *section) {
                if (entry.key.empty() || normalize_file_key(entry.key) == "none")
                    continue;
                if (!safe_asset_name(entry.key)) {
                    Log::Error("INI asset '{}' is not confined to its source roots", entry.key);
                    return std::nullopt;
                }
            }
        }

        auto security_names = security_file_names();
        if (const auto* security = doc.get("security")) {
            for (const auto& entry : *security)
                security_names.push_back(normalize_file_key(entry.key));
        }
        AssetSearch search(search_paths, options, std::move(security_names));
        IniFilesResult result{};
        std::unordered_map<std::string, size_t> chain_counters;
        for (const auto& entry : *bl_sec) {
            const auto key = normalize_file_key(entry.key);
            if (key.empty() || key == "none")
                continue;
            // IniParser counts prefixes of the original key, including any
            // directory. Use the normalized family, including numeric aliases.
            const auto stem = std::filesystem::path(key).stem().string();
            auto prefix = key.substr(0, std::min(key.find('_'), key.find('.')));
            if (key.starts_with("cf") || stem == "6bl")
                prefix = "cf";
            else if (key.starts_with("cg") || stem == "7bl")
                prefix = "cg";
            const auto chain = chain_counters[prefix]++;
            auto found = search.find(entry.key, AssetKind::Bootloader);
            if (!found) {
                Log::Error("Required bootloader file '{}' not found", entry.key);
                return std::nullopt;
            }
            auto data = std::move(found->data);
            if (key.starts_with("cba") || key.starts_with("cb_a") || key.starts_with("sb") ||
                key == "2bl") {
                result.bootloaders.cb_or_a = std::move(data);
            } else if (key.starts_with("cbx") || key.starts_with("cb_x")) {
                result.bootloaders.cb_x = std::move(data);
            } else if (key.starts_with("cbb") || key.starts_with("cb_b")) {
                result.bootloaders.cb_b = std::move(data);
            } else if (key.starts_with("cb_") || key == "cb") {
                if (chain == 0 || result.bootloaders.cb_or_a.empty())
                    result.bootloaders.cb_or_a = std::move(data);
                else
                    result.bootloaders.cb_b = std::move(data);
            } else if (key.starts_with("sc") || stem == "3bl") {
                result.bootloaders.sc = std::move(data);
            } else if (key.starts_with("cd") || key == "4bl") {
                result.bootloaders.cd = std::move(data);
            } else if (key.starts_with("ce") || key == "5bl") {
                result.bootloaders.ce = std::move(data);
            } else if (key.starts_with("cf") || stem == "6bl") {
                if (chain == 0 || !result.bootloaders.cf0)
                    result.bootloaders.cf0 = std::move(data);
                else
                    result.bootloaders.cf1 = std::move(data);
            } else if (key.starts_with("cg") || stem == "7bl") {
                if (chain == 0 || !result.bootloaders.cg0)
                    result.bootloaders.cg0 = std::move(data);
                else
                    result.bootloaders.cg1 = std::move(data);
            }
        }

        // Preserve INI order for unique payloads, replacing only when a better
        // source is found for an alias of an already selected basename.
        std::unordered_map<std::string, std::pair<size_t, SourceRank>> payloads;
        auto process_payload_entry = [&](const Ini::Entry& entry, bool optional) {
            const auto key = normalize_file_key(entry.key);
            if (key.empty() || key == "none")
                return;
            if (auto found = search.find(entry.key)) {
                const auto [it, inserted] =
                    payloads.emplace(key, std::pair{result.flashfs_sec.size(), found->rank});
                if (inserted) {
                    result.flashfs_sec.emplace_back(key, std::move(found->data));
                } else if (found->rank < it->second.second) {
                    result.flashfs_sec[it->second.first].second = std::move(found->data);
                    it->second.second = found->rank;
                }
            } else if (optional) {
                Log::Debug("Optional asset '{}' not present", entry.key);
            } else {
                Log::Warn("Payload asset '{}' not found in eligible loose files or STFS packages",
                          entry.key);
            }
        };
        if (const auto* security = doc.get("security")) {
            for (const auto& entry : *security)
                process_payload_entry(entry, normalize_file_key(entry.key) == "fcrt.bin");
        }
        if (const auto* flashfs = doc.get("flashfs")) {
            for (const auto& entry : *flashfs)
                process_payload_entry(entry, false);
        }
        if (search.invalid_path())
            return std::nullopt;
        return result;
    }

} // namespace gxbuild3::utils
