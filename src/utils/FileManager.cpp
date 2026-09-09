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
#include <mutex>
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

        struct CachedPackage {
            std::filesystem::path path; // Empty for in-memory packages
            std::vector<uint8_t> raw_data;
            std::unique_ptr<Stfs::StfsContainer> container;
            std::unordered_map<std::string, std::vector<uint8_t>> extracted_files;
            bool xboxupd_attempted = false;
            std::optional<bootloaders::XboxupdParts> xboxupd_parts;
            std::string xboxupd_error;
        };

        struct DiskCacheEntry {
            std::filesystem::file_time_type mtime;
            uintmax_t file_size = 0;
            std::shared_ptr<CachedPackage> package;
            std::string error;
            bool failed = false;
        };

        std::mutex g_stfs_cache_mutex;
        std::unordered_map<std::string, DiskCacheEntry> g_disk_package_cache;
        std::unordered_map<std::string, std::shared_ptr<CachedPackage>> g_memory_package_cache;
        std::unordered_map<
            std::string,
            std::pair<std::filesystem::file_time_type, std::optional<std::filesystem::path>>>
            g_dir_stfs_cache;

        const std::vector<uint8_t>* get_package_file(CachedPackage& pkg, const std::string& key) {
            auto it = pkg.extracted_files.find(key);
            if (it != pkg.extracted_files.end()) {
                return &it->second;
            }
            if (!pkg.container || !pkg.container->containsFileByName(key)) {
                return nullptr;
            }
            const auto extracted = pkg.container->extractFileByName(key);
            it = pkg.extracted_files.emplace(key, to_u8(extracted)).first;
            return &it->second;
        }

        const bootloaders::XboxupdParts* get_xboxupd_parts(CachedPackage& pkg) {
            if (!pkg.xboxupd_attempted) {
                pkg.xboxupd_attempted = true;
                if (!pkg.container || !pkg.container->containsFileByName("xboxupd.bin")) {
                    pkg.xboxupd_error = "STFS package does not contain xboxupd.bin";
                    return nullptr;
                }
                try {
                    auto it = pkg.extracted_files.find("xboxupd.bin");
                    if (it == pkg.extracted_files.end()) {
                        const auto extracted = pkg.container->extractFileByName("xboxupd.bin");
                        it = pkg.extracted_files.emplace("xboxupd.bin", to_u8(extracted)).first;
                    }
                    pkg.xboxupd_parts = bootloaders::split_xboxupd_raw(std::span(it->second));
                } catch (const std::exception& e) {
                    pkg.xboxupd_error = e.what();
                    return nullptr;
                } catch (...) {
                    pkg.xboxupd_error = "Unknown error splitting xboxupd.bin";
                    return nullptr;
                }
            }
            if (pkg.xboxupd_parts) {
                return &(*pkg.xboxupd_parts);
            }
            return nullptr;
        }

        std::optional<std::filesystem::path> find_stfs_file(const std::filesystem::path& dir) {
            std::error_code ec;
            auto mtime = std::filesystem::last_write_time(dir, ec);
            if (!ec) {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                auto it = g_dir_stfs_cache.find(dir.string());
                if (it != g_dir_stfs_cache.end() && it->second.first == mtime) {
                    return it->second.second;
                }
            }

            std::optional<std::filesystem::path> result;
            ec.clear();
            for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
                if (ec)
                    break;
                const auto candidate = entry.path();
                if (entry.is_regular_file(ec) && !candidate.has_extension() &&
                    normalize_file_key(candidate.filename().string()).starts_with("su")) {
                    // Preserve one package per directory, with a deterministic tie-break.
                    if (!result || candidate < *result)
                        result = candidate;
                }
            }
            if (!ec) {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_dir_stfs_cache[dir.string()] = {mtime, result};
            }
            return result;
        }

        std::shared_ptr<CachedPackage> get_or_load_disk_package(const std::filesystem::path& path) {
            std::error_code ec;
            const auto canonical_path = std::filesystem::weakly_canonical(path, ec);
            const std::string key = ec ? path.string() : canonical_path.string();

            ec.clear();
            const auto mtime = std::filesystem::last_write_time(path, ec);
            if (ec) {
                throw std::runtime_error("Could not inspect STFS package: " + ec.message());
            }
            const auto size = std::filesystem::file_size(path, ec);
            if (ec) {
                throw std::runtime_error("Could not inspect STFS package: " + ec.message());
            }

            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                auto it = g_disk_package_cache.find(key);
                if (it != g_disk_package_cache.end() && it->second.mtime == mtime &&
                    it->second.file_size == size) {
                    if (it->second.failed) {
                        throw std::runtime_error(it->second.error);
                    }
                    return it->second.package;
                }
            }

            auto data = read_file(path);
            if (!data) {
                throw std::runtime_error("Could not read STFS package");
            }

            auto pkg = std::make_shared<CachedPackage>();
            pkg->path = path;
            pkg->raw_data = std::move(*data);
            try {
                pkg->container =
                    std::make_unique<Stfs::StfsContainer>(std::as_bytes(std::span(pkg->raw_data)));
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_disk_package_cache[key] = DiskCacheEntry{.mtime = mtime,
                                                           .file_size = size,
                                                           .package = nullptr,
                                                           .error = e.what(),
                                                           .failed = true};
                throw;
            } catch (...) {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_disk_package_cache[key] =
                    DiskCacheEntry{.mtime = mtime,
                                   .file_size = size,
                                   .package = nullptr,
                                   .error = "Could not inspect STFS package",
                                   .failed = true};
                throw;
            }

            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_disk_package_cache[key] = DiskCacheEntry{.mtime = mtime,
                                                           .file_size = size,
                                                           .package = pkg,
                                                           .error = "",
                                                           .failed = false};
            }
            return pkg;
        }

        std::string compute_memory_package_key(const InMemoryStfsPackage& mem_pkg) {
            std::string key = mem_pkg.name + "_" + std::to_string(mem_pkg.data.size()) + "_";
            const size_t sample_size = std::min(mem_pkg.data.size(), size_t{4096});
            uint64_t hash = 14695981039346656037ULL;
            for (size_t i = 0; i < sample_size; ++i) {
                hash ^= mem_pkg.data[i];
                hash *= 1099511628211ULL;
            }
            key += std::to_string(hash);
            return key;
        }

        std::shared_ptr<CachedPackage>
        get_or_load_memory_package(const InMemoryStfsPackage& mem_pkg) {
            if (mem_pkg.data.empty()) {
                throw std::runtime_error("In-memory STFS package is empty");
            }
            const std::string key = compute_memory_package_key(mem_pkg);
            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                auto it = g_memory_package_cache.find(key);
                if (it != g_memory_package_cache.end()) {
                    return it->second;
                }
            }

            auto pkg = std::make_shared<CachedPackage>();
            pkg->path = std::filesystem::path{};
            pkg->raw_data = mem_pkg.data;
            pkg->container =
                std::make_unique<Stfs::StfsContainer>(std::as_bytes(std::span(pkg->raw_data)));

            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_memory_package_cache[key] = pkg;
            }
            return pkg;
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
                : options_(std::move(options)),
                  excluded_(options_.nosusecurity ? std::move(security_names)
                                                  : std::vector<std::string>{}) {
                for (const auto& root : roots)
                    roots_.push_back({root});
            }

            std::optional<LocatedFile>
            find(std::string_view name, AssetKind kind = AssetKind::Regular, bool contents = true) {
                if (!safe_asset_name(name))
                    return std::nullopt;
                const auto relative = entry_to_lookup_path(name);
                const auto key = normalize_file_key(std::string(name));
                const auto stem = std::filesystem::path(key).stem().string();
                const bool wants_xboxupd_part = key.starts_with("cf") || key.starts_with("cg") ||
                                                stem == "6bl" || stem == "7bl";
                const bool excluded =
                    options_.nosusecurity &&
                    std::find(excluded_.begin(), excluded_.end(), key) != excluded_.end();

                // 1. In-memory STFS packages (evaluated first with highest priority)
                if (!options_.nosu && !excluded) {
                    for (size_t mem_idx = 0; mem_idx < options_.in_memory_stfs.size(); ++mem_idx) {
                        try {
                            auto pkg = get_or_load_memory_package(options_.in_memory_stfs[mem_idx]);
                            if (pkg && pkg->container) {
                                bool contains = pkg->container->containsFileByName(key);
                                std::string matched_name = key;
                                if (!contains && !contents) {
                                    if (std::find(excluded_.begin(), excluded_.end(), stem) ==
                                            excluded_.end() &&
                                        pkg->container->containsFileByName(stem)) {
                                        contains = true;
                                        matched_name = stem;
                                    }
                                }
                                if (contains) {
                                    std::vector<uint8_t> data;
                                    if (contents) {
                                        const auto* p_data = get_package_file(*pkg, matched_name);
                                        if (p_data)
                                            data = *p_data;
                                    }
                                    return LocatedFile{{}, std::move(data), mem_idx,
                                                       AssetSource::Stfs, {mem_idx, 1}};
                                }

                                if (kind == AssetKind::Bootloader && wants_xboxupd_part &&
                                    pkg->container->containsFileByName("xboxupd.bin")) {
                                    const auto* parts = get_xboxupd_parts(*pkg);
                                    if (parts) {
                                        const std::vector<uint8_t>* part = nullptr;
                                        if (key.starts_with("cf") || stem == "6bl")
                                            part = &parts->cf_raw;
                                        else if (key.starts_with("cg") || stem == "7bl")
                                            part = &parts->cg_raw;
                                        if (part && !part->empty()) {
                                            return LocatedFile{{},
                                                               contents ? *part
                                                                        : std::vector<uint8_t>{},
                                                               mem_idx,
                                                               AssetSource::Xboxupd,
                                                               {mem_idx, 2}};
                                        }
                                    }
                                }
                            }
                        } catch (const std::exception& e) {
                            Log::Warn("Failed to inspect in-memory STFS package: {}", e.what());
                        } catch (...) {
                            Log::Warn("Failed to inspect in-memory STFS package");
                        }
                    }
                }

                // 2. Disk roots
                const size_t mem_offset = options_.in_memory_stfs.size();
                for (size_t index = 0; index < roots_.size(); ++index) {
                    const auto& root = roots_[index];
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
                                candidate, {}, index, AssetSource::Loose, {mem_offset + index, 0}};
                        if (auto data = read_file(candidate))
                            return LocatedFile{candidate, std::move(*data), index,
                                               AssetSource::Loose, {mem_offset + index, 0}};
                    }
                    if (options_.nosu || excluded)
                        continue;

                    try {
                        const auto package = find_stfs_file(root.path);
                        if (!package)
                            continue;
                        auto pkg = get_or_load_disk_package(*package);
                        if (pkg && pkg->container) {
                            bool contains = pkg->container->containsFileByName(key);
                            std::string matched_name = key;
                            if (!contains && !contents) {
                                if (std::find(excluded_.begin(), excluded_.end(), stem) ==
                                        excluded_.end() &&
                                    pkg->container->containsFileByName(stem)) {
                                    contains = true;
                                    matched_name = stem;
                                }
                            }
                            if (contains) {
                                std::vector<uint8_t> data;
                                if (contents) {
                                    const auto* p_data = get_package_file(*pkg, matched_name);
                                    if (p_data)
                                        data = *p_data;
                                }
                                return LocatedFile{*package, std::move(data), index,
                                                   AssetSource::Stfs, {mem_offset + index, 1}};
                            }

                            if (kind == AssetKind::Bootloader && wants_xboxupd_part &&
                                pkg->container->containsFileByName("xboxupd.bin")) {
                                const auto* parts = get_xboxupd_parts(*pkg);
                                if (parts) {
                                    const std::vector<uint8_t>* part = nullptr;
                                    if (key.starts_with("cf") || stem == "6bl")
                                        part = &parts->cf_raw;
                                    else if (key.starts_with("cg") || stem == "7bl")
                                        part = &parts->cg_raw;
                                    if (part && !part->empty()) {
                                        return LocatedFile{*package,
                                                           contents ? *part : std::vector<uint8_t>{},
                                                           index,
                                                           AssetSource::Xboxupd,
                                                           {mem_offset + index, 2}};
                                    }
                                }
                            }
                        }
                    } catch (const std::exception& e) {
                        Log::Warn("Failed to inspect STFS assets in '{}': {}", root.path.string(),
                                  e.what());
                    } catch (...) {
                        Log::Warn("Failed to inspect STFS assets in '{}'", root.path.string());
                    }
                }
                return std::nullopt;
            }

            bool invalid_path() const { return invalid_path_; }

          private:
            struct Root {
                std::filesystem::path path;
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
        const auto stem = std::filesystem::path(key).stem().string();
        const bool wants_xboxupd_part =
            key.starts_with("cf") || key.starts_with("cg") || stem == "6bl" || stem == "7bl";
        const auto security_names = security_file_names();
        const auto excluded =
            options.nosusecurity &&
            std::find(security_names.begin(), security_names.end(), key) != security_names.end();

        // 1. In-memory STFS packages
        if (!options.nosu && !excluded) {
            for (size_t mem_idx = 0; mem_idx < options.in_memory_stfs.size(); ++mem_idx) {
                try {
                    auto pkg = get_or_load_memory_package(options.in_memory_stfs[mem_idx]);
                    if (pkg && pkg->container) {
                        if (pkg->container->containsFileByName(key)) {
                            const auto* data = get_package_file(*pkg, key);
                            if (data) {
                                return ResolvedFile{std::string(filename), {}, *data, mem_idx,
                                                    AssetSource::Stfs};
                            }
                        }
                        if (kind == AssetKind::Bootloader && wants_xboxupd_part &&
                            pkg->container->containsFileByName("xboxupd.bin")) {
                            const auto* parts = get_xboxupd_parts(*pkg);
                            if (parts) {
                                const std::vector<uint8_t>* part = nullptr;
                                if (key.starts_with("cf") || stem == "6bl") {
                                    part = &parts->cf_raw;
                                } else if (key.starts_with("cg") || stem == "7bl") {
                                    part = &parts->cg_raw;
                                }
                                if (part && !part->empty()) {
                                    return ResolvedFile{std::string(filename), {}, *part,
                                                        mem_idx, AssetSource::Xboxupd};
                                }
                            }
                        }
                    }
                } catch (const std::exception& exception) {
                    Log::Warn("Failed to inspect in-memory STFS package: {}", exception.what());
                } catch (...) {
                    Log::Warn("Failed to inspect in-memory STFS package");
                }
            }
        }

        // 2. Disk roots
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
                auto pkg = get_or_load_disk_package(*package);
                if (!pkg || !pkg->container) {
                    continue;
                }
                if (pkg->container->containsFileByName(key)) {
                    try {
                        const auto* data = get_package_file(*pkg, key);
                        if (data) {
                            return ResolvedFile{std::string(filename), *package, *data,
                                                root_index, AssetSource::Stfs};
                        }
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

                if (kind != AssetKind::Bootloader || !wants_xboxupd_part ||
                    !pkg->container->containsFileByName("xboxupd.bin")) {
                    continue;
                }
                try {
                    const auto* parts = get_xboxupd_parts(*pkg);
                    if (!parts) {
                        Log::Warn("Failed to derive '{}' from xboxupd.bin in STFS '{}': {}",
                                  filename, package->string(), pkg->xboxupd_error);
                        continue;
                    }
                    const std::vector<uint8_t>* part = nullptr;
                    if (key.starts_with("cf") || stem == "6bl") {
                        part = &parts->cf_raw;
                    } else if (key.starts_with("cg") || stem == "7bl") {
                        part = &parts->cg_raw;
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
        const auto stem = std::filesystem::path(key).stem().string();
        const bool wants_xboxupd_part =
            key.starts_with("cf") || key.starts_with("cg") || stem == "6bl" || stem == "7bl";
        const auto security_names = security_file_names();
        const bool excluded =
            options.nosusecurity &&
            std::find(security_names.begin(), security_names.end(), key) != security_names.end();

        // 1. In-memory STFS packages (highest priority)
        if (!options.nosu && !excluded) {
            for (size_t mem_idx = 0; mem_idx < options.in_memory_stfs.size(); ++mem_idx) {
                const auto& mem_pkg = options.in_memory_stfs[mem_idx];
                std::shared_ptr<CachedPackage> pkg;
                try {
                    pkg = get_or_load_memory_package(mem_pkg);
                } catch (const std::exception& exception) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Could not inspect in-memory STFS package: " +
                                   std::string(exception.what()),
                        .source_path = {},
                        .root_path = {},
                        .root_index = mem_idx,
                        .source = AssetSource::Stfs});
                } catch (...) {
                    return std::unexpected(FileLookupError{
                        .code = FileLookupErrorCode::InspectionFailed,
                        .message = "Could not inspect in-memory STFS package",
                        .source_path = {},
                        .root_path = {},
                        .root_index = mem_idx,
                        .source = AssetSource::Stfs});
                }

                if (pkg && pkg->container) {
                    if (pkg->container->containsFileByName(key)) {
                        try {
                            const auto* data = get_package_file(*pkg, key);
                            if (data) {
                                return std::optional<ResolvedFile>{ResolvedFile{
                                    std::string(filename), {}, *data, mem_idx, AssetSource::Stfs}};
                            }
                        } catch (const std::exception& exception) {
                            return std::unexpected(FileLookupError{
                                .code = FileLookupErrorCode::InspectionFailed,
                                .message = "Could not extract requested STFS entry: " +
                                           std::string(exception.what()),
                                .source_path = {},
                                .root_path = {},
                                .root_index = mem_idx,
                                .source = AssetSource::Stfs});
                        } catch (...) {
                            return std::unexpected(FileLookupError{
                                .code = FileLookupErrorCode::InspectionFailed,
                                .message = "Could not extract requested STFS entry",
                                .source_path = {},
                                .root_path = {},
                                .root_index = mem_idx,
                                .source = AssetSource::Stfs});
                        }
                    }

                    if (kind == AssetKind::Bootloader && wants_xboxupd_part &&
                        pkg->container->containsFileByName("xboxupd.bin")) {
                        try {
                            const auto* parts = get_xboxupd_parts(*pkg);
                            if (!parts) {
                                return std::unexpected(FileLookupError{
                                    .code = FileLookupErrorCode::InspectionFailed,
                                    .message =
                                        "Could not derive requested bootloader from xboxupd.bin: " +
                                        pkg->xboxupd_error,
                                    .source_path = {},
                                    .root_path = {},
                                    .root_index = mem_idx,
                                    .source = AssetSource::Xboxupd});
                            }
                            const std::vector<uint8_t>* part = nullptr;
                            if (key.starts_with("cf") || stem == "6bl") {
                                part = &parts->cf_raw;
                            } else if (key.starts_with("cg") || stem == "7bl") {
                                part = &parts->cg_raw;
                            }
                            if (part && !part->empty()) {
                                return std::optional<ResolvedFile>{ResolvedFile{
                                    std::string(filename), {}, *part, mem_idx,
                                    AssetSource::Xboxupd}};
                            }
                        } catch (const std::exception& exception) {
                            return std::unexpected(FileLookupError{
                                .code = FileLookupErrorCode::InspectionFailed,
                                .message =
                                    "Could not derive requested bootloader from xboxupd.bin: " +
                                    std::string(exception.what()),
                                .source_path = {},
                                .root_path = {},
                                .root_index = mem_idx,
                                .source = AssetSource::Xboxupd});
                        } catch (...) {
                            return std::unexpected(FileLookupError{
                                .code = FileLookupErrorCode::InspectionFailed,
                                .message =
                                    "Could not derive requested bootloader from xboxupd.bin",
                                .source_path = {},
                                .root_path = {},
                                .root_index = mem_idx,
                                .source = AssetSource::Xboxupd});
                        }
                    }
                }
            }
        }

        // 2. Disk roots
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

                std::shared_ptr<CachedPackage> pkg;
                try {
                    pkg = get_or_load_disk_package(*package);
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

                if (pkg->container->containsFileByName(key)) {
                    try {
                        const auto* data = get_package_file(*pkg, key);
                        if (data) {
                            return std::optional<ResolvedFile>{ResolvedFile{
                                std::string(filename), *package, *data, root_index,
                                AssetSource::Stfs}};
                        }
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

                if (kind != AssetKind::Bootloader || !wants_xboxupd_part ||
                    !pkg->container->containsFileByName("xboxupd.bin")) {
                    continue;
                }
                try {
                    const auto* parts = get_xboxupd_parts(*pkg);
                    if (!parts) {
                        return std::unexpected(FileLookupError{
                            .code = FileLookupErrorCode::InspectionFailed,
                            .message = "Could not derive requested bootloader from xboxupd.bin: " +
                                       pkg->xboxupd_error,
                            .source_path = *package,
                            .root_path = root,
                            .root_index = root_index,
                            .source = AssetSource::Xboxupd});
                    }
                    const std::vector<uint8_t>* part = nullptr;
                    if (key.starts_with("cf") || stem == "6bl") {
                        part = &parts->cf_raw;
                    } else if (key.starts_with("cg") || stem == "7bl") {
                        part = &parts->cg_raw;
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

    void ClearStfsCache() {
        std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
        g_disk_package_cache.clear();
        g_memory_package_cache.clear();
        g_dir_stfs_cache.clear();
    }

} // namespace gxbuild3::utils
