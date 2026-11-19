#include "utils/FileManager.hpp"

#include "ini/IniParser.hpp"
#include "nand/objects/Xboxupd.hpp"
#include "stfs/StfsContainer.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <format>
#include <memory>
#include <mutex>
#include <span>
#include <unordered_map>
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

        // Basename with the caller's original casing preserved. normalize_file_key
        // lowercases for case-insensitive lookup keys, but the FlashFS stores entry
        // names case-sensitively and the dashboard looks up resources (e.g. fonts) by
        // their exact mixed-case name, so the on-disk name must keep the INI casing.
        std::string display_basename(std::string_view key) {
            std::string result{key};
            std::replace(result.begin(), result.end(), '\\', '/');
            if (auto pos = result.rfind('/'); pos != std::string::npos)
                result.erase(0, pos + 1);
            return result;
        }

        // Xbox dashboard patch payloads live in the flash filesystem with a numeric
        // update-slot suffix. Firmware packs ship them unsuffixed ("aac.xexp",
        // "xenonclatin.xttp") but the dash only loads "<name>.xexpN" and ignores an
        // unsuffixed copy. The suffix is the number of update slots the build type has:
        // '2' on a JTAG image, which carries two update pairs, and '1' on every other
        // (xeBuild 1.21 JTAG writes aac.xexp2; RGBuild and build360 write '1'). It is
        // appended when the name does not already end in a digit and either ends in "xexp"
        // or "xttp", or ends in 'p' and the INI states a checksum for it: xeBuild 1.21 writes
        // 17489's "rrbkgnd.bmp" as "rrbkgnd.bmp1". ".xtt" fonts are not suffixed.
        std::string flashfs_patch_suffix(std::string name, BuildType build_type,
                                         bool has_checksum) {
            const std::string_view view{name};
            const bool trailing_digit = !name.empty() && name.back() >= '0' && name.back() <= '9';
            const bool ends_in_p = !name.empty() && (name.back() == 'p' || name.back() == 'P');
            if (!trailing_digit &&
                (view.ends_with("xexp") || view.ends_with("xttp") || (ends_in_p && has_checksum)))
                name += build_type == BuildType::Jtag ? '2' : '1';
            return name;
        }

        // A checksum an INI entry states: anything but nothing or zero.
        bool states_checksum(std::string_view value) {
            return std::any_of(value.begin(), value.end(), [](char c) {
                return std::isxdigit(static_cast<unsigned char>(c)) != 0 && c != '0';
            });
        }

        std::string lowercase(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        // The version a CF/CG request names after its stage prefix: 4532 for "cf_4532.bin"
        // or "cg4532.bin". Empty when the name states none ("cf.bin", "6bl.bin").
        std::optional<uint32_t> requested_bootloader_version(std::string_view stem) {
            if (!stem.starts_with("cf") && !stem.starts_with("cg"))
                return std::nullopt;
            stem.remove_prefix(2);
            if (stem.starts_with('_') || stem.starts_with('.'))
                stem.remove_prefix(1);
            uint32_t version = 0;
            size_t digits = 0;
            while (digits < stem.size() && digits < 6 && stem[digits] >= '0' &&
                   stem[digits] <= '9') {
                version = version * 10 + static_cast<uint32_t>(stem[digits] - '0');
                ++digits;
            }
            if (digits == 0)
                return std::nullopt;
            return version;
        }

        // The CF or CG an update package's xboxupd.bin supplies for a request, or null when
        // the request names another stage, or a version other than the one the package
        // carries: "cf_4532.bin" is never answered with the CF of a 17559 package. A request
        // naming no version takes the package's.
        const std::vector<uint8_t>* xboxupd_part_for(const nand::XboxupdParts& parts,
                                                     std::string_view key, std::string_view stem) {
            const std::vector<uint8_t>* part = nullptr;
            if (key.starts_with("cf") || stem == "6bl")
                part = &parts.cf_raw;
            else if (key.starts_with("cg") || stem == "7bl")
                part = &parts.cg_raw;
            // The stage version is the big-endian word at +2 of its clear header.
            if (!part || part->size() < 4)
                return nullptr;
            if (const auto requested = requested_bootloader_version(stem)) {
                const uint32_t supplied =
                    (static_cast<uint32_t>((*part)[2]) << 8) | static_cast<uint32_t>((*part)[3]);
                if (*requested != supplied)
                    return nullptr;
            }
            return part;
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

        // The loose file `relative` names under `root`: the exact path when it exists,
        // otherwise the entry matching each missing component without regard to case. A
        // release INI may name "sc_17489.bin" for the file "SC_17489.bin", which a
        // case-sensitive filesystem does not find. Of several such entries the first in
        // name order is taken. Without a match, or for a match outside the root, the exact
        // path is returned. A directory listing that fails part-way is an IoError.
        [[nodiscard]] Result<std::filesystem::path>
        loose_candidate(const std::filesystem::path& root, const std::filesystem::path& relative) {
            const auto exact = root / relative;
            std::error_code error;
            if (std::filesystem::exists(exact, error) || error)
                return exact;
            std::filesystem::path current = root;
            for (const auto& component : relative) {
                auto next = current / component;
                error.clear();
                if (!std::filesystem::exists(next, error)) {
                    if (error)
                        return exact;
                    const auto wanted = lowercase(component.string());
                    std::optional<std::filesystem::path> match;
                    std::filesystem::directory_iterator it(current, error);
                    if (error)
                        return exact;
                    while (it != std::filesystem::directory_iterator{}) {
                        const auto name = it->path().filename();
                        if (lowercase(name.string()) == wanted && (!match || name < *match))
                            match = name;
                        it.increment(error);
                        if (error)
                            return from_error_code(error, current);
                    }
                    if (!match)
                        return exact;
                    next = current / *match;
                }
                current = std::move(next);
            }
            if (!contained_asset_path(root, current.lexically_relative(root)))
                return exact;
            return current;
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
            std::unique_ptr<stfs::StfsContainer> container;
            std::unordered_map<std::string, std::vector<uint8_t>> extracted_files;
            bool xboxupd_attempted = false;
            std::optional<nand::XboxupdParts> xboxupd_parts;
            std::optional<Error> xboxupd_error;
        };

        // A package that failed to open is cached with its Error until the file changes.
        struct DiskCacheEntry {
            std::filesystem::file_time_type mtime;
            uintmax_t file_size = 0;
            std::shared_ptr<CachedPackage> package;
            std::optional<Error> error;
        };

        std::mutex g_stfs_cache_mutex;
        std::unordered_map<std::string, DiskCacheEntry> g_disk_package_cache;
        std::unordered_map<std::string, std::shared_ptr<CachedPackage>> g_memory_package_cache;
        std::unordered_map<std::string, std::pair<std::filesystem::file_time_type,
                                                  std::optional<std::filesystem::path>>>
            g_dir_stfs_cache;

        // The bytes of a package entry, extracted once and cached; null when the package has no
        // entry by that name.
        [[nodiscard]] Result<const std::vector<uint8_t>*> get_package_file(CachedPackage& pkg,
                                                                           const std::string& key) {
            auto it = pkg.extracted_files.find(key);
            if (it != pkg.extracted_files.end()) {
                return &it->second;
            }
            if (!pkg.container || !pkg.container->contains_file_by_name(key)) {
                return nullptr;
            }
            const auto extracted = pkg.container->extract_file_by_name(key);
            if (!extracted) {
                return std::unexpected(extracted.error());
            }
            it = pkg.extracted_files.emplace(key, to_u8(*extracted)).first;
            return &it->second;
        }

        // The CF and CG split from the package's xboxupd.bin. The first attempt is cached,
        // including its Error.
        [[nodiscard]] Result<const nand::XboxupdParts*> get_xboxupd_parts(CachedPackage& pkg) {
            if (!pkg.xboxupd_attempted) {
                pkg.xboxupd_attempted = true;
                auto raw = get_package_file(pkg, "xboxupd.bin");
                if (!raw) {
                    pkg.xboxupd_error = std::move(raw).error();
                } else if (*raw == nullptr) {
                    pkg.xboxupd_error =
                        Error(ErrorCode::NotFound, "STFS package does not contain xboxupd.bin");
                } else if (auto parts = nand::split_xboxupd_raw(std::span(**raw))) {
                    pkg.xboxupd_parts = std::move(*parts);
                } else {
                    pkg.xboxupd_error = std::move(parts).error();
                }
            }
            if (pkg.xboxupd_error) {
                return std::unexpected(*pkg.xboxupd_error);
            }
            return &*pkg.xboxupd_parts;
        }

        // The system-update package in `dir`, if any. A directory listing that fails part-way
        // is an IoError.
        [[nodiscard]] Result<std::optional<std::filesystem::path>>
        find_stfs_file(const std::filesystem::path& dir) {
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
            std::filesystem::directory_iterator it(dir, ec);
            while (!ec && it != std::filesystem::directory_iterator{}) {
                const auto candidate = it->path();
                if (it->is_regular_file(ec) && !candidate.has_extension() &&
                    normalize_file_key(candidate.filename().string()).starts_with("su")) {
                    // Preserve one package per directory, with a deterministic tie-break.
                    if (!result || candidate < *result)
                        result = candidate;
                }
                if (ec)
                    break;
                it.increment(ec);
                if (ec)
                    return from_error_code(ec, dir);
            }
            if (!ec) {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_dir_stfs_cache[dir.string()] = {mtime, result};
            }
            return result;
        }

        [[nodiscard]] Result<std::shared_ptr<CachedPackage>>
        get_or_load_disk_package(const std::filesystem::path& path) {
            std::error_code ec;
            const auto canonical_path = std::filesystem::weakly_canonical(path, ec);
            const std::string key = ec ? path.string() : canonical_path.string();

            ec.clear();
            const auto mtime = std::filesystem::last_write_time(path, ec);
            if (ec) {
                return from_error_code(ec, path);
            }
            const auto size = std::filesystem::file_size(path, ec);
            if (ec) {
                return from_error_code(ec, path);
            }

            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                auto it = g_disk_package_cache.find(key);
                if (it != g_disk_package_cache.end() && it->second.mtime == mtime &&
                    it->second.file_size == size) {
                    if (it->second.error) {
                        return std::unexpected(*it->second.error);
                    }
                    return it->second.package;
                }
            }

            auto data = read_file(path);
            if (!data) {
                return std::unexpected(
                    std::move(data).error().add_context("Could not read STFS package"));
            }

            auto pkg = std::make_shared<CachedPackage>();
            pkg->path = path;
            pkg->raw_data = std::move(*data);
            auto container = stfs::StfsContainer::open(std::as_bytes(std::span(pkg->raw_data)));
            if (!container) {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_disk_package_cache[key] = DiskCacheEntry{.mtime = mtime,
                                                           .file_size = size,
                                                           .package = nullptr,
                                                           .error = container.error()};
                return std::unexpected(std::move(container).error());
            }
            pkg->container = std::make_unique<stfs::StfsContainer>(std::move(*container));

            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_disk_package_cache[key] = DiskCacheEntry{
                    .mtime = mtime, .file_size = size, .package = pkg, .error = std::nullopt};
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

        [[nodiscard]] Result<std::shared_ptr<CachedPackage>>
        get_or_load_memory_package(const InMemoryStfsPackage& mem_pkg) {
            if (mem_pkg.data.empty()) {
                return fail(ErrorCode::InvalidArgument, "In-memory STFS package is empty");
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
            auto container = stfs::StfsContainer::open(std::as_bytes(std::span(pkg->raw_data)));
            if (!container) {
                return std::unexpected(std::move(container).error());
            }
            pkg->container = std::make_unique<stfs::StfsContainer>(std::move(*container));

            {
                std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
                g_memory_package_cache[key] = pkg;
            }
            return pkg;
        }

        // Lower ranks win: root index first, then loose / STFS / derived parts.
        using SourceRank = std::pair<size_t, unsigned>;

        struct LocatedFile {
            ResolvedFile file;
            SourceRank rank;
        };

        using LocateResult = std::expected<std::optional<LocatedFile>, FileLookupError>;

        // How a lookup treats a source it cannot inspect or read. Strict fails with the first
        // such source. Lenient skips it with a warning and goes on, as xeBuild does. Either
        // way, an asset name or path that escapes its source root fails the lookup.
        enum class LookupPolicy {
            Strict,
            Lenient
        };

        struct Provenance {
            std::filesystem::path source_path;
            std::filesystem::path root_path;
            size_t root_index = 0;
            AssetSource source = AssetSource::Loose;
        };

        [[nodiscard]] FileLookupError lookup_error(Error error, std::string layer,
                                                   Provenance where) {
            if (!layer.empty())
                error.add_context(std::move(layer));
            return FileLookupError{std::move(error), std::move(where.source_path),
                                   std::move(where.root_path), where.root_index, where.source};
        }

        // Under the lenient policy, reports a source that is skipped and returns true. A failed
        // CF/CG derivation from xboxupd.bin is only a debug message: most packages hold none.
        [[nodiscard]] bool tolerated(LookupPolicy policy, const FileLookupError& error) {
            if (policy == LookupPolicy::Strict)
                return false;
            const auto where = error.source_path.empty()
                                   ? std::format("in-memory STFS package {}", error.root_index)
                                   : error.source_path.string();
            if (error.source == AssetSource::Xboxupd)
                Log::Debug("Skipping '{}': {}", where, error.describe());
            else
                Log::Warn("Skipping '{}': {}", where, error.describe());
            return true;
        }

        // The entry `key` of one package (Stfs) or, for a bootloader request, the CF/CG its
        // xboxupd.bin supplies (Xboxupd). A failure carries `where` with its source set.
        [[nodiscard]] std::expected<std::optional<std::pair<std::vector<uint8_t>, AssetSource>>,
                                    FileLookupError>
        search_package(CachedPackage& pkg, const std::string& key, const std::string& stem,
                       bool wants_xboxupd_part, Provenance where) {
            if (pkg.container->contains_file_by_name(key)) {
                auto data = get_package_file(pkg, key);
                if (!data) {
                    where.source = AssetSource::Stfs;
                    return std::unexpected(lookup_error(std::move(data).error(),
                                                        "Could not extract requested STFS entry",
                                                        std::move(where)));
                }
                if (*data)
                    return std::pair{**data, AssetSource::Stfs};
            }
            if (!wants_xboxupd_part || !pkg.container->contains_file_by_name("xboxupd.bin"))
                return std::nullopt;
            auto parts = get_xboxupd_parts(pkg);
            if (!parts) {
                where.source = AssetSource::Xboxupd;
                return std::unexpected(lookup_error(
                    std::move(parts).error(),
                    "Could not derive requested bootloader from xboxupd.bin", std::move(where)));
            }
            if (const auto* part = xboxupd_part_for(**parts, key, stem); part && !part->empty())
                return std::pair{*part, AssetSource::Xboxupd};
            return std::nullopt;
        }

        // The one asset lookup: in-memory packages first, then each root's loose file, its
        // STFS entry and its derived CF/CG. `security_names` are the names nosusecurity keeps
        // out of STFS.
        [[nodiscard]] LocateResult locate(std::string_view name,
                                          const std::vector<std::filesystem::path>& roots,
                                          const ScanOptions& options,
                                          const std::vector<std::string>& security_names,
                                          AssetKind kind, LookupPolicy policy) {
            if (!safe_asset_name(name)) {
                return std::unexpected(
                    lookup_error(Error(ErrorCode::InvalidArgument,
                                       "Asset name must be a confined relative path"),
                                 {}, {entry_to_lookup_path(name), {}, 0, AssetSource::Loose}));
            }
            const auto relative = entry_to_lookup_path(name);
            const auto key = normalize_file_key(std::string(name));
            const auto stem = std::filesystem::path(key).stem().string();
            const bool wants_xboxupd_part =
                kind == AssetKind::Bootloader &&
                (key.starts_with("cf") || key.starts_with("cg") || stem == "6bl" || stem == "7bl");
            const bool excluded = options.nosusecurity &&
                                  std::find(security_names.begin(), security_names.end(), key) !=
                                      security_names.end();
            const auto located = [&](std::filesystem::path path, std::vector<uint8_t> data,
                                     size_t root_index, AssetSource source,
                                     size_t rank_root) -> LocateResult {
                const unsigned order = source == AssetSource::Loose  ? 0
                                       : source == AssetSource::Stfs ? 1
                                                                     : 2;
                return LocatedFile{ResolvedFile{std::string(name), std::move(path), std::move(data),
                                                root_index, source},
                                   {rank_root, order}};
            };

            // 1. In-memory STFS packages (highest priority)
            if (!options.nosu && !excluded) {
                for (size_t mem_idx = 0; mem_idx < options.in_memory_stfs.size(); ++mem_idx) {
                    const Provenance where{{}, {}, mem_idx, AssetSource::Stfs};
                    auto pkg = get_or_load_memory_package(options.in_memory_stfs[mem_idx]);
                    if (!pkg) {
                        auto failure =
                            lookup_error(std::move(pkg).error(),
                                         "Could not inspect in-memory STFS package", where);
                        if (tolerated(policy, failure))
                            continue;
                        return std::unexpected(std::move(failure));
                    }
                    auto found = search_package(**pkg, key, stem, wants_xboxupd_part, where);
                    if (!found) {
                        if (tolerated(policy, found.error()))
                            continue;
                        return std::unexpected(std::move(found).error());
                    }
                    if (*found)
                        return located({}, std::move((*found)->first), mem_idx, (*found)->second,
                                       mem_idx);
                }
            }

            // 2. Disk roots
            const size_t memory_count = options.in_memory_stfs.size();
            for (size_t root_index = 0; root_index < roots.size(); ++root_index) {
                const auto& root = roots[root_index];
                if (root.empty())
                    continue;
                const auto failure_at = [&](Error error, std::string layer,
                                            std::filesystem::path source_path,
                                            AssetSource source = AssetSource::Loose) {
                    return lookup_error(std::move(error), std::move(layer),
                                        {std::move(source_path), root, root_index, source});
                };

                std::error_code status_error;
                const auto root_status = std::filesystem::status(root, status_error);
                if (status_error && root_status.type() != std::filesystem::file_type::not_found) {
                    auto failure = failure_at(from_error_code(status_error, root).error(),
                                              "Could not inspect source root", root);
                    if (tolerated(policy, failure))
                        continue;
                    return std::unexpected(std::move(failure));
                }
                if (root_status.type() == std::filesystem::file_type::not_found ||
                    !std::filesystem::is_directory(root_status))
                    continue;

                std::filesystem::path candidate;
                if (auto found_candidate = loose_candidate(root, relative)) {
                    candidate = std::move(*found_candidate);
                } else {
                    auto failure = failure_at(std::move(found_candidate).error(),
                                              "Could not inspect source root", root);
                    if (!tolerated(policy, failure))
                        return std::unexpected(std::move(failure));
                    candidate = root / relative;
                }
                if (!contained_asset_path(root, relative)) {
                    return std::unexpected(failure_at(
                        Error(ErrorCode::InvalidArgument,
                              "Asset path escapes its source root or cannot be inspected"),
                        {}, candidate));
                }

                // A loose candidate that cannot be used is skipped (lenient) in favour of the
                // root's STFS package.
                status_error.clear();
                const auto candidate_status = std::filesystem::status(candidate, status_error);
                if (status_error &&
                    candidate_status.type() != std::filesystem::file_type::not_found) {
                    auto failure = failure_at(from_error_code(status_error, candidate).error(),
                                              "Could not inspect loose candidate", candidate);
                    if (!tolerated(policy, failure))
                        return std::unexpected(std::move(failure));
                } else if (candidate_status.type() != std::filesystem::file_type::not_found &&
                           std::filesystem::exists(candidate_status)) {
                    if (!std::filesystem::is_regular_file(candidate_status)) {
                        auto failure = failure_at(
                            Error(ErrorCode::Unsupported, "Loose candidate is not a regular file"),
                            {}, candidate);
                        if (!tolerated(policy, failure))
                            return std::unexpected(std::move(failure));
                    } else if (auto data = read_file(candidate)) {
                        return located(candidate, std::move(*data), root_index, AssetSource::Loose,
                                       memory_count + root_index);
                    } else {
                        auto failure = failure_at(std::move(data).error(),
                                                  "Could not read loose candidate", candidate);
                        if (!tolerated(policy, failure))
                            return std::unexpected(std::move(failure));
                    }
                }

                if (options.nosu || excluded)
                    continue;

                auto package_path = find_stfs_file(root);
                if (!package_path) {
                    auto failure = failure_at(std::move(package_path).error(),
                                              "Could not inspect source root", root);
                    if (tolerated(policy, failure))
                        continue;
                    return std::unexpected(std::move(failure));
                }
                if (!*package_path)
                    continue;
                const auto package = std::move(**package_path);

                auto pkg = get_or_load_disk_package(package);
                if (!pkg) {
                    auto failure =
                        failure_at(std::move(pkg).error(), "Could not inspect STFS package",
                                   package, AssetSource::Stfs);
                    if (tolerated(policy, failure))
                        continue;
                    return std::unexpected(std::move(failure));
                }
                auto found = search_package(**pkg, key, stem, wants_xboxupd_part,
                                            {package, root, root_index, AssetSource::Stfs});
                if (!found) {
                    if (tolerated(policy, found.error()))
                        continue;
                    return std::unexpected(std::move(found).error());
                }
                if (*found)
                    return located(package, std::move((*found)->first), root_index,
                                   (*found)->second, memory_count + root_index);
            }
            return std::optional<LocatedFile>{};
        }

    } // namespace

    std::string ini_asset_name(std::string_view entry) {
        std::string name{entry};
        std::replace(name.begin(), name.end(), '\\', '/');
        std::string_view rest{name};
        while (rest.starts_with("../") || rest.starts_with("./"))
            rest.remove_prefix(rest.find('/') + 1);
        return std::string(rest);
    }

    bool ini_asset_is_outside(std::string_view entry) {
        return entry.starts_with("..\\") || entry.starts_with("../");
    }

    FileLookupResult find_file_data_detailed(std::string_view filename,
                                             const std::vector<std::filesystem::path>& search_paths,
                                             ScanOptions options, AssetKind kind) {
        auto found = locate(filename, search_paths, options, security_file_names(), kind,
                            LookupPolicy::Strict);
        if (!found)
            return std::unexpected(std::move(found).error());
        if (!*found)
            return std::optional<ResolvedFile>{};
        return std::optional<ResolvedFile>{std::move((*found)->file)};
    }

    Result<IniFilesResult> read_ini_files(std::string_view version, std::string_view type,
                                          std::string_view target_section,
                                          const std::filesystem::path& fw_dir, ScanOptions options,
                                          BuildType build_type) {
        std::error_code cwd_error;
        const auto cwd = std::filesystem::current_path(cwd_error);
        if (cwd_error)
            return from_error_code(cwd_error, ".");
        const auto version_dir = cwd / version;
        return read_ini_files(
            version_dir / ("_" + std::string(type) + ".ini"), target_section,
            {fw_dir.empty() ? cwd / "mydata" : fw_dir, version_dir, cwd / "common"}, options,
            build_type);
    }

    Result<IniFilesResult> read_ini_files(const std::filesystem::path& ini_path,
                                          std::string_view target_section,
                                          const std::vector<std::filesystem::path>& search_paths,
                                          ScanOptions options, BuildType build_type) {
        auto doc_res = ini::parse_file(ini_path);
        if (!doc_res)
            return std::unexpected(
                std::move(doc_res).error().add_context("Could not parse INI file"));
        const auto& doc = *doc_res;
        const ini::Section* bl_sec = doc.get(target_section);
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
            return fail(ErrorCode::NotFound, "Bootloader section '[{}]' not found in INI '{}'",
                        target_section, ini_path.string());
        }

        // Validate all names before loading anything, including optional payloads.
        // An unsafe name must never become a basename-only STFS lookup.
        // A payload may name a file outside its release ("..\\data\\x.bin"); a bootloader may
        // not.
        for (const auto* section :
             {bl_sec, doc.get("security"), doc.get("flashfs"), doc.get("rawpatch")}) {
            if (!section)
                continue;
            for (const auto& entry : *section) {
                if (entry.key.empty() || normalize_file_key(entry.key) == "none")
                    continue;
                if (!safe_asset_name(section == bl_sec ? entry.key : ini_asset_name(entry.key)))
                    return fail(ErrorCode::InvalidArgument,
                                "INI asset '{}' is not confined to its source roots", entry.key);
            }
        }

        auto security_names = security_file_names();
        if (const auto* security = doc.get("security")) {
            for (const auto& entry : *security)
                security_names.push_back(normalize_file_key(entry.key));
        }
        // A file from outside the release is only ever a loose one.
        ScanOptions loose_options = options;
        loose_options.nosu = true;
        const auto search = [&](std::string_view name, const ScanOptions& scan,
                                AssetKind kind = AssetKind::Regular) {
            return locate(name, search_paths, scan, security_names, kind, LookupPolicy::Lenient);
        };
        // A lenient lookup fails only for an asset that escapes its source root.
        const auto escaped = [](std::string_view entry, FileLookupError&& failure) {
            Error error = std::move(failure);
            return std::unexpected(
                std::move(error).add_context(std::format("INI asset '{}'", entry)));
        };
        IniFilesResult result{};
        const bool is_jtag = build_type == BuildType::Jtag;
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
            auto found = search(entry.key, options, AssetKind::Bootloader);
            if (!found)
                return escaped(entry.key, std::move(found).error());
            if (!*found)
                return fail(ErrorCode::NotFound, "Required bootloader file '{}' not found",
                            entry.key);
            auto data = std::move((*found)->file.data);
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
                else if (is_jtag)
                    result.bootloaders.extra_cb = std::move(data);
                else
                    result.bootloaders.cb_b = std::move(data);
            } else if (key.starts_with("sc") || stem == "3bl") {
                result.bootloaders.sc = std::move(data);
            } else if (key.starts_with("sd")) {
                // A devkit chain's SD and SE take the CD and CE positions.
                result.bootloaders.cd = std::move(data);
            } else if (key.starts_with("se")) {
                result.bootloaders.ce = std::move(data);
            } else if (key.starts_with("cd") || key == "4bl") {
                if (chain == 0 || result.bootloaders.cd.empty())
                    result.bootloaders.cd = std::move(data);
                else if (is_jtag)
                    result.bootloaders.extra_cd = std::move(data);
                else
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
        // An entry from outside the release is found under its path in the roots, then by its
        // basename, and only as a loose file.
        const auto find_listed = [&](std::string_view entry) -> LocateResult {
            if (!ini_asset_is_outside(entry))
                return search(entry, options);
            const auto name = ini_asset_name(entry);
            auto found = search(name, loose_options);
            if (found && !*found)
                found = search(display_basename(name), loose_options);
            return found;
        };
        auto process_payload_entry = [&](const ini::Entry& entry, bool optional) -> Result<void> {
            const auto key = normalize_file_key(entry.key);
            if (key.empty() || key == "none")
                return {};
            auto found = find_listed(entry.key);
            if (!found)
                return escaped(entry.key, std::move(found).error());
            if (*found) {
                auto& winner = **found;
                std::string stored = flashfs_patch_suffix(display_basename(entry.key), build_type,
                                                          states_checksum(entry.value));
                const auto [it, inserted] = payloads.emplace(
                    normalize_file_key(stored), std::pair{result.flashfs_sec.size(), winner.rank});
                if (inserted) {
                    result.flashfs_sec.emplace_back(std::move(stored), std::move(winner.file.data));
                } else if (winner.rank < it->second.second) {
                    result.flashfs_sec[it->second.first].second = std::move(winner.file.data);
                    it->second.second = winner.rank;
                }
            } else if (ini_asset_is_outside(entry.key)) {
                Log::Warn("Could not read file '{}', skipping", entry.key);
            } else if (optional) {
                Log::Debug("Optional asset '{}' not present", entry.key);
            } else {
                Log::Warn("Payload asset '{}' not found in eligible loose files or STFS packages",
                          entry.key);
            }
            return {};
        };
        // The FlashFS lists the [flashfs] files and then the [security] files, each in the order
        // the INI names them (xeBuild 1.21).
        if (const auto* flashfs = doc.get("flashfs")) {
            for (const auto& entry : *flashfs) {
                if (auto added = process_payload_entry(entry, false); !added)
                    return std::unexpected(std::move(added).error());
            }
        }
        if (const auto* security = doc.get("security")) {
            for (const auto& entry : *security) {
                const bool optional = normalize_file_key(entry.key) == "fcrt.bin";
                if (auto added = process_payload_entry(entry, optional); !added)
                    return std::unexpected(std::move(added).error());
            }
        }
        // [rawpatch] lists "file,offset": the file goes into the image as it is at that clean
        // offset. A file no root supplies is skipped with a warning.
        if (const auto* rawpatch = doc.get("rawpatch")) {
            for (const auto& entry : *rawpatch) {
                const auto key = normalize_file_key(entry.key);
                if (key.empty() || key == "none")
                    continue;
                std::string_view digits = entry.value;
                int base = 10;
                if (digits.starts_with("0x") || digits.starts_with("0X")) {
                    digits.remove_prefix(2);
                    base = 16;
                }
                uint32_t offset = 0;
                const auto parsed =
                    std::from_chars(digits.data(), digits.data() + digits.size(), offset, base);
                if (digits.empty() || parsed.ec != std::errc{} ||
                    parsed.ptr != digits.data() + digits.size()) {
                    return fail(ErrorCode::Malformed,
                                "[rawpatch] entry '{}' states no usable offset ('{}')", entry.key,
                                entry.value);
                }
                auto found = find_listed(entry.key);
                if (!found)
                    return escaped(entry.key, std::move(found).error());
                if (!*found) {
                    Log::Warn("[rawpatch] file '{}' was not found; it is skipped", entry.key);
                    continue;
                }
                result.raw_patches.push_back(InputRawPatch{display_basename(entry.key), offset,
                                                           std::move((*found)->file.data)});
            }
        }
        return result;
    }

    void clear_stfs_cache() {
        std::lock_guard<std::mutex> lock(g_stfs_cache_mutex);
        g_disk_package_cache.clear();
        g_memory_package_cache.clear();
        g_dir_stfs_cache.clear();
    }

} // namespace gxbuild3::utils
