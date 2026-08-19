#include "utils/FileManager.hpp"
#include "ini/IniParser.hpp"
#include "nand/objects/Xboxupd.hpp"
#include "stfs/StfsContainer.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace gxbuild3::utils {

    namespace {

        std::string normalize_file_key(std::string key) {
            std::replace(key.begin(), key.end(), '\\', '/');
            auto pos = key.rfind('/');
            if (pos != std::string::npos)
                key = key.substr(pos + 1);
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return key;
        }

        std::filesystem::path entry_to_lookup_path(std::string_view entry_name) {
            std::string normalized{entry_name};
            std::replace(normalized.begin(), normalized.end(), '\\', '/');
            return std::filesystem::path(normalized);
        }

        std::optional<std::filesystem::path> find_stfs_file(const std::filesystem::path& dir) {
            if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
                return std::nullopt;
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (!entry.is_regular_file())
                    continue;
                const auto candidate = entry.path();
                std::string fname_lower = candidate.filename().string();
                std::transform(fname_lower.begin(), fname_lower.end(), fname_lower.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (!candidate.has_extension() && fname_lower.starts_with("su")) {
                    return candidate;
                }
            }
            return std::nullopt;
        }

    } // namespace

    std::optional<IniFilesResult> ReadIniFiles(
        std::string_view version,
        std::string_view type,
        std::string_view target_section,
        const std::filesystem::path& fw_dir
    ) {
        const std::filesystem::path cwd = std::filesystem::current_path();
        const std::filesystem::path version_dir = cwd / version;
        const std::filesystem::path common_dir = cwd / "common";
        const std::filesystem::path effective_fw_dir =
            !fw_dir.empty() ? fw_dir : (cwd / "mydata");

        const std::filesystem::path ini_path = version_dir / ("_" + std::string(type) + ".ini");
        Log::Debug("Searching for INI configuration file at '{}'", ini_path.string());
        auto doc_res = Ini::ParseFile(ini_path);
        if (!doc_res) {
            Log::Error("Could not parse INI file at '{}'", ini_path.string());
            return std::nullopt;
        }

        const auto& doc = *doc_res;

        std::vector<std::filesystem::path> search_dirs;
        if (!effective_fw_dir.empty() && std::filesystem::exists(effective_fw_dir))
            search_dirs.push_back(effective_fw_dir);
        if (std::filesystem::exists(version_dir))
            search_dirs.push_back(version_dir);
        if (std::filesystem::exists(common_dir))
            search_dirs.push_back(common_dir);

        auto find_loose_file = [&](std::string_view entry_name) -> std::optional<std::vector<uint8_t>> {
            const auto lookup_rel = entry_to_lookup_path(entry_name);
            for (const auto& root : search_dirs) {
                if (root.empty())
                    continue;
                const auto candidate = root / lookup_rel;
                if (auto data = read_file(candidate)) {
                    Log::Debug("Located loose asset '{}' at '{}' ({} bytes)", entry_name, candidate.string(), data->size());
                    return data;
                }
            }
            return std::nullopt;
        };

        std::optional<Stfs::ExtractedFiles> stfs_files;
        std::optional<std::filesystem::path> stfs_path;
        for (const auto& dir : {effective_fw_dir, version_dir, common_dir}) {
            if (auto p = find_stfs_file(dir)) {
                stfs_path = std::move(p);
                break;
            }
        }

        if (stfs_path) {
            Log::Debug("Found STFS package at '{}'", stfs_path->string());
            if (auto stfs_data = read_file(*stfs_path)) {
                std::span<const std::byte> span(
                    reinterpret_cast<const std::byte*>(stfs_data->data()),
                    stfs_data->size()
                );
                try {
                    const Stfs::StfsContainer container(span);
                    stfs_files = container.extractToMemory();
                    Log::Info("Extracted {} files from STFS container '{}'", stfs_files->size(), stfs_path->string());
                } catch (const std::exception& e) {
                    Log::Warn("Failed to extract STFS package '{}': {}", stfs_path->string(), e.what());
                }
            }
        }

        std::optional<bootloaders::XboxupdParts> xboxupd_parts;
        if (stfs_files) {
            auto it = stfs_files->find("xboxupd.bin");
            if (it != stfs_files->end()) {
                std::span<const std::byte> xbu_span(it->second.data(), it->second.size());
                try {
                    xboxupd_parts = bootloaders::split_xboxupd_raw(xbu_span);
                    Log::Debug("Split STFS xboxupd.bin into CF ({} bytes) and CG ({} bytes)",
                               xboxupd_parts->cf_raw.size(), xboxupd_parts->cg_raw.size());
                } catch (const std::exception& e) {
                    Log::Warn("Failed to split xboxupd.bin: {}", e.what());
                }
            }
        }

        auto find_bootloader_file = [&](std::string_view entry_name) -> std::optional<std::vector<uint8_t>> {
            if (auto loose = find_loose_file(entry_name)) {
                return loose;
            }

            std::string norm = normalize_file_key(std::string(entry_name));
            if (stfs_files) {
                auto it = stfs_files->find(norm);
                if (it != stfs_files->end()) {
                    std::vector<uint8_t> out;
                    out.reserve(it->second.size());
                    for (const auto b : it->second) {
                        out.push_back(std::to_integer<uint8_t>(b));
                    }
                    Log::Debug("Located bootloader asset '{}' in STFS container ({} bytes)", entry_name, out.size());
                    return out;
                }
            }

            if (xboxupd_parts) {
                if (norm.starts_with("cf") && !xboxupd_parts->cf_raw.empty()) {
                    Log::Debug("Extracted bootloader asset '{}' from STFS xboxupd.bin ({} bytes)", entry_name, xboxupd_parts->cf_raw.size());
                    return xboxupd_parts->cf_raw;
                }
                if (norm.starts_with("cg") && !xboxupd_parts->cg_raw.empty()) {
                    Log::Debug("Extracted bootloader asset '{}' from STFS xboxupd.bin ({} bytes)", entry_name, xboxupd_parts->cg_raw.size());
                    return xboxupd_parts->cg_raw;
                }
            }

            return std::nullopt;
        };

        IniFilesResult result{};

        const Ini::Section* bl_sec = doc.get(target_section);
        if (!bl_sec) {
            std::string alt{target_section};
            auto underscore_pos = alt.find('_');
            if (underscore_pos != std::string::npos) {
                std::string base = alt.substr(0, underscore_pos);
                std::string suffix = alt.substr(underscore_pos);
                if (!base.ends_with("bl")) {
                    bl_sec = doc.get(base + "bl" + suffix);
                }
            } else if (!alt.ends_with("bl")) {
                bl_sec = doc.get(alt + "bl");
            }
        }

        if (!bl_sec) {
            Log::Error("Bootloader section '[{}]' not found in INI configuration", target_section);
            return std::nullopt;
        }

        for (const auto& entry : *bl_sec) {
            std::string key_lower = entry.key;
            std::transform(key_lower.begin(), key_lower.end(), key_lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (key_lower.empty() || key_lower == "none")
                continue;

            auto data_opt = find_bootloader_file(entry.key);
            if (!data_opt) {
                Log::Error("Required bootloader file '{}' not found", entry.key);
                return std::nullopt;
            }

            auto data = std::move(*data_opt);

                if (key_lower.starts_with("cba") || key_lower.starts_with("cb_a") ||
                    key_lower.starts_with("sb") || key_lower == "2bl") {
                    result.bootloaders.cb_or_a = std::move(data);
                } else if (key_lower.starts_with("cbx") || key_lower.starts_with("cb_x")) {
                    result.bootloaders.cb_x = std::move(data);
                } else if (key_lower.starts_with("cbb") || key_lower.starts_with("cb_b")) {
                    result.bootloaders.cb_b = std::move(data);
                } else if (key_lower.starts_with("cb_") || key_lower == "cb") {
                    if (entry.chain == 0 || result.bootloaders.cb_or_a.empty()) {
                        result.bootloaders.cb_or_a = std::move(data);
                    } else {
                        result.bootloaders.cb_b = std::move(data);
                    }
                } else if (key_lower.starts_with("cd") || key_lower == "4bl") {
                    result.bootloaders.cd = std::move(data);
                } else if (key_lower.starts_with("ce") || key_lower == "5bl") {
                    result.bootloaders.ce = std::move(data);
                } else if (key_lower.starts_with("cf") || key_lower == "6bl") {
                    if (entry.chain == 0 || !result.bootloaders.cf0.has_value()) {
                        result.bootloaders.cf0 = std::move(data);
                    } else {
                        result.bootloaders.cf1 = std::move(data);
                    }
                } else if (key_lower.starts_with("cg") || key_lower == "7bl") {
                    if (entry.chain == 0 || !result.bootloaders.cg0.has_value()) {
                        result.bootloaders.cg0 = std::move(data);
                    } else {
                        result.bootloaders.cg1 = std::move(data);
                    }
                }
            }

        auto process_payload_entry = [&](const Ini::Entry& entry, bool is_optional = false) {
            if (entry.key.empty() || entry.key == "none")
                return;

            if (auto loose = find_loose_file(entry.key)) {
                result.flashfs_sec.push_back({entry.key, std::move(*loose)});
                return;
            }

            if (stfs_files) {
                const std::string norm_key = normalize_file_key(entry.key);
                auto it = stfs_files->find(norm_key);
                if (it != stfs_files->end()) {
                    std::vector<uint8_t> out;
                    out.reserve(it->second.size());
                    for (const auto b : it->second) {
                        out.push_back(std::to_integer<uint8_t>(b));
                    }
                    Log::Debug("Located asset '{}' in STFS container ({} bytes)", entry.key, out.size());
                    result.flashfs_sec.push_back({entry.key, std::move(out)});
                    return;
                }
            }

            if (is_optional) {
                Log::Debug("Optional asset '{}' not present", entry.key);
            } else {
                Log::Warn("Payload asset '{}' not found in loose files or STFS package", entry.key);
            }
        };

        if (const auto* sec = doc.get("security")) {
            for (const auto& entry : *sec) {
                bool opt = (entry.key == "fcrt.bin");
                process_payload_entry(entry, opt);
            }
        }

        if (const auto* flashfs = doc.get("flashfs")) {
            for (const auto& entry : *flashfs) {
                process_payload_entry(entry, false);
            }
        }

        return result;
    }

} // namespace gxbuild3::utils
