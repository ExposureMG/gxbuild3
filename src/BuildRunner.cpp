#include "BuildRunner.hpp"

#include "FlashImage.hpp"
#include "Log.hpp"
#include "Options.hpp"
#include "Utils.hpp"
#include "bootloaders/2bl.hpp"
#include "bootloaders/Keyvault.hpp"
#include "bootloaders/SMC.hpp"
#include "bootloaders/Xboxupd.hpp"
#include "ini/IniParser.hpp"
#include "patchers/BinaryParser.hpp"
#include "patchers/Patcher.hpp"
#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"
#include "stfs/StfsContainer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// File-local helpers (mirrors the static helpers in Main.cpp)
// ---------------------------------------------------------------------------

static std::optional<std::vector<uint8_t>> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto from_hex = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        int h = from_hex(hex[i]);
        int l = from_hex(hex[i + 1]);
        if (h < 0 || l < 0)
            return std::nullopt;
        out.push_back(static_cast<uint8_t>((h << 4) | l));
    }
    return out;
}

static std::optional<std::vector<uint8_t>> ReadFile(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

static std::span<const std::byte> AsByteSpan(const std::vector<uint8_t>& data) {
    return {reinterpret_cast<const std::byte*>(data.data()), data.size()};
}

// ---------------------------------------------------------------------------
// RunBuild
// ---------------------------------------------------------------------------

std::optional<std::vector<uint8_t>> RunBuild(GxArgs args) {
    // Derive build_type_str from the enum (used for patch-file naming and INI path).
    std::string build_type_str;
    if (args.build_type) {
        for (const auto& [s, bt] : kBuildTypeMap) {
            if (bt == *args.build_type) {
                build_type_str = s;
                break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 1. Key parsing
    // -----------------------------------------------------------------------
    std::vector<uint8_t> cpu_key_bytes;
    if (args.cpu_key) {
        auto parsed = HexToBytes(*args.cpu_key);
        if (!parsed || parsed->size() != 16) {
            Log::Error("Invalid CPU key: must be a 32-character hex string");
            return std::nullopt;
        }
        cpu_key_bytes = std::move(*parsed);
        if (!cpukey_valid(cpu_key_bytes)) {
            Log::Error("CPU key failed ECC/hamming validation");
            return std::nullopt;
        }
        Log::Info("CPU key accepted");
    }

    std::vector<uint8_t> bl_key_bytes;
    if (args.bl_key) {
        auto parsed = HexToBytes(*args.bl_key);
        if (!parsed || parsed->size() != 16) {
            Log::Error("Invalid 1BL key: must be a 32-character hex string");
            return std::nullopt;
        }
        bl_key_bytes = std::move(*parsed);
        Log::Info("1BL key accepted");
    }

    // -----------------------------------------------------------------------
    // 2. Options.ini
    // -----------------------------------------------------------------------
    OptionsArgs options{};
    const std::filesystem::path data_dir = args.data_dir.value_or(std::filesystem::current_path());
    {
        std::filesystem::path opts_path = data_dir / "options.ini";
        auto opts_res = Ini::ParseOptionsIniFile(opts_path);
        if (!opts_res) {
            std::visit(
                [](auto&& err) {
                    using T = std::decay_t<decltype(err)>;
                    if constexpr (std::is_same_v<T, Ini::ParseError>) {
                        if (err != Ini::ParseError::FileNotFound)
                            Log::Warn("options.ini: {}", Ini::ParseErrorString(err));
                    } else {
                        Log::Error("options.ini: {}", Ini::OptionsErrorString(err));
                    }
                },
                opts_res.error());
        } else {
            options = std::move(*opts_res);
            Log::Info("Loaded options.ini");
        }
    }

    for (const auto& [key, value] : args.options) {
        Ini::ApplyOption(options, key, value);
    }

    if (cpu_key_bytes.empty() && options.cpukey) {
        auto parsed = HexToBytes(*options.cpukey);
        if (parsed && parsed->size() == 16 && cpukey_valid(*parsed)) {
            cpu_key_bytes = std::move(*parsed);
            Log::Info("CPU key loaded from merged options");
        }
    }

    if (cpu_key_bytes.empty()) {
        if (std::filesystem::exists(data_dir) && std::filesystem::is_directory(data_dir)) {
            for (const auto& entry : std::filesystem::directory_iterator(data_dir)) {
                if (!entry.is_regular_file())
                    continue;
                std::string fname = entry.path().filename().string();
                std::string fname_lower = fname;
                std::transform(fname_lower.begin(), fname_lower.end(), fname_lower.begin(),
                               ::tolower);
                if (fname_lower == "cpukey.txt" || fname_lower == "cpukey.bin") {
                    if (fname_lower == "cpukey.bin") {
                        auto file_data = ReadFile(entry.path());
                        if (file_data && file_data->size() == 16) {
                            cpu_key_bytes = std::move(*file_data);
                            Log::Info("CPU key loaded from '{}'", entry.path().filename().string());
                            break;
                        }
                    } else {
                        auto file_data = ReadFile(entry.path());
                        if (file_data) {
                            std::string content(file_data->begin(), file_data->end());
                            content.erase(content.find_last_not_of(" \t\n\r") + 1);
                            content.erase(0, content.find_first_not_of(" \t\n\r"));
                            auto parsed = HexToBytes(content);
                            if (parsed && parsed->size() == 16) {
                                cpu_key_bytes = std::move(*parsed);
                                Log::Info("CPU key loaded from '{}'",
                                          entry.path().filename().string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if (cpu_key_bytes.empty()) {
        cpu_key_bytes.assign(16, 0);
        Log::Info("No CPU key provided, defaulting to all 0s");
    }

    if (bl_key_bytes.empty() && options.key_1bl) {
        auto parsed = HexToBytes(*options.key_1bl);
        if (parsed && parsed->size() == 16) {
            bl_key_bytes = std::move(*parsed);
            Log::Info("1BL key loaded from merged options");
        }
    }

    if (bl_key_bytes.empty()) {
        auto parsed = HexToBytes("DD88AD0C9ED669E7B56794FB68563EFA");
        if (parsed && parsed->size() == 16) {
            bl_key_bytes = std::move(*parsed);
            Log::Info("1BL key defaulted to DD88AD0C9ED669E7B56794FB68563EFA");
        }
    }

    Options::Init(options);

    // -----------------------------------------------------------------------
    // 3. INI loading — inline content takes priority over disk
    // -----------------------------------------------------------------------
    std::optional<Ini::Document> build_doc;
    if (args.ini_content) {
        auto res = Ini::Parse(*args.ini_content);
        if (!res) {
            Log::Error("Failed to parse provided INI content");
            return std::nullopt;
        }
        build_doc = std::move(*res);
        Log::Info("Loaded INI from inline content");
    } else {
        if (build_type_str.empty()) {
            Log::Error("Build type is required when no inline INI content is provided (use -t)");
            return std::nullopt;
        }
        std::filesystem::path ini_path = data_dir / ("_" + build_type_str + ".ini");
        auto res = Ini::ParseFile(ini_path);
        if (!res) {
            Log::Error("Failed to load build INI '{}': {}", ini_path.string(),
                       Ini::ParseErrorString(res.error()));
            return std::nullopt;
        }
        build_doc = std::move(*res);
        Log::Info("Loaded build INI: {}", ini_path.string());
    }

    if (!build_doc)
        return std::nullopt;

    // -----------------------------------------------------------------------
    // 4. Main build block
    // -----------------------------------------------------------------------
    const auto& opts = Options::Get();
    const std::optional<std::filesystem::path> common_dir = args.common_dir;
    std::filesystem::path fw_dir = args.fw_dir.value_or(data_dir);
    std::optional<Stfs::ExtractedFiles> stfs_files;

    auto normalize_file_key = [](std::string key) {
        std::replace(key.begin(), key.end(), '\\', '/');
        auto pos = key.rfind('/');
        if (pos != std::string::npos)
            key = key.substr(pos + 1);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        return key;
    };

    auto sanitize_file_key = [](std::string key) {
        std::replace(key.begin(), key.end(), '\\', '/');
        auto pos = key.rfind('/');
        if (pos != std::string::npos)
            key = key.substr(pos + 1);
        return key;
    };

    auto entry_to_lookup_path = [](std::string_view entry_name) {
        std::string normalized{entry_name};
        std::replace(normalized.begin(), normalized.end(), '\\', '/');
        return std::filesystem::path(normalized);
    };

    using resolved_file_t = std::pair<std::filesystem::path, std::vector<uint8_t>>;

    auto load_from_root = [&](const std::filesystem::path& root,
                              std::string_view entry_name) -> std::optional<resolved_file_t> {
        const auto candidate = root / entry_to_lookup_path(entry_name);
        auto file_data = ReadFile(candidate);
        if (!file_data)
            return std::nullopt;
        return resolved_file_t{candidate, std::move(*file_data)};
    };

    auto load_from_common_dir = [&](std::string_view entry_name) -> std::optional<resolved_file_t> {
        if (!common_dir)
            return std::nullopt;
        return load_from_root(*common_dir, entry_name);
    };

    auto load_main_section_file =
        [&](std::string_view entry_name) -> std::optional<resolved_file_t> {
        if (auto loaded = load_from_root(fw_dir, entry_name))
            return loaded;
        if (auto loaded = load_from_root(data_dir, entry_name))
            return loaded;
        return load_from_common_dir(entry_name);
    };

    auto load_payload_file = [&](std::string_view filename) -> std::optional<resolved_file_t> {
        if (auto loaded = load_from_root(fw_dir, filename))
            return loaded;
        if (auto loaded = load_from_root(fw_dir / "payloads", filename))
            return loaded;
        return std::nullopt;
    };

    std::optional<gxbuild3::bootloaders::XboxupdParts> cached_xboxupd_parts;
    bool tried_loading_xboxupd = false;
    auto load_xboxupd_parts = [&]() -> std::optional<gxbuild3::bootloaders::XboxupdParts> {
        if (tried_loading_xboxupd)
            return cached_xboxupd_parts;
        tried_loading_xboxupd = true;

        auto try_parse = [&](const std::filesystem::path& source_path,
                             const std::vector<uint8_t>& xboxupd_data)
            -> std::optional<gxbuild3::bootloaders::XboxupdParts> {
            try {
                auto parts = gxbuild3::bootloaders::split_xboxupd_raw(
                    std::span<const uint8_t>(xboxupd_data.data(), xboxupd_data.size()));
                Log::Info("Parsed xboxupd '{}' into CF ({} bytes) and CG ({} bytes)",
                          source_path.string(), parts.cf_raw.size(), parts.cg_raw.size());
                return parts;
            } catch (const std::exception& ex) {
                Log::Warn("Failed to parse xboxupd '{}': {}", source_path.string(), ex.what());
                return std::nullopt;
            }
        };

        auto try_load_xboxupd_file = [&](const std::filesystem::path& candidate_path)
            -> std::optional<gxbuild3::bootloaders::XboxupdParts> {
            auto xboxupd_data = ReadFile(candidate_path);
            if (!xboxupd_data)
                return std::nullopt;
            return try_parse(candidate_path, *xboxupd_data);
        };

        if (args.xboxupd) {
            if (args.xboxupd->is_absolute()) {
                if (auto parts = try_load_xboxupd_file(*args.xboxupd)) {
                    cached_xboxupd_parts = std::move(*parts);
                    return cached_xboxupd_parts;
                }
            } else {
                if (auto parts = try_load_xboxupd_file(fw_dir / *args.xboxupd)) {
                    cached_xboxupd_parts = std::move(*parts);
                    return cached_xboxupd_parts;
                }
                if (auto parts = try_load_xboxupd_file(data_dir / *args.xboxupd)) {
                    cached_xboxupd_parts = std::move(*parts);
                    return cached_xboxupd_parts;
                }
                if (common_dir) {
                    if (auto parts = try_load_xboxupd_file(*common_dir / *args.xboxupd)) {
                        cached_xboxupd_parts = std::move(*parts);
                        return cached_xboxupd_parts;
                    }
                }
            }
        }

        if (stfs_files) {
            const auto stfs_it = stfs_files->find(normalize_file_key("xboxupd.bin"));
            if (stfs_it != stfs_files->end()) {
                std::vector<uint8_t> xboxupd_data;
                xboxupd_data.reserve(stfs_it->second.size());
                for (const auto byte : stfs_it->second)
                    xboxupd_data.push_back(std::to_integer<uint8_t>(byte));
                if (auto parts =
                        try_parse(std::filesystem::path{"<stfs>/xboxupd.bin"}, xboxupd_data)) {
                    cached_xboxupd_parts = std::move(*parts);
                    return cached_xboxupd_parts;
                }
            }
        }

        if (auto parts = try_load_xboxupd_file(fw_dir / "xboxupd.bin")) {
            cached_xboxupd_parts = std::move(*parts);
            return cached_xboxupd_parts;
        }
        if (auto parts = try_load_xboxupd_file(data_dir / "xboxupd.bin")) {
            cached_xboxupd_parts = std::move(*parts);
            return cached_xboxupd_parts;
        }
        if (common_dir) {
            if (auto parts = try_load_xboxupd_file(*common_dir / "xboxupd.bin")) {
                cached_xboxupd_parts = std::move(*parts);
                return cached_xboxupd_parts;
            }
        }

        return std::nullopt;
    };

    auto load_stage_or_xboxupd =
        [&](std::string_view entry_name) -> std::optional<resolved_file_t> {
        if (auto loaded = load_main_section_file(entry_name))
            return loaded;

        std::string basename = entry_to_lookup_path(entry_name).filename().string();
        std::transform(basename.begin(), basename.end(), basename.begin(), ::tolower);

        const bool wants_cf = basename.starts_with("cf");
        const bool wants_cg = basename.starts_with("cg");
        if (!wants_cf && !wants_cg)
            return std::nullopt;

        const auto xboxupd_parts = load_xboxupd_parts();
        if (!xboxupd_parts)
            return std::nullopt;

        const auto source_path =
            std::filesystem::path{wants_cf ? "<xboxupd>/cf.bin" : "<xboxupd>/cg.bin"};
        return resolved_file_t{source_path,
                               wants_cf ? xboxupd_parts->cf_raw : xboxupd_parts->cg_raw};
    };

    auto load_xell_file = [&]() -> std::optional<resolved_file_t> {
        static constexpr std::string_view kGlitchXellName = "xell-gggggg.bin";
        static constexpr std::string_view kJtagXellName = "xell-2f.bin";
        if (args.build_type && *args.build_type == BuildType::Jtag)
            return load_payload_file(kJtagXellName);
        return load_payload_file(kGlitchXellName);
    };

    const bool is_xell_build_type =
        args.build_type &&
        (*args.build_type == BuildType::Jtag || *args.build_type == BuildType::Glitch ||
         *args.build_type == BuildType::Glitch2 || *args.build_type == BuildType::Glitch3);

    std::string section_name;
    if (args.console) {
        static const std::map<ConsoleType, std::string> kConsoleSectionSuffix = {
            {ConsoleType::Xenon, "xenon"},
            {ConsoleType::Zephyr, "zephyr"},
            {ConsoleType::Falcon, "falcon"},
            {ConsoleType::Jasper, "jasper"},
            {ConsoleType::Jasper256, "jasper"},
            {ConsoleType::Jasper512, "jasper"},
            {ConsoleType::JasperBB, "jasper"},
            {ConsoleType::JasperBigFFS, "jasper"},
            {ConsoleType::Trinity, "trinity"},
            {ConsoleType::TrinityBB, "trinity"},
            {ConsoleType::TrinityBigFFS, "trinity"},
            {ConsoleType::Corona, "corona"},
            {ConsoleType::Corona4G, "corona"},
            {ConsoleType::Winchester, "winchester"},
            {ConsoleType::Winchester4G, "winchester"},
        };
        auto it = kConsoleSectionSuffix.find(*args.console);
        if (it != kConsoleSectionSuffix.end())
            section_name = it->second + "bl";
    }

    // STFS auto-discovery from data_dir (su* filenames), plus explicit stfs_package override.
    {
        std::optional<std::filesystem::path> stfs_path;

        // Explicit STFS package takes priority over auto-discovery.
        if (args.stfs_package && std::filesystem::exists(*args.stfs_package)) {
            stfs_path = args.stfs_package;
        } else if (std::filesystem::exists(data_dir) && std::filesystem::is_directory(data_dir)) {
            for (const auto& dir_entry : std::filesystem::directory_iterator(data_dir)) {
                if (!dir_entry.is_regular_file())
                    continue;
                const auto candidate = dir_entry.path();
                const std::string filename = candidate.filename().string();
                std::string filename_lower = filename;
                std::transform(filename_lower.begin(), filename_lower.end(), filename_lower.begin(),
                               ::tolower);
                if (!candidate.has_extension() && filename_lower.starts_with("su")) {
                    if (stfs_path) {
                        Log::Warn("Multiple STFS candidates found in '{}', using '{}'",
                                  data_dir.string(), stfs_path->filename().string());
                        break;
                    }
                    stfs_path = candidate;
                }
            }
        }

        if (stfs_path) {
            auto stfs_data = ReadFile(*stfs_path);
            if (!stfs_data) {
                Log::Error("Failed to read STFS package: {}", stfs_path->string());
                return std::nullopt;
            }
            try {
                const Stfs::StfsContainer container{AsByteSpan(*stfs_data)};
                stfs_files = container.extractToMemory();
                Log::Info("Loaded STFS package '{}' with {} extracted files",
                          stfs_path->filename().string(), stfs_files->size());
            } catch (const std::exception& ex) {
                Log::Error("Failed to parse STFS package '{}': {}", stfs_path->string(), ex.what());
                return std::nullopt;
            }
        }
    }

    // Patch file lookup.
    const std::string console_name = [&]() -> std::string {
        if (!args.console)
            return {};
        switch (*args.console) {
            case ConsoleType::Xenon:
                return "xenon";
            case ConsoleType::Zephyr:
                return "zephyr";
            case ConsoleType::Falcon:
                return "falcon";
            case ConsoleType::Jasper:
            case ConsoleType::Jasper256:
            case ConsoleType::Jasper512:
            case ConsoleType::JasperBB:
            case ConsoleType::JasperBigFFS:
                return "jasper";
            case ConsoleType::Trinity:
            case ConsoleType::TrinityBB:
            case ConsoleType::TrinityBigFFS:
                return "trinity";
            case ConsoleType::Corona:
                return "corona";
            case ConsoleType::Corona4G:
                return "corona4g";
            case ConsoleType::Winchester:
                return "winchester";
            case ConsoleType::Winchester4G:
                return "winchester4g";
        }
        return {};
    }();

    std::string g1_model = console_name;
    if (console_name == "xenon" || console_name == "elpis" || console_name == "zephyr" ||
        console_name == "falcon" || console_name == "opus" || console_name == "jasper" ||
        console_name == "jasperbb" || console_name == "jasperbigffs" ||
        console_name == "tonasket") {
        g1_model = "fat";
    } else if (console_name == "trinity" || console_name == "trinitybb" ||
               console_name == "trinitybigffs" || console_name == "corona" ||
               console_name == "corona4g" || console_name == "winchester" ||
               console_name == "winchester4g") {
        g1_model = "trinity";
    }

    const std::string patch_mobo =
        console_name + (args.bl_ext ? "_" + *args.bl_ext : std::string{});
    std::filesystem::path patches_dir = data_dir / "bin";
    std::filesystem::path patch;

    if (args.build_type) {
        switch (*args.build_type) {
            case BuildType::Retail:
            case BuildType::Devkit:
                break;
            case BuildType::Glitch:
                patch = patches_dir / ("patches_" + g1_model + ".bin");
                break;
            case BuildType::Glitch2:
                patch = patches_dir / ("patches_g2" + patch_mobo + ".bin");
                break;
            case BuildType::Glitch2m:
                patch = patches_dir / ("patches_g2m" + patch_mobo + ".bin");
                break;
            case BuildType::Glitch3:
                patch = patches_dir / ("patches_g3" + patch_mobo + ".bin");
                break;
            case BuildType::Jtag:
                patch = patches_dir / ("patches_" + patch_mobo + ".bin");
                break;
        }
    }

    std::optional<ParsedPatchSet> parsed_patchset;

    if (!patch.empty()) {
        auto patch_data = ReadFile(patch);
        if (!patch_data) {
            Log::Error("Failed to read patch file: {}", patch.string());
            return std::nullopt;
        }

        auto load_addon_file = [&](std::string_view addon_name) -> std::optional<resolved_file_t> {
            const auto try_load =
                [&](std::string_view candidate_name) -> std::optional<resolved_file_t> {
                if (auto loaded = load_from_root(data_dir, candidate_name))
                    return loaded;
                if (auto loaded = load_from_root(data_dir / "payloads", candidate_name))
                    return loaded;
                return std::nullopt;
            };
            if (auto loaded = try_load(addon_name))
                return loaded;
            const std::filesystem::path addon_path{std::string{addon_name}};
            if (!addon_path.has_extension()) {
                const std::string addon_with_bin = std::string{addon_name} + ".bin";
                return try_load(addon_with_bin);
            }
            return std::nullopt;
        };

        parsed_patchset.emplace();
        if (!args.build_type ||
            !BinaryParser::ParsePatchSet(patch.string(), *args.build_type, *parsed_patchset)) {
            Log::Error("Failed to parse patchset '{}'", patch.string());
            return std::nullopt;
        }

        auto raw_tail_it =
            std::find_if(parsed_patchset->sections.begin(), parsed_patchset->sections.end(),
                         [](const ParsedPatchSection& section) {
                             return section.target == PatchSectionTarget::Khv ||
                                    section.target == PatchSectionTarget::JtagSection4;
                         });
        if (raw_tail_it == parsed_patchset->sections.end()) {
            Log::Error("Parsed patchset '{}' is missing a raw insert section", patch.string());
            return std::nullopt;
        }

        for (const auto& addon_name : args.addons) {
            auto addon_file = load_addon_file(addon_name);
            if (!addon_file) {
                Log::Error("Failed to resolve addon patch '{}'", addon_name);
                return std::nullopt;
            }
            raw_tail_it->raw_data.insert(raw_tail_it->raw_data.end(), addon_file->second.begin(),
                                         addon_file->second.end());
            Log::Info("Appended addon '{}' ({} bytes) to '{}'", addon_file->first.string(),
                      addon_file->second.size(), raw_tail_it->identifier);
        }

        Log::Info("Parsed patchset '{}' as {} with {} sections", patch.filename().string(),
                  parsed_patchset->kind == PatchSetKind::Jtag ? "JTAG" : "Glitch",
                  parsed_patchset->sections.size());
    }

    flash_image_t new_nand{};
    std::optional<flash_image_t> donor_nand;

    // Source NAND: inline bytes take priority over path discovery.
    if (args.source_nand_bytes && !args.source_nand_bytes->empty()) {
        Log::Info("Parsing source NAND from inline bytes ({} bytes)...",
                  args.source_nand_bytes->size());
        donor_nand = FlashImage::parse(*args.source_nand_bytes);
        if (!donor_nand->nand_results || !donor_nand->nand_results->valid) {
            Log::Error("Failed to parse provided source NAND bytes");
            return std::nullopt;
        }
        new_nand.keyvault = donor_nand->keyvault;
        new_nand.smc = donor_nand->smc;
        new_nand.xconfig = donor_nand->xconfig;
        new_nand.mobile_data = donor_nand->mobile_data;
        new_nand.cb_or_A = donor_nand->cb_or_A;
        new_nand.cb_X = donor_nand->cb_X;
        new_nand.cb_B = donor_nand->cb_B;
        new_nand.sc = donor_nand->sc;
        new_nand.cd = donor_nand->cd;
        new_nand.ce = donor_nand->ce;
        new_nand.patchslot_0 = donor_nand->patchslot_0;
        new_nand.patchslot_1 = donor_nand->patchslot_1;
    } else {
        if (!args.source_nand) {
            static const std::vector<std::string> kDonorCandidates = {
                "nanddump.bin", "nanddump1.bin", "nanddump2.bin", "nand.bin", "dump.bin"};
            std::vector<std::filesystem::path> search_roots;
            if (args.fw_dir)
                search_roots.push_back(*args.fw_dir);
            search_roots.push_back(std::filesystem::current_path());

            for (const auto& candidate : kDonorCandidates) {
                for (const auto& root : search_roots) {
                    if (std::filesystem::exists(root / candidate)) {
                        args.source_nand = (root / candidate).string();
                        break;
                    }
                }
                if (args.source_nand)
                    break;
            }
        }

        if (args.source_nand) {
            std::filesystem::path source_nand_path = *args.source_nand;
            if (!std::filesystem::exists(source_nand_path)) {
                std::filesystem::path alt_path =
                    args.fw_dir.value_or(args.data_dir.value_or(std::filesystem::current_path())) /
                    *args.source_nand;
                if (std::filesystem::exists(alt_path))
                    source_nand_path = alt_path;
            }
            auto source_nand_data = ReadFile(source_nand_path);
            if (!source_nand_data) {
                Log::Error("Failed to read source NAND file: {}", source_nand_path.string());
                return std::nullopt;
            }
            Log::Info("Parsing source NAND image '{}' ({} bytes)...", source_nand_path.string(),
                      source_nand_data->size());
            donor_nand = FlashImage::parse(*source_nand_data);
            if (!donor_nand->nand_results || !donor_nand->nand_results->valid) {
                Log::Error("Failed to parse source NAND file: {}", source_nand_path.string());
                return std::nullopt;
            }
            new_nand.keyvault = donor_nand->keyvault;
            new_nand.smc = donor_nand->smc;
            new_nand.xconfig = donor_nand->xconfig;
            new_nand.mobile_data = donor_nand->mobile_data;
            new_nand.cb_or_A = donor_nand->cb_or_A;
            new_nand.cb_X = donor_nand->cb_X;
            new_nand.cb_B = donor_nand->cb_B;
            new_nand.sc = donor_nand->sc;
            new_nand.cd = donor_nand->cd;
            new_nand.ce = donor_nand->ce;
            new_nand.patchslot_0 = donor_nand->patchslot_0;
            new_nand.patchslot_1 = donor_nand->patchslot_1;
        }
    }

    if (args.smc_path) {
        if (auto smc_data = ReadFile(*args.smc_path)) {
            new_nand.smc = std::move(*smc_data);
            Log::Info("Loaded SMC from explicit path '{}'", args.smc_path->string());
        }
    } else if (auto smc_file = load_from_root(fw_dir, "smc.bin")) {
        new_nand.smc = std::move(smc_file->second);
        Log::Info("Loaded SMC from '{}'{}", smc_file->first.string(),
                  donor_nand && donor_nand->smc ? " (overriding donor NAND)" : "");
    } else if (new_nand.smc) {
        Log::Info("Loaded SMC from donor NAND");
    }

    if (args.smc_config_path) {
        if (auto cfg_data = ReadFile(*args.smc_config_path)) {
            new_nand.xconfig = std::move(*cfg_data);
            Log::Info("Loaded SMC config from explicit path '{}'", args.smc_config_path->string());
        }
    } else if (auto smc_cfg_file = load_from_root(fw_dir, "smc_config.bin")) {
        new_nand.xconfig = std::move(smc_cfg_file->second);
        Log::Info("Loaded SMC Config from '{}'{}", smc_cfg_file->first.string(),
                  donor_nand && donor_nand->xconfig ? " (overriding donor NAND)" : "");
    } else if (new_nand.xconfig) {
        Log::Info("Loaded SMC Config from donor NAND");
    }

    auto load_mobile_file = [&](char letter, std::optional<std::vector<uint8_t>>& dest) {
        std::string upper = std::string("Mobile") + letter + ".bin";
        std::string lower = std::string("mobile_") + static_cast<char>(std::tolower(letter)) + ".bin";
        std::string alt = std::string("mobile") + static_cast<char>(std::tolower(letter)) + ".bin";
        if (auto file = load_from_root(fw_dir, upper)) {
            dest = std::move(file->second);
            Log::Info("Loaded Mobile {} from '{}'", letter, file->first.string());
        } else if (auto file2 = load_from_root(fw_dir, lower)) {
            dest = std::move(file2->second);
            Log::Info("Loaded Mobile {} from '{}'", letter, file2->first.string());
        } else if (auto file3 = load_from_root(fw_dir, alt)) {
            dest = std::move(file3->second);
            Log::Info("Loaded Mobile {} from '{}'", letter, file3->first.string());
        }
    };

    if (!new_nand.mobile_data) {
        new_nand.mobile_data.emplace();
    }
    load_mobile_file('B', new_nand.mobile_data->x31);
    load_mobile_file('C', new_nand.mobile_data->x32);
    load_mobile_file('D', new_nand.mobile_data->x33);
    load_mobile_file('E', new_nand.mobile_data->x34);
    load_mobile_file('F', new_nand.mobile_data->x35);
    load_mobile_file('G', new_nand.mobile_data->x36);
    load_mobile_file('H', new_nand.mobile_data->x37);
    load_mobile_file('I', new_nand.mobile_data->x38);
    load_mobile_file('J', new_nand.mobile_data->x39);

    if (!new_nand.smc) {
        Log::Warn("No SMC found — build may produce an invalid image");
    }

    if (new_nand.smc) {
        auto& smc = *new_nand.smc;

        if (smc_is_encrypted(smc)) {
            Log::Info("SMC is encrypted, decrypting...");
            smc = smc_decrypt(smc);
        } else {
            Log::Info("SMC is already decrypted");
        }

        if (!opts.smcnocheck.value_or(false)) {
            static const std::map<uint8_t, std::string_view> kSmcConsoleNibble = {
                {1, "Xenon"},  {2, "Zephyr"},  {3, "Falcon/Opus"},
                {4, "Jasper"}, {5, "Trinity"}, {6, "Corona"},
            };
            static const std::map<ConsoleType, uint8_t> kExpectedNibble = {
                {ConsoleType::Xenon, 1},         {ConsoleType::Zephyr, 2},
                {ConsoleType::Falcon, 3},        {ConsoleType::Jasper, 4},
                {ConsoleType::Jasper256, 4},     {ConsoleType::Jasper512, 4},
                {ConsoleType::JasperBB, 4},      {ConsoleType::JasperBigFFS, 4},
                {ConsoleType::Trinity, 5},       {ConsoleType::TrinityBB, 5},
                {ConsoleType::TrinityBigFFS, 5}, {ConsoleType::Corona, 6},
                {ConsoleType::Corona4G, 6},      {ConsoleType::Winchester, 6},
                {ConsoleType::Winchester4G, 6},
            };

            const uint8_t smc_nibble = (smc[0x100] >> 4) & 0xF;
            const auto nibble_it = kSmcConsoleNibble.find(smc_nibble);
            const std::string_view smc_console =
                nibble_it != kSmcConsoleNibble.end() ? nibble_it->second : "Unknown";
            Log::Info("SMC console type: {} (nibble={})", smc_console, smc_nibble);

            if (args.console) {
                const auto exp_it = kExpectedNibble.find(*args.console);
                if (exp_it != kExpectedNibble.end() && exp_it->second != smc_nibble) {
                    Log::Warn("SMC console type '{}' does not match expected console '{}' "
                              "-- pass smcnocheck=1 to suppress",
                              smc_console, console_name);
                }
            }

            const SmcType smc_type = smc_get_type(smc);
            Log::Info("SMC patch type: {}", smc_type_name(smc_type));

            const bool build_is_retail = args.build_type && *args.build_type == BuildType::Retail;
            const bool build_is_jtag = args.build_type && *args.build_type == BuildType::Jtag;
            const bool build_is_glitch =
                args.build_type &&
                (*args.build_type == BuildType::Glitch || *args.build_type == BuildType::Glitch2 ||
                 *args.build_type == BuildType::Glitch2m || *args.build_type == BuildType::Glitch3);

            const bool smc_is_retail = smc_type == SmcType::Retail;
            const bool smc_is_jtag = smc_type == SmcType::Jtag || smc_type == SmcType::RJtag ||
                                     smc_type == SmcType::Cygnos ||
                                     smc_type == SmcType::RJtagCygnos;
            const bool smc_is_glitch = smc_type == SmcType::Glitch || smc_type == SmcType::RJtag ||
                                       smc_type == SmcType::RJtagCygnos ||
                                       smc_type == SmcType::CR4 || smc_type == SmcType::SmcPlus ||
                                       smc_type == SmcType::Rgh3V1 || smc_type == SmcType::Rgh3V2 ||
                                       smc_type == SmcType::Rgh13;

            if (build_is_retail && !smc_is_retail) {
                Log::Warn("Build type is retail but SMC appears to be '{}' "
                          "-- pass smcnocheck=true to suppress",
                          smc_type_name(smc_type));
            } else if (build_is_jtag && !smc_is_jtag) {
                Log::Warn("Build type is JTAG but SMC appears to be '{}' "
                          "-- pass smcnocheck=true to suppress",
                          smc_type_name(smc_type));
            } else if (build_is_glitch && !smc_is_glitch) {
                if (smc_is_retail) {
                    Log::Info("Retail SMC detected in {} mode, applying Glitch SMC patch...",
                              describe_build_type(*args.build_type));
                    uint32_t patches_applied = Signature::ApplyPatch(
                        smc.data(), static_cast<uint32_t>(smc.size()), Glitch.addr, Glitch.value);
                    if (patches_applied > 0) {
                        Log::Info("Applied {} Glitch SMC patch match(es)", patches_applied);
                    } else {
                        Log::Warn("Failed to match Glitch SMC patch pattern in retail SMC");
                    }
                } else {
                    Log::Warn("Build type is Glitch but SMC appears to be '{}' "
                              "-- pass smcnocheck=true to suppress",
                              smc_type_name(smc_type));
                }
            }
        } else {
            Log::Warn("SMC checks skipped (smcnocheck)");
        }
    }

    // Keyvault.
    if (args.kv_path) {
        if (auto kv_data = ReadFile(*args.kv_path)) {
            new_nand.keyvault = std::move(*kv_data);
            Log::Info("Loaded keyvault from explicit path '{}'", args.kv_path->string());
        }
    } else if (auto kv_file = load_from_root(fw_dir, "kv.bin")) {
        new_nand.keyvault = std::move(kv_file->second);
        Log::Info("Loaded keyvault from '{}'{}", kv_file->first.string(),
                  donor_nand && donor_nand->keyvault ? " (overriding donor NAND)" : "");
    } else if (new_nand.keyvault) {
        Log::Info("Loaded keyvault from donor NAND");
    }

    if (!new_nand.keyvault) {
        Log::Warn("No keyvault found — build may produce an invalid image");
    }

    if (is_xell_build_type) {
        if (auto xell_file = load_xell_file()) {
            if (!new_nand.xellblock)
                new_nand.xellblock.emplace();
            new_nand.xellblock->xell_main = std::move(xell_file->second);
            Log::Info("Loaded XeLL from '{}'", xell_file->first.string());
        }
    }

    if (args.build_type && *args.build_type == BuildType::Jtag) {
        auto ensure_payloads = [&new_nand]() -> payloads_t& {
            if (!new_nand.payloads)
                new_nand.payloads.emplace();
            return *new_nand.payloads;
        };

        if (auto payload_file = load_payload_file("payload.bin")) {
            ensure_payloads().jtag_payload = std::move(payload_file->second);
            Log::Info("Loaded JTAG payload from '{}'", payload_file->first.string());
        }
        if (auto freeboot_file = load_payload_file("freeboot.bin")) {
            ensure_payloads().jtag_rebooter = std::move(freeboot_file->second);
            Log::Info("Loaded JTAG rebooter from '{}'", freeboot_file->first.string());
        }
        if (auto fuses_file = load_payload_file("fuses.bin")) {
            ensure_payloads().vfuses = std::move(fuses_file->second);
            Log::Info("Loaded JTAG fuses from '{}'", fuses_file->first.string());
        }
    }

    const Ini::Section* sec_sec = build_doc->get("security");
    const Ini::Section* flashfs_sec = build_doc->get("flashfs");
    const Ini::Section* payloads_sec = build_doc->get("payloads");
    (void) payloads_sec;

    auto stfs_file_to_u8 = [&stfs_files, &normalize_file_key](
                               std::string_view name) -> std::optional<std::vector<uint8_t>> {
        if (!stfs_files)
            return std::nullopt;
        const auto it = stfs_files->find(normalize_file_key(std::string{name}));
        if (it == stfs_files->end())
            return std::nullopt;
        std::vector<uint8_t> out;
        out.reserve(it->second.size());
        for (const auto byte : it->second)
            out.push_back(std::to_integer<uint8_t>(byte));
        return out;
    };

    auto ensure_flashfs_files = [&new_nand]() -> flashfs_files_t& {
        if (!new_nand.flashfs_files)
            new_nand.flashfs_files.emplace();
        return *new_nand.flashfs_files;
    };

    auto ensure_flashfs_payloads = [&new_nand]() -> flashfs_payload_map_t& {
        if (!new_nand.flashfs_payloads)
            new_nand.flashfs_payloads.emplace();
        return *new_nand.flashfs_payloads;
    };

    auto ensure_payloads = [&new_nand]() -> payloads_t& {
        if (!new_nand.payloads)
            new_nand.payloads.emplace();
        return *new_nand.payloads;
    };

    auto find_patch_section = [&](PatchSectionTarget target) -> const ParsedPatchSection* {
        if (!parsed_patchset)
            return nullptr;
        const auto it = std::find_if(
            parsed_patchset->sections.begin(), parsed_patchset->sections.end(),
            [target](const ParsedPatchSection& section) { return section.target == target; });
        return it != parsed_patchset->sections.end() ? &*it : nullptr;
    };

    auto has_any_key_bytes = [](const std::array<uint8_t, 16>& key) {
        return std::any_of(key.begin(), key.end(), [](uint8_t byte) { return byte != 0; });
    };

    auto apply_glitch_patch_section = [&](std::vector<uint8_t>& bytes, PatchSectionTarget target,
                                          std::string_view stage_name) -> bool {
        if (opts.noblpatch.value_or(false)) {
            Log::Info("Skipping {} bootloader patching (noblpatch option enabled)", stage_name);
            return true;
        }
        const auto* section = find_patch_section(target);
        if (!section)
            return true;
        if (section->encoding != PatchSectionEncoding::XePatch) {
            Log::Error("Patch section '{}' for {} is not an xePatch section", section->identifier,
                       stage_name);
            return false;
        }

        XePatchSection xe_section;
        xe_section.identifier = section->identifier;
        xe_section.entries = section->entries;

        size_t total_patch_words = 0;
        uint64_t required_end = bytes.size();
        for (const auto& entry : section->entries) {
            total_patch_words += entry.length;
            const uint64_t entry_end =
                static_cast<uint64_t>(entry.address) + static_cast<uint64_t>(entry.length) * 4U;
            required_end = std::max(required_end, entry_end);
        }

        Log::Info("Applying {} patch section '{}' (entries={}, patch_words=0x{:x}, "
                  "patch_bytes=0x{:x}, target_buffer=0x{:x})",
                  stage_name, section->identifier, section->entries.size(), total_patch_words,
                  total_patch_words * sizeof(uint32_t), bytes.size());

        if (required_end > bytes.size()) {
            Log::Info("Extending {} patch target buffer for section '{}' from 0x{:x} to 0x{:x}",
                      stage_name, section->identifier, bytes.size(), required_end);
            bytes.resize(static_cast<size_t>(required_end), 0x00);
        }

        if (!XePatch::ApplyPatchSection(bytes.data(), static_cast<uint32_t>(bytes.size()),
                                        xe_section)) {
            Log::Error("Failed to apply {} patch section '{}' (entries={}, patch_words=0x{:x}, "
                       "patch_bytes=0x{:x}, target_buffer=0x{:x})",
                       stage_name, section->identifier, section->entries.size(), total_patch_words,
                       total_patch_words * sizeof(uint32_t), bytes.size());
            return false;
        }

        if (bytes.size() >= sizeof(bl_header)) {
            uint32_t raw_declared_size = 0;
            std::memcpy(&raw_declared_size, bytes.data() + offsetof(bl_header, size),
                        sizeof(raw_declared_size));
            const uint32_t declared_size = bswap32(raw_declared_size);
            if (declared_size < bytes.size()) {
                const uint32_t updated_size = static_cast<uint32_t>(bytes.size());
                raw_declared_size = bswap32(updated_size);
                std::memcpy(bytes.data() + offsetof(bl_header, size), &raw_declared_size,
                            sizeof(raw_declared_size));
                Log::Info("Updated {} serialized size field after patching from 0x{:x} to 0x{:x}",
                          stage_name, declared_size, updated_size);
            }
        }

        Log::Info("Applied {} patch section '{}'", stage_name, section->identifier);
        return true;
    };

    auto load_security_from_data_or_common =
        [&](std::string_view entry_name) -> std::optional<resolved_file_t> {
        if (auto loaded = load_from_root(fw_dir, entry_name))
            return loaded;
        if (auto loaded = load_from_root(data_dir, entry_name))
            return loaded;
        return load_from_common_dir(entry_name);
    };

    auto load_flashfs_payload_file =
        [&](std::string_view entry_name) -> std::optional<resolved_file_t> {
        if (auto loaded = load_from_root(fw_dir, entry_name))
            return loaded;
        if (auto loaded = load_from_root(data_dir, entry_name))
            return loaded;
        if (auto stfs_file = stfs_file_to_u8(entry_name))
            return resolved_file_t{std::filesystem::path{"<stfs>"}, std::move(*stfs_file)};
        return load_from_common_dir(entry_name);
    };

    if (sec_sec) {
        for (const auto& entry : *sec_sec) {
            const std::string key_lower = normalize_file_key(entry.key);
            std::optional<std::vector<uint8_t>>* target_dest = nullptr;

            if (key_lower == "fcrt.bin") {
                if (opts.nofcrt.value_or(false))
                    continue;
                target_dest = &ensure_flashfs_files().fcrt;
            } else if (key_lower == "crl.bin") {
                target_dest = &ensure_flashfs_files().crl;
            } else if (key_lower == "dae.bin") {
                target_dest = &ensure_flashfs_files().dae;
            } else if (key_lower == "extended.bin") {
                target_dest = &ensure_flashfs_files().extended;
            } else if (key_lower == "secdata.bin") {
                target_dest = &ensure_flashfs_files().secdata;
            } else {
                continue;
            }

            const bool nosecurity = opts.nosecurity.value_or(false);
            const bool nosusecurity = opts.nosusecurity.value_or(false);

            std::optional<std::vector<uint8_t>> donor_file;
            if (donor_nand && donor_nand->flashfs_files) {
                if (key_lower == "fcrt.bin") donor_file = donor_nand->flashfs_files->fcrt;
                else if (key_lower == "crl.bin") donor_file = donor_nand->flashfs_files->crl;
                else if (key_lower == "dae.bin") donor_file = donor_nand->flashfs_files->dae;
                else if (key_lower == "extended.bin") donor_file = donor_nand->flashfs_files->extended;
                else if (key_lower == "secdata.bin") donor_file = donor_nand->flashfs_files->secdata;
            }

            if (nosecurity) {
                if (auto stfs_file = stfs_file_to_u8(key_lower)) {
                    *target_dest = std::move(*stfs_file);
                    Log::Info("Loaded security file '{}' from STFS (nosecurity)", entry.key);
                } else if (auto data_file = load_security_from_data_or_common(entry.key)) {
                    *target_dest = std::move(data_file->second);
                    Log::Info("Loaded security file '{}' from '{}' (nosecurity)", entry.key,
                              data_file->first.string());
                } else {
                    Log::Error("nosecurity: required security file '{}' not found in STFS or data directory",
                               entry.key);
                    return std::nullopt;
                }
            } else if (nosusecurity) {
                if (donor_file && !donor_file->empty()) {
                    *target_dest = std::move(*donor_file);
                    Log::Info("Loaded security file '{}' from donor NAND (nosusecurity)", entry.key);
                } else if (auto data_file = load_security_from_data_or_common(entry.key)) {
                    *target_dest = std::move(data_file->second);
                    Log::Info("Loaded security file '{}' from '{}' (nosusecurity)", entry.key,
                              data_file->first.string());
                } else {
                    Log::Error("nosusecurity: required security file '{}' not found in donor NAND or data directory",
                               entry.key);
                    return std::nullopt;
                }
            } else {
                if (donor_file && !donor_file->empty()) {
                    *target_dest = std::move(*donor_file);
                    Log::Info("Loaded security file '{}' from donor NAND", entry.key);
                } else if (auto stfs_file = stfs_file_to_u8(key_lower)) {
                    *target_dest = std::move(*stfs_file);
                    Log::Info("Loaded security file '{}' from STFS", entry.key);
                } else if (auto data_file = load_security_from_data_or_common(entry.key)) {
                    *target_dest = std::move(data_file->second);
                    Log::Info("Loaded security file '{}' from '{}'", entry.key,
                              data_file->first.string());
                }
            }
        }
    }

    if (flashfs_sec) {
        for (const auto& entry : *flashfs_sec) {
            const auto key_clean = sanitize_file_key(entry.key);
            if (auto flashfs_file = load_flashfs_payload_file(entry.key))
                ensure_flashfs_payloads()[key_clean] = std::move(flashfs_file->second);
        }
    }

    std::array<uint8_t, 16> cb_key{};
    std::array<uint8_t, 16> cb_b_key{};
    std::array<uint8_t, 16> cd_key{};
    std::optional<bl2_header> cb_a_header;
    bool ini_cf_slot0_filled = false;
    bool ini_cg_slot0_filled = false;

    const Ini::Section* main_sec = build_doc->get(section_name);
    if (main_sec) {
        for (const auto& entry : *main_sec) {
            std::string key_lower = entry.key;
            std::transform(key_lower.begin(), key_lower.end(), key_lower.begin(), ::tolower);

            if (key_lower == "none")
                continue;

            auto resolved_stage = load_stage_or_xboxupd(entry.key);
            if (!resolved_stage) {
                Log::Warn("Stage file '{}' not found in fw/data/common directories", entry.key);
                continue;
            }

            auto& [stage_path, stage_data] = *resolved_stage;

            try {
                if (key_lower.starts_with("cba") || key_lower.starts_with("cb_a") ||
                    key_lower.starts_with("cb_") || key_lower.starts_with("sb_") ||
                    key_lower == "cb" || key_lower == "2bl" || key_lower == "sb") {
                    auto cb = BootloaderCb::parse(stage_data);
                    if (!cb.is_decrypted() && bl_key_bytes.size() == 16)
                        cb.decrypt(bl_key_bytes.data());
                    auto cb_bytes = cb.serialize();
                    if (cb.is_decrypted()) {
                        cb_a_header = cb.header;
                        if (!cb.derived_key && bl_key_bytes.size() == 16 &&
                            cb_bytes.size() >= 0x20) {
                            uint8_t digest[20];
                            ExCryptHmacSha(bl_key_bytes.data(), 16, cb_bytes.data() + 0x10, 0x10,
                                           nullptr, 0, nullptr, 0, digest, 20);
                            std::array<uint8_t, 16> k;
                            std::memcpy(k.data(), digest, 16);
                            cb.derived_key = k;
                        }
                        if (cb.derived_key)
                            cb_key = *cb.derived_key;
                        if (!apply_glitch_patch_section(cb_bytes, PatchSectionTarget::Cb, "CB"))
                            return std::nullopt;
                        new_nand.cb_or_A = cb_bytes;
                        Log::Info("CB '{}' parsed and decrypted successfully (v{})", entry.key,
                                  cb.header.header.version);
                    } else {
                        new_nand.cb_or_A = std::move(stage_data);
                        Log::Warn("CB '{}' parsed but is not decrypted", entry.key);
                    }
                } else if (key_lower.starts_with("cbx")) {
                    auto cbx = BootloaderCb::parse(stage_data);
                    if (!cbx.is_decrypted() && bl_key_bytes.size() == 16)
                        cbx.decrypt(bl_key_bytes.data());
                    if (cbx.is_decrypted()) {
                        new_nand.cb_X = cbx.serialize();
                        Log::Info("CBX '{}' parsed and decrypted successfully (v{})", entry.key,
                                  cbx.header.header.version);
                    } else {
                        new_nand.cb_X = std::move(stage_data);
                        Log::Warn("CBX '{}' parsed but is not decrypted", entry.key);
                    }
                } else if (key_lower.starts_with("cbb") || key_lower.starts_with("cb_b")) {
                    auto cbb = BootloaderCb::parse(stage_data);
                    if (!cbb.is_decrypted() && has_any_key_bytes(cb_key) &&
                        cpu_key_bytes.size() == 16) {
                        cbb.decrypt_v1(cb_key.data(), cpu_key_bytes.data());
                        if (!cbb.is_decrypted() && cb_a_header)
                            cbb.decrypt_v2(*cb_a_header, cb_key.data(), cpu_key_bytes.data());
                    }
                    auto cbb_bytes = cbb.serialize();
                    if (cbb.is_decrypted()) {
                        if (!cbb.derived_key && has_any_key_bytes(cb_key) &&
                            cpu_key_bytes.size() == 16 && cbb_bytes.size() >= 0x20) {
                            uint8_t digest[20];
                            ExCryptHmacSha(cb_key.data(), 16, cbb_bytes.data() + 0x10, 16,
                                           cpu_key_bytes.data(), 16, nullptr, 0, digest, 20);
                            std::array<uint8_t, 16> k;
                            std::memcpy(k.data(), digest, 16);
                            cbb.derived_key = k;
                        }
                        if (cbb.derived_key)
                            cb_b_key = *cbb.derived_key;
                        if (!apply_glitch_patch_section(cbb_bytes, PatchSectionTarget::Cbb, "CB_B"))
                            return std::nullopt;
                        new_nand.cb_B = cbb_bytes;
                        Log::Info("CBB '{}' parsed and decrypted successfully (v{})", entry.key,
                                  cbb.header.header.version);
                    } else {
                        new_nand.cb_B = std::move(stage_data);
                        Log::Warn("CBB '{}' parsed but is not decrypted", entry.key);
                    }
                } else if (key_lower.starts_with("sc") || key_lower == "3bl") {
                    auto sc = BootloaderSc::parse(stage_data);
                    const uint8_t* active_cb_key =
                        has_any_key_bytes(cb_b_key)
                            ? cb_b_key.data()
                            : (has_any_key_bytes(cb_key) ? cb_key.data() : nullptr);
                    if (!sc.is_decrypted() && active_cb_key)
                        sc.decrypt(active_cb_key);
                    if (sc.is_decrypted()) {
                        new_nand.sc = sc.serialize();
                        Log::Info("SC '{}' parsed and decrypted successfully (v{})", entry.key,
                                  sc.header.header.version);
                    } else {
                        new_nand.sc = std::move(stage_data);
                        Log::Info("SC '{}' parsed successfully (v{})", entry.key,
                                  sc.header.header.version);
                    }
                } else if (key_lower.starts_with("cd") || key_lower == "4bl") {
                    auto cd = BootloaderCd::parse(stage_data);
                    const uint8_t* active_cb_key =
                        has_any_key_bytes(cb_b_key)
                            ? cb_b_key.data()
                            : (has_any_key_bytes(cb_key) ? cb_key.data() : nullptr);
                    if (!cd.is_decrypted() && active_cb_key)
                        cd.decrypt(active_cb_key);
                    auto cd_bytes = cd.serialize();
                    if (cd.is_decrypted()) {
                        if (active_cb_key && cd_bytes.size() >= 0x20) {
                            uint8_t digest[20];
                            ExCryptHmacSha(active_cb_key, 16, cd_bytes.data() + 0x10, 0x10, nullptr,
                                           0, nullptr, 0, digest, 20);
                            std::memcpy(cd_key.data(), digest, 16);
                        }
                        if (!apply_glitch_patch_section(cd_bytes, PatchSectionTarget::Cd, "CD"))
                            return std::nullopt;
                        new_nand.cd = cd_bytes;
                        Log::Info("CD '{}' parsed, patched, and decrypted successfully (v{})",
                                  entry.key, cd.header.header.version);
                    } else {
                        new_nand.cd = std::move(stage_data);
                        Log::Warn("CD '{}' parsed but is not decrypted", entry.key);
                    }
                } else if (key_lower.starts_with("ce") || key_lower == "5bl") {
                    auto ce = BootloaderCe::parse(stage_data);
                    if (!ce.is_decrypted() && has_any_key_bytes(cd_key))
                        ce.decrypt(cd_key.data());
                    if (ce.is_decrypted()) {
                        new_nand.ce = ce.serialize();
                        Log::Info("CE '{}' parsed and decrypted successfully (v{})", entry.key,
                                  ce.header.header.version);
                    } else {
                        new_nand.ce = std::move(stage_data);
                        Log::Info("CE '{}' parsed successfully (v{})", entry.key,
                                  ce.header.header.version);
                    }
                } else if (key_lower.starts_with("cf") || key_lower == "6bl") {
                    auto cf = BootloaderCf::parse(stage_data);
                    if (!cf.is_decrypted() && bl_key_bytes.size() == 16)
                        cf.decrypt(bl_key_bytes.data());
                    bool is_slot1 = ini_cf_slot0_filled;
                    ini_cf_slot0_filled = true;
                    auto& slot = is_slot1 ? new_nand.patchslot_1 : new_nand.patchslot_0;
                    if (!slot)
                        slot.emplace();
                    if (cf.is_decrypted()) {
                        slot->cf = cf.serialize();
                        Log::Info("CF ({}) '{}' parsed and decrypted successfully (v{})",
                                  is_slot1 ? "slot 1" : "slot 0", entry.key,
                                  cf.header.header.version);
                    } else {
                        slot->cf = std::move(stage_data);
                        Log::Info("CF ({}) '{}' parsed successfully (v{})",
                                  is_slot1 ? "slot 1" : "slot 0", entry.key,
                                  cf.header.header.version);
                    }
                } else if (key_lower.starts_with("cg") || key_lower == "7bl") {
                    auto cg = BootloaderCg::parse(stage_data);
                    std::array<uint8_t, 16> cg_hmac{};
                    bool has_cg_hmac = false;
                    bool is_slot1 = ini_cg_slot0_filled;
                    ini_cg_slot0_filled = true;
                    auto& slot = is_slot1 ? new_nand.patchslot_1 : new_nand.patchslot_0;
                    if (slot && slot->cf) {
                        auto parsed_cf = BootloaderCf::parse(*slot->cf);
                        std::memcpy(cg_hmac.data(), parsed_cf.header.cg_key, 16);
                        has_cg_hmac = true;
                    }
                    if (cg.is_decrypted() && has_cg_hmac)
                        cg.encrypt(cg_hmac.data());
                    if (!slot)
                        slot.emplace();
                    slot->cg = cg.serialize();
                    Log::Info("CG ({}) '{}' parsed successfully (v{}, 0x{:x} bytes)",
                              is_slot1 ? "slot 1" : "slot 0", entry.key, cg.header.header.version,
                              slot->cg->size());
                } else {
                    Log::Trace("Ignoring unhandled bootloader stage '{}'", entry.key);
                }
            } catch (const std::exception& ex) {
                Log::Error("Stage '{}' parse failed: {}", entry.key, ex.what());
            }
        }
    } else if (!section_name.empty()) {
        Log::Warn("Section '{}' not found in build INI", section_name);
    }

    if (parsed_patchset) {
        if (parsed_patchset->kind == PatchSetKind::Glitch) {
            if (const auto* khv_section = find_patch_section(PatchSectionTarget::Khv)) {
                ensure_payloads().addon_patches = khv_section->raw_data;
                Log::Info("Assigned merged glitch payloads from '{}' ({} bytes)",
                          khv_section->identifier, khv_section->raw_data.size());
            }
        } else if (parsed_patchset->kind == PatchSetKind::Jtag) {
            auto serialized_patchset = BinaryParser::SerializePatchSet(*parsed_patchset);
            ensure_payloads().addon_patches = std::move(serialized_patchset);
            Log::Info("Assigned merged JTAG patch payloads ({} bytes)",
                      ensure_payloads().addon_patches->size());
        }
    }

    if (!args.build_type) {
        Log::Error("Build type is required for image serialization");
        return std::nullopt;
    }
    if (!args.console) {
        Log::Error("Console type is required for image serialization");
        return std::nullopt;
    }

    Log::Info("Build preparation complete: donor={}, smc={}, kv={}, cb={}, cbx={}, cbb={}, "
              "sc={}, cd={}, ce={}, patchslot0={}, patchslot1={}, payloads={}, xell={}, "
              "flashfs_files={}, flashfs_payloads={}",
              donor_nand.has_value() ? "yes" : "no", new_nand.smc ? "yes" : "no",
              new_nand.keyvault ? "yes" : "no", new_nand.cb_or_A ? "yes" : "no",
              new_nand.cb_X ? "yes" : "no", new_nand.cb_B ? "yes" : "no",
              new_nand.sc ? "yes" : "no", new_nand.cd ? "yes" : "no", new_nand.ce ? "yes" : "no",
              new_nand.patchslot_0 ? "yes" : "no", new_nand.patchslot_1 ? "yes" : "no",
              new_nand.payloads ? "yes" : "no",
              (new_nand.xellblock && new_nand.xellblock->xell_main) ? "yes" : "no",
              new_nand.flashfs_files ? "yes" : "no", new_nand.flashfs_payloads ? "yes" : "no");

    const bool nomobile = opts.nomobile.value_or(false);
    auto built_image = build(new_nand, *args.build_type, args.console, nomobile, cpu_key_bytes);
    if (!built_image) {
        Log::Error("Failed to build NAND image");
        return std::nullopt;
    }

    return built_image;
}
