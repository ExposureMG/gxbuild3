#include "GxBuild.hpp"

#include "BuildRunner.hpp"
#include "Log.hpp"

#include <algorithm>
#include <cstdint>
#include <string>

namespace GxBuild {

    namespace {

        static std::string BytesToHex(const std::vector<uint8_t>& bytes) {
            static constexpr const char* kHex = "0123456789ABCDEF";
            std::string out;
            out.reserve(bytes.size() * 2);
            for (uint8_t b : bytes) {
                out.push_back(kHex[(b >> 4) & 0xF]);
                out.push_back(kHex[b & 0xF]);
            }
            return out;
        }

    } // namespace

    std::expected<std::vector<uint8_t>, std::string>
    BuildNandFromXeBuildIni(std::string_view ini_string, std::string_view image_type,
                            std::string_view console_model, const BuildOptions& options,
                            const std::function<void(const std::string&)>& /*log_callback*/) {
        GxArgs args{};
        args.mode = "build";

        // INI content is provided inline — RunBuild will skip disk loading.
        args.ini_content = std::string(ini_string);

        // Resolve build type from image_type string.
        {
            std::string bt = std::string(image_type);
            std::transform(bt.begin(), bt.end(), bt.begin(), ::tolower);
            auto it = kBuildTypeMap.find(bt);
            if (it == kBuildTypeMap.end())
                return std::unexpected("Unknown image_type: " + bt);
            args.build_type = it->second;
        }

        // Resolve console type from console_model string.
        {
            std::string cm = std::string(console_model);
            std::transform(cm.begin(), cm.end(), cm.begin(), ::tolower);
            // Strip trailing "bl" suffix if present (e.g. "jasperbl" → "jasper").
            if (cm.size() > 2 && cm.substr(cm.size() - 2) == "bl")
                cm = cm.substr(0, cm.size() - 2);
            auto it = kConsoleTypeMap.find(cm);
            if (it == kConsoleTypeMap.end())
                return std::unexpected("Unknown console_model: " + std::string(console_model));
            args.console = it->second;
        }

        // Directory paths.
        args.fw_dir   = options.fw_dir;
        args.data_dir = options.data_dir;
        args.common_dir = options.common_dir;

        // Source NAND — bytes take priority over path.
        args.source_nand_bytes = options.source_nand_bytes;
        if (!args.source_nand_bytes && options.source_nand_path)
            args.source_nand = options.source_nand_path;

        // Per-file overrides.
        args.kv_path         = options.custom_kv_path;
        args.smc_path        = options.custom_smc_path;
        args.smc_config_path = options.custom_smc_config_path;

        // xboxupd.bin path.
        args.xboxupd = options.xboxupd_path;

        // STFS addon packages: map the first one to stfs_package so RunBuild's
        // auto-discovery picks it up. Additional packages are not yet supported.
        if (!options.addon_stfs_paths.empty())
            args.stfs_package = options.addon_stfs_paths.front();

        // Keys: convert bytes → hex strings for GxArgs.
        if (options.cpu_key)
            args.cpu_key = BytesToHex(*options.cpu_key);
        if (options.bl_key)
            args.bl_key = BytesToHex(*options.bl_key);

        // Options and raw patch lists.
        args.options     = options.options;
        args.raw_patches = options.raw_patches;

        // Run the shared build core.
        auto result = RunBuild(std::move(args));
        if (!result)
            return std::unexpected(
                "RunBuild failed to assemble the target NAND image (check logs)");

        return std::move(*result);
    }

} // namespace GxBuild
