#include "Args.hpp"
#include "BuildRunner.hpp"
#include "ini/IniParser.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/Keyvault.hpp"
#include "utils/FileManager.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <argparse/argparse.hpp>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {
    Log::Init();

    argparse::ArgumentParser program("gxbuild", "3.2.0");

    program.add_argument("-l", "--image")
        .help("Input image (NAND/ECC/STFS)");

    program.add_argument("-p", "--cpukey")
        .help("Unique CPU Key");

    program.add_argument("-b", "--1blkey")
        .help("1BL Key override");

    program.add_argument("-f", "--firmware")
        .default_value(std::string("17559"))
        .help("Path to firmware dir or dash version");

    program.add_argument("-d", "--data")
        .default_value(std::string("mydata"))
        .help("Path to data dir");

    program.add_argument("--common")
        .default_value(std::string("common"))
        .help("Path to common dir");

    program.add_argument("-t", "--type")
        .default_value(std::string("retail"))
        .help("Image type");

    program.add_argument("-i", "--iniext")
        .help("Image type extension");

    program.add_argument("-c", "--console")
        .default_value(std::string("jasper"))
        .help("Console type");

    program.add_argument("-r", "--blext")
        .help("INI section extension");

    program.add_argument("-o", "--option")
        .help("List of options")
        .append();

    program.add_argument("-a", "--addon")
        .help("List of addon patches")
        .append();

    program.add_argument("-8", "--rawpatch")
        .help("Raw patch")
        .append();

    program.add_argument("-u", "--output")
        .default_value(std::string("updflash.bin"))
        .help("Output NAND file path");

    program.add_argument("-g", "--output-dir")
        .help("Output directory");

    program.add_argument("-V", "--verbose")
        .flag()
        .help("Enable verbose logging");

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        Log::Critical("Command line argument error: {}", err.what());
        std::cerr << program;
        return 1;
    }

    if (program.get<bool>("--verbose")) {
        Log::SetVerbose(true);
        Log::Debug("Verbose logging enabled");
    }

    OptionsManager options_mgr;
    if (std::filesystem::exists("options.ini")) {
        Log::Debug("Loading options from options.ini");
        options_mgr.parse_file("options.ini");
    }

    if (auto raw_options = program.present<std::vector<std::string>>("-o")) {
        Log::Debug("Parsing {} command-line options", raw_options->size());
        options_mgr.parse(*raw_options);
    }

    std::vector<uint8_t> cpu_key_bytes;
    if (auto cpukey_str = program.present<std::string>("-p")) {
        auto res = validate_cpu_key_hex(*cpukey_str);
        if (res.status == CpuKeyStatus::Valid) {
            cpu_key_bytes = std::move(res.key);
            Log::Debug("CPU key validated successfully");
        } else if (res.status == CpuKeyStatus::Corrected) {
            cpu_key_bytes = std::move(res.key);
            Log::Warn("{}", res.message);
        } else {
            Log::Error("Invalid CPU key: {}", res.message);
            return 1;
        }
    }

    std::optional<std::filesystem::path> nand_path;
    if (auto img_arg = program.present<std::string>("-l")) {
        nand_path = *img_arg;
    } else {
        std::filesystem::path data_dir = program.get<std::string>("-d");
        static const std::vector<std::string> kCandidates = {
            "nanddump.bin", "nanddump1.bin", "nanddump2.bin", "nand.bin", "dump.bin"};
        for (const auto& candidate : kCandidates) {
            if (std::filesystem::exists(data_dir / candidate)) {
                nand_path = data_dir / candidate;
                break;
            }
            if (std::filesystem::exists(candidate)) {
                nand_path = candidate;
                break;
            }
        }
    }

    InputMetadata metadata{};
    if (nand_path && std::filesystem::exists(*nand_path)) {
        Log::Info("Reading NAND image from '{}'", nand_path->string());
        auto nand_data = Utils::read_file(*nand_path);
        if (!nand_data) {
            Log::Error("Failed to read NAND image from '{}'", nand_path->string());
            return 1;
        }

        auto extracted = ExtractMetadata(*nand_data, cpu_key_bytes);
        if (!extracted) {
            Log::Error("Failed to extract metadata from NAND image");
            return 1;
        }
        metadata = std::move(*extracted);
        Log::Debug("Extracted metadata from NAND image successfully");
    } else {
        metadata.cpu_key = cpu_key_bytes;
        if (auto cbldv_opt = options_mgr.get_string("cbldv")) {
            metadata.cb_ldv = static_cast<uint8_t>(std::strtoul(cbldv_opt->c_str(), nullptr, 0));
        }
        if (auto cfldv_opt = options_mgr.get_string("cfldv")) {
            metadata.cf_ldv = static_cast<uint8_t>(std::strtoul(cfldv_opt->c_str(), nullptr, 0));
        }
        if (auto pd_opt = options_mgr.get_string("pairing_data")) {
            auto pd_bytes = Utils::hex_string_to_bytes(*pd_opt);
            if (pd_bytes.size() >= 3) {
                std::copy_n(pd_bytes.begin(), 3, metadata.pairing_data);
            }
        }
    }

    std::string version = program.get<std::string>("-f");
    std::string type = program.get<std::string>("-t");
    if (auto iniext = program.present<std::string>("-i")) {
        type += "_" + *iniext;
    }

    std::string section = program.get<std::string>("-c");
    if (auto blext = program.present<std::string>("-r")) {
        section += "_" + *blext;
    }

    std::filesystem::path fw_dir = program.get<std::string>("-d");

    Log::Info("Loading files for version='{}', type='{}', section='{}'...", version, type, section);
    auto ini_files = FileManager::ReadIniFiles(version, type, section, fw_dir);
    if (!ini_files) {
        Log::Error("Failed to locate or parse INI configuration for '_{}.ini' (section '[{}]')", type, section);
        return 1;
    }

    Input input{};
    input.metadata = std::move(metadata);
    input.bootloaders = std::move(ini_files->bootloaders);
    input.flashfs_sec = std::move(ini_files->flashfs_sec);

    std::string console_lower = section;
    std::transform(console_lower.begin(), console_lower.end(), console_lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (console_lower.find("corona") != std::string::npos &&
        (console_lower.find("4g") != std::string::npos || options_mgr.get_bool("nandmu").value_or(false))) {
        input.overrides.ksb_image = true;
        Log::Debug("Console target override: eMMC/KSB layout");
    } else if (console_lower.find("jasper") != std::string::npos || console_lower.find("trinity") != std::string::npos) {
        input.overrides.psb_image = true;
        Log::Debug("Console target override: NewSmall/PSB layout");
    } else {
        input.overrides.xsb_image = true;
        Log::Debug("Console target override: Small/XSB layout");
    }

    Log::Info("Running NAND builder...");
    auto built_image = RunBuild(input);
    if (!built_image) {
        Log::Error("Build failed");
        return 1;
    }

    std::filesystem::path out_path = program.get<std::string>("-u");
    if (auto out_dir = program.present<std::string>("-g")) {
        std::filesystem::create_directories(*out_dir);
        if (out_path.is_relative()) {
            out_path = std::filesystem::path(*out_dir) / out_path;
        }
    }

    if (out_path.has_parent_path()) {
        std::filesystem::create_directories(out_path.parent_path());
    }

    if (!Utils::write_file(out_path, *built_image)) {
        Log::Error("Failed to write output image to '{}'", out_path.string());
        return 1;
    }

    Log::Info("Successfully built NAND image '{}' ({} bytes)", out_path.string(), built_image->size());
    return 0;
}