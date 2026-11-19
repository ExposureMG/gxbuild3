#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

enum class BuildType {
    Retail,
    Jtag,
    Glitch,
    Glitch2,
    Glitch2m,
    Glitch3,
    Devkit,
};

enum class ConsoleType {
    Xenon,
    Zephyr,
    Falcon,
    Jasper,
    Jasper256,
    Jasper512,
    JasperBB,
    JasperBigFFS,
    Trinity,
    TrinityBB,
    TrinityBigFFS,
    Corona,
    Corona4G,
    Winchester,
    Winchester4G,
};

inline const std::map<std::string, BuildType> kBuildTypeMap = {
    {"retail", BuildType::Retail},     {"jtag", BuildType::Jtag},
    {"glitch", BuildType::Glitch},     {"glitch2", BuildType::Glitch2},
    {"glitch2m", BuildType::Glitch2m}, {"glitch3", BuildType::Glitch3},
    {"devkit", BuildType::Devkit},
};

inline const std::map<std::string, ConsoleType> kConsoleTypeMap = {
    {"xenon", ConsoleType::Xenon},
    {"zephyr", ConsoleType::Zephyr},
    {"falcon", ConsoleType::Falcon},
    {"jasper", ConsoleType::Jasper},
    {"jasper256", ConsoleType::Jasper256},
    {"jasper512", ConsoleType::Jasper512},
    {"jasperbb", ConsoleType::JasperBB},
    {"jasperbigffs", ConsoleType::JasperBigFFS},
    {"trinity", ConsoleType::Trinity},
    {"trinitybb", ConsoleType::TrinityBB},
    {"trinitybigffs", ConsoleType::TrinityBigFFS},
    {"corona", ConsoleType::Corona},
    {"corona4g", ConsoleType::Corona4G},
    {"winchester", ConsoleType::Winchester},
    {"winchester4g", ConsoleType::Winchester4G},
};

struct GxArgs {
    std::string mode;
    std::optional<BuildType> build_type;
    std::optional<ConsoleType> console;
    std::optional<std::string> cpu_key;
    std::optional<std::string> bl_key;
    std::optional<std::filesystem::path> data_dir;
    std::optional<std::filesystem::path> common_dir;
    std::optional<std::filesystem::path> fw_dir;
    std::optional<std::filesystem::path> sha_file;
    std::optional<std::filesystem::path> source_nand;
    std::optional<std::filesystem::path> stfs_package;
    std::optional<std::filesystem::path> ecc;
    std::optional<std::filesystem::path> xboxupd;
    std::optional<std::filesystem::path> output_dir;
    std::optional<std::filesystem::path> output;
    std::optional<std::string> ini_ext;
    std::optional<std::string> bl_ext;
    std::optional<std::string> preset;
    std::optional<std::string> cmd;
    std::optional<std::string> format;
    std::vector<std::pair<std::string, std::string>> options;
    std::vector<std::string> addons;
    std::vector<std::string> raw_patches;
    bool xsb{false};
    bool full_image{false};
    bool bigblock{false};
    bool verbose{false};
    bool extract_all{false};
    bool stfs_split_xboxupd{false};
    bool license{false};
    // ---- Library-facing extensions ----
    // Inline INI content. When set RunBuild skips loading from disk.
    std::optional<std::string> ini_content;
    // Inline source NAND bytes (alternative to source_nand path).
    std::optional<std::vector<uint8_t>> source_nand_bytes;
    // Explicit file overrides (used by the library; CLI discovers these automatically).
    std::optional<std::filesystem::path> kv_path;
    std::optional<std::filesystem::path> smc_path;
    std::optional<std::filesystem::path> smc_config_path;
};

struct OptionsArgs {
    // Identity / keys
    std::optional<std::string> type;
    std::optional<std::string> rev;
    std::optional<std::string> key_1bl;
    std::optional<std::string> cpukey;
    std::optional<std::string> cfldv;
    std::optional<std::string> dvdkey;

    // Common boot behavior
    std::optional<std::string> xellbutton;
    std::optional<std::string> xellbutton2;
    std::vector<std::string> addons;

    // JTAG / glitch toggles
    std::optional<bool> cygnos;
    std::optional<bool> demon;
    std::optional<bool> olddvd;
    std::optional<bool> nodvd;
    std::optional<std::string> dualboot;

    // General builder behavior
    std::optional<bool> nomobile;
    std::optional<bool> nofcrt;
    std::optional<bool> noremap;
    std::optional<bool> noecdremap;
    std::optional<bool> nandmu;
    std::optional<bool> nosecurity;
    std::optional<bool> nosusecurity;
    std::optional<bool> smcnocheck;
    std::optional<bool> noblpatch;

    // SMC config overrides
    std::optional<std::string> cputemp;
    std::optional<std::string> gputemp;
    std::optional<std::string> edramtemp;
    std::optional<std::string> overcputemp;
    std::optional<std::string> overgputemp;
    std::optional<std::string> overedramtemp;
    std::optional<std::string> cpufan;
    std::optional<std::string> gpufan;

    // KV / config overrides
    std::optional<std::string> avregion;
    std::optional<std::string> gameregion;
    std::optional<std::string> dvdregion;
    std::optional<std::string> macid;
};
