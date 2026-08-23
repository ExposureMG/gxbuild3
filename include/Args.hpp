#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
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
    Trinity,
    Corona,
    Winchester,
};

enum class ImageType {
    SmallBlock,
    NewSmallBlock,
    BigBlock,
    Emmc,
};

inline const std::map<std::string, BuildType>
    kBuildTypeMap = {
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
    {"jasper256", ConsoleType::Jasper},
    {"jasper512", ConsoleType::Jasper},
    {"jasperbb", ConsoleType::Jasper},
    {"jasperbigffs", ConsoleType::Jasper},
    {"trinity", ConsoleType::Trinity},
    {"trinitybb", ConsoleType::Trinity},
    {"trinitybigffs", ConsoleType::Trinity},
    {"corona", ConsoleType::Corona},
    {"corona4g", ConsoleType::Corona},
    {"winchester", ConsoleType::Winchester},
    {"winchester4g", ConsoleType::Winchester},
};

inline const std::map<std::string, ImageType> kImageTypeMap = {
    {"xenon", ImageType::SmallBlock},
    {"xenonbb", ImageType::BigBlock},
    {"xenon4g", ImageType::Emmc},
    {"zephyr", ImageType::SmallBlock},
    {"zephyrbb", ImageType::BigBlock},
    {"zephyr4g", ImageType::Emmc},
    {"falcon", ImageType::SmallBlock},
    {"falconbb", ImageType::BigBlock},
    {"falcon4g", ImageType::Emmc},
    {"jasper", ImageType::NewSmallBlock},
    {"jasperbb", ImageType::BigBlock},
    {"jasper4g", ImageType::Emmc},
    {"trinity", ImageType::NewSmallBlock},
    {"trinitybb", ImageType::BigBlock},
    {"trinity4g", ImageType::Emmc},
    {"corona", ImageType::NewSmallBlock},
    {"coronabb", ImageType::BigBlock},
    {"corona4g", ImageType::Emmc},
    {"winchester", ImageType::NewSmallBlock},
    {"winchesterbb", ImageType::BigBlock},
    {"winchester4g", ImageType::Emmc},
};

struct InputMetadata {
    std::vector<uint8_t> cpu_key;
    std::optional<std::vector<uint8_t>> nand_image;
    std::optional<std::vector<uint8_t>> keyvault;
    std::optional<std::vector<uint8_t>> smc;
    uint8_t cb_ldv;
    std::optional<uint8_t> cf_ldv;
    uint8_t pairing_data[3];
    uint8_t console_type;
    uint8_t console_sequence;
    uint16_t console_sequence_allow;
};

struct BootloaderEntryInfo {
    std::string name;
    uint16_t version{0};
    uint32_t size{0};
    uint16_t flags{0};
    uint32_t entrypoint{0};
    bool present{false};
    bool decrypted{false};
    std::optional<uint8_t> ldv;
    std::optional<std::array<uint8_t, 3>> pairing_data;
};

struct BootloaderChainInfo {
    std::optional<BootloaderEntryInfo> cb_a;
    std::optional<BootloaderEntryInfo> cb_b;
    std::optional<BootloaderEntryInfo> cb_x;
    std::optional<BootloaderEntryInfo> sc;
    std::optional<BootloaderEntryInfo> cd;
    std::optional<BootloaderEntryInfo> ce;
    std::optional<BootloaderEntryInfo> cf_0;
    std::optional<BootloaderEntryInfo> cg_0;
    std::optional<BootloaderEntryInfo> cf_1;
    std::optional<BootloaderEntryInfo> cg_1;

    uint8_t cb_ldv{0};
    std::array<uint8_t, 3> cb_pairing_data{};
    std::optional<uint8_t> cf0_ldv;
    std::optional<std::array<uint8_t, 3>> cf0_pairing_data;
    std::optional<uint8_t> cf1_ldv;
    std::optional<std::array<uint8_t, 3>> cf1_pairing_data;
};

struct SmcSummaryInfo {
    std::string version;
    std::string motherboard_name;
    std::string type_name;
    uint32_t size{0};
    bool present{false};
    bool decrypted{false};
};

struct FlashFsFileInfo {
    std::string filename;
    uint16_t block_number{0};
    uint32_t length{0};
    uint32_t timestamp{0};
};

struct FlashFsSummaryInfo {
    std::vector<FlashFsFileInfo> files;
    bool present{false};
};

struct KeyvaultSummaryInfo {
    std::string serial_number;
    std::string dvd_key;
    std::string console_id_raw;
    std::string console_id_friendly;
    std::string osig;
    std::string mfr_date;
    std::string region_name;
    uint16_t region_raw{0};
    uint8_t kv_type{0};
    bool fcrt_required{false};
    bool present{false};
    bool decrypted{false};
};

struct AllNandInfo {
    uint16_t header_magic{0};
    uint16_t header_version{0};
    uint16_t header_flags{0};
    uint32_t header_size{0};
    std::string copyright;

    BootloaderChainInfo bootloaders;
    SmcSummaryInfo smc;
    FlashFsSummaryInfo flashfs;
    KeyvaultSummaryInfo keyvault;

    std::vector<uint8_t> cpu_key;
    std::optional<std::vector<uint8_t>> raw_keyvault;
};

struct InputBootloaders {
    std::vector<uint8_t> cb_or_a;
    std::optional<std::vector<uint8_t>> cb_x;
    std::optional<std::vector<uint8_t>> cb_b;
    std::vector<uint8_t> cd;
    std::optional<std::vector<uint8_t>> ce;
    std::optional<std::vector<uint8_t>> cf0;
    std::optional<std::vector<uint8_t>> cg0;
    std::optional<std::vector<uint8_t>> cf1;
    std::optional<std::vector<uint8_t>> cg1;
};

struct InputPayloads {
    std::optional<std::vector<uint8_t>> xell;
    std::optional<std::vector<uint8_t>> rebooter;
    std::optional<std::vector<uint8_t>> fuses;
    std::optional<std::vector<uint8_t>> patches;
    std::optional<std::vector<uint8_t>> payload;
};

struct OverrideMetadata {
    bool xsb_image = false; // old sfc
    bool psb_image = false; // new sfc
    bool ksb_image = false; // emmc
};

struct Input {
    InputMetadata metadata;
    InputBootloaders bootloaders;
    std::optional<InputPayloads> payloads;
    std::optional<std::vector<std::pair<std::string, std::vector<uint8_t>>>> flashfs_sec;
    OverrideMetadata overrides;
};

struct OptionsArgs {
    std::optional<std::string> cbldv;
    std::optional<std::string> pairing_data;
    std::optional<std::string> cfldv;
    

    // JTAG / glitch inputs
    std::optional<std::string> xellbutton;
    std::optional<std::string> xellbutton2;

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

    // KV overrides
    std::optional<std::string> dvdkey;
    std::optional<std::string> avregion;
    std::optional<std::string> gameregion;
    std::optional<std::string> dvdregion;
    std::optional<std::string> macid;
};

class OptionsManager {
public:
    OptionsManager() = default;
    explicit OptionsManager(OptionsArgs args);
    explicit OptionsManager(std::string_view raw_args);

    bool parse(std::string_view raw_args);
    bool parse(const std::vector<std::string>& raw_args_list);
    bool parse_file(const std::filesystem::path& path);
    bool parse_ini(std::string_view content);

    static bool is_known_option(std::string_view name);
    static bool is_bool_option(std::string_view name);
    bool has(std::string_view name) const;

    bool set_bool(std::string_view name, bool value);
    bool set(std::string_view name, std::string_view value);
    bool unset(std::string_view name);

    bool toggle(std::string_view name);

    std::optional<bool> get_bool(std::string_view name) const;
    std::optional<std::string> get_string(std::string_view name) const;
    std::optional<std::string> get(std::string_view name) const;

    const OptionsArgs& data() const noexcept { return m_args; }
    OptionsArgs& data() noexcept { return m_args; }

private:
    OptionsArgs m_args{};
};
