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
    // A development kernel (SB/SC/SD/SE) carrying the glitch2m patches: its patched SD is
    // signed again with the SB private key.
    Devgl,
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

inline const std::map<std::string, BuildType> kBuildTypeMap = {
    {"retail", BuildType::Retail},     {"jtag", BuildType::Jtag},
    {"glitch", BuildType::Glitch},     {"glitch2", BuildType::Glitch2},
    {"glitch2m", BuildType::Glitch2m}, {"glitch3", BuildType::Glitch3},
    {"devkit", BuildType::Devkit},     {"devgl", BuildType::Devgl},
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

// The 16 bytes a stage stores in clear and keys its seal from: +0x10 on CB/SC/CD/CE/CG, the
// header fixpoint at +0x20 on CF.
using BootloaderNonce = std::array<uint8_t, 16>;

// Nonces read from a donor image. RunBuild seals each new boot-chain stage under the donor nonce
// at the same position and every CF and CG it writes under the donor's CF and CG nonce, and
// draws a random nonce for any nonce left empty here.
struct DonorNonces {
    // Boot-chain positions: first CB (SB), second CB (SC), CD (SD), CE (SE).
    std::array<std::optional<BootloaderNonce>, 4> stages;
    // CF and CG nonce of the donor slot stating the largest CF LDV.
    std::optional<BootloaderNonce> cf;
    std::optional<BootloaderNonce> cg;
};

struct InputMetadata {
    std::vector<uint8_t> cpu_key;
    std::optional<std::vector<uint8_t>> nand_image;
    // Canonical keyvault input: authenticated serialized header bytes 0..15 are retained; the
    // body is plaintext at the Input boundary. RunBuild encrypts the body for the output NAND.
    std::optional<std::vector<uint8_t>> keyvault;
    std::optional<std::vector<uint8_t>> smc;
    // Writable CB/CB_B per-box LDV at +0x23, not the display value at +0x3B1.
    uint8_t cb_ldv{0};
    // CF per-box LDV and pairing, taken from the donor slot stating the largest CF LDV. A CF
    // without its own pairing here takes pairing_data.
    std::optional<uint8_t> cf_ldv;
    std::array<uint8_t, 3> pairing_data{};
    std::optional<std::array<uint8_t, 3>> cf_pairing_data;
    uint8_t console_type{0};
    uint8_t console_sequence{0};
    uint16_t console_sequence_allow{0};
    // Empty when there is no donor or its chain does not reach CE.
    std::optional<DonorNonces> donor_nonces;
    // The console's settings block (0x400 bytes whose head checksum holds) and its statistics
    // and manufacturing blocks (0x1000 bytes each; all 0xFF where the console keeps none).
    // They go to the target layout's own offsets, so a donor of another layout keeps them.
    std::optional<std::vector<uint8_t>> smc_config;
    std::optional<std::vector<uint8_t>> statistics;
    std::optional<std::vector<uint8_t>> manufacturing;
    // The console's own crl.bin, dae.bin and secdata.bin, in the form flashfs_sec carries them
    // (secdata.bin in the clear behind its nonce). RunBuild seals the FlashFS's copies of these
    // files with the vector, file key, heads and field these copies carry.
    std::vector<std::pair<std::string, std::vector<uint8_t>>> console_secured_files;
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
    std::optional<ImageType> block_type;

    BootloaderChainInfo bootloaders;
    SmcSummaryInfo smc;
    FlashFsSummaryInfo flashfs;
    KeyvaultSummaryInfo keyvault;

    std::vector<uint8_t> cpu_key;
    std::optional<std::vector<uint8_t>> raw_keyvault;
};

struct InputBootloaders {
    std::vector<uint8_t> cb_or_a;
    // Plaintext CB_X payload, as returned by ExtractAll. Its executable body does
    // not necessarily have the zero signature region used to recognize retail CBs.
    std::optional<std::vector<uint8_t>> cb_x;
    std::optional<std::vector<uint8_t>> cb_b;
    std::optional<std::vector<uint8_t>> sc;
    std::vector<uint8_t> cd;
    std::optional<std::vector<uint8_t>> ce;
    std::optional<std::vector<uint8_t>> cf0;
    std::optional<std::vector<uint8_t>> cg0;
    std::optional<std::vector<uint8_t>> cf1;
    std::optional<std::vector<uint8_t>> cg1;
    // JTAG only: the second CB and second CD listed in the INI are staged into the
    // JTAG payload window as "extra bootloaders"; they are not part of the boot chain.
    std::optional<std::vector<uint8_t>> extra_cb;
    std::optional<std::vector<uint8_t>> extra_cd;
};

struct InputPayloads {
    std::optional<std::vector<uint8_t>> xell;
    std::optional<std::vector<uint8_t>> rebooter;
    std::optional<std::vector<uint8_t>> fuses;
    std::optional<std::vector<uint8_t>> patches;
    std::optional<std::vector<uint8_t>> payload;
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
    // Stages whose automatic patches are skipped: any of cb, cd, khv, joined with '+'.
    std::optional<std::string> nopatch;

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

struct NoPatch {
    bool cb = false;
    bool cd = false;
    bool khv = false;
};

// The stages whose automatic patches are skipped. `noblpatch` is the older spelling of
// `nopatch=cb+cd`.
[[nodiscard]] NoPatch ResolveNoPatch(const OptionsArgs& options);

class OptionsManager {
  public:
    OptionsManager() = default;
    explicit OptionsManager(OptionsArgs args);

    bool parse(std::string_view raw_args);

    static bool is_known_option(std::string_view name);
    static bool is_bool_option(std::string_view name);
    // The header byte for a power-on reason named by xellbutton, xellbutton2 or dualboot
    // (any case): the device in the high nibble, the button in the low one, as xeBuild
    // writes it. Nothing for a name xeBuild does not take.
    static std::optional<uint8_t> power_on_reason(std::string_view name);
    bool has(std::string_view name) const;

    bool set_bool(std::string_view name, bool value);
    bool set(std::string_view name, std::string_view value);

    std::optional<bool> get_bool(std::string_view name) const;
    std::optional<std::string> get_string(std::string_view name) const;

    const OptionsArgs& data() const noexcept { return m_args; }
    OptionsArgs& data() noexcept { return m_args; }

  private:
    OptionsArgs m_args{};
};

struct InputMobileData {
    std::array<std::optional<std::vector<uint8_t>>, 9> slots{};

    std::optional<std::vector<uint8_t>>* slot(uint8_t block_type) noexcept {
        if (block_type < 0x31 || block_type > 0x39) {
            return nullptr;
        }
        return &slots[block_type - 0x31];
    }

    const std::optional<std::vector<uint8_t>>* slot(uint8_t block_type) const noexcept {
        if (block_type < 0x31 || block_type > 0x39) {
            return nullptr;
        }
        return &slots[block_type - 0x31];
    }
};

struct InputPatchFile {
    std::string name;
    std::vector<uint8_t> data;
};

struct InputPatches {
    std::optional<InputPatchFile> automatic;
    std::vector<InputPatchFile> addons;
};

// A release INI [rawpatch] entry: the file's bytes written as they are at a clean image
// offset, after everything else is laid.
struct InputRawPatch {
    std::string name;
    uint32_t offset{0};
    std::vector<uint8_t> data;
};

struct Input {
    BuildType build_type{BuildType::Retail};
    ImageType image_type{ImageType::SmallBlock};
    // The board the image is built for; it selects the NAND header copyright.
    std::optional<ConsoleType> console;
    OptionsArgs options{};
    InputMetadata metadata{};
    InputBootloaders bootloaders{};
    InputMobileData mobiles{};
    std::optional<InputPatches> patches;
    std::optional<InputPayloads> payloads;
    std::optional<std::vector<std::pair<std::string, std::vector<uint8_t>>>> flashfs_sec;
    std::vector<InputRawPatch> raw_patches;
    // The XeCrypt RSA-2048 private key a devgl build signs its patched SD with (SB_priv.bin,
    // 0x390 bytes). Supplied by the user, never logged, and needed by no other build type.
    std::optional<std::vector<uint8_t>> sb_private_key;
};
