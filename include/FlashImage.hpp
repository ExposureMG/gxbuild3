#pragma once
#include "bootloaders/2bl.hpp"
#include "bootloaders/3bl.hpp"
#include "bootloaders/4bl.hpp"
#include "bootloaders/5bl.hpp"
#include "bootloaders/6bl.hpp"
#include "bootloaders/7bl.hpp"
#include "bootloaders/Common.hpp"
#include "bootloaders/FlashFileSystem.hpp"
#include "utils/FlashBlockDriver.hpp"
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

enum class BuildType;
enum class ConsoleType;

// NAND Header structure based on NANDFS.md
// Note: This appears to start with a bl_header (magic, version, pairing, flags, entrypoint, size)
// followed by NAND-specific fields
typedef struct _raw_nand_header {
    uint16_t magic;             // 0x00
    uint16_t version;           // 0x02
    uint16_t pairing;           // 0x04
    uint16_t flags;             // 0x06
    uint32_t entrypoint;         // 0x08
    uint32_t size;              // 0x0C
    uint8_t reserved_0x10[0x50 - 0x10]; // 0x10-0x4F (40 bytes)
    uint32_t payload_indicator;  // 0x50
    uint8_t reserved_0x54[0x60 - 0x54]; // 0x54-0x5F (12 bytes)
    uint32_t kv_size;            // 0x60
    uint32_t cf1_offset;         // 0x64
    uint16_t patch_slots;        // 0x68
    uint16_t kv_version;         // 0x6A
    uint32_t kv_offset;          // 0x6C
    uint32_t fs_offset;          // 0x70 (FlashFS offset)
    uint32_t smc_config_offset;  // 0x74
    uint32_t smc_size;           // 0x78
    uint32_t smc_offset;         // 0x7C
} raw_nand_header_t;

typedef struct BlResults {
    uint32_t offset;
    uint16_t version;
    uint32_t size;
    uint32_t magic;
} bl_results_t;

typedef struct MobileResult {
    uint8_t block_type;
    uint32_t data_sequence;
    uint32_t start_page;
    uint32_t page_count;
    uint32_t data_length;
} mobile_result_t;

typedef struct MobileResults {
    std::optional<mobile_result_t> x31;
    std::optional<mobile_result_t> x32;
    std::optional<mobile_result_t> x33;
    std::optional<mobile_result_t> x34;
    std::optional<mobile_result_t> x35;
    std::optional<mobile_result_t> x36;
    std::optional<mobile_result_t> x37;
    std::optional<mobile_result_t> x38;
    std::optional<mobile_result_t> x39;
} mobile_results_t;

typedef struct NandResults {
    bool valid;
    bl_results_t cb_or_a;
    std::optional<bl_results_t> cbx;
    std::optional<bl_results_t> cbb;
    std::optional<bl_results_t> sc;
    std::optional<bl_results_t> cd;
    std::optional<bl_results_t> ce;
    // patchslots
    std::optional<bl_results_t> cf0;
    std::optional<bl_results_t> cg0;
    std::optional<bl_results_t> cf1;
    std::optional<bl_results_t> cg1;
    uint32_t kv_offset;
    uint32_t kv_size;
    uint32_t kv_version;
    uint32_t smc_size;
    uint32_t smc_offset;
    uint32_t smc_config_offset;
    uint32_t fs_offset;
    std::optional<uint16_t> fs_block_idx;
    std::optional<mobile_results_t> mobile_results;
    uint32_t payload_indicator;
    uint16_t patch_slots;
} nand_results_t;

typedef struct _patchslot_t {
    std::optional<std::vector<uint8_t>> cf;
    std::optional<std::vector<uint8_t>> cg;
} patchslot_t;

typedef struct _xellblock_t {
    std::optional<std::vector<uint8_t>> xell_main;
    std::optional<std::vector<uint8_t>> xell_backup;
} xellblock_t;

typedef struct _payloads_t {
    std::optional<std::vector<uint8_t>> addon_patches;
    std::optional<std::vector<uint8_t>> jtag_rebooter;
    std::optional<std::vector<uint8_t>> jtag_payload;
    std::optional<std::vector<uint8_t>> vfuses;
} payloads_t;

typedef struct MobileData {
    std::optional<std::vector<uint8_t>> x31;
    std::optional<std::vector<uint8_t>> x32;
    std::optional<std::vector<uint8_t>> x33;
    std::optional<std::vector<uint8_t>> x34;
    std::optional<std::vector<uint8_t>> x35;
    std::optional<std::vector<uint8_t>> x36;
    std::optional<std::vector<uint8_t>> x37;
    std::optional<std::vector<uint8_t>> x38;
    std::optional<std::vector<uint8_t>> x39;
} mobile_data_t;

typedef struct _flashfs_files_t {
    std::optional<std::vector<uint8_t>> crl;
    std::optional<std::vector<uint8_t>> dae;
    std::optional<std::vector<uint8_t>> extended;
    std::optional<std::vector<uint8_t>> fcrt;
    std::optional<std::vector<uint8_t>> secdata;
} flashfs_files_t;

struct flashfs_payload_map_t {
    std::vector<std::pair<std::string, std::vector<uint8_t>>> entries;

    static bool iequals(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i]))) {
                return false;
            }
        }
        return true;
    }

    std::vector<uint8_t>& operator[](const std::string& key) {
        for (auto& [k, v] : entries) {
            if (iequals(k, key)) {
                return v;
            }
        }
        entries.emplace_back(key, std::vector<uint8_t>{});
        return entries.back().second;
    }

    bool contains(std::string_view key) const {
        for (const auto& [k, v] : entries) {
            if (iequals(k, key)) {
                return true;
            }
        }
        return false;
    }

    auto find(std::string_view key) {
        return std::find_if(entries.begin(), entries.end(), [&](const auto& p) {
            return iequals(p.first, key);
        });
    }

    auto find(std::string_view key) const {
        return std::find_if(entries.cbegin(), entries.cend(), [&](const auto& p) {
            return iequals(p.first, key);
        });
    }

    auto begin() { return entries.begin(); }
    auto end() { return entries.end(); }
    auto begin() const { return entries.begin(); }
    auto end() const { return entries.end(); }
    auto cbegin() const { return entries.cbegin(); }
    auto cend() const { return entries.cend(); }

    size_t size() const { return entries.size(); }
    bool empty() const { return entries.empty(); }
    void clear() { entries.clear(); }
};

struct FlashImage {
    gxbuild3::utils::FlashBlockDriver driver;
    raw_nand_header_t header{};
    std::optional<nand_results_t> nand_results;
    std::optional<std::vector<uint8_t>> cb_or_A;
    std::optional<std::vector<uint8_t>> cb_X;
    std::optional<std::vector<uint8_t>> cb_B;
    std::optional<std::vector<uint8_t>> sc;
    std::optional<std::vector<uint8_t>> cd;
    std::optional<std::vector<uint8_t>> ce;
    std::optional<patchslot_t> patchslot_0;
    std::optional<patchslot_t> patchslot_1;
    std::optional<std::vector<uint8_t>> smc;
    std::optional<std::vector<uint8_t>> xconfig;
    std::optional<std::vector<uint8_t>> keyvault;

    std::optional<xellblock_t> xellblock;
    std::optional<payloads_t> payloads;
    
    std::optional<mobile_data_t> mobile_data;
    std::optional<gxbuild3::bootloaders::FlashFileSystem> filesystem;
    std::optional<flashfs_files_t> flashfs_files;
    std::optional<flashfs_payload_map_t> flashfs_payloads;
    std::optional<gxbuild3::bootloaders::XeCoronaFsData> corona_fs_data;

    static FlashImage parse(std::vector<uint8_t> data);
};

typedef FlashImage flash_image_t;

typedef struct FlashImageMetadata {
    std::optional<std::vector<uint8_t>> cpu_key;
    std::optional<uint8_t> cbldv;
    std::optional<uint8_t> cfldv;
    std::optional<std::vector<uint8_t>> pairingdata;
} flash_image_metadata_t;

typedef struct BuildLayout {
    std::optional<uint32_t> smc_offset;
    std::optional<uint32_t> smc_config_offset;
    std::optional<uint32_t> kv_offset;
    std::optional<uint32_t> bootloader_chain_offset;
    std::optional<uint32_t> payload_offset;
    std::optional<uint32_t> payload_region_size;
    std::optional<uint32_t> freeboot_offset;
    std::optional<uint32_t> freeboot_region_size;
    std::optional<uint32_t> patches_offset;
    std::optional<uint32_t> patches_region_size;
    std::optional<uint32_t> fuses_offset;
    std::optional<uint32_t> fuses_region_size;
    std::optional<uint32_t> xell_offset;
    std::optional<uint32_t> xell_region_size;
    std::optional<uint32_t> patchslot_base;
    std::optional<uint32_t> patchslot_1_base;
    uint32_t patchslot_length{0};
} build_layout_t;

nand_results_t read(const std::vector<uint8_t>& data);

// New function that uses FlashBlockDriver directly
nand_results_t read(const gxbuild3::utils::FlashBlockDriver& driver);

std::optional<gxbuild3::bootloaders::XeCoronaFsData>
read_corona_config_block(const gxbuild3::utils::FlashBlockDriver& driver);

bool write_corona_config_block(gxbuild3::utils::FlashBlockDriver& driver,
                               const gxbuild3::bootloaders::XeCoronaFsData& config);

raw_nand_header_t parse_nand_header(std::span<const uint8_t> raw);

flash_image_t parse(const std::vector<uint8_t>& data);

// bool decrypt_all(const flash_image_t& flash, const std::vector<uint8_t>& cpu_key);

// bool encrypt_all(const flash_image_t& flash, const std::vector<uint8_t>& cpu_key);

bool extract_all(const flash_image_t& flash, const std::filesystem::path& output_dir, const std::vector<uint8_t>& cpu_key_bytes, const std::vector<uint8_t>& bl_key_bytes);

const char* describe_build_type(BuildType build_type);

std::optional<build_layout_t> resolve_build_layout(const flash_image_t& image, BuildType build_type);

std::optional<std::vector<uint8_t>> build(const flash_image_t& image, BuildType build_type,
                                          std::optional<ConsoleType> console_type = std::nullopt,
                                          bool nomobile = false,
                                          std::span<const uint8_t> cpu_key = {});
