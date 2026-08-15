#include "FlashImage.hpp"

#include "Log.hpp"
#include "Utils.hpp"
#include "bootloaders/Common.hpp"
#include "bootloaders/Keyvault.hpp"
#include "bootloaders/SMC.hpp"
#include "bootloaders/BootloaderPacker.hpp"
#include "excrypt.h"
#include "utils/FlashBlockDriver.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>

using namespace gxbuild3::bootloaders;

namespace {

    constexpr uint32_t kGlitchXellRawOffset = 0x70000;
    constexpr uint32_t kXellSlotSize = 0x40000;
    constexpr uint32_t kSyntheticSmcOffset = 0x00001000;
    constexpr uint32_t kSyntheticSmcSize = 0x00003000;
    constexpr uint32_t kSyntheticKvOffset = 0x00004000;
    constexpr uint32_t kSyntheticKvSize = 0x00004000;
    constexpr uint32_t kSyntheticBootloaderChainOffset = 0x00008000;
    // constexpr uint32_t kSyntheticFsRootBlockDistanceFromReserve = 0x54;
    constexpr uint32_t kSyntheticHeaderVersion = 0x00000760;
    constexpr uint32_t kOldSmallBlockPatchslotBase = 0x00070000;
    constexpr uint32_t kNewSmallBlockPatchslotBase = 0x000B0000;
    constexpr uint32_t kBigBlockPatchslotBase = 0x000C0000;
    constexpr uint32_t kDevkitPatchslotBase = 0x000D0000;
    constexpr uint32_t kJtagPayloadOffset = 0x00000200;
    constexpr uint32_t kJtagPayloadRegionSize = 0x200;
    constexpr uint32_t kJtagFreebootOffset = 0x00090000;
    constexpr uint32_t kJtagFreebootRegionSize = 0x1000;
    constexpr uint32_t kJtagPatchesOffset = 0x00091000;
    constexpr uint32_t kJtagPatchesRegionSize = 0x4000;
    constexpr uint32_t kJtagFusesOffset = 0x00095000;
    constexpr uint32_t kJtagFusesRegionSize = 0x60;
    constexpr uint32_t kJtagXellOffset = 0x00095060;

    uint32_t align_up_0x10(uint32_t value) {
        return (value + 0x0FU) & ~0x0FU;
    }

    bool is_glitch_build(BuildType build_type) {
        switch (build_type) {
            case BuildType::Glitch:
            case BuildType::Glitch2:
            case BuildType::Glitch2m:
            case BuildType::Glitch3:
                return true;
            default:
                return false;
        }
    }

    bool is_jtag_build(BuildType build_type) {
        return build_type == BuildType::Jtag;
    }

    enum class SyntheticNandFamily {
        OldSmallBlock,
        NewSmallBlock,
        BigBlock,
        Emmc,
    };

    struct SyntheticNandTarget {
        SyntheticNandFamily family;
        uint32_t image_length;
        uint32_t flash_config;
        uint32_t patchslot_base;
        uint16_t patch_slots;
    };

    std::optional<SyntheticNandFamily> resolve_synthetic_nand_family(ConsoleType console_type) {
        switch (console_type) {
            case ConsoleType::Xenon:
            case ConsoleType::Zephyr:
            case ConsoleType::Falcon:
                return SyntheticNandFamily::OldSmallBlock;

            case ConsoleType::Jasper:
            case ConsoleType::Trinity:
            case ConsoleType::Corona:
            case ConsoleType::Winchester:
                return SyntheticNandFamily::NewSmallBlock;

            case ConsoleType::Jasper256:
            case ConsoleType::Jasper512:
            case ConsoleType::JasperBB:
            case ConsoleType::JasperBigFFS:
            case ConsoleType::TrinityBB:
            case ConsoleType::TrinityBigFFS:
                return SyntheticNandFamily::BigBlock;

            case ConsoleType::Corona4G:
            case ConsoleType::Winchester4G:
                return SyntheticNandFamily::Emmc;
        }

        return std::nullopt;
    }

    const char* describe_synthetic_nand_family(SyntheticNandFamily family) {
        switch (family) {
            case SyntheticNandFamily::OldSmallBlock:
                return "old small-block";
            case SyntheticNandFamily::NewSmallBlock:
                return "new small-block";
            case SyntheticNandFamily::BigBlock:
                return "big-block";
            case SyntheticNandFamily::Emmc:
                return "eMMC";
        }

        return "unknown";
    }

} // namespace

const char* describe_build_type(BuildType build_type) {
    switch (build_type) {
        case BuildType::Retail:
            return "retail";
        case BuildType::Glitch:
            return "glitch";
        case BuildType::Jtag:
            return "jtag";
        case BuildType::Glitch2:
            return "glitch2";
        case BuildType::Glitch2m:
            return "glitch2m";
        case BuildType::Glitch3:
            return "glitch3";
        case BuildType::Devkit:
            return "devkit";
    }

    return "unknown";
}

namespace {

    std::optional<SyntheticNandTarget>
    resolve_synthetic_target(std::optional<ConsoleType> console_type, BuildType build_type) {
        if (!console_type) {
            Log::Error("build: console type is required to synthesize a NAND image");
            return std::nullopt;
        }

        const auto family = resolve_synthetic_nand_family(*console_type);
        if (!family) {
            Log::Error("build: console type is unsupported for NAND synthesis");
            return std::nullopt;
        }

        switch (*family) {
            case SyntheticNandFamily::OldSmallBlock:
                return SyntheticNandTarget{
                    .family = *family,
                    .image_length = build_type == BuildType::Devkit ? 0x04000000U : 0x01000000U,
                    .flash_config = build_type == BuildType::Devkit
                                        ? gxbuild3::utils::FlashConfig::AllOther64M
                                        : gxbuild3::utils::FlashConfig::AllOther16M,
                    .patchslot_base = build_type == BuildType::Devkit ? kDevkitPatchslotBase
                                                                      : kOldSmallBlockPatchslotBase,
                    .patch_slots = 2U,
                };

            case SyntheticNandFamily::NewSmallBlock:
                return SyntheticNandTarget{
                    .family = *family,
                    .image_length = build_type == BuildType::Devkit ? 0x04000000U : 0x01000000U,
                    .flash_config = build_type == BuildType::Devkit
                                        ? gxbuild3::utils::FlashConfig::Jasper64M_NewSB
                                        : gxbuild3::utils::FlashConfig::Jasper16M_NewSB,
                    .patchslot_base = build_type == BuildType::Retail ? kOldSmallBlockPatchslotBase
                                      : (build_type == BuildType::Devkit ? kDevkitPatchslotBase : kNewSmallBlockPatchslotBase),
                    .patch_slots = 2U,
                };

            case SyntheticNandFamily::BigBlock:
                return SyntheticNandTarget{
                    .family = *family,
                    .image_length = 0x04000000U,
                    .flash_config = gxbuild3::utils::FlashConfig::Jasper256_512_LargeBlock,
                    .patchslot_base = build_type == BuildType::Retail ? kOldSmallBlockPatchslotBase : kBigBlockPatchslotBase,
                    .patch_slots = 2U,
                };

            case SyntheticNandFamily::Emmc:
                if (build_type == BuildType::Devkit) {
                    Log::Warn("build: ignoring devkit 64MB size override for eMMC console type");
                }
                return SyntheticNandTarget{
                    .family = *family,
                    .image_length = 0x03000000U,
                    .flash_config = gxbuild3::utils::FlashConfig::Corona4GB,
                    .patchslot_base = build_type == BuildType::Retail ? kOldSmallBlockPatchslotBase : kNewSmallBlockPatchslotBase,
                    .patch_slots = 2U,
                };
        }

        return std::nullopt;
    }

    uint32_t resolve_synthetic_fs_offset(const gxbuild3::utils::FlashBlockDriver& driver) {
        if (driver.flash_config() == gxbuild3::utils::FlashConfig::Jasper256_512_LargeBlock) {
            return 0xC0000U;
        }
        return 0x10000U;
    }

    uint32_t resolve_synthetic_header_version(const flash_image_t& image) {
        const uint32_t current_version = bswap16(image.header.version);
        if (current_version != 0) {
            return current_version;
        }

        return kSyntheticHeaderVersion;
    }

    raw_nand_header_t create_synthetic_header(const flash_image_t& image,
                                              const gxbuild3::utils::FlashBlockDriver& driver,
                                              const SyntheticNandTarget& target) {
        raw_nand_header_t header{};
        header.magic = bswap16(0xFF4FU);
        header.version = bswap16(static_cast<uint16_t>(resolve_synthetic_header_version(image)));
        header.entrypoint = bswap32(kSyntheticBootloaderChainOffset);
        header.size = bswap32(target.patchslot_base);
        header.kv_size = bswap32(kSyntheticKvSize);
        header.cf1_offset = bswap32(target.patchslot_base);
        header.patch_slots = bswap16(target.patch_slots);
        header.kv_offset = bswap32(kSyntheticKvOffset);
        header.fs_offset = bswap32(resolve_synthetic_fs_offset(driver));
        header.kv_version = image.header.kv_version;
        if (header.kv_version == 0 && image.nand_results) {
            header.kv_version = bswap16(image.nand_results->kv_version);
        }
        if (header.kv_version == 0) {
            header.kv_version = bswap16(0x0712);
        }

        static const uint8_t kCopyrightStr[] = {
            0xA9, ' ', '2', '0',  '0',  '4',  '-',  '2',  '0',  '1',  '0',  ' ', 'M',
            'i',  'c', 'r', 'o',  's',  'o',  'f',  't',  ' ',  'C',  'o',  'r', 'p',
            'o',  'r', 'a', 't',  'i',  'o',  'n',  '.',  ' ',  'A',  'l',  'l', ' ',
            'r',  'i', 'g', 'h',  't',  's',  ' ',  'r',  'e',  's',  'e',  'r', 'v',
            'e',  'd', '.', 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12};
        std::memcpy(header.reserved_0x10, kCopyrightStr,
                    std::min(sizeof(header.reserved_0x10), sizeof(kCopyrightStr)));

        if (image.nand_results && image.nand_results->smc_config_offset != 0) {
            header.smc_config_offset = bswap32(image.nand_results->smc_config_offset);
        } else {
            header.smc_config_offset = 0;
        }
        header.smc_size =
            bswap32(static_cast<uint32_t>(image.smc ? image.smc->size() : kSyntheticSmcSize));
        header.smc_offset = bswap32(kSyntheticSmcOffset);
        return header;
    }

    bool write_raw_nand_header(gxbuild3::utils::FlashBlockDriver& driver,
                               const raw_nand_header_t& header) {
        return driver.write(0, reinterpret_cast<const uint8_t*>(&header), sizeof(header));
    }

    bool has_backing_image(const flash_image_t& image) {
        return image.driver.image_length_real() != 0 && !image.driver.image_data().empty();
    }

    bool ensure_build_backing_image(flash_image_t& image, BuildType build_type,
                                    std::optional<ConsoleType> console_type) {
        if (has_backing_image(image)) {
            Log::Info(
                "build: using parsed NAND backing image (length 0x{:x}, flash config 0x{:08x})",
                image.driver.image_length_real(), image.driver.flash_config());
            return true;
        }

        const auto target = resolve_synthetic_target(console_type, build_type);
        if (!target) {
            return false;
        }

        if (!image.driver.create_image(target->image_length, target->flash_config)) {
            Log::Error("build: failed to synthesize NAND backing image");
            return false;
        }

        std::fill(image.driver.image_data().begin(), image.driver.image_data().end(), 0xFF);
        image.driver.init_spare();
        image.header = create_synthetic_header(image, image.driver, *target);
        image.nand_results.reset();
        image.filesystem.reset();

        if (!write_raw_nand_header(image.driver, image.header)) {
            Log::Error("build: failed to write synthetic NAND header");
            return false;
        }

        Log::Info(
            "build: synthesized fresh {} NAND backing image (length 0x{:x}, flash config 0x{:08x})",
            describe_synthetic_nand_family(target->family), target->image_length,
            target->flash_config);
        return true;
    }

    std::optional<uint32_t> resolve_build_patchslot_base(const flash_image_t& image) {
        if (image.nand_results && image.nand_results->cf0) {
            return image.nand_results->cf0->offset;
        }
        const uint32_t header_offset = bswap32(image.header.cf1_offset);
        if (header_offset != 0 && header_offset != 0xFFFFFFFFU) {
            return header_offset;
        }
        return std::nullopt;
    }

    std::optional<uint32_t> resolve_build_smc_offset(const flash_image_t& image) {
        if (image.nand_results && image.nand_results->smc_offset != 0 &&
            image.nand_results->smc_offset != 0xFFFFFFFFU) {
            return image.nand_results->smc_offset;
        }

        const uint32_t header_offset = bswap32(image.header.smc_offset);
        if (header_offset != 0 && header_offset != 0xFFFFFFFFU) {
            return header_offset;
        }

        return std::nullopt;
    }

    std::optional<uint32_t> resolve_build_smc_config_offset(const flash_image_t& image) {
        if (image.nand_results && image.nand_results->smc_config_offset != 0 &&
            image.nand_results->smc_config_offset != 0xFFFFFFFFU) {
            return image.nand_results->smc_config_offset;
        }

        const uint32_t header_offset = bswap32(image.header.smc_config_offset);
        if (header_offset != 0 && header_offset != 0xFFFFFFFFU) {
            return header_offset;
        }

        if (image.driver.lil_block_length() > 0 && image.driver.reserve_block_idx() >= 4) {
            return (image.driver.reserve_block_idx() - 4) * image.driver.lil_block_length();
        }

        return std::nullopt;
    }

    std::optional<uint32_t> resolve_build_kv_offset(const flash_image_t& image) {
        if (image.nand_results && image.nand_results->kv_offset != 0 &&
            image.nand_results->kv_offset != 0xFFFFFFFFU) {
            return image.nand_results->kv_offset;
        }

        const uint32_t header_offset = bswap32(image.header.kv_offset);
        if (header_offset != 0 && header_offset != 0xFFFFFFFFU) {
            return header_offset;
        }

        return std::nullopt;
    }

    std::optional<uint32_t> resolve_build_bootloader_chain_offset(const flash_image_t& image) {
        if (image.nand_results && image.nand_results->cb_or_a.offset != 0 &&
            image.nand_results->cb_or_a.offset != 0xFFFFFFFFU) {
            return image.nand_results->cb_or_a.offset;
        }

        const uint32_t header_offset = bswap32(image.header.entrypoint);
        if (header_offset != 0 && header_offset != 0xFFFFFFFFU) {
            return header_offset;
        }

        return std::nullopt;
    }

    bool has_spare_data(const gxbuild3::utils::FlashBlockDriver& driver) {
        return driver.page_length() >= 0x210;
    }

    bool is_flashfs_root_block_type(uint8_t block_type) {
        return block_type == 0x30 || block_type == 0x2C;
    }

    struct FlashFsRootCandidate {
        uint32_t block_idx;
        uint32_t sequence;
    };

    struct MobilePageCandidate {
        uint32_t page_idx;
        uint8_t block_type;
        uint32_t data_sequence;
        uint32_t data_length;
        uint32_t page_count;
        uint32_t encoded_page_count;
    };

    uint32_t ceil_div_u32(uint32_t value, uint32_t divisor) {
        if (divisor == 0) {
            return 0;
        }
        return value / divisor + ((value % divisor) != 0U ? 1U : 0U);
    }

    std::optional<mobile_result_t>* get_mobile_result_slot(mobile_results_t& results,
                                                           uint8_t block_type) {
        switch (block_type) {
            case 0x31:
                return &results.x31;
            case 0x32:
                return &results.x32;
            case 0x33:
                return &results.x33;
            case 0x34:
                return &results.x34;
            case 0x35:
                return &results.x35;
            case 0x36:
                return &results.x36;
            case 0x37:
                return &results.x37;
            case 0x38:
                return &results.x38;
            case 0x39:
                return &results.x39;
            default:
                return nullptr;
        }
    }

    const std::optional<mobile_result_t>* get_mobile_result_slot(const mobile_results_t& results,
                                                                 uint8_t block_type) {
        switch (block_type) {
            case 0x31:
                return &results.x31;
            case 0x32:
                return &results.x32;
            case 0x33:
                return &results.x33;
            case 0x34:
                return &results.x34;
            case 0x35:
                return &results.x35;
            case 0x36:
                return &results.x36;
            case 0x37:
                return &results.x37;
            case 0x38:
                return &results.x38;
            case 0x39:
                return &results.x39;
            default:
                return nullptr;
        }
    }

    std::optional<std::vector<uint8_t>>* get_mobile_data_slot(mobile_data_t& data,
                                                              uint8_t block_type) {
        switch (block_type) {
            case 0x31:
                return &data.x31;
            case 0x32:
                return &data.x32;
            case 0x33:
                return &data.x33;
            case 0x34:
                return &data.x34;
            case 0x35:
                return &data.x35;
            case 0x36:
                return &data.x36;
            case 0x37:
                return &data.x37;
            case 0x38:
                return &data.x38;
            case 0x39:
                return &data.x39;
            default:
                return nullptr;
        }
    }

    std::optional<uint16_t> fs_offset_to_block_idx(const gxbuild3::utils::FlashBlockDriver& driver,
                                                   uint32_t fs_offset) {
        const uint32_t lil_block_length = driver.lil_block_length();
        if (lil_block_length == 0 || (fs_offset % lil_block_length) != 0) {
            return std::nullopt;
        }

        const uint32_t block_idx = fs_offset / lil_block_length;
        if (block_idx >= driver.lil_block_count() ||
            block_idx > std::numeric_limits<uint16_t>::max()) {
            return std::nullopt;
        }

        return static_cast<uint16_t>(block_idx);
    }

    std::optional<FlashFsRootCandidate>
    detect_flashfs_root_from_spare(const gxbuild3::utils::FlashBlockDriver& driver) {
        if (!has_spare_data(driver)) {
            return std::nullopt;
        }

        std::optional<FlashFsRootCandidate> best_root;

        for (uint32_t block_idx = 0; block_idx < driver.lil_block_count(); ++block_idx) {
            auto spare = driver.read_lil_block_spare(block_idx);
            if (!spare) {
                continue;
            }

            const uint8_t* spare_data = spare->data();
            const uint32_t sequence = driver.get_spare_seq_field(spare_data);
            const uint8_t block_type = driver.get_spare_block_type_field(spare_data);

            if (sequence == 0 || !is_flashfs_root_block_type(block_type)) {
                continue;
            }

            if (!best_root || sequence > best_root->sequence ||
                (sequence == best_root->sequence && block_idx > best_root->block_idx)) {
                best_root = FlashFsRootCandidate{.block_idx = block_idx, .sequence = sequence};
            }
        }

        if (!best_root) {
            return std::nullopt;
        }

        return best_root;
    }

    std::optional<mobile_results_t>
    detect_mobile_results_from_spare(const gxbuild3::utils::FlashBlockDriver& driver) {
        if (!has_spare_data(driver) || driver.page_length() == 0 || driver.block_length() == 0) {
            return std::nullopt;
        }

        const uint32_t pages_per_block = driver.block_length() / driver.page_length();
        if (pages_per_block == 0) {
            return std::nullopt;
        }

        std::vector<MobilePageCandidate> found_pages;
        found_pages.reserve(driver.page_count());

        for (uint32_t page_idx = 0; page_idx < driver.page_count(); ++page_idx) {
            auto spare = driver.read_page_spare(page_idx);
            if (!spare) {
                continue;
            }

            const uint8_t* spare_data = spare->data();
            const uint8_t fs_page_count = driver.get_spare_page_count_field(spare_data);
            const uint8_t block_type = driver.get_spare_block_type_field(spare_data);
            if (fs_page_count == 0 || !driver.is_mobile_data(block_type)) {
                continue;
            }

            const uint32_t data_length = driver.get_spare_size_field(spare_data);
            if (data_length == 0) {
                continue;
            }

            const uint32_t page_count = ceil_div_u32(data_length, 0x200);
            const uint32_t encoded_page_count = pages_per_block - fs_page_count;
            if (page_count != encoded_page_count && page_count == 1 && data_length >= 0x200) {
                continue;
            }

            found_pages.push_back(MobilePageCandidate{
                .page_idx = page_idx,
                .block_type = block_type,
                .data_sequence = driver.get_spare_seq_field(spare_data),
                .data_length = data_length,
                .page_count = page_count,
                .encoded_page_count = encoded_page_count,
            });
        }

        if (found_pages.empty()) {
            return std::nullopt;
        }

        mobile_results_t results{};
        bool found_any = false;

        for (const auto& candidate : found_pages) {
            auto* slot = get_mobile_result_slot(results, candidate.block_type);
            if (!slot) {
                continue;
            }

            if (*slot && ((*slot)->start_page + (*slot)->page_count) > candidate.page_idx) {
                continue;
            }

            size_t matched_pages = 0;
            bool mismatch = false;
            for (const auto& page : found_pages) {
                if (page.block_type != candidate.block_type) {
                    continue;
                }
                if (page.page_idx < candidate.page_idx ||
                    page.page_idx >= (candidate.page_idx + candidate.page_count)) {
                    continue;
                }

                if (page.encoded_page_count != candidate.encoded_page_count) {
                    mismatch = true;
                    break;
                }

                matched_pages++;
            }

            if (mismatch || matched_pages != candidate.page_count) {
                continue;
            }

            if (*slot && (candidate.data_sequence < (*slot)->data_sequence ||
                          (candidate.data_sequence == (*slot)->data_sequence &&
                           candidate.page_idx <= (*slot)->start_page))) {
                continue;
            }

            *slot = mobile_result_t{
                .block_type = candidate.block_type,
                .data_sequence = candidate.data_sequence,
                .start_page = candidate.page_idx,
                .page_count = candidate.page_count,
                .data_length = candidate.data_length,
            };
            found_any = true;
        }

        if (!found_any) {
            return std::nullopt;
        }

        return results;
    }

    std::optional<mobile_data_t>
    load_mobile_data_from_results(const gxbuild3::utils::FlashBlockDriver& driver,
                                  const mobile_results_t& results) {
        mobile_data_t data{};
        bool found_any = false;

        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            const auto* result_slot = get_mobile_result_slot(results, block_type);
            auto* data_slot = get_mobile_data_slot(data, block_type);
            if (!result_slot || !data_slot || !(*result_slot)) {
                continue;
            }

            const auto& result = **result_slot;
            const uint64_t start_offset = static_cast<uint64_t>(result.start_page) * 0x200ULL;
            if (start_offset > std::numeric_limits<size_t>::max()) {
                Log::Warn("Skipping mobile 0x{:02x}: start offset out of range", block_type);
                continue;
            }

            auto mobile_bytes = driver.read(static_cast<size_t>(start_offset), result.data_length);
            if (!mobile_bytes) {
                Log::Warn("Failed to read mobile 0x{:02x} at page 0x{:x}", block_type,
                          result.start_page);
                continue;
            }

            *data_slot = std::move(*mobile_bytes);
            found_any = true;
        }

        if (!found_any) {
            return std::nullopt;
        }

        return data;
    }

    uint16_t calculate_mobile_blocks_count(const mobile_results_t& mobile,
                                           uint32_t pages_per_block) {
        if (pages_per_block == 0)
            return 0;
        uint32_t max_page = 0;
        uint32_t min_page = UINT32_MAX;
        bool found = false;

        auto check_slot = [&](const std::optional<mobile_result_t>& res) {
            if (res) {
                min_page = std::min(min_page, res->start_page);
                max_page = std::max(max_page, res->start_page + res->page_count);
                found = true;
            }
        };

        check_slot(mobile.x31);
        check_slot(mobile.x32);
        check_slot(mobile.x33);
        check_slot(mobile.x34);
        check_slot(mobile.x35);
        check_slot(mobile.x36);
        check_slot(mobile.x37);
        check_slot(mobile.x38);
        check_slot(mobile.x39);

        if (!found)
            return 0;
        uint32_t total_pages = max_page - min_page;
        return static_cast<uint16_t>(ceil_div_u32(total_pages, pages_per_block));
    }

    void load_known_flashfs_files(const gxbuild3::bootloaders::FlashFileSystem& filesystem,
                                  flashfs_files_t& files) {
        struct FlashFsFileBinding {
            std::string_view filename;
            std::optional<std::vector<uint8_t>> flashfs_files_t::* target;
        };

        static constexpr std::array<FlashFsFileBinding, 5> kBindings = {{
            {"crl.bin", &flashfs_files_t::crl},
            {"dae.bin", &flashfs_files_t::dae},
            {"extended.bin", &flashfs_files_t::extended},
            {"fcrt.bin", &flashfs_files_t::fcrt},
            {"secdata.bin", &flashfs_files_t::secdata},
        }};

        for (const auto& binding : kBindings) {
            const auto* entry = filesystem.find_file(binding.filename);
            if (!entry) {
                continue;
            }

            auto data = filesystem.get_file_data(*entry);
            if (!data) {
                Log::Warn("Failed to read FlashFS file '{}'", binding.filename);
                continue;
            }

            files.*(binding.target) = std::move(*data);
        }
    }

    void add_known_flashfs_files_to_payloads(const flashfs_files_t& files,
                                             flashfs_payload_map_t& payloads) {
        const auto assign_if_present =
            [&payloads](std::string_view name, const std::optional<std::vector<uint8_t>>& data) {
                if (data && !payloads.contains(name)) {
                    payloads[std::string{name}] = *data;
                }
            };

        assign_if_present("crl.bin", files.crl);
        assign_if_present("dae.bin", files.dae);
        assign_if_present("extended.bin", files.extended);
        assign_if_present("fcrt.bin", files.fcrt);
        assign_if_present("secdata.bin", files.secdata);
    }

    flashfs_payload_map_t collect_build_flashfs_payloads(const flash_image_t& image) {
        flashfs_payload_map_t payloads;

        if (image.flashfs_payloads) {
            for (const auto& [name, data] : *image.flashfs_payloads) {
                std::string clean_name{name};
                std::replace(clean_name.begin(), clean_name.end(), '\\', '/');
                auto pos = clean_name.rfind('/');
                if (pos != std::string::npos) {
                    clean_name = clean_name.substr(pos + 1);
                }
                if (!payloads.contains(clean_name)) {
                    payloads[clean_name] = data;
                }
            }
        }
        if (image.flashfs_files) {
            add_known_flashfs_files_to_payloads(*image.flashfs_files, payloads);
        }
        return payloads;
    }

    uint32_t resolve_build_sys_update_addr(const flash_image_t& image) {
        if (image.nand_results && image.nand_results->cf0) {
            return image.nand_results->cf0->offset;
        }
        return bswap32(image.header.cf1_offset);
    }

    uint32_t resolve_build_fs_version(const flash_image_t& image) {
        if (image.filesystem) {
            return image.filesystem->version();
        }
        return 1;
    }

} // namespace

std::optional<build_layout_t> resolve_build_layout(const flash_image_t& image,
                                                   BuildType build_type) {
    build_layout_t layout{};
    layout.smc_offset = resolve_build_smc_offset(image);
    layout.smc_config_offset = resolve_build_smc_config_offset(image);
    layout.kv_offset = resolve_build_kv_offset(image);
    layout.bootloader_chain_offset = resolve_build_bootloader_chain_offset(image);
    layout.patchslot_base = resolve_build_patchslot_base(image);
    layout.patchslot_length = image.driver.patch_slot_length();
    if (layout.patchslot_base && layout.patchslot_length != 0) {
        layout.patchslot_1_base = *layout.patchslot_base + layout.patchslot_length;
    }

    if (is_glitch_build(build_type)) {
        if (!layout.patchslot_base) {
            return std::nullopt;
        }
        if (layout.patchslot_length <= 0x10U) {
            return std::nullopt;
        }

        layout.patches_offset = *layout.patchslot_base + layout.patchslot_length + 0x10U;
        layout.patches_region_size = layout.patchslot_length - 0x10U;
        layout.xell_offset = kGlitchXellRawOffset;
        layout.xell_region_size = kXellSlotSize;
        return layout;
    }

    if (is_jtag_build(build_type)) {
        if (!layout.patchslot_base) {
            return std::nullopt;
        }
        layout.payload_offset = kJtagPayloadOffset;
        layout.payload_region_size = kJtagPayloadRegionSize;
        layout.freeboot_offset = kJtagFreebootOffset;
        layout.freeboot_region_size = kJtagFreebootRegionSize;
        layout.patches_offset = kJtagPatchesOffset;
        layout.patches_region_size = kJtagPatchesRegionSize;
        layout.fuses_offset = kJtagFusesOffset;
        layout.fuses_region_size = kJtagFusesRegionSize;
        layout.xell_offset = kJtagXellOffset;
        layout.xell_region_size = kXellSlotSize;
        return layout;
    }

    if (layout.patchslot_base) {
        return layout;
    }

    return std::nullopt;
}

namespace {

    size_t optional_blob_size(const std::optional<std::vector<uint8_t>>& data) {
        return data ? data->size() : 0U;
    }

    size_t count_flashfs_payloads(const flashfs_payload_map_t& payloads) {
        return payloads.size();
    }

    size_t total_flashfs_payload_bytes(const flashfs_payload_map_t& payloads) {
        size_t total = 0;
        for (const auto& [_, data] : payloads) {
            total += data.size();
        }
        return total;
    }

    void log_build_layout(const build_layout_t& layout, BuildType build_type) {
        Log::Info("build: layout for {} -> smc=0x{:x}, kv=0x{:x}, chain=0x{:x}, patchslot0=0x{:x}, "
                  "patchslot1=0x{:x}, patchlen=0x{:x}",
                  describe_build_type(build_type), layout.smc_offset.value_or(0),
                  layout.kv_offset.value_or(0), layout.bootloader_chain_offset.value_or(0),
                  layout.patchslot_base.value_or(0), layout.patchslot_1_base.value_or(0),
                  layout.patchslot_length);

        if (layout.payload_offset || layout.freeboot_offset || layout.patches_offset ||
            layout.fuses_offset || layout.xell_offset) {
            Log::Info("build: payload layout -> payload=0x{:x}/0x{:x}, freeboot=0x{:x}/0x{:x}, "
                      "patches=0x{:x}/0x{:x}, fuses=0x{:x}/0x{:x}, xell=0x{:x}/0x{:x}",
                      layout.payload_offset.value_or(0), layout.payload_region_size.value_or(0),
                      layout.freeboot_offset.value_or(0), layout.freeboot_region_size.value_or(0),
                      layout.patches_offset.value_or(0), layout.patches_region_size.value_or(0),
                      layout.fuses_offset.value_or(0), layout.fuses_region_size.value_or(0),
                      layout.xell_offset.value_or(0), layout.xell_region_size.value_or(0));
        }
    }

    void log_staged_build_inputs(const flash_image_t& image, BuildType build_type) {
        Log::Info("build: staged inputs for {} -> smc=0x{:x}, kv=0x{:x}, cb=0x{:x}, cbx=0x{:x}, "
                  "cbb=0x{:x}, sc=0x{:x}, cd=0x{:x}, ce=0x{:x}",
                  describe_build_type(build_type), optional_blob_size(image.smc),
                  optional_blob_size(image.keyvault), optional_blob_size(image.cb_or_A),
                  optional_blob_size(image.cb_X), optional_blob_size(image.cb_B),
                  optional_blob_size(image.sc), optional_blob_size(image.cd),
                  optional_blob_size(image.ce));

        if (image.patchslot_0 || image.patchslot_1) {
            Log::Info("build: staged patchslots -> slot0(cf=0x{:x}, cg=0x{:x}), slot1(cf=0x{:x}, "
                      "cg=0x{:x})",
                      image.patchslot_0 ? optional_blob_size(image.patchslot_0->cf) : 0U,
                      image.patchslot_0 ? optional_blob_size(image.patchslot_0->cg) : 0U,
                      image.patchslot_1 ? optional_blob_size(image.patchslot_1->cf) : 0U,
                      image.patchslot_1 ? optional_blob_size(image.patchslot_1->cg) : 0U);
        }

        if (image.payloads) {
            Log::Info("build: staged payloads -> patches=0x{:x}, payload=0x{:x}, freeboot=0x{:x}, "
                      "fuses=0x{:x}, xell=0x{:x}",
                      optional_blob_size(image.payloads->addon_patches),
                      optional_blob_size(image.payloads->jtag_payload),
                      optional_blob_size(image.payloads->jtag_rebooter),
                      optional_blob_size(image.payloads->vfuses),
                      image.xellblock ? optional_blob_size(image.xellblock->xell_main) : 0U);
        } else if (image.xellblock && image.xellblock->xell_main) {
            Log::Info("build: staged payloads -> xell=0x{:x}", image.xellblock->xell_main->size());
        }
    }

    bool write_build_region(gxbuild3::utils::FlashBlockDriver& driver, uint32_t offset,
                            uint32_t region_size, const std::vector<uint8_t>& data,
                            std::string_view label) {
        if (data.size() > region_size) {
            Log::Error("build: {} size 0x{:x} exceeds available region 0x{:x}", label, data.size(),
                       region_size);
            return false;
        }

        std::vector<uint8_t> region(region_size, 0xFF);
        std::memcpy(region.data(), data.data(), data.size());

        Log::Info("Writing {} to image offset 0x{:x} len 0x{:x} (end 0x{:x})...", label, offset,
                  region_size, offset + region_size);
        if (!driver.write(offset, region.data(), region.size())) {
            Log::Error("build: failed to write {} at 0x{:x}", label, offset);
            return false;
        }

        Log::Info(
            "Writing {} to image offset 0x{:x} len 0x{:x} (end 0x{:x})...done! data len 0x{:x}",
            label, offset, region_size, offset + region_size, data.size());
        return true;
    }

    bool write_build_blob(gxbuild3::utils::FlashBlockDriver& driver, uint32_t offset,
                          const std::vector<uint8_t>& data, std::string_view label) {
        Log::Info("Writing {} to image offset 0x{:x} len 0x{:x} (end 0x{:x})...", label, offset,
                  data.size(), offset + static_cast<uint32_t>(data.size()));
        if (!driver.write(offset, data.data(), data.size())) {
            Log::Error("build: failed to write {} at 0x{:x}", label, offset);
            return false;
        }

        Log::Info("Writing {} to image offset 0x{:x} len 0x{:x} (end 0x{:x})...done!", label,
                  offset, data.size(), offset + static_cast<uint32_t>(data.size()));
        return true;
    }

    bool write_optional_blob(gxbuild3::utils::FlashBlockDriver& driver,
                             const std::optional<std::vector<uint8_t>>& data,
                             const std::optional<uint32_t>& offset, std::string_view label) {
        if (!data) {
            return true;
        }
        if (!offset) {
            Log::Error("build: no resolved offset for {}", label);
            return false;
        }
        return write_build_blob(driver, *offset, *data, label);
    }

    bool write_patchslot_chain(flash_image_t& image, const patchslot_t& patchslot,
                               uint32_t slot_base, std::string_view slot_label,
                               uint8_t update_slot_idx,
                               std::span<const uint8_t> cpu_key,
                               uint32_t& cursor) {
        Log::Info("build: serializing {} from base 0x{:x}", slot_label, slot_base);

        if (!patchslot.cf) {
            return true;
        }

        auto cf = BootloaderCf::parse(*patchslot.cf);
        if (!cf.is_decrypted()) {
            cf.decrypt(key_1bl);
        }

        std::vector<uint8_t> cg_data;
        if (patchslot.cg) {
            cg_data = *patchslot.cg;
            auto cg = BootloaderCg::parse(cg_data);
            if (cg.is_decrypted()) {
                cg.encrypt(cf.header.cg_key);
                cg_data = cg.serialize();
            }
        }

        const uint32_t slot_size = image.driver.patch_slot_length();
        const size_t cf_size = sizeof(bl6_header) + cf.data.size();
        const size_t base_cg_size = (slot_size > cf_size) ? (slot_size - cf_size) : 0;

        const size_t cg_first_part_len = std::min(cg_data.size(), base_cg_size);
        std::vector<uint8_t> cg_overflow;
        if (cg_data.size() > base_cg_size) {
            cg_overflow.assign(cg_data.begin() + base_cg_size, cg_data.end());
        }

        const uint32_t lil_block_len = image.driver.lil_block_length();
        size_t overflow_blocks_count = 0;

        if (!cg_overflow.empty() && lil_block_len > 0) {
            const size_t num_blocks =
                ceil_div_u32(static_cast<uint32_t>(cg_overflow.size()), lil_block_len);
            const uint32_t min_alloc_block = ceil_div_u32(cursor, lil_block_len);
            for (size_t b = 0; b < num_blocks && b < 223; ++b) {
                auto allocated_block = image.driver.allocate_logical_block(0, 0, min_alloc_block);
                if (!allocated_block) {
                    Log::Error("build: failed to allocate logical block for CG overflow {}", b);
                    return false;
                }

                const size_t chunk_offset = b * lil_block_len;
                const size_t chunk_size =
                    std::min(static_cast<size_t>(lil_block_len), cg_overflow.size() - chunk_offset);

                if (!image.driver.write_logical_block(*allocated_block,
                                                      cg_overflow.data() + chunk_offset,
                                                      chunk_size)) {
                    Log::Error("build: failed to write CG overflow block 0x{:x}", *allocated_block);
                    return false;
                }

                cf.header.cg_blocks[b] = bswap16(static_cast<uint16_t>(*allocated_block));
                overflow_blocks_count++;
                cursor = std::max(cursor, (*allocated_block + 1) * lil_block_len);
            }
        }

        cf.header.cg_block_count = bswap16(static_cast<uint16_t>(overflow_blocks_count));
        cf.header.cg_size = bswap32(static_cast<uint32_t>(cg_data.size()));
        cf.header.update_slot = update_slot_idx;

        if (cpu_key.size() == 16) {
            cf.calc_mac(key_1bl, cpu_key.data());
            Log::Info("build: calculated per-box HMAC for {}", slot_label);
        }

        cf.encrypt(key_1bl);
        auto cf_serialized = cf.serialize();

        if (!write_build_blob(image.driver, slot_base, cf_serialized,
                              std::string(slot_label) + " CF")) {
            return false;
        }

        if (cg_first_part_len > 0) {
            std::vector<uint8_t> cg_first_part(cg_data.begin(), cg_data.begin() + cg_first_part_len);
            if (!write_build_blob(image.driver,
                                  slot_base + static_cast<uint32_t>(cf_serialized.size()),
                                  cg_first_part, std::string(slot_label) + " CG (base)")) {
                return false;
            }
        }

        return true;
    }

    bool write_build_bootloaders(flash_image_t& image, BuildType build_type, uint32_t& cursor_out,
                                  std::span<const uint8_t> cpu_key = {}) {
        const auto layout = resolve_build_layout(image, build_type);
        if (!layout) {
            Log::Warn("build: no layout available, skipping bootloader serialization");
            return true;
        }

        log_build_layout(*layout, build_type);

        std::optional<std::vector<uint8_t>> encrypted_smc;
        if (image.smc) {
            if (!smc_is_encrypted(*image.smc)) {
                encrypted_smc = smc_encrypt(*image.smc);
                Log::Info("build: SMC re-encrypted for output ({} bytes)", encrypted_smc->size());
            } else {
                encrypted_smc = *image.smc;
                Log::Info("build: SMC already encrypted for output ({} bytes)", encrypted_smc->size());
            }
        }
        if (!write_optional_blob(image.driver, encrypted_smc, layout->smc_offset, "SMC")) {
            return false;
        }

        if (image.xconfig && layout->smc_config_offset) {
            if (!write_optional_blob(image.driver, image.xconfig, layout->smc_config_offset, "SMC Config")) {
                return false;
            }
        }

        if (image.keyvault) {
            std::vector<uint8_t> kv_to_write = *image.keyvault;
            if (kv_to_write.size() > 0x4000) {
                kv_to_write.resize(0x4000);
            }
            if (!cpu_key.empty()) {
                std::vector<uint8_t> cpu_vec(cpu_key.begin(), cpu_key.end());
                if (!keyvault_is_encrypted(cpu_vec, kv_to_write)) {
                    try {
                        kv_to_write = keyvault_encrypt(cpu_vec, kv_to_write);
                        Log::Info("build: encrypted Keyvault with CPU key for output");
                    } catch (const std::exception& e) {
                        Log::Warn("build: failed to encrypt Keyvault: {}", e.what());
                    }
                }
            }
            if (!write_optional_blob(image.driver, kv_to_write, layout->kv_offset, "Keyvault")) {
                return false;
            }
        }

        uint32_t cursor = layout->bootloader_chain_offset.value_or(0x8000);
        Log::Info("build: packing and encrypting bootloader chain from 0x{:x}", cursor);

        auto packed_bldr = pack_and_encrypt_bootloaders(image, cpu_key);
        if (packed_bldr && !packed_bldr->empty()) {
            if (!write_build_blob(image.driver, cursor, *packed_bldr, "Bootloader Chain")) {
                return false;
            }
            cursor = align_up_0x10(cursor + static_cast<uint32_t>(packed_bldr->size()));
        }

        uint32_t su_addr = 0x70000;
        if (layout->patchslot_base && *layout->patchslot_base > su_addr) {
            su_addr = *layout->patchslot_base;
        }

        uint32_t patchslot_0_base = su_addr;
        if (is_glitch_build(build_type) && image.xellblock && image.xellblock->xell_main) {
            Log::Info("build: placing XeLL at SysUpdateAddr (0x{:x}) before patchslots", su_addr);
            if (!write_build_blob(image.driver, su_addr, *image.xellblock->xell_main, "XeLL")) {
                return false;
            }
            patchslot_0_base = su_addr + kXellSlotSize;
        }

        const uint32_t lil_block_len = image.driver.lil_block_length();
        uint32_t patch_area_end = patchslot_0_base + 2 * image.driver.patch_slot_length();
        if (lil_block_len > 0) {
            image.driver.reserve_logical_blocks(0, ceil_div_u32(patch_area_end, lil_block_len));
        }

        uint32_t overflow_cursor = patch_area_end;

        if (image.patchslot_0) {
            Log::Info("build: serializing patchslot 0 from base 0x{:x}", patchslot_0_base);
            if (!write_patchslot_chain(image, *image.patchslot_0, patchslot_0_base, "patchslot 0", 0, cpu_key, overflow_cursor)) {
                return false;
            }
        }

        patchslot_t effective_slot_1{};
        if (image.patchslot_1) {
            effective_slot_1 = *image.patchslot_1;
        } else if (image.patchslot_0 && image.patchslot_0->cf) {
            effective_slot_1 = *image.patchslot_0;
        }

        if (effective_slot_1.cf) {
            uint32_t patchslot_1_base = patchslot_0_base + image.driver.patch_slot_length();
            Log::Info("build: serializing patchslot 1 from base 0x{:x}", patchslot_1_base);
            if (!write_patchslot_chain(image, effective_slot_1, patchslot_1_base, "patchslot 1", 1, cpu_key, overflow_cursor)) {
                return false;
            }
        }

        cursor = overflow_cursor;

        raw_nand_header_t header_update = image.header;
        header_update.entrypoint = bswap32(layout->bootloader_chain_offset.value_or(0x8000));
        header_update.size = bswap32(su_addr);
        header_update.cf1_offset = bswap32(su_addr);
        header_update.patch_slots = bswap16(2);
        header_update.kv_offset = bswap32(layout->kv_offset.value_or(0x4000));
        header_update.kv_size = bswap32(0x4000);
        if (layout->smc_offset) {
            header_update.smc_offset = bswap32(*layout->smc_offset);
        }
        if (encrypted_smc) {
            header_update.smc_size = bswap32(static_cast<uint32_t>(encrypted_smc->size()));
        }
        image.header = header_update;
        image.driver.write(0, reinterpret_cast<const uint8_t*>(&header_update), sizeof(raw_nand_header_t));

        cursor_out = cursor;
        if (lil_block_len > 0) {
            image.driver.reserve_logical_blocks(0, ceil_div_u32(cursor, lil_block_len));
        }
        if (layout->smc_config_offset && lil_block_len > 0) {
            image.driver.reserve_logical_blocks(*layout->smc_config_offset / lil_block_len, 4);
        }
        return true;
    }

    bool write_build_xell(flash_image_t& image, BuildType build_type, uint32_t& cursor) {
        if (is_glitch_build(build_type)) {
            return true;
        }

        const auto layout = resolve_build_layout(image, build_type);
        if (!layout || !layout->xell_offset || !layout->xell_region_size) {
            return true;
        }

        if (!image.xellblock || !image.xellblock->xell_main) {
            return true;
        }

        uint32_t target_offset = align_up_0x10(cursor);
        if (layout->xell_offset && *layout->xell_offset > target_offset) {
            target_offset = *layout->xell_offset;
        }

        if (!write_build_region(image.driver, target_offset, *layout->xell_region_size,
                                *image.xellblock->xell_main, "XeLL")) {
            return false;
        }

        cursor = target_offset + static_cast<uint32_t>(image.xellblock->xell_main->size());
        return true;
    }

    bool write_build_addon_patches(flash_image_t& image, BuildType build_type, uint32_t& cursor) {
        const auto layout = resolve_build_layout(image, build_type);
        if (!layout || !layout->patches_offset || !layout->patches_region_size) {
            return true;
        }

        if (!image.payloads || !image.payloads->addon_patches) {
            return true;
        }

        uint32_t target_offset = align_up_0x10(cursor);
        if (layout->patches_offset && *layout->patches_offset > target_offset) {
            target_offset = *layout->patches_offset;
        }

        if (!write_build_region(image.driver, target_offset, *layout->patches_region_size,
                                *image.payloads->addon_patches, "patch blob")) {
            return false;
        }

        cursor = target_offset + static_cast<uint32_t>(image.payloads->addon_patches->size());
        const uint32_t lil_block_len = image.driver.lil_block_length();
        if (lil_block_len > 0) {
            image.driver.reserve_logical_blocks(target_offset / lil_block_len,
                                                ceil_div_u32(static_cast<uint32_t>(image.payloads->addon_patches->size()), lil_block_len));
        }
        return true;
    }

    bool write_build_jtag_payloads(flash_image_t& image, BuildType build_type, uint32_t& cursor) {
        if (!is_jtag_build(build_type)) {
            return true;
        }

        const auto layout = resolve_build_layout(image, build_type);
        if (!layout || !image.payloads) {
            return true;
        }

        if (layout->payload_offset && layout->payload_region_size && image.payloads->jtag_payload) {
            uint32_t target_offset = align_up_0x10(cursor);
            if (*layout->payload_offset > target_offset) {
                target_offset = *layout->payload_offset;
            }
            if (!write_build_region(image.driver, target_offset, *layout->payload_region_size,
                                    *image.payloads->jtag_payload, "JTAG payload")) {
                return false;
            }
            cursor = target_offset + static_cast<uint32_t>(image.payloads->jtag_payload->size());
        }

        if (layout->freeboot_offset && layout->freeboot_region_size &&
            image.payloads->jtag_rebooter) {
            uint32_t target_offset = align_up_0x10(cursor);
            if (*layout->freeboot_offset > target_offset) {
                target_offset = *layout->freeboot_offset;
            }
            if (!write_build_region(image.driver, target_offset, *layout->freeboot_region_size,
                                    *image.payloads->jtag_rebooter, "JTAG rebooter")) {
                return false;
            }
            cursor = target_offset + static_cast<uint32_t>(image.payloads->jtag_rebooter->size());
        }

        if (layout->fuses_offset && layout->fuses_region_size && image.payloads->vfuses) {
            uint32_t target_offset = align_up_0x10(cursor);
            if (*layout->fuses_offset > target_offset) {
                target_offset = *layout->fuses_offset;
            }
            if (!write_build_region(image.driver, target_offset, *layout->fuses_region_size,
                                    *image.payloads->vfuses, "JTAG fuses")) {
                return false;
            }
            cursor = target_offset + static_cast<uint32_t>(image.payloads->vfuses->size());
        }

        return true;
    }

    void log_flashfs_plan(const flash_image_t& image, const flashfs_payload_map_t& payloads,
                          uint16_t fs_block_idx, uint32_t fs_version, uint32_t sys_update_addr) {
        Log::Info("build: FlashFS root block 0x{:x}, version {}, sysupdate 0x{:x}, xconfig={}, "
                  "payload files={}, payload bytes=0x{:x}",
                  fs_block_idx, fs_version, sys_update_addr,
                  image.xconfig.has_value() ? "yes" : "no", count_flashfs_payloads(payloads),
                  total_flashfs_payload_bytes(payloads));
        for (const auto& [filename, data] : payloads) {
            Log::Info("build: FlashFS file '{}' staged (0x{:x} bytes)", filename, data.size());
        }
    }

} // namespace

bl_type get_bl_type(uint16_t value) {
    switch (value & 0x0FFF) {
        case 0x342:
            return CB;
        case 0x343:
            return SC;
        case 0x344:
            return CD;
        case 0x345:
            return CE;
        case 0x346:
            return CF;
        case 0x347:
            return CG;
        case 0xD4D:
            return XKE;
        case 0xE4E:
            return KV;
        default:
            throw std::runtime_error("Unknown bootloader type: " + std::to_string(value));
    }
}
// Helper function to read a bootloader header at a given offset using FlashBlockDriver
static auto read_bl_header(const gxbuild3::utils::FlashBlockDriver& driver, uint32_t offset)
    -> std::optional<bl_results_t> {
    // Check bounds: bl_header is 0x10 bytes
    if (offset + sizeof(bl_header) > driver.image_length_real()) {
        Log::Trace("read_bl_header: offset {:x} + {:x} exceeds image size {:x}", offset,
                   sizeof(bl_header), driver.image_length_real());
        return std::nullopt;
    }

    auto header_data = driver.read(offset, sizeof(bl_header));
    if (!header_data) {
        Log::Trace("read_bl_header: failed to read at offset {:x}", offset);
        return std::nullopt;
    }
    const auto* bl_hdr = reinterpret_cast<const bl_header*>(header_data->data());

    uint16_t magic = bswap16(bl_hdr->magic);
    if (magic == 0) {
        return std::nullopt;
    }
    try {
        get_bl_type(magic);
    } catch (...) {
        return std::nullopt;
    }

    bl_results_t result;
    result.magic = magic;
    result.offset = offset;
    result.version = bswap16(bl_hdr->version);
    result.size = bswap32(bl_hdr->size);

    return result;
}

// Helper function to find the next bootloader in the chain
static uint32_t find_next_bl_offset(uint32_t current_offset, uint32_t current_size) {
    // Align to 16 bytes (0x10)
    return current_offset + ((current_size + 0xF) & ~0xF);
}

std::optional<XeCoronaFsData> read_corona_config_block(const gxbuild3::utils::FlashBlockDriver& driver) {
    if (driver.flash_config() != gxbuild3::utils::FlashConfig::Corona4GB) {
        return std::nullopt;
    }

    const uint32_t config_block = driver.config_block_idx();
    const uint32_t config_offset = config_block * driver.block_length();

    auto data = driver.read(config_offset, sizeof(XeCoronaFsData));
    if (!data || data->size() < sizeof(XeCoronaFsData)) {
        Log::Error("read_corona_config_block: failed to read config block at offset 0x{:x}", config_offset);
        return std::nullopt;
    }

    XeCoronaFsData raw_cfg{};
    std::memcpy(&raw_cfg, data->data(), sizeof(XeCoronaFsData));

    XeCoronaFsData cfg{};
    std::memcpy(cfg.section_digest, raw_cfg.section_digest, sizeof(cfg.section_digest));
    cfg.unknown1 = bswap32(raw_cfg.unknown1);
    cfg.fs_version = bswap32(raw_cfg.fs_version);
    cfg.fs_block_idx = bswap16(raw_cfg.fs_block_idx);
    cfg.unknown2 = bswap16(raw_cfg.unknown2);
    cfg.mobile1_block_idx = bswap16(raw_cfg.mobile1_block_idx);
    cfg.mobile1_length = bswap16(raw_cfg.mobile1_length);
    std::memcpy(cfg.unknown3, raw_cfg.unknown3, sizeof(cfg.unknown3));
    cfg.mobile2_block_idx = bswap16(raw_cfg.mobile2_block_idx);
    cfg.mobile2_length = bswap16(raw_cfg.mobile2_length);
    std::memcpy(cfg.reserved, raw_cfg.reserved, sizeof(cfg.reserved));

    Log::Info("Read Corona config block at block 0x{:x} (0x{:x}): fs_block_idx=0x{:x}, fs_version=0x{:x}",
              config_block, config_offset, cfg.fs_block_idx, cfg.fs_version);

    return cfg;
}

bool write_corona_config_block(gxbuild3::utils::FlashBlockDriver& driver,
                               const XeCoronaFsData& config) {
    if (driver.flash_config() != gxbuild3::utils::FlashConfig::Corona4GB) {
        return false;
    }

    XeCoronaFsData raw_cfg{};
    raw_cfg.unknown1 = bswap32(config.unknown1);
    raw_cfg.fs_version = bswap32(config.fs_version);
    raw_cfg.fs_block_idx = bswap16(config.fs_block_idx);
    raw_cfg.unknown2 = bswap16(config.unknown2);
    raw_cfg.mobile1_block_idx = bswap16(config.mobile1_block_idx);
    raw_cfg.mobile1_length = bswap16(config.mobile1_length);
    std::memcpy(raw_cfg.unknown3, config.unknown3, sizeof(raw_cfg.unknown3));
    raw_cfg.mobile2_block_idx = bswap16(config.mobile2_block_idx);
    raw_cfg.mobile2_length = bswap16(config.mobile2_length);
    std::memcpy(raw_cfg.reserved, config.reserved, sizeof(raw_cfg.reserved));

    // Compute SHA1 digest of payload (offset 0x14 to 0x200, length 0x1EC = 492 bytes)
    ExCryptSha(reinterpret_cast<const uint8_t*>(&raw_cfg) + 0x14, 0x1EC,
               nullptr, 0, nullptr, 0,
               raw_cfg.section_digest, 0x14);

    const uint32_t config_block = driver.config_block_idx();
    const uint32_t config_offset = config_block * driver.block_length();

    Log::Info("Writing Corona config block at block 0x{:x} (0x{:x}): fs_block_idx=0x{:x}, fs_version=0x{:x}",
              config_block, config_offset, config.fs_block_idx, config.fs_version);

    return driver.write(config_offset, reinterpret_cast<const uint8_t*>(&raw_cfg), sizeof(XeCoronaFsData));
}

nand_results_t read(const gxbuild3::utils::FlashBlockDriver& driver) {
    nand_results_t results{};
    const size_t image_size = driver.image_length_real();

    // Check if data is large enough to contain the raw NAND header
    if (image_size < sizeof(raw_nand_header_t)) {
        results.valid = false;
        return results;
    }

    // Read the raw NAND header from the data using driver
    auto header_data = driver.read(0, sizeof(raw_nand_header_t));
    if (!header_data) {
        results.valid = false;
        return results;
    }
    const raw_nand_header_t* header =
        reinterpret_cast<const raw_nand_header_t*>(header_data->data());

    // Validate magic
    uint16_t magic = bswap16(header->magic);
    if (magic == 0) {
        results.valid = false;
        return results;
    }

    // Set valid flag
    results.valid = true;

    // Parse NAND header metadata with proper endian swapping
    results.kv_offset = bswap32(header->kv_offset);
    if (results.kv_offset == 0 || results.kv_offset == 0xFFFFFFFF) {
        results.kv_offset = 0x4000;
    }
    results.kv_size = bswap32(header->kv_size);
    if (results.kv_size == 0 || results.kv_size == 0xFFFFFFFF || results.kv_size > 0x4000) {
        results.kv_size = 0x4000;
    }
    results.kv_version = bswap16(header->kv_version);
    results.smc_size = bswap32(header->smc_size);
    if (results.smc_size == 0 || results.smc_size == 0xFFFFFFFF) {
        results.smc_size = 0x3000;
    }
    results.smc_offset = bswap32(header->smc_offset);
    if (results.smc_offset == 0 || results.smc_offset == 0xFFFFFFFF) {
        results.smc_offset = 0x1000;
    }
    results.smc_config_offset = bswap32(header->smc_config_offset);
    results.fs_offset = bswap32(header->fs_offset);
    results.payload_indicator = bswap32(header->payload_indicator);
    results.patch_slots = bswap16(header->patch_slots);

    results.mobile_results = detect_mobile_results_from_spare(driver);

    uint16_t mobile_blocks = 0;
    if (results.mobile_results && driver.block_length() != 0 && driver.page_length() != 0) {
        const uint32_t pages_per_block = driver.block_length() / driver.page_length();
        mobile_blocks = calculate_mobile_blocks_count(*results.mobile_results, pages_per_block);
    }

    if (driver.flash_config() == gxbuild3::utils::FlashConfig::Corona4GB) {
        auto corona_cfg = read_corona_config_block(driver);
        if (corona_cfg && corona_cfg->fs_block_idx != 0) {
            results.fs_block_idx = corona_cfg->fs_block_idx;
            results.fs_offset = corona_cfg->fs_block_idx * driver.lil_block_length();
            Log::Info("Detected FlashFS from Corona config block at 0x{:x} (block 0x{:x}, version 0x{:x})",
                      results.fs_offset, *results.fs_block_idx, corona_cfg->fs_version);

            if (corona_cfg->mobile1_block_idx != 0 || corona_cfg->mobile2_block_idx != 0) {
                mobile_results_t mob{};
                const uint32_t pages_per_block = (driver.block_length() != 0 && driver.page_length() != 0)
                    ? (driver.block_length() / driver.page_length()) : 32;

                if (corona_cfg->mobile1_block_idx != 0) {
                    mobile_result_t res1{};
                    res1.block_type = 0x31;
                    res1.start_page = corona_cfg->mobile1_block_idx * pages_per_block;
                    res1.page_count = corona_cfg->mobile1_length * pages_per_block;
                    res1.data_length = corona_cfg->mobile1_length * driver.block_length();
                    mob.x31 = res1;
                }
                if (corona_cfg->mobile2_block_idx != 0) {
                    mobile_result_t res2{};
                    res2.block_type = 0x32;
                    res2.start_page = corona_cfg->mobile2_block_idx * pages_per_block;
                    res2.page_count = corona_cfg->mobile2_length * pages_per_block;
                    res2.data_length = corona_cfg->mobile2_length * driver.block_length();
                    mob.x32 = res2;
                }
                results.mobile_results = mob;
            }
        }
    }

    if (!results.fs_block_idx) {
        if (auto detected_root = detect_flashfs_root_from_spare(driver)) {
            const uint32_t detected_fs_offset = detected_root->block_idx * driver.lil_block_length();
            Log::Info("Detected FlashFS from spare data at 0x{:x} (block 0x{:x}, header hint: 0x{:x}, "
                      "mobile blocks: {})",
                      detected_fs_offset, detected_root->block_idx, results.fs_offset, mobile_blocks);
            results.fs_offset = detected_fs_offset;
            results.fs_block_idx = static_cast<uint16_t>(detected_root->block_idx);
        } else {
            auto base_fs_block = fs_offset_to_block_idx(driver, results.fs_offset);
            if (base_fs_block) {
                results.fs_block_idx = static_cast<uint16_t>(*base_fs_block + mobile_blocks);
                Log::Info("Resolved FlashFS root block index 0x{:x} from header offset 0x{:x} + {} "
                          "mobile blocks",
                          *results.fs_block_idx, results.fs_offset, mobile_blocks);
            } else {
                results.fs_block_idx = std::nullopt;
            }
        }
    }

    // Parse CB (2BL) offset
    // entrypoint at 0x08 serves as the CB offset
    uint32_t cb_offset = bswap32(header->entrypoint);
    auto cb_result = read_bl_header(driver, cb_offset);
    if (!cb_result) {
        results.valid = false;
        return results;
    }
    results.cb_or_a = *cb_result;

    // Walk the bootloader chain
    uint32_t current_offset = results.cb_or_a.offset;
    uint32_t current_size = results.cb_or_a.size;

    // Check if CB has flags & 0x0800 (dual 2BL)
    auto cb_hdr_data = driver.read(current_offset, sizeof(bl_header));
    if (!cb_hdr_data) {
        return results;
    }
    const auto* cb_hdr = reinterpret_cast<const bl_header*>(cb_hdr_data->data());
    uint16_t cb_flags = bswap16(cb_hdr->flags);
    if ((cb_flags & 0x0800) == 0x0800) {
        uint32_t next_cb_offset = find_next_bl_offset(current_offset, current_size);
        auto next_cb_result = read_bl_header(driver, next_cb_offset);
        if (next_cb_result) {
            uint32_t possible_other_cb_offset =
                find_next_bl_offset(next_cb_offset, next_cb_result->size);
            auto possible_other_cb_result = read_bl_header(driver, possible_other_cb_offset);
            if (possible_other_cb_result && get_bl_type(possible_other_cb_result->magic) == CB) {
                results.cbx = *next_cb_result;
                results.cbb = *possible_other_cb_result;
                current_offset = results.cbb->offset;
                current_size = results.cbb->size;
            } else {
                results.cbb = *next_cb_result;
                current_offset = results.cbb->offset;
                current_size = results.cbb->size;
            }
        }
    }

    uint32_t next_offset = find_next_bl_offset(current_offset, current_size);
    for (size_t i = 0; i < 8; i++) {
        auto next_result = read_bl_header(driver, next_offset);
        if (!next_result)
            break;

        switch (get_bl_type(static_cast<uint16_t>(next_result->magic))) {
            case SC:
                results.sc = *next_result;
                break;
            case CD:
                results.cd = *next_result;
                break;
            case CE:
                results.ce = *next_result;
                break;
            case CF:
                if (!results.cf0)
                    results.cf0 = *next_result;
                else if (!results.cf1)
                    results.cf1 = *next_result;
                break;
            case CG:
                if (!results.cg0)
                    results.cg0 = *next_result;
                else if (!results.cg1)
                    results.cg1 = *next_result;
                break;
            default:
                break;
        }

        current_offset = next_result->offset;
        current_size = next_result->size;
        next_offset = find_next_bl_offset(current_offset, current_size);
    }

    // Also check CF from NAND header if we haven't found it yet
    uint32_t cf1_offset_swapped = bswap32(header->cf1_offset);
    if (!results.cf0 && cf1_offset_swapped != 0 && cf1_offset_swapped != 0xFFFFFFFF) {
        auto cf_result = read_bl_header(driver, cf1_offset_swapped);
        if (cf_result) {
            results.cf0 = *cf_result;
            next_offset = find_next_bl_offset(results.cf0->offset, results.cf0->size);
            auto cg0_result = read_bl_header(driver, next_offset);
            if (cg0_result) {
                if (get_bl_type(static_cast<uint16_t>(cg0_result->magic)) == CG)
                    results.cg0 = *cg0_result;
            }
        }
    }

    // Handle Patchslot 1 fallback probing (0x10000 / 64KB after Patchslot 0)
    if (results.cf0 && !results.cf1) {
        uint32_t cf1_offset = results.cf0->offset + 0x10000;
        auto cf1_result = read_bl_header(driver, cf1_offset);
        if (cf1_result && get_bl_type(static_cast<uint16_t>(cf1_result->magic)) == CF) {
            results.cf1 = *cf1_result;
            uint32_t cg1_offset = cf1_result->offset + cf1_result->size;
            auto cg1_result = read_bl_header(driver, cg1_offset);
            if (cg1_result && get_bl_type(static_cast<uint16_t>(cg1_result->magic)) == CG) {
                results.cg1 = *cg1_result;
            }
        }
    }

    return results;
}

// Backward compatibility wrapper
nand_results_t read(const std::vector<uint8_t>& data) {
    gxbuild3::utils::FlashBlockDriver driver{std::vector<uint8_t>(data)};
    if (!driver.open_continue(driver.image_data().size(), 528)) {
        nand_results_t out{};
        out.valid = false;
        return out;
    }
    return read(static_cast<const gxbuild3::utils::FlashBlockDriver&>(driver));
}

raw_nand_header_t parse_nand_header(std::span<const uint8_t> raw) {
    if (raw.size() < sizeof(raw_nand_header_t))
        throw std::runtime_error("NAND header data too short");

    raw_nand_header_t header{};
    std::memcpy(&header, raw.data(), sizeof(raw_nand_header_t));

    if (bswap16(header.magic) == 0)
        throw std::runtime_error("Invalid NAND header magic");

    return header;
}

FlashImage FlashImage::parse(std::vector<uint8_t> data) {
    FlashImage image{};

    image.driver = gxbuild3::utils::FlashBlockDriver(std::move(data));
    if (!image.driver.open_continue(image.driver.image_data().size(), 528)) {
        Log::Error("FlashImage::parse: Failed to initialize FlashBlockDriver");
        return image;
    }

    auto header_data = image.driver.read(0, sizeof(raw_nand_header_t));
    if (!header_data)
        throw std::runtime_error("Failed to read NAND header");

    image.header = parse_nand_header(std::span<const uint8_t>(*header_data));

    if (image.driver.flash_config() == gxbuild3::utils::FlashConfig::Corona4GB) {
        image.corona_fs_data = read_corona_config_block(image.driver);
    }

    image.nand_results = read(image.driver);

    if (image.nand_results && image.nand_results->valid) {
        if (image.nand_results->kv_offset != 0 && image.nand_results->kv_offset != 0xFFFFFFFF &&
            image.nand_results->kv_size != 0) {
            uint32_t read_kv_size = std::min<uint32_t>(image.nand_results->kv_size, 0x4000);
            image.keyvault = image.driver.read(image.nand_results->kv_offset, read_kv_size);
            if (image.keyvault) {
                if (image.keyvault->size() > 0x4000) {
                    image.keyvault->resize(0x4000);
                }
                Log::Info("Parsed Keyvault from image at 0x{:x} (0x{:x} bytes)",
                          image.nand_results->kv_offset, image.keyvault->size());
            }
        }

        if (image.nand_results->smc_offset != 0 && image.nand_results->smc_offset != 0xFFFFFFFF &&
            image.nand_results->smc_size != 0) {
            image.smc =
                image.driver.read(image.nand_results->smc_offset, image.nand_results->smc_size);
            if (image.smc) {
                Log::Info("Parsed SMC from image at 0x{:x} (0x{:x} bytes)",
                          image.nand_results->smc_offset, image.smc->size());
            }
        }

        if (image.nand_results->mobile_results) {
            image.mobile_data =
                load_mobile_data_from_results(image.driver, *image.nand_results->mobile_results);
        }

        if (image.nand_results->fs_block_idx) {
            auto fs_driver = std::make_shared<gxbuild3::utils::FlashBlockDriver>(image.driver);
            std::shared_ptr<XeCoronaFsData> corona_data;
            if (image.corona_fs_data) {
                corona_data = std::make_shared<XeCoronaFsData>(*image.corona_fs_data);
            }
            gxbuild3::bootloaders::FlashFileSystem filesystem(fs_driver, corona_data);
            if (filesystem.load(*image.nand_results->fs_block_idx)) {
                image.flashfs_files = flashfs_files_t{};
                load_known_flashfs_files(filesystem, *image.flashfs_files);
                image.filesystem = std::move(filesystem);
            } else {
                Log::Warn("FlashImage::parse: Failed to load FlashFS at block 0x{:x}",
                          *image.nand_results->fs_block_idx);
            }
        }

        const auto& r = *image.nand_results;
        if (r.cb_or_a.offset != 0 && r.cb_or_a.size != 0) {
            image.cb_or_A = image.driver.read(r.cb_or_a.offset, r.cb_or_a.size);
        }
        if (r.cbx && r.cbx->offset != 0 && r.cbx->size != 0) {
            image.cb_X = image.driver.read(r.cbx->offset, r.cbx->size);
        }
        if (r.cbb && r.cbb->offset != 0 && r.cbb->size != 0) {
            image.cb_B = image.driver.read(r.cbb->offset, r.cbb->size);
        }
        if (r.sc && r.sc->offset != 0 && r.sc->size != 0) {
            image.sc = image.driver.read(r.sc->offset, r.sc->size);
        }
        if (r.cd && r.cd->offset != 0 && r.cd->size != 0) {
            image.cd = image.driver.read(r.cd->offset, r.cd->size);
        }
        if (r.ce && r.ce->offset != 0 && r.ce->size != 0) {
            image.ce = image.driver.read(r.ce->offset, r.ce->size);
        }
        if (r.cf0 && r.cf0->offset != 0 && r.cf0->size != 0) {
            if (!image.patchslot_0) image.patchslot_0.emplace();
            image.patchslot_0->cf = image.driver.read(r.cf0->offset, r.cf0->size);
            if (r.cg0 && r.cg0->offset != 0 && r.cg0->size != 0) {
                image.patchslot_0->cg = image.driver.read(r.cg0->offset, r.cg0->size);
            }
        }
        if (r.cf1 && r.cf1->offset != 0 && r.cf1->size != 0) {
            if (!image.patchslot_1) image.patchslot_1.emplace();
            image.patchslot_1->cf = image.driver.read(r.cf1->offset, r.cf1->size);
            if (r.cg1 && r.cg1->offset != 0 && r.cg1->size != 0) {
                image.patchslot_1->cg = image.driver.read(r.cg1->offset, r.cg1->size);
            }
        }
    }

    return image;
}

flash_image_t parse(const std::vector<uint8_t>& data) {
    return FlashImage::parse(std::vector<uint8_t>(data));
}

static bool WriteFile(const std::filesystem::path& path, std::span<const std::byte> data) {
    std::ofstream f(path, std::ios::binary);
    if (!f)
        return false;
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(f);
}

static std::span<const std::byte> AsByteSpan(const std::vector<uint8_t>& data) {
    return {reinterpret_cast<const std::byte*>(data.data()), data.size()};
}

bool extract_all(const flash_image_t& flash, const std::filesystem::path& output_dir,
                 const std::vector<uint8_t>& cpu_key_bytes,
                 const std::vector<uint8_t>& bl_key_bytes) {
    std::filesystem::create_directories(output_dir);

    const auto& driver = flash.driver;
    nand_results_t results{};
    if (flash.nand_results) {
        results = *flash.nand_results;
    } else {
        results = read(driver);
    }
    if (!results.valid) {
        Log::Error("Extraction failed: invalid NAND");
        return false;
    }

    auto extract_region = [&](uint32_t offset,
                              uint32_t size) -> std::optional<std::vector<uint8_t>> {
        if (offset == 0 || offset == 0xFFFFFFFF || size == 0)
            return std::nullopt;
        return driver.read(offset, size);
    };

    uint8_t cb_key[16] = {};
    uint8_t cb_b_key[16] = {};

    auto cb_bytes = extract_region(results.cb_or_a.offset, results.cb_or_a.size);
    if (cb_bytes) {
        auto cb = BootloaderCb::parse(*cb_bytes);
        if (!bl_key_bytes.empty())
            cb.decrypt(bl_key_bytes.data());

        const auto cb_serialized = cb.serialize();
        const std::string crypt_str = cb.is_decrypted() ? "dec" : "enc";
        const std::string type_str = results.cbb ? "cba" : "cb";
        const std::string filename = fmt::format("{}_{}_{}.bin", type_str, cb.header.header.version, crypt_str);
        WriteFile(output_dir / filename, AsByteSpan(cb_serialized));
        Log::Info("Extracted 2BL: {} (v{})", filename, cb.header.header.version);

        if (cb.is_decrypted() && cb.derived_key)
            std::memcpy(cb_key, cb.derived_key->data(), 16);
    }

    if (results.cbx) {
        auto cbx_bytes = extract_region(results.cbx->offset, results.cbx->size);
        if (cbx_bytes) {
            const std::string filename = "cbx_enc.bin";
            WriteFile(output_dir / filename, AsByteSpan(*cbx_bytes));
            Log::Info("Extracted 2BL_X: {}", filename);
        }
    }

    if (results.cbb && cb_bytes) {
        auto cbb_bytes = extract_region(results.cbb->offset, results.cbb->size);
        if (cbb_bytes) {
            auto cb_b = BootloaderCb::parse(*cbb_bytes);
            if (cb_key[0] != 0 && !cpu_key_bytes.empty()) {
                auto cb_a = BootloaderCb::parse(*cb_bytes);
                cb_b.decrypt_v2(cb_a.header, cb_key, cpu_key_bytes.data());
            }

            const auto cb_b_serialized = cb_b.serialize();
            const std::string crypt_str = cb_b.is_decrypted() ? "dec" : "enc";
            const std::string filename = fmt::format("cbb_{}_{}.bin", cb_b.header.header.version, crypt_str);
            WriteFile(output_dir / filename, AsByteSpan(cb_b_serialized));
            Log::Info("Extracted 2BL_B: {} (v{})", filename, cb_b.header.header.version);

            if (cb_b.is_decrypted() && cb_b.derived_key)
                std::memcpy(cb_b_key, cb_b.derived_key->data(), 16);
        }
    }

    std::optional<std::vector<uint8_t>> sc_bytes;
    if (results.sc) {
        sc_bytes = extract_region(results.sc->offset, results.sc->size);
    }
    uint8_t cd_key[16] = {};
    if (sc_bytes) {
        auto sc = BootloaderSc::parse(*sc_bytes);
        const uint8_t* active_cb_key = (cb_b_key[0] != 0) ? cb_b_key : cb_key;
        if (active_cb_key[0] != 0)
            sc.decrypt(active_cb_key);

        const auto sc_serialized = sc.serialize();
        const std::string crypt_str = sc.is_decrypted() ? "dec" : "enc";
        const std::string filename = fmt::format("sc_{}_{}.bin", sc.header.header.version, crypt_str);
        WriteFile(output_dir / filename, AsByteSpan(sc_serialized));
        Log::Info("Extracted 3BL/SC: {} (v{})", filename, sc.header.header.version);
    }

    uint8_t ce_key[16] = {};
    uint8_t cg_hmac[16] = {};

    if (results.cd) {
        auto cd_bytes = extract_region(results.cd->offset, results.cd->size);
        if (cd_bytes) {
            auto cd = BootloaderCd::parse(*cd_bytes);
            const uint8_t* active_cb_key = (cb_b_key[0] != 0) ? cb_b_key : cb_key;
            if (active_cb_key[0] != 0)
                cd.decrypt(active_cb_key);

            const auto cd_serialized = cd.serialize();
            const std::string crypt_str = cd.is_decrypted() ? "dec" : "enc";
            const std::string filename = fmt::format("cd_{}_{}.bin", cd.header.header.version, crypt_str);
            WriteFile(output_dir / filename, AsByteSpan(cd_serialized));
            Log::Info("Extracted 4BL/CD: {} (v{})", filename, cd.header.header.version);

            if (active_cb_key[0] != 0) {
                std::memcpy(cd_key, cd.header.rsa_pub_key, 16);
                ExCryptHmacSha(active_cb_key, 16, cd_key, 16, nullptr, 0, nullptr, 0, cd_key, 16);
            }
        }
    }

    if (results.ce) {
        auto ce_bytes = extract_region(results.ce->offset, results.ce->size);
        if (ce_bytes) {
            auto ce = BootloaderCe::parse(*ce_bytes);
            if (cd_key[0] != 0)
                ce.decrypt(cd_key);

            const auto ce_serialized = ce.serialize();
            const std::string crypt_str = ce.is_decrypted() ? "dec" : "enc";
            const std::string filename = fmt::format("ce_{}_{}.bin", ce.header.header.version, crypt_str);
            WriteFile(output_dir / filename, AsByteSpan(ce_serialized));
            Log::Info("Extracted 5BL/CE: {} (v{})", filename, ce.header.header.version);

            if (ce.is_decrypted())
                std::memcpy(ce_key, cd_key, 16);
        }
    }

    std::optional<BootloaderCf> cf_slot0;
    if (results.cf0) {
        auto cf_bytes = extract_region(results.cf0->offset, results.cf0->size);
        if (cf_bytes) {
            auto cf = BootloaderCf::parse(*cf_bytes);
            if (!bl_key_bytes.empty())
                cf.decrypt(bl_key_bytes.data());

            const auto cf_serialized = cf.serialize();
            const std::string crypt_str = cf.is_decrypted() ? "dec" : "enc";
            const std::string filename = fmt::format("cf0_{}_{}.bin", cf.header.header.version, crypt_str);
            WriteFile(output_dir / filename, AsByteSpan(cf_serialized));
            Log::Info("Extracted 6BL/CF Slot 0: {} (v{})", filename, cf.header.header.version);

            if (cf.is_decrypted())
                cf_slot0 = cf;
        }
    }

    if (cf_slot0) {
        std::memcpy(cg_hmac, cf_slot0->header.key, 16);
    }

    if (results.cg0) {
        auto cg_bytes = extract_region(results.cg0->offset, results.cg0->size);
        if (cg_bytes) {
            if (flash.filesystem) {
                const auto* sysupd_entry = flash.filesystem->find_file("sysupdate.xexp1");
                if (!sysupd_entry)
                    sysupd_entry = flash.filesystem->find_file("sysupdate.xexp");
                if (sysupd_entry) {
                    auto sysupd_data = flash.filesystem->get_file_data(*sysupd_entry);
                    if (sysupd_data && !sysupd_data->empty()) {
                        cg_bytes->insert(cg_bytes->end(), sysupd_data->begin(), sysupd_data->end());
                        Log::Info("Rejoined CG0 with {} (total size: 0x{:x})", sysupd_entry->filename, cg_bytes->size());
                    }
                }
            }

            auto cg = BootloaderCg::parse(*cg_bytes);
            cg.header.header.size = static_cast<uint32_t>(cg_bytes->size());
            if (cg_hmac[0] != 0)
                cg.decrypt(cg_hmac);

            const auto cg_serialized = cg.serialize();
            const std::string crypt_str = cg.is_decrypted() ? "dec" : "enc";
            const std::string filename = fmt::format("cg0_{}_{}.bin", cg.header.header.version, crypt_str);
            WriteFile(output_dir / filename, AsByteSpan(cg_serialized));
            Log::Info("Extracted 7BL/CG Slot 0: {} (v{})", filename, cg.header.header.version);
        }
    }

    if (results.cf1) {
        auto cf_bytes = extract_region(results.cf1->offset, results.cf1->size);
        if (cf_bytes) {
            try {
                auto cf = BootloaderCf::parse(*cf_bytes);
                if (!bl_key_bytes.empty())
                    cf.decrypt(bl_key_bytes.data());

                const auto cf_serialized = cf.serialize();
                const std::string crypt_str = cf.is_decrypted() ? "dec" : "enc";
                const std::string filename = fmt::format("cf1_{}_{}.bin", cf.header.header.version, crypt_str);
                WriteFile(output_dir / filename, AsByteSpan(cf_serialized));
                Log::Info("Extracted 6BL/CF Slot 1: {} (v{})", filename, cf.header.header.version);

                if (cf.is_decrypted())
                    std::memcpy(cg_hmac, cf.header.key, 16);
            } catch (const std::exception& ex) {
                Log::Warn("Failed to parse CF Slot 1: {}", ex.what());
            }
        }
    }

    if (results.cg1) {
        auto cg_bytes = extract_region(results.cg1->offset, results.cg1->size);
        if (cg_bytes) {
            try {
                if (flash.filesystem) {
                    const auto* sysupd_entry = flash.filesystem->find_file("sysupdate.xexp2");
                    if (sysupd_entry) {
                        auto sysupd_data = flash.filesystem->get_file_data(*sysupd_entry);
                        if (sysupd_data && !sysupd_data->empty()) {
                            cg_bytes->insert(cg_bytes->end(), sysupd_data->begin(), sysupd_data->end());
                            Log::Info("Rejoined CG1 with {} (total size: 0x{:x})", sysupd_entry->filename, cg_bytes->size());
                        }
                    }
                }

                auto cg = BootloaderCg::parse(*cg_bytes);
                cg.header.header.size = static_cast<uint32_t>(cg_bytes->size());
                if (cg_hmac[0] != 0)
                    cg.decrypt(cg_hmac);

                const auto cg_serialized = cg.serialize();
                const std::string crypt_str = cg.is_decrypted() ? "dec" : "enc";
                const std::string filename = fmt::format("cg1_{}_{}.bin", cg.header.header.version, crypt_str);
                WriteFile(output_dir / filename, AsByteSpan(cg_serialized));
                Log::Info("Extracted 7BL/CG Slot 1: {} (v{})", filename, cg.header.header.version);
            } catch (const std::exception& ex) {
                Log::Warn("Failed to parse CG Slot 1: {}", ex.what());
            }
        }
    }



    auto smc_bytes = extract_region(results.smc_offset, results.smc_size);
    if (smc_bytes) {
        const auto smc_dec = smc_decrypt(*smc_bytes);
        WriteFile(output_dir / "smc_dec.bin", AsByteSpan(smc_dec));
        WriteFile(output_dir / "smc_enc.bin", AsByteSpan(*smc_bytes));
        Log::Info("Extracted SMC: smc_dec.bin, smc_enc.bin");
    }

    if (results.smc_config_offset != 0 && results.smc_config_offset != 0xFFFFFFFF) {
        auto smc_cfg_bytes = extract_region(results.smc_config_offset, 0x10000);
        if (smc_cfg_bytes) {
            WriteFile(output_dir / "smc_config.bin", AsByteSpan(*smc_cfg_bytes));
            Log::Info("Extracted SMC Config: smc_config.bin");
        }
    }

    auto kv_bytes = extract_region(results.kv_offset, results.kv_size);
    if (kv_bytes) {
        WriteFile(output_dir / "kv_enc.bin", AsByteSpan(*kv_bytes));
        Log::Info("Extracted Keyvault: kv_enc.bin");
        if (!cpu_key_bytes.empty()) {
            try {
                const auto kv_dec = keyvault_decrypt(cpu_key_bytes, *kv_bytes);
                WriteFile(output_dir / "kv_dec.bin", AsByteSpan(kv_dec));
                Log::Info("Extracted decrypted Keyvault: kv_dec.bin");
            } catch (const std::exception& e) {
                Log::Warn("Failed to decrypt KV: {}", e.what());
            }
        }
    }

    if (flash.filesystem) {
        const auto fs_dir = output_dir / "fs";
        std::filesystem::create_directories(fs_dir);
        size_t count = 0;
        for (const auto& entry : flash.filesystem->entries()) {
            if (entry.filename[0] != '\0' && static_cast<uint8_t>(entry.filename[0]) != 0xFF &&
                entry.filename[0] != '$' && entry.is_valid()) {
                std::string fname{entry.filename};
                auto data = flash.filesystem->get_file_data(entry);
                if (data && !data->empty()) {
                    if (!cpu_key_bytes.empty() && (fname == "secdata.bin" || fname == "extended.bin")) {
                        crypt_secfile(cpu_key_bytes, *data);
                        Log::Info("Decrypted FlashFS secure file '{}' for extraction", fname);
                    }
                    WriteFile(fs_dir / fname, AsByteSpan(*data));
                    count++;
                } else {
                    Log::Warn("Skipped unreadable FlashFS file '{}'", fname);
                }
            }
        }
        Log::Info("Extracted {} FlashFS file(s) to 'fs/'", count);
    }

    return true;
}

bool write_build_mobile_data(flash_image_t& image, uint32_t base_fs_block,
                             uint16_t& written_mobile_blocks) {
    written_mobile_blocks = 0;
    if (!image.mobile_data) {
        return true;
    }

    const auto& data = *image.mobile_data;
    const uint32_t lil_block_length = image.driver.lil_block_length();
    if (lil_block_length == 0) {
        return true;
    }

    uint32_t current_block_idx = base_fs_block;

    for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
        const auto* data_slot =
            get_mobile_data_slot(const_cast<mobile_data_t&>(data), block_type);
        if (!data_slot || !(*data_slot) || (*data_slot)->empty()) {
            continue;
        }

        const auto& mobile_bytes = **data_slot;
        const uint32_t blocks_needed =
            ceil_div_u32(static_cast<uint32_t>(mobile_bytes.size()), lil_block_length);

        uint32_t sequence = 1;
        uint16_t data_length = static_cast<uint16_t>(mobile_bytes.size());
        if (image.nand_results && image.nand_results->mobile_results) {
            const auto* result_slot =
                get_mobile_result_slot(*image.nand_results->mobile_results, block_type);
            if (result_slot && *result_slot) {
                sequence = (*result_slot)->data_sequence;
                data_length = static_cast<uint16_t>((*result_slot)->data_length);
            }
        }

        Log::Info(
            "build: writing mobile 0x{:02x} len 0x{:x} to block 0x{:x} ({} blocks)...",
            block_type, mobile_bytes.size(), current_block_idx, blocks_needed);

        for (uint32_t b = 0; b < blocks_needed; ++b) {
            const size_t blk_offset = static_cast<size_t>(b) * lil_block_length;
            const size_t blk_size =
                std::min(static_cast<size_t>(lil_block_length), mobile_bytes.size() - blk_offset);

            if (!image.driver.write_logical_block(
                    current_block_idx + b, mobile_bytes.data() + blk_offset, blk_size,
                    block_type, sequence, data_length)) {
                Log::Error("build: failed to write mobile 0x{:02x} block 0x{:x}", block_type,
                           current_block_idx + b);
                return false;
            }
        }

        if (image.driver.flash_config() == gxbuild3::utils::FlashConfig::Corona4GB) {
            if (!const_cast<flash_image_t&>(image).corona_fs_data) {
                const_cast<flash_image_t&>(image).corona_fs_data = XeCoronaFsData{};
            }
            if (block_type == 0x31) {
                const_cast<flash_image_t&>(image).corona_fs_data->mobile1_block_idx =
                    static_cast<uint16_t>(current_block_idx);
                const_cast<flash_image_t&>(image).corona_fs_data->mobile1_length =
                    static_cast<uint16_t>(blocks_needed);
            } else if (block_type == 0x32) {
                const_cast<flash_image_t&>(image).corona_fs_data->mobile2_block_idx =
                    static_cast<uint16_t>(current_block_idx);
                const_cast<flash_image_t&>(image).corona_fs_data->mobile2_length =
                    static_cast<uint16_t>(blocks_needed);
            }
        }

        current_block_idx += blocks_needed;
        written_mobile_blocks += static_cast<uint16_t>(blocks_needed);
    }

    return true;
}

std::optional<std::vector<uint8_t>> build(const flash_image_t& image, BuildType build_type,
                                          std::optional<ConsoleType> console_type, bool nomobile,
                                          std::span<const uint8_t> cpu_key) {
    flash_image_t built = image;
    const bool had_backing_image = has_backing_image(image);

    Log::Info("build: starting {} image build{}", describe_build_type(build_type),
              had_backing_image ? " on parsed NAND" : " on synthesized NAND");
    log_staged_build_inputs(built, build_type);

    if (!ensure_build_backing_image(built, build_type, console_type)) {
        return std::nullopt;
    }

    uint32_t cursor = 0x8000;
    if (!write_build_bootloaders(built, build_type, cursor, cpu_key)) {
        return std::nullopt;
    }

    if (!write_build_jtag_payloads(built, build_type, cursor)) {
        return std::nullopt;
    }

    if (!write_build_addon_patches(built, build_type, cursor)) {
        return std::nullopt;
    }

    if (!write_build_xell(built, build_type, cursor)) {
        return std::nullopt;
    }

    const uint32_t lil_block_len = built.driver.lil_block_length();
    uint32_t base_fs_block = (lil_block_len > 0) ? ceil_div_u32(cursor, lil_block_len) : 0;

    uint16_t written_mobile_blocks = 0;
    if (nomobile) {
        Log::Info("build: nomobile option set to true, skipping mobile partitions");
    } else if (built.mobile_data) {
        if (!write_build_mobile_data(built, base_fs_block, written_mobile_blocks)) {
            return std::nullopt;
        }
    }

    uint16_t fs_root_block_idx = static_cast<uint16_t>(base_fs_block + written_mobile_blocks);
    if (nomobile && built.nand_results && built.nand_results->fs_block_idx) {
        fs_root_block_idx = *built.nand_results->fs_block_idx;
    }

    const auto payloads = collect_build_flashfs_payloads(built);
    if (payloads.empty() && had_backing_image && written_mobile_blocks == 0) {
        Log::Info("build: no FlashFS payload changes staged, returning rebuilt donor image");
        built.driver.recalculate_all_ecc();
        return built.driver.image_data();
    }

    const uint32_t fs_version = resolve_build_fs_version(built);
    const uint32_t sys_update_addr = resolve_build_sys_update_addr(built);
    log_flashfs_plan(built, payloads, fs_root_block_idx, fs_version, sys_update_addr);

    auto fs_driver = std::make_shared<gxbuild3::utils::FlashBlockDriver>(built.driver);
    std::shared_ptr<XeCoronaFsData> corona_data;
    if (built.driver.flash_config() == gxbuild3::utils::FlashConfig::Corona4GB) {
        if (built.corona_fs_data) {
            corona_data = std::make_shared<XeCoronaFsData>(*built.corona_fs_data);
        } else {
            corona_data = std::make_shared<XeCoronaFsData>();
        }
    }

    gxbuild3::bootloaders::FlashFileSystem filesystem(fs_driver, corona_data);

    Log::Info("Initializing FlashFS defaults at block 0x{:x}...", fs_root_block_idx);
    if (!filesystem.create_defaults(fs_root_block_idx, fs_version, sys_update_addr,
                                    built.xconfig.has_value())) {
        Log::Error("build: failed to initialize FlashFS defaults");
        return std::nullopt;
    }

    for (uint32_t i = 0; i < written_mobile_blocks; ++i) {
        const uint32_t mb_idx = base_fs_block + i;
        if (mb_idx < built.driver.lil_block_count()) {
            filesystem.allocate_blocks(1, static_cast<uint16_t>(mb_idx));
        }
    }

    Log::Info("Initializing FlashFS defaults at block 0x{:x}...done!", fs_root_block_idx);

    for (const auto& [filename, data] : payloads) {
        std::vector<uint8_t> file_data = data;
        if (!cpu_key.empty() && (filename == "secdata.bin" || filename == "extended.bin")) {
            crypt_secfile(cpu_key, file_data);
            Log::Info("build: applied CryptSecfile to FlashFS secure file '{}'", filename);
        }

        gxbuild3::bootloaders::FlashFileSystemEntry* entry = nullptr;
        Log::Info("Adding FlashFS file '{}'...", filename);
        if (!filesystem.add_file(filename, entry) || entry == nullptr) {
            Log::Error("build: failed to add FlashFS file '{}'", filename);
            return std::nullopt;
        }

        Log::Info("Writing FlashFS file '{}' len 0x{:x}...", filename, file_data.size());
        if (!filesystem.set_file_data(*entry, file_data)) {
            Log::Error("build: failed to write FlashFS file '{}'", filename);
            return std::nullopt;
        }
        Log::Info("Writing FlashFS file '{}' len 0x{:x}...done!", filename, file_data.size());
    }

    Log::Info("Saving FlashFS to block 0x{:x}...", fs_root_block_idx);
    if (!filesystem.save(fs_root_block_idx)) {
        Log::Error("build: failed to save FlashFS");
        return std::nullopt;
    }
    Log::Info("Saving FlashFS to block 0x{:x}...done!", fs_root_block_idx);

    built.driver = *fs_driver;

    if (built.driver.flash_config() == gxbuild3::utils::FlashConfig::Corona4GB) {
        auto& corona = filesystem.corona_data();
        if (corona) {
            write_corona_config_block(built.driver, *corona);
        }
    }

    built.driver.recalculate_all_ecc();

    Log::Info("build: image serialization complete (0x{:x} bytes)",
              built.driver.image_data().size());
    return built.driver.image_data();
}
