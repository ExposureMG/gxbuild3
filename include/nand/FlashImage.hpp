#pragma once

#include "core/Args.hpp"
#include "gxbuild/Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/XConfig.hpp"
#include "nand/objects/XeLL.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild::nand {

    enum class BootStageId : uint8_t { CbA, CbX, CbB, Sc, Cd, Ce };

    struct CbSection {
        BootloaderCb cb_or_A;
        std::optional<BootloaderCb> cb_x;
        std::optional<BootloaderCb> cb_B;
        std::optional<BootloaderSc> sc;
    };

    struct KernelSection {
        BootloaderCd cd;
        std::optional<BootloaderCe> ce;
    };

    struct SystemUpdate {
        std::optional<BootloaderCf> cf;
        std::optional<BootloaderCg> cg;
        std::vector<uint16_t> cg_spill_blocks{};
    };

    struct Payloads {
        std::optional<XeLL> xell;
        std::optional<std::vector<uint8_t>> fuses;
        std::optional<std::vector<uint8_t>> payload;
        std::optional<std::vector<uint8_t>> rebooter;
        std::optional<ParsedPatchSet> patchset;
        std::optional<BootloaderCb> extra_cb;
        std::optional<BootloaderCd> extra_cd;
        std::optional<BootloaderCe> extra_se;
    };

    struct FlashImage {
        nand_header header;
        bool preserve_layout = false;
        std::optional<BuildType>
            build_type;
        std::optional<Smc> smc;
        std::optional<Keyvault> keyvault;
        CbSection cb_section;
        KernelSection kernel_section;
        SystemUpdate system_update_0;
        SystemUpdate system_update_1;
        std::optional<SmcConfigBlock> smc_config;
        std::optional<StatisticsBlock> statistics;
        std::optional<ManufacturingBlock> manufacturing;
        std::optional<CoronaConfig> corona_config;
        std::optional<MobileData> mobile_data;
        std::optional<FlashFileSystem> filesystem;
        Payloads payloads;
        std::vector<InputRawPatch> raw_patches;

        Driver flash_driver;

        static std::optional<FlashImage> read(std::vector<uint8_t> raw_image);
        static FlashImage create(Driver::ImageSize size, Driver::DriverMode mode,
                                 std::optional<BuildType> type = std::nullopt);
        [[nodiscard]] Result<void> parse();

        template <class Self, class Fn>
        static void for_each_present_stage(Self& image, Fn&& fn) {
            if (!image.cb_section.cb_or_A.data.empty()) {
                fn(BootStageId::CbA, std::string_view{"CB_A"}, image.cb_section.cb_or_A);
            }
            if (image.cb_section.cb_x) {
                fn(BootStageId::CbX, std::string_view{"CB_X"}, *image.cb_section.cb_x);
            }
            if (image.cb_section.cb_B) {
                fn(BootStageId::CbB, std::string_view{"CB_B"}, *image.cb_section.cb_B);
            }
            if (image.cb_section.sc) {
                fn(BootStageId::Sc, std::string_view{"SC"}, *image.cb_section.sc);
            }
            if (!image.kernel_section.cd.data.empty()) {
                fn(BootStageId::Cd, std::string_view{"CD"}, image.kernel_section.cd);
            }
            if (image.kernel_section.ce) {
                fn(BootStageId::Ce, std::string_view{"CE"}, *image.kernel_section.ce);
            }
        }

        [[nodiscard]] bool devkit_chain() const;

        [[nodiscard]] Result<void> decrypt_all(std::span<const uint8_t> cpu_key);
        [[nodiscard]] Result<void> encrypt_all(std::span<const uint8_t> cpu_key,
                                               BuildType seal_type = BuildType::Retail);

        [[nodiscard]] Result<void> clear_bootloader_chain();
        [[nodiscard]] std::optional<DonorNonces> collect_nonces() const;
        [[nodiscard]] Result<void>
        apply_nonces(const std::optional<DonorNonces>& donor = std::nullopt);
        [[nodiscard]] Result<void> apply_bootloader_metadata(const InputMetadata& metadata,
                                                             BuildType target_type);

        [[nodiscard]] std::vector<BlockRange> active_payload_block_ranges() const;

        [[nodiscard]] uint32_t update_slots_end() const;
        [[nodiscard]] uint32_t patch_slot_offset() const;

        [[nodiscard]] Result<void> payload_layout() const;

        [[nodiscard]] Result<FlashFileSystem*> format_filesystem(uint32_t timestamp = 0);

        [[nodiscard]] Result<void> write_to_driver();
        [[nodiscard]] Result<std::vector<uint8_t>> write();
    };

    // jtag leaves update slot 0 unbound with zeroed per-box data
    [[nodiscard]] constexpr bool update_slot_binds_console(BuildType build_type, size_t slot) {
        return !(build_type == BuildType::Jtag && slot == 0);
    }

} // namespace gxbuild::nand
