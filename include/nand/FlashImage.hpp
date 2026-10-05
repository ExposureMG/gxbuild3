#pragma once

#include "Args.hpp"
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
#include "nand/FlashDriver.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace gxbuild3::NAND {

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
        std::vector<uint16_t> cg_spill_blocks; // Logical 16 KiB clusters from CF + 0x32.
    };

    struct Payloads {
        std::optional<XeLL> xell;
        std::optional<std::vector<uint8_t>> fuses;
        std::optional<std::vector<uint8_t>> payload;
        std::optional<std::vector<uint8_t>> rebooter;
        std::optional<ParsedPatchSet> patchset;
        std::optional<BootloaderCb> extra_cb;
        std::optional<BootloaderCd> extra_cd;
    };

    struct FlashImage {
        nand_header header;
        bool preserve_layout = false; // Direct read/write retains header-defined update anchors.
        std::optional<BuildType> build_type; // Runtime layout; inferred conservatively when reading.
        std::optional<Smc> smc;
        std::optional<Keyvault> keyvault;
        CbSection cb_section;
        KernelSection kernel_section;
        SystemUpdate system_update_0;
        SystemUpdate system_update_1;
        // The console's 0x400-byte settings block (fan curves, MAC, regions), carried as bytes.
        // Only a block whose own head checksum holds is kept.
        std::optional<std::vector<uint8_t>> smc_config;
        // The statistics and manufacturing blocks, one and two erase blocks below the settings
        // block: 0x1000 bytes each, carried as bytes. All 0xFF where the console keeps none, which
        // the writer leaves erased.
        std::optional<std::vector<uint8_t>> statistics;
        std::optional<std::vector<uint8_t>> manufacturing;
        std::optional<CoronaConfig> corona_config;
        std::optional<MobileData> mobile_data;
        std::optional<FlashFileSystem> filesystem;
        Payloads payloads;
        // Written as they are at their clean offsets after everything else is laid.
        std::vector<InputRawPatch> raw_patches;

        Driver flash_driver;

        static std::optional<FlashImage> read(std::vector<uint8_t> raw_image);
        bool parse();

        // A devkit chain: SB, SC, SD and SE, held in the CB, SC, CD and CE positions. SB is keyed
        // from the 1BL key like a single CB, SC from sixteen zero bytes, SD from SC and SE from SD.
        [[nodiscard]] bool devkit_chain() const;

        bool decrypt_all(std::span<const uint8_t> cpu_key);
        // Hacked chains may deliberately leave stages plaintext for their patched parent.
        bool encrypt_all(std::span<const uint8_t> cpu_key, BuildType build_type = BuildType::Retail);

        // Remove serialized bootloader records inherited from a donor before replacing the chain:
        // the chain is zeroed and the CF/CG records in the update slots are erased (0xFF). This
        // deliberately leaves the donor's non-bootloader payloads intact.
        bool clear_bootloader_chain();

        [[nodiscard]] std::vector<BlockRange> active_payload_block_ranges() const;

        // The clean offset just past the second update slot, where the image writer would lay
        // them now.
        [[nodiscard]] uint32_t update_slots_end() const;
        // The clean offset of the second update slot, which a glitch or devgl image fills with its
        // KHV patches.
        [[nodiscard]] uint32_t patch_slot_offset() const;

        // Describes a collision between payload writers, if the resolved layout is unsafe.
        [[nodiscard]] std::optional<std::string> payload_layout_error() const;

        // Lays the image into the driver. Unless preserve_layout is set (a parsed dump written
        // back), every good block is erased first, so what the writer does not lay stays erased.
        bool write_to_driver() const;
        [[nodiscard]] std::vector<uint8_t> write() const;
    };

    // Whether update slot `slot` carries the console: its slot number at 0x21B, pairing, LDV and
    // the CPU-key binding at 0x220. A JTAG image's first pair is the one its exploit boots: its CF
    // keeps the per-box block it was supplied with (xeBuild 1.21 JTAG: CF 4532, 0x21B..0x22F zero).
    [[nodiscard]] constexpr bool update_slot_binds_console(BuildType build_type, size_t slot) {
        return !(build_type == BuildType::Jtag && slot == 0);
    }

    using cb_section = CbSection;
    using kernel_section = KernelSection;
    using system_update = SystemUpdate;
    using payloads = Payloads;
    using mobile_data = MobileData;
    using flash_image = FlashImage;

} // namespace gxbuild3::NAND
