#pragma once

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
    std::optional<Smc> smc;
    std::optional<Keyvault> keyvault;
    CbSection cb_section;
    KernelSection kernel_section;
    SystemUpdate system_update_0;
    SystemUpdate system_update_1;
    std::optional<SmcConfig> smc_config;
    std::optional<CoronaConfig> corona_config;
    std::optional<MobileData> mobile_data;
    std::optional<FlashFileSystem> filesystem;
    Payloads payloads;

    Driver flash_driver;

    static std::optional<FlashImage> read(std::vector<uint8_t> raw_image);
    bool parse();

    bool decrypt_all(std::span<const uint8_t> cpu_key);
    bool encrypt_all(std::span<const uint8_t> cpu_key);

    bool write_to_driver() const;
    [[nodiscard]] std::vector<uint8_t> write() const;
};

using cb_section = CbSection;
using kernel_section = KernelSection;
using system_update = SystemUpdate;
using payloads = Payloads;
using mobile_data = MobileData;
using flash_image = FlashImage;

} // namespace gxbuild3::NAND
