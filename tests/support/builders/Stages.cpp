#include "Stages.hpp"

#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <array>

namespace gxbuild3::test {

    using nand::BootloaderCb;
    using nand::BootloaderCd;
    using nand::BootloaderSc;
    using nand::cd_header;
    using nand::generic_header;
    using nand::Keyvault;
    using nand::keyvault_decrypt;
    using nand::keyvault_encrypt;
    using nand::NANDBootloaderMagic;
    using nand::sc_header;

    Bytes make_smc(uint8_t marker) {
        Bytes smc(0x300, marker);
        smc[0x100] = 0x10;
        return smc;
    }

    void mark_jtag_smc(Bytes& smc) {
        const Bytes mark{0xD0, 0x00, 0x00, 0x1B};
        std::copy(mark.begin(), mark.end(), smc.begin() + 0x200);
    }

    Bytes make_jtag_smc(uint8_t marker) {
        auto smc = make_smc(marker);
        mark_jtag_smc(smc);
        return smc;
    }

    Bytes clean_retail_smc() {
        Bytes smc(0x300, 0x11);
        smc[0x100] = 0x40;
        const std::array<uint8_t, 6> site{0x05, 0x6C, 0xE5, 0x2A, 0xB4, 0x05};
        std::copy(site.begin(), site.end(), smc.begin() + kSmcRebootSite);
        std::fill(smc.end() - 4, smc.end(), uint8_t{0});
        return smc;
    }

    Bytes canonical_keyvault(std::span<const uint8_t> cpu_key, Bytes plaintext) {
        return keyvault_decrypt(cpu_key, keyvault_encrypt(cpu_key, plaintext).value()).value();
    }

    Bytes canonical_keyvault_filled(std::span<const uint8_t> cpu_key, uint8_t marker) {
        return canonical_keyvault(cpu_key, Bytes(Keyvault::kSize, marker));
    }

    Bytes encrypted_keyvault(std::span<const uint8_t> cpu_key, uint8_t marker) {
        return keyvault_encrypt(cpu_key, canonical_keyvault_filled(cpu_key, marker)).value();
    }

    InputBootloaders valid_bootloaders() {
        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.data.resize(0x380, 0);
        cb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb.data.size());
        cb.decrypted = true;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + 0x20);
        cd.header.ce_hash[0] = 1;
        std::ranges::copy(gxbuild3::nand::kRomSalt6bl, cd.header.salt_6bl);
        cd.data.resize(0x20, 0x42);
        cd.decrypted = true;

        InputBootloaders bootloaders{};
        bootloaders.cb_or_a = cb.serialize();
        bootloaders.cd = cd.serialize();
        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.version = 1;
        sc.header.header.size = static_cast<uint32_t>(sizeof(sc_header) + 0x20);
        sc.data.assign(0x20, 0x53);
        sc.decrypted = true;
        bootloaders.sc = sc.serialize();
        return bootloaders;
    }

} // namespace gxbuild3::test
