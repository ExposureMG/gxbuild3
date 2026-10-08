#include "Inputs.hpp"

#include "Patchsets.hpp"
#include "Stages.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/SMC.hpp"
#include "support/Bytes.hpp"
#include "support/Keys.hpp"
#include "support/XeRsaTestKey.hpp"

#include <algorithm>
#include <iterator>
#include <string>

namespace gxbuild3::test {

    using nand::BootloaderCb;
    using nand::BootloaderCd;
    using nand::BootloaderCe;
    using nand::BootloaderCf;
    using nand::BootloaderCg;
    using nand::BootloaderSc;
    using nand::cd_header;
    using nand::ce_header;
    using nand::cf_header;
    using nand::cg_header;
    using nand::Driver;
    using nand::FlashImage;
    using nand::generic_header;
    using nand::key_1bl;
    using nand::Keyvault;
    using nand::MobileData;
    using nand::NANDBootloaderMagic;
    using nand::sc_header;
    using nand::Smc;

    Input fresh_input(ImageType image_type) {
        Input input{};
        const auto cpu_key = valid_cpu_key();
        input.image_type = image_type;
        input.metadata.cpu_key.assign(cpu_key.begin(), cpu_key.end());
        input.metadata.smc = make_smc(0x11);
        input.metadata.keyvault =
            canonical_keyvault(input.metadata.cpu_key, Bytes(Keyvault::kSize, 0x22));
        input.bootloaders = valid_bootloaders();
        return input;
    }

    Bytes valid_xell() {
        Bytes bytes(0x40000, 0);
        bytes[0] = 0x7F;
        bytes[1] = 'E';
        bytes[2] = 'L';
        bytes[3] = 'F';
        return bytes;
    }

    std::pair<Bytes, Bytes> valid_system_update(uint8_t marker) {
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.data.assign(0x340, marker);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = false;
        std::fill(std::begin(cf.header.fixpoint_nonce), std::end(cf.header.fixpoint_nonce),
                  static_cast<uint8_t>(marker + 1));

        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.version = 1;
        cg.header.source_size = 0;
        cg.data.assign(0x40, marker);
        cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg.data.size());
        cg.decrypted = false;
        return {cf.serialize(), cg.serialize()};
    }

    Result<std::optional<Bytes>> opened_cg(const Bytes& cf_bytes, const Bytes& cg_bytes) {
        auto cf = with_context(BootloaderCf::parse(cf_bytes), "opened_cg: CF");
        if (!cf) {
            return std::unexpected(std::move(cf.error()));
        }
        if (!cf->is_decrypted()) {
            if (auto opened = with_context(cf->decrypt(key_1bl), "opened_cg: CF"); !opened) {
                return std::unexpected(std::move(opened.error()));
            }
        }
        const auto key = cf->cg_key();
        if (!key || cg_bytes.size() < sizeof(cg_header)) {
            return std::optional<Bytes>{};
        }
        auto cg = with_context(BootloaderCg::parse(cg_bytes), "opened_cg: CG");
        if (!cg) {
            return std::unexpected(std::move(cg.error()));
        }
        if (!cg->decrypted) {
            if (auto opened = with_context(cg->decrypt(key->data()), "opened_cg: CG"); !opened) {
                return std::unexpected(std::move(opened.error()));
            }
        }
        auto opened = cg->serialize();
        std::fill(opened.begin() + 0x10, opened.begin() + 0x20, 0);
        return std::optional<Bytes>{std::move(opened)};
    }

    Result<Bytes> decrypted_cf(uint8_t lockdown_value, std::array<uint8_t, 3> pairing_data,
                               uint16_t source_version, uint16_t source_qfe,
                               uint16_t target_version, uint16_t target_qfe, uint32_t reserved,
                               uint32_t cg_size) {
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.header.source_version = source_version;
        cf.header.source_qfe = source_qfe;
        cf.header.target_version = target_version;
        cf.header.target_qfe = target_qfe;
        cf.header.reserved = reserved;
        cf.header.cg_size = cg_size;
        cf.data.assign(0x340, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = true;
        if (auto parsed = with_context(cf.parse_perbox(), "decrypted_cf"); !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }
        cf.perbox->lockdown_value = lockdown_value;
        std::copy(pairing_data.begin(), pairing_data.end(), cf.perbox->pairing_data);
        if (auto serialized = with_context(cf.serialize_perbox(), "decrypted_cf"); !serialized) {
            return std::unexpected(std::move(serialized.error()));
        }
        return cf.serialize();
    }

    Result<Bytes> make_donor(const Input& source,
                             std::initializer_list<std::pair<uint8_t, Bytes>> mobiles) {
        if (!source.metadata.smc || !source.metadata.keyvault || !source.bootloaders.sc) {
            return fail(ErrorCode::InvalidArgument,
                        "make_donor: the source needs an SMC, a keyvault and an SC");
        }
        FlashImage donor{};
        donor.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        auto smc = with_context(Smc::parse(*source.metadata.smc), "make_donor: SMC");
        if (!smc) {
            return std::unexpected(std::move(smc.error()));
        }
        donor.smc = std::move(*smc);
        auto keyvault =
            with_context(Keyvault::parse(*source.metadata.keyvault), "make_donor: keyvault");
        if (!keyvault) {
            return std::unexpected(std::move(keyvault.error()));
        }
        donor.keyvault = std::move(*keyvault);
        donor.keyvault->encrypted = false;
        if (auto sealed = with_context(donor.keyvault->encrypt(source.metadata.cpu_key),
                                       "make_donor: keyvault");
            !sealed) {
            return std::unexpected(std::move(sealed.error()));
        }
        auto cb = with_context(BootloaderCb::parse(source.bootloaders.cb_or_a), "make_donor: CB");
        if (!cb) {
            return std::unexpected(std::move(cb.error()));
        }
        donor.cb_section.cb_or_A = std::move(*cb);
        auto sc = with_context(BootloaderSc::parse(*source.bootloaders.sc), "make_donor: SC");
        if (!sc) {
            return std::unexpected(std::move(sc.error()));
        }
        donor.cb_section.sc = std::move(*sc);
        auto cd = with_context(BootloaderCd::parse(source.bootloaders.cd), "make_donor: CD");
        if (!cd) {
            return std::unexpected(std::move(cd.error()));
        }
        donor.kernel_section.cd = std::move(*cd);
        if (auto sealed = with_context(donor.encrypt_all(source.metadata.cpu_key), "make_donor");
            !sealed) {
            return std::unexpected(std::move(sealed.error()));
        }
        donor.mobile_data = MobileData{};
        for (const auto& [block_type, bytes] : mobiles) {
            auto* slot = donor.mobile_data->get_slot(block_type);
            if (slot == nullptr) {
                return fail(ErrorCode::InvalidArgument, "make_donor: no mobile slot 0x{:02X}",
                            block_type);
            }
            *slot = bytes;
        }
        return with_context(donor.write(), "make_donor: write");
    }

    Bytes valid_ce() {
        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 1;
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + 0x20);
        std::fill(std::begin(ce.header.key), std::end(ce.header.key), uint8_t{0x55});
        ce.data.assign(0x20, 0xCE);
        ce.decrypted = true;
        return ce.serialize();
    }

    BootloaderNonce filled_nonce(uint8_t value) {
        BootloaderNonce nonce{};
        nonce.fill(value);
        return nonce;
    }

    Bytes nonce_bytes(std::span<const uint8_t> bytes) {
        return Bytes(bytes.begin(), bytes.begin() + 0x10);
    }

    InputBootloaders devkit_bootloaders() {
        BootloaderCb sb{};
        sb.header.header.magic = NANDBootloaderMagic::SB;
        sb.header.header.version = 10375;
        // Long enough to hold a whole CB header, so its per-box block reads back.
        sb.data.assign(0x400, 0);
        std::fill(sb.data.begin() + 0x100, sb.data.end(), 0x5B);
        sb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + sb.data.size());
        sb.decrypted = true;

        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.version = 17489;
        sc.data.assign(0x48, 0x5C);
        sc.header.header.size = static_cast<uint32_t>(sizeof(sc_header) + sc.data.size());
        sc.decrypted = true;

        BootloaderCd sd{};
        sd.header.header.magic = NANDBootloaderMagic::SD;
        sd.header.header.version = 17489;
        sd.data.assign(0x30, 0x5D);
        sd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + sd.data.size());
        sd.decrypted = true;

        BootloaderCe se{};
        se.header.header.magic = NANDBootloaderMagic::SE;
        se.header.header.version = 17489;
        se.data.assign(0x42, 0x5E);
        se.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + se.data.size());
        se.decrypted = true;

        InputBootloaders bootloaders{};
        bootloaders.cb_or_a = sb.serialize();
        bootloaders.sc = sc.serialize();
        bootloaders.cd = sd.serialize();
        bootloaders.ce = se.serialize();
        return bootloaders;
    }

    Input devkit_input(ImageType image_type) {
        auto input = fresh_input(image_type);
        input.build_type = BuildType::Devkit;
        input.console = ConsoleType::Jasper;
        input.bootloaders = devkit_bootloaders();
        input.metadata.pairing_data = {0x12, 0x34, 0x56};
        return input;
    }

    Bytes devgl_khv() {
        Bytes khv;
        append_be32(khv, 0x00001000);
        append_be32(khv, 2);
        append_be32(khv, 0x60000000);
        append_be32(khv, 0x4E800020);
        return khv;
    }

    uint32_t devgl_sd_patch_address(const Input& input) {
        return static_cast<uint32_t>(input.bootloaders.cd.size() + 0x10);
    }

    Input devgl_input(ImageType image_type) {
        auto input = devkit_input(image_type);
        input.build_type = BuildType::Devgl;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"patches_g2mjasper.bin",
                           glitch_patchset(0x20, 0xA1B2C3D4, devgl_sd_patch_address(input),
                                           0x10203040, devgl_khv())};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.fuses = Bytes(0x60, 0xF5);
        input.payloads = std::move(payloads);
        input.sb_private_key = xe_rsa::shared_private_key();
        return input;
    }

    DonorNonces pinned_donor_nonces() {
        DonorNonces nonces{};
        nonces.stages = {filled_nonce(0xA1), filled_nonce(0xA2), filled_nonce(0xA3),
                         filled_nonce(0xA4)};
        nonces.cf = filled_nonce(0xB1);
        nonces.cg = filled_nonce(0xC1);
        return nonces;
    }

    Input digest_input(ImageType image_type, BuildType build_type) {
        Input input{};
        switch (build_type) {
            case BuildType::Devkit:
                input = devkit_input(image_type);
                break;
            case BuildType::Devgl:
                input = devgl_input(image_type);
                break;
            case BuildType::Glitch2: {
                input = fresh_input(image_type);
                input.build_type = BuildType::Glitch2;
                input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                input.bootloaders.ce = valid_ce();
                const auto [cf, cg] = valid_system_update(0x61);
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                InputPatches patches{};
                patches.automatic = InputPatchFile{
                    "automatic", glitch_patchset(0x20, 0xA1B2C3D4, 0x30, 0x10203040, Bytes{0xA5})};
                input.patches = std::move(patches);
                InputPayloads payloads{};
                payloads.xell = valid_xell();
                input.payloads = std::move(payloads);
                break;
            }
            default: {
                input = fresh_input(image_type);
                input.build_type = build_type;
                input.bootloaders.ce = valid_ce();
                const auto [cf, cg] = valid_system_update(0x51);
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                break;
            }
        }
        input.metadata.donor_nonces = pinned_donor_nonces();
        return input;
    }

    Bytes invalid_cpu_key() {
        return Bytes(16, 0xFF);
    }

    Input glitch_input(BuildType build_type, Bytes patchset) {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = build_type;
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", std::move(patchset)};
        input.patches = std::move(patches);
        return input;
    }

    Input jtag_input(Bytes section4) {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        input.metadata.smc = make_jtag_smc(0x11);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(section4)};
        input.patches = std::move(patches);
        return input;
    }

} // namespace gxbuild3::test
