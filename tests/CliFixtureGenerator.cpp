#include "BuildRunner.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/Keyvault.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::NAND::Keyvault;

    constexpr std::array<uint8_t, 16> kCpuKey{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0xe5, 0x8d,
    };

    bool write_bytes(const std::filesystem::path& path, std::span<const uint8_t> bytes) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) {
            return false;
        }
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        return output.good();
    }

    bool write_text(const std::filesystem::path& path, std::string_view text) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) {
            return false;
        }
        output << text;
        return output.good();
    }

    InputBootloaders valid_bootloaders() {
        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.data.resize(0x380, 0);
        cb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb.data.size());
        cb.decrypted = true;

        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.version = 2;
        sc.header.header.size = static_cast<uint32_t>(sizeof(sc_header) + 0x20);
        sc.data.assign(0x20, 0x53);
        sc.decrypted = true;
        auto cb_for_sc_key = cb;
        cb_for_sc_key.encrypt(key_1bl);
        if (!cb_for_sc_key.derived_key) {
            return {};
        }
        sc.encrypt(cb_for_sc_key.derived_key->data());

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 3;
        cd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + 0x20);
        cd.header.ce_hash[0] = 1;
        cd.data.resize(0x20, 0x42);
        cd.decrypted = true;

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 4;
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + 0x20);
        ce.data.assign(0x20, 0x45);
        ce.decrypted = true;

        const auto make_cf = [](uint16_t version, uint8_t marker) {
            BootloaderCf cf{};
            cf.header.header.magic = NANDBootloaderMagic::CF;
            cf.header.header.version = version;
            cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + 0x200);
            std::fill(std::begin(cf.header.cg_key), std::end(cf.header.cg_key), marker);
            cf.data.assign(0x200, 0);
            cf.data[2] = marker;
            cf.decrypted = true;
            return cf;
        };
        const auto make_cg = [](uint16_t version, uint8_t marker) {
            BootloaderCg cg{};
            cg.header.header.magic = NANDBootloaderMagic::CG;
            cg.header.header.version = version;
            cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + 0x40);
            cg.header.source_size = 0x1000;
            cg.data.assign(0x40, marker);
            cg.decrypted = true;
            return cg;
        };

        auto cf0 = make_cf(5, 0x50);
        auto cg0 = make_cg(6, 0x60);
        cg0.encrypt(cf0.header.cg_key);
        auto cf1 = make_cf(7, 0x70);
        auto cg1 = make_cg(8, 0x80);
        cg1.encrypt(cf1.header.cg_key);

        InputBootloaders bootloaders{};
        bootloaders.cb_or_a = cb.serialize();
        bootloaders.sc = sc.serialize();
        bootloaders.cd = cd.serialize();
        bootloaders.ce = ce.serialize();
        bootloaders.cf0 = cf0.serialize();
        bootloaders.cg0 = cg0.serialize();
        bootloaders.cf1 = cf1.serialize();
        bootloaders.cg1 = cg1.serialize();
        return bootloaders;
    }

    std::optional<Bytes> donor_nand(const InputBootloaders& bootloaders) {
        Input input{};
        input.image_type = ImageType::SmallBlock;
        input.metadata.cpu_key.assign(kCpuKey.begin(), kCpuKey.end());
        input.metadata.smc = Bytes(0x300, 0x61);
        (*input.metadata.smc)[0x100] = 0x10;
        input.metadata.keyvault = keyvault_decrypt(
            kCpuKey, keyvault_encrypt(kCpuKey, Bytes(Keyvault::kSize, 0x72)));
        input.bootloaders = bootloaders;

        const auto built = RunBuild(input);
        if (!built) {
            return std::nullopt;
        }
        return *built;
    }

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: gxbuild3_cli_fixture_generator <fixture-root>\n";
        return 2;
    }
    if (!gxbuild3::NAND::cpukey_valid(kCpuKey)) {
        std::cerr << "fixture CPU key is invalid\n";
        return 3;
    }

    const std::filesystem::path root(argv[1]);
    const std::filesystem::path source = root / "source";
    std::error_code error;
    std::filesystem::create_directories(source, error);
    if (error) {
        std::cerr << "could not create fixture source directory: " << error.message() << '\n';
        return 4;
    }

    const auto bootloaders = valid_bootloaders();
    const auto donor = donor_nand(bootloaders);
    if (!donor) {
        std::cerr << "could not create fixture donor NAND\n";
        return 5;
    }
    if (!write_bytes(root / "donor-nand.bin", *donor) ||
        !write_bytes(source / "cb_1.bin", bootloaders.cb_or_a) ||
        !write_bytes(source / "sc.bin", *bootloaders.sc) ||
        !write_bytes(source / "cd.bin", bootloaders.cd) ||
        !write_bytes(source / "ce.bin", *bootloaders.ce) ||
        !write_bytes(source / "cf_1.bin", *bootloaders.cf0) ||
        !write_bytes(source / "cg_1.bin", *bootloaders.cg0) ||
        !write_bytes(source / "cf_2.bin", *bootloaders.cf1) ||
        !write_bytes(source / "cg_2.bin", *bootloaders.cg1) ||
        !write_bytes(source / "validation.bin",
                     std::array<uint8_t, 8>{0x47, 0x58, 0x42, 0x33, 0x00, 0xff, 0x10, 0x7e}) ||
        !write_text(root / "build.ini",
                    "[falconbl]\ncb_1.bin\nsc.bin\ncd.bin\nce.bin\ncf_1.bin\ncg_1.bin\n"
                    "cf_2.bin\ncg_2.bin\n[flashfs]\nvalidation.bin\n")) {
        std::cerr << "could not write CLI integration fixture files\n";
        return 6;
    }
    return 0;
}
