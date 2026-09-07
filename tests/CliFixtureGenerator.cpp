#include "BuildRunner.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
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

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + 0x20);
        cd.header.ce_hash[0] = 1;
        cd.data.resize(0x20, 0x42);
        cd.decrypted = true;

        InputBootloaders bootloaders{};
        bootloaders.cb_or_a = cb.serialize();
        bootloaders.cd = cd.serialize();
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
        !write_bytes(source / "cd.bin", bootloaders.cd) ||
        !write_text(root / "build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n")) {
        std::cerr << "could not write CLI integration fixture files\n";
        return 6;
    }
    return 0;
}
