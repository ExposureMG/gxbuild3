#include "nand/FlashImage.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::NAND::FlashImage;

    constexpr std::array<uint8_t, 16> kCpuKey{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0xe5, 0x8d,
    };

    std::optional<Bytes> read_bytes(const std::filesystem::path& path) {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if (!input) {
            return std::nullopt;
        }
        const auto end = input.tellg();
        if (end < 0) {
            return std::nullopt;
        }
        Bytes bytes(static_cast<size_t>(end));
        input.seekg(0, std::ios::beg);
        if (!bytes.empty()) {
            input.read(reinterpret_cast<char*>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()));
        }
        if (!input) {
            return std::nullopt;
        }
        return bytes;
    }

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "output verification failed: " << message << '\n';
        }
        return condition;
    }

    template <typename Bootloader>
    bool verify_stage(std::string_view name, const Bootloader* stage,
                      NANDBootloaderMagic expected_magic, uint16_t expected_version) {
        if (!require(stage != nullptr, std::string(name) + " is absent")) {
            return false;
        }
        return require(!stage->data.empty(), std::string(name) + " has no payload") &&
               require(stage->header.header.magic == expected_magic,
                       std::string(name) + " has the wrong magic") &&
               require(stage->is_decrypted(), std::string(name) + " is not decrypted") &&
               require(stage->header.header.version == expected_version,
                       std::string(name) + " has the wrong version");
    }

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: gxbuild3_cli_output_verifier <built-nand>\n";
        return 2;
    }

    const auto bytes = read_bytes(argv[1]);
    if (!require(bytes.has_value(), "could not read the built NAND")) {
        return 3;
    }
    auto image = FlashImage::read(*bytes);
    if (!require(image.has_value(), "FlashImage::read rejected the built NAND")) {
        return 4;
    }
    if (!require(image->parse(), "FlashImage::parse rejected the built NAND")) {
        return 5;
    }
    if (!require(image->decrypt_all(kCpuKey), "FlashImage::decrypt_all failed")) {
        return 6;
    }

    bool valid = true;
    valid = verify_stage("CB", &image->cb_section.cb_or_A, NANDBootloaderMagic::CB, 1) && valid;
    valid = verify_stage("SC", image->cb_section.sc ? &*image->cb_section.sc : nullptr,
                         NANDBootloaderMagic::SC, 2) && valid;
    valid = verify_stage("CD", &image->kernel_section.cd, NANDBootloaderMagic::CD, 3) && valid;
    valid = verify_stage("CE", image->kernel_section.ce ? &*image->kernel_section.ce : nullptr,
                         NANDBootloaderMagic::CE, 4) && valid;
    valid = verify_stage("CF0", image->system_update_0.cf ? &*image->system_update_0.cf : nullptr,
                         NANDBootloaderMagic::CF, 5) && valid;
    valid = verify_stage("CG0", image->system_update_0.cg ? &*image->system_update_0.cg : nullptr,
                         NANDBootloaderMagic::CG, 6) && valid;
    valid = verify_stage("CF1", image->system_update_1.cf ? &*image->system_update_1.cf : nullptr,
                         NANDBootloaderMagic::CF, 7) && valid;
    valid = verify_stage("CG1", image->system_update_1.cg ? &*image->system_update_1.cg : nullptr,
                         NANDBootloaderMagic::CG, 8) && valid;

    valid = require(image->filesystem.has_value(), "FlashFS is absent") && valid;
    if (image->filesystem) {
        const auto file = image->filesystem->get_file("validation.bin");
        const Bytes expected{0x47, 0x58, 0x42, 0x33, 0x00, 0xff, 0x10, 0x7e};
        valid = require(file.has_value(), "FlashFS validation.bin is absent") && valid;
        valid = require(file == expected, "FlashFS validation.bin bytes differ") && valid;
    }

    return valid ? 0 : 7;
}
