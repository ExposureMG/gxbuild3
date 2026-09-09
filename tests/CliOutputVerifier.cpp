#include "nand/FlashImage.hpp"

#include <algorithm>
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

    template <typename Bootloader>
    bool verify_literal_payload(std::string_view name, const Bootloader* stage,
                                size_t expected_size, uint8_t expected_byte) {
        if (stage == nullptr) {
            return false;
        }
        return require(stage->data.size() == expected_size,
                       std::string(name) + " has the wrong plaintext payload size") &&
               require(std::all_of(stage->data.begin(), stage->data.end(),
                                   [expected_byte](uint8_t byte) {
                                       return byte == expected_byte;
                                   }),
                       std::string(name) + " has the wrong plaintext payload bytes");
    }

    bool verify_cf_plaintext(std::string_view name, const BootloaderCf* stage,
                             uint8_t expected_cg_key_byte, uint8_t expected_marker) {
        if (stage == nullptr) {
            return false;
        }
        return require(std::all_of(std::begin(stage->header.cg_key),
                                   std::end(stage->header.cg_key),
                                   [expected_cg_key_byte](uint8_t byte) {
                                       return byte == expected_cg_key_byte;
                                   }),
                       std::string(name) + " has the wrong CG key") &&
               require(stage->data.size() == 0x200,
                       std::string(name) + " has the wrong plaintext payload size") &&
               require(stage->data[0] == 0x00 && stage->data[1] == 0x00 &&
                           stage->data[2] == expected_marker &&
                           std::all_of(stage->data.begin() + 3,
                                       stage->data.begin() + 0x1C0,
                                       [](uint8_t byte) { return byte == 0x00; }),
                       std::string(name) + " has the wrong plaintext payload prefix");
    }

    bool verify_cg_plaintext(std::string_view name, const BootloaderCg* stage,
                             uint8_t expected_marker) {
        if (stage == nullptr) {
            return false;
        }
        return require(stage->header.source_size == 0x1000,
                       std::string(name) + " has the wrong plaintext source size") &&
               verify_literal_payload(name, stage, 0x40, expected_marker);
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

    valid = verify_literal_payload("CB", &image->cb_section.cb_or_A, 0x380, 0x00) && valid;
    valid = verify_literal_payload("SC", image->cb_section.sc ? &*image->cb_section.sc : nullptr,
                                   0x20, 0x53) && valid;
    valid = verify_literal_payload("CD", &image->kernel_section.cd, 0x20, 0x42) && valid;
    valid = verify_literal_payload("CE", image->kernel_section.ce ? &*image->kernel_section.ce
                                                                  : nullptr,
                                   0x20, 0x45) && valid;
    valid = verify_cf_plaintext("CF0", image->system_update_0.cf
                                           ? &*image->system_update_0.cf
                                           : nullptr,
                                0x50, 0x50) && valid;
    valid = verify_cg_plaintext("CG0", image->system_update_0.cg
                                           ? &*image->system_update_0.cg
                                           : nullptr,
                                0x60) && valid;
    valid = verify_cf_plaintext("CF1", image->system_update_1.cf
                                           ? &*image->system_update_1.cf
                                           : nullptr,
                                0x70, 0x70) && valid;
    valid = verify_cg_plaintext("CG1", image->system_update_1.cg
                                           ? &*image->system_update_1.cg
                                           : nullptr,
                                0x80) && valid;

    valid = require(image->filesystem.has_value(), "FlashFS is absent") && valid;
    if (image->filesystem) {
        const auto file = image->filesystem->get_file("validation.bin");
        const Bytes expected{0x47, 0x58, 0x42, 0x33, 0x00, 0xff, 0x10, 0x7e};
        valid = require(file.has_value(), "FlashFS validation.bin is absent") && valid;
        valid = require(file == expected, "FlashFS validation.bin bytes differ") && valid;
    }

    return valid ? 0 : 7;
}
