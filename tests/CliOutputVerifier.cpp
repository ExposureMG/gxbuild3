#include "nand/FlashImage.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;
    using Nonce = std::array<uint8_t, 16>;
    using gxbuild3::nand::FlashImage;

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
                                   [expected_byte](uint8_t byte) { return byte == expected_byte; }),
                       std::string(name) + " has the wrong plaintext payload bytes");
    }

    // Without a donor the CF fixpoint nonce is not predictable, so only the payload is checked.
    // The fixture CF carries its marker at payload +2, inside the CG continuation table, and
    // `marker ^ 0xFF` as its 7BL nonce at payload +0x300. A CG that fits behind its CF has the
    // whole continuation table cleared by the build (FlashImageCrypt.cpp prepare_cg_tail), so
    // the marker must be gone, and the 7BL nonce identifies which source CF reached the slot.
    bool verify_cf_plaintext(std::string_view name, const BootloaderCf* stage,
                             const std::optional<Nonce>& expected_fixpoint_nonce,
                             uint8_t expected_marker) {
        if (stage == nullptr) {
            return false;
        }
        const auto is_zero = [](uint8_t byte) { return byte == 0x00; };
        const auto expected_7bl_byte = static_cast<uint8_t>(expected_marker ^ 0xFF);
        return require(!expected_fixpoint_nonce ||
                           std::equal(std::begin(stage->header.fixpoint_nonce),
                                      std::end(stage->header.fixpoint_nonce),
                                      expected_fixpoint_nonce->begin(),
                                      expected_fixpoint_nonce->end()),
                       std::string(name) + " has the wrong CF fixpoint nonce") &&
               require(stage->data.size() == 0x340,
                       std::string(name) + " has the wrong plaintext payload size") &&
               require(std::all_of(stage->data.begin(), stage->data.begin() + 0x1C0, is_zero),
                       std::string(name) + " has an uncleared CG continuation table") &&
               require(
                   std::all_of(stage->data.begin() + 0x200, stage->data.begin() + 0x300, is_zero) &&
                       std::all_of(stage->data.begin() + 0x300, stage->data.begin() + 0x310,
                                   [expected_7bl_byte](uint8_t byte) {
                                       return byte == expected_7bl_byte;
                                   }) &&
                       std::all_of(stage->data.begin() + 0x310, stage->data.end(), is_zero),
                   std::string(name) + " has the wrong plaintext payload (7BL nonce)");
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

    // Reads, parses and decrypts a NAND under the fixture CPU key; on failure prints why and
    // returns the exit code for the step that failed (3 read, 4 FlashImage::read, 5 parse,
    // 6 decrypt_all).
    std::optional<FlashImage> open_image(const char* path, std::string_view what, int& exit_code) {
        const auto bytes = read_bytes(path);
        if (!require(bytes.has_value(), "could not read the " + std::string(what))) {
            exit_code = 3;
            return std::nullopt;
        }
        auto image = FlashImage::read(*bytes);
        if (!require(image.has_value(), "FlashImage::read rejected the " + std::string(what))) {
            exit_code = 4;
            return std::nullopt;
        }
        if (!require(image->parse().has_value(),
                     "FlashImage::parse rejected the " + std::string(what))) {
            exit_code = 5;
            return std::nullopt;
        }
        if (!require(image->decrypt_all(kCpuKey).has_value(),
                     "FlashImage::decrypt_all failed on the " + std::string(what))) {
            exit_code = 6;
            return std::nullopt;
        }
        return image;
    }

    // The CF fixpoint nonce a build takes from its donor: the nonce of the update slot whose CF
    // states the largest LDV, slot 0 on a tie (the rule BuildRunner applies, restated here so
    // the verifier does not trust the code under test). A zero nonce is no donor nonce.
    std::optional<Nonce> donor_cf_nonce(const FlashImage& donor) {
        const std::array<const SystemUpdate*, 2> slots{&donor.system_update_0,
                                                       &donor.system_update_1};
        const SystemUpdate* chosen = nullptr;
        uint8_t chosen_ldv = 0;
        for (const auto* slot : slots) {
            const auto& cf = slot->cf;
            if (!cf || cf->data.empty() || !cf->perbox) {
                continue;
            }
            if (chosen == nullptr || cf->perbox->lockdown_value > chosen_ldv) {
                chosen = slot;
                chosen_ldv = cf->perbox->lockdown_value;
            }
        }
        if (chosen == nullptr) {
            chosen = &donor.system_update_0;
        }
        if (!chosen->cf || chosen->cf->data.empty()) {
            return std::nullopt;
        }
        Nonce nonce{};
        static_assert(sizeof(chosen->cf->header.fixpoint_nonce) == std::tuple_size_v<Nonce>);
        std::ranges::copy(chosen->cf->header.fixpoint_nonce, nonce.begin());
        if (std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; })) {
            return std::nullopt;
        }
        return nonce;
    }

} // namespace

int main(int argc, char* argv[]) {
    const bool with_donor = argc == 4 && std::string_view(argv[2]) == "--donor";
    if (argc != 2 && !with_donor) {
        std::cerr << "usage: gxbuild3_cli_output_verifier <built-nand> [--donor <donor-nand>]\n";
        return 2;
    }

    int exit_code = 0;
    auto image = open_image(argv[1], "built NAND", exit_code);
    if (!image) {
        return exit_code;
    }
    std::optional<Nonce> expected_cf_nonce;
    if (with_donor) {
        const auto donor = open_image(argv[3], "donor NAND", exit_code);
        if (!donor) {
            return exit_code;
        }
        expected_cf_nonce = donor_cf_nonce(*donor);
        if (!require(expected_cf_nonce.has_value(),
                     "the donor NAND has no CF fixpoint nonce in its max-LDV slot")) {
            return 7;
        }
    }

    bool valid = true;
    valid = verify_stage("CB", &image->cb_section.cb_or_A, NANDBootloaderMagic::CB, 1) && valid;
    valid = verify_stage("SC", image->cb_section.sc ? &*image->cb_section.sc : nullptr,
                         NANDBootloaderMagic::SC, 2) &&
            valid;
    valid = verify_stage("CD", &image->kernel_section.cd, NANDBootloaderMagic::CD, 3) && valid;
    valid = verify_stage("CE", image->kernel_section.ce ? &*image->kernel_section.ce : nullptr,
                         NANDBootloaderMagic::CE, 4) &&
            valid;
    valid = verify_stage("CF0", image->system_update_0.cf ? &*image->system_update_0.cf : nullptr,
                         NANDBootloaderMagic::CF, 5) &&
            valid;
    valid = verify_stage("CG0", image->system_update_0.cg ? &*image->system_update_0.cg : nullptr,
                         NANDBootloaderMagic::CG, 6) &&
            valid;
    valid = verify_stage("CF1", image->system_update_1.cf ? &*image->system_update_1.cf : nullptr,
                         NANDBootloaderMagic::CF, 7) &&
            valid;
    valid = verify_stage("CG1", image->system_update_1.cg ? &*image->system_update_1.cg : nullptr,
                         NANDBootloaderMagic::CG, 8) &&
            valid;

    valid = verify_literal_payload("CB", &image->cb_section.cb_or_A, 0x380, 0x00) && valid;
    valid = verify_literal_payload("SC", image->cb_section.sc ? &*image->cb_section.sc : nullptr,
                                   0x20, 0x53) &&
            valid;
    valid = verify_literal_payload("CD", &image->kernel_section.cd, 0x20, 0x42) && valid;
    valid = verify_literal_payload("CE",
                                   image->kernel_section.ce ? &*image->kernel_section.ce : nullptr,
                                   0x20, 0x45) &&
            valid;
    valid = verify_cf_plaintext("CF0",
                                image->system_update_0.cf ? &*image->system_update_0.cf : nullptr,
                                expected_cf_nonce, 0x50) &&
            valid;
    valid = verify_cg_plaintext(
                "CG0", image->system_update_0.cg ? &*image->system_update_0.cg : nullptr, 0x60) &&
            valid;
    valid = verify_cf_plaintext("CF1",
                                image->system_update_1.cf ? &*image->system_update_1.cf : nullptr,
                                expected_cf_nonce, 0x70) &&
            valid;
    valid = verify_cg_plaintext(
                "CG1", image->system_update_1.cg ? &*image->system_update_1.cg : nullptr, 0x80) &&
            valid;

    valid = require(image->filesystem.has_value(), "FlashFS is absent") && valid;
    if (image->filesystem) {
        const auto file = image->filesystem->get_file("validation.bin");
        const Bytes expected{0x47, 0x58, 0x42, 0x33, 0x00, 0xff, 0x10, 0x7e};
        valid = require(file.has_value(), "FlashFS validation.bin is absent") && valid;
        valid = require(file == expected, "FlashFS validation.bin bytes differ") && valid;
    }

    return valid ? 0 : 7;
}
