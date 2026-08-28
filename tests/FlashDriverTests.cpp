#include "excrypt.h"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/objects/XConfig.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using gxbuild3::NAND::BlockMetadata;
using gxbuild3::NAND::Driver;
using gxbuild3::NAND::FlashImage;
using gxbuild3::NAND::FlashFileSystem;
using gxbuild3::NAND::Smc;
using gxbuild3::NAND::SmcConfig;

static_assert(sizeof(cd_header) == 0x260);
static_assert(offsetof(cd_header, nonce_6bl) == 0x230);
static_assert(offsetof(cd_header, salt_6bl) == 0x240);

namespace {

bool check(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        return false;
    }
    return true;
}

bool test_fresh_blocks_are_not_bad() {
    Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    return check(!driver.is_bad_block(100), "fresh unused blocks must have a good-block marker");
}

bool test_big_block_sequence_layout() {
    Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
    BlockMetadata metadata{};
    metadata.logical_block_id = 2;
    metadata.sequence = 0x123456;
    driver.write_block_metadata(2, metadata);

    const auto spare = driver.read_page_spare(2 * driver.pages_per_block());
    return check(spare.size() == 16, "Big Block spare data must be readable") &&
           check(spare[3] == 0x12 && spare[4] == 0x34 && spare[5] == 0x56,
                 "Big Block sequence must use spare bytes 3, 4, and 5") &&
           check(spare[6] == 0, "Big Block spare byte 6 must remain reserved");
}

bool test_block_type_masks_ecc_bits() {
    Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    BlockMetadata metadata{};
    metadata.logical_block_id = 0;
    metadata.block_type = 0x30;
    driver.write_block_metadata(0, metadata);

    for (size_t page = 0; page < 2; ++page) {
        auto spare = driver.read_page_spare(page);
        std::array<uint8_t, 16> updated{};
        std::copy(spare.begin(), spare.end(), updated.begin());
        updated[0xC] = 0xF0;
        driver.write_page_spare(page, updated);
    }

    return check(driver.interpret_block(0).block_type == 0x30,
                 "ECC bits must not be returned as part of the block type");
}

bool test_flash_image_reads_cross_page_config() {
    Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    auto config = SmcConfig{};
    config.Static.Version = 0x12345678;
    auto config_bytes = config.serialize(0x10000, 0);
    const size_t config_offset = (0x3E0 - 4) * source.block_size_clean();
    source.write_offset(config_offset, config_bytes);

    auto image = FlashImage::read(source.serialize());
    if (!check(image.has_value(), "FlashImage must accept a valid-sized NAND image")) {
        return false;
    }
    if (!check(image->parse(), "FlashImage must parse the NAND image")) {
        return false;
    }
    return check(image->smc_config.has_value(),
                 "FlashImage must read configuration ranges that cross raw page spare gaps") &&
           check(image->smc_config->Static.Version == config.Static.Version,
                 "FlashImage must read SMC config from the reference reserve-block location");
}

bool test_flash_image_reassembles_latest_mobile_data() {
    Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    const size_t block_size = source.block_size_clean();
    const size_t old_block = 0x80;
    const size_t new_block = 0x90;

    std::vector<uint8_t> old_data(block_size, 0x11);
    source.write_block(old_block, old_data);
    BlockMetadata old_meta{};
    old_meta.logical_block_id = static_cast<uint16_t>(old_block);
    old_meta.sequence = 1;
    old_meta.block_type = 0x31;
    old_meta.page_count = static_cast<uint8_t>(block_size / 512);
    source.write_block_metadata(old_block, old_meta);

    std::vector<uint8_t> latest_data(block_size + 123, 0x22);
    source.write_block(new_block, std::span<const uint8_t>(latest_data.data(), block_size));
    source.write_block(new_block + 1,
                       std::span<const uint8_t>(latest_data.data() + block_size, 123));

    BlockMetadata latest_meta{};
    latest_meta.sequence = 2;
    latest_meta.block_type = 0x31;
    latest_meta.fs_size = static_cast<uint16_t>(latest_data.size());
    latest_meta.page_count = static_cast<uint8_t>(block_size / 512);
    latest_meta.logical_block_id = static_cast<uint16_t>(new_block);
    source.write_block_metadata(new_block, latest_meta);
    latest_meta.logical_block_id = static_cast<uint16_t>(new_block + 1);
    latest_meta.page_count = 1;
    source.write_block_metadata(new_block + 1, latest_meta);

    auto image = FlashImage::read(source.serialize());
    if (!check(image.has_value(), "FlashImage must accept a valid-sized NAND image")) {
        return false;
    }
    if (!check(image->parse(), "FlashImage must parse mobile block metadata")) {
        return false;
    }

    const auto* mobile = image->mobile_data ? image->mobile_data->x31.operator->() : nullptr;
    return check(mobile != nullptr, "FlashImage must expose the latest mobile data version") &&
           check(*mobile == latest_data,
                 "FlashImage must concatenate all blocks from the latest mobile data version");
}

bool test_flash_image_places_filesystem_root_consistently() {
    FlashImage image{};
    image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);

    FlashFileSystem filesystem{};
    if (!check(filesystem.format(image.flash_driver.block_count()),
               "FlashFS must format before placement")) {
        return false;
    }
    const std::vector<uint8_t> file_data{0x10, 0x20, 0x30};
    if (!check(filesystem.add_file("test.bin", file_data),
               "FlashFS must accept a test file")) {
        return false;
    }
    image.filesystem = std::move(filesystem);

    if (!check(image.write_to_driver(), "FlashImage must write a filesystem image")) {
        return false;
    }

    const auto root_block = image.filesystem->root_block();
    if (!check(image.flash_driver.layout().fs_root_block == root_block,
               "FlashImage layout must identify the block containing the filesystem root")) {
        return false;
    }
    if (!check(root_block != 0x3E0,
               "FlashImage must relocate the default filesystem root away from file allocations")) {
        return false;
    }

    auto parsed = FlashImage::read(image.flash_driver.serialize());
    if (!check(parsed.has_value() && parsed->parse(),
               "FlashImage must parse the filesystem it just wrote")) {
        return false;
    }
    return check(parsed->filesystem.has_value(),
                 "FlashImage must find the filesystem root at the recorded block") &&
           check(parsed->filesystem->get_file("test.bin") == file_data,
                 "FlashImage must preserve files after root relocation");
}

bool test_flash_image_accepts_legacy_filesystem_root_type() {
    Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    FlashFileSystem filesystem{};
    if (!check(filesystem.format(source.block_count(), 0x80),
               "FlashFS must format at a test root block")) {
        return false;
    }
    filesystem.set_driver(&source);
    if (!check(filesystem.save(), "FlashFS must serialize its test root")) {
        return false;
    }

    BlockMetadata metadata{};
    metadata.logical_block_id = 0x80;
    metadata.sequence = 3;
    metadata.block_type = 0x2C;
    source.write_block_metadata(0x80, metadata);

    auto image = FlashImage::read(source.serialize());
    if (!check(image.has_value() && image->parse(),
               "FlashImage must parse a NAND image with a legacy filesystem root")) {
        return false;
    }
    return check(image->filesystem.has_value(),
                 "FlashImage must recognize filesystem block type 0x2C");
}

bool test_writes_reject_out_of_range_data() {
    Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    const size_t image_size = driver.block_count() * driver.block_size_clean();
    const std::array<uint8_t, 2> bytes{0xAA, 0xBB};
    const auto before = driver.read_clean(image_size - 1, 1);
    driver.write_offset(image_size - 1, bytes);
    const auto after = driver.read_clean(image_size - 1, 1);
    return check(before.size() == 1 && after.size() == 1 && before[0] == after[0],
                 "Driver must reject offset writes that exceed clean NAND capacity");
}

bool test_flash_image_rejects_oversized_smc() {
    FlashImage image{};
    image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
    Smc oversized_smc{};
    oversized_smc.data.resize(0x4001, 0xA5);
    image.smc = std::move(oversized_smc);

    return check(!image.write_to_driver(),
                 "FlashImage must reject an SMC that cannot fit before writing it");
}

bool test_cd_cpu_key_derivation_matches_single_cb_chain() {
    BootloaderCd cd{};
    cd.header.header.magic = NANDBootloaderMagic::CD;
    cd.header.header.version = 1920;
    cd.header.header.size = sizeof(cd_header) + 0x20;
    for (size_t i = 0; i < sizeof(cd.header.key); ++i) {
        cd.header.key[i] = static_cast<uint8_t>(0x10 + i);
    }
    std::fill_n(reinterpret_cast<uint8_t*>(&cd.header) + 0x20, sizeof(cd_header) - 0x20, 0x5A);
    cd.header.nonce_6bl[0] = 0xA5;
    cd.header.ce_hash[0] = 0xC3;
    cd.data.resize(0x20, 0x6B);
    cd.decrypted = true;

    const std::array<uint8_t, 16> parent_key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const std::array<uint8_t, 16> cpu_key{0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
                                          0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F};

    const auto plaintext = cd.serialize();
    auto expected = plaintext;
    uint8_t parent_digest[20]{};
    uint8_t rc4_key[20]{};
    ExCryptHmacSha(parent_key.data(), parent_key.size(), plaintext.data() + 0x10, 0x10, nullptr, 0,
                   nullptr, 0, parent_digest, sizeof(parent_digest));
    ExCryptHmacSha(cpu_key.data(), cpu_key.size(), parent_digest, 0x10, nullptr, 0, nullptr, 0,
                   rc4_key, sizeof(rc4_key));
    ExCryptRc4(rc4_key, 0x10, expected.data() + 0x20,
               static_cast<uint32_t>(expected.size() - 0x20));

    cd.encrypt(parent_key.data(), cpu_key.data());
    if (!check(cd.serialize() == expected,
               "single-CB CD encryption must apply the CPU-key HMAC after the parent-key HMAC")) {
        return false;
    }

    cd.decrypt(parent_key.data(), cpu_key.data());
    if (!check(cd.serialize() == plaintext,
               "single-CB CD decryption must reverse the CPU-key-derived encryption")) {
        return false;
    }

    auto expected_split_chain = plaintext;
    ExCryptRc4(parent_digest, 0x10, expected_split_chain.data() + 0x20,
               static_cast<uint32_t>(expected_split_chain.size() - 0x20));
    cd.encrypt(parent_key.data());
    if (!check(cd.serialize() == expected_split_chain,
               "split-CB CD encryption must use only the CB_B-derived parent key")) {
        return false;
    }

    cd.decrypt(parent_key.data());
    return check(cd.serialize() == plaintext,
                 "split-CB CD decryption must reverse the default parent-key encryption");
}

bool test_single_cb_cpu_key_requirement() {
    BootloaderCb cb{};
    cb.header.header.version = 1920;
    cb.data.resize(0x30, 0);
    cb.data[0x10] = 1;
    if (!check(cb.requires_cpu_key_for_cd(),
               "non-zero-paired single CB build 1920 must use the CPU key for CD")) {
        return false;
    }

    cb.header.header.version = 1919;
    if (!check(!cb.requires_cpu_key_for_cd(),
               "single CB builds before 1920 must not use the CPU key for CD")) {
        return false;
    }

    cb.header.header.version = 1920;
    std::fill(cb.data.begin() + 0x10, cb.data.begin() + 0x30, 0);
    return check(!cb.requires_cpu_key_for_cd(),
                 "zero-paired single CB must not use the CPU key for CD");
}

bool test_flash_image_rejects_split_chain_without_cb_b_key() {
    FlashImage image{};
    image.cb_section.cb_or_A.derived_key = std::array<uint8_t, 16>{0x11};
    image.cb_section.cb_B = BootloaderCb{};

    image.kernel_section.cd.header.header.size = sizeof(cd_header) + 0x20;
    image.kernel_section.cd.header.key[0] = 1;
    image.kernel_section.cd.data.resize(0x20, 0x6B);
    image.kernel_section.cd.decrypted = true;
    const auto cd_before = image.kernel_section.cd.serialize();

    return check(!image.encrypt_all(std::array<uint8_t, 16>{}),
                 "split-CB chain must reject a missing CB_B-derived key") &&
           check(image.kernel_section.cd.serialize() == cd_before,
                 "failed split-CB encryption must not fall back to the CB_A-derived key");
}

bool test_missing_single_cb_cpu_key_does_not_mutate_encryption_state() {
    FlashImage image{};
    auto& cb = image.cb_section.cb_or_A;
    cb.header.header.version = 1920;
    cb.header.header.size = sizeof(generic_header) + 0x30;
    cb.data.resize(0x30, 0);
    cb.data[0] = 0xA5;
    cb.data[0x10] = 1;
    cb.perbox = cb_perbox{};
    cb.perbox->pairing_data[0] = 1;
    cb.decrypted = true;

    image.kernel_section.cd.header.header.size = sizeof(cd_header) + 0x20;
    image.kernel_section.cd.header.key[0] = 1;
    image.kernel_section.cd.data.resize(0x20, 0x6B);
    image.kernel_section.cd.decrypted = true;

    const auto cb_before = cb.serialize();
    const auto cd_before = image.kernel_section.cd.serialize();
    if (!check(!image.encrypt_all({}),
               "qualifying single-CB encryption must reject a missing CPU key")) {
        return false;
    }
    return check(cb.serialize() == cb_before,
                 "missing CPU key must be detected before CB encryption mutates state") &&
           check(image.kernel_section.cd.serialize() == cd_before,
                 "missing CPU key must leave CD encryption state unchanged");
}

} // namespace

int main() {
    bool passed = true;
    passed = test_fresh_blocks_are_not_bad() && passed;
    passed = test_big_block_sequence_layout() && passed;
    passed = test_block_type_masks_ecc_bits() && passed;
    passed = test_flash_image_reads_cross_page_config() && passed;
    passed = test_flash_image_reassembles_latest_mobile_data() && passed;
    passed = test_flash_image_places_filesystem_root_consistently() && passed;
    passed = test_flash_image_accepts_legacy_filesystem_root_type() && passed;
    passed = test_writes_reject_out_of_range_data() && passed;
    passed = test_flash_image_rejects_oversized_smc() && passed;
    passed = test_cd_cpu_key_derivation_matches_single_cb_chain() && passed;
    passed = test_single_cb_cpu_key_requirement() && passed;
    passed = test_flash_image_rejects_split_chain_without_cb_b_key() && passed;
    passed = test_missing_single_cb_cpu_key_does_not_mutate_encryption_state() && passed;
    return passed ? 0 : 1;
}
