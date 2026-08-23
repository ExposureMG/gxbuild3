#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/XConfig.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using gxbuild3::NAND::BlockMetadata;
using gxbuild3::NAND::Driver;
using gxbuild3::NAND::FlashImage;
using gxbuild3::NAND::Smc;
using gxbuild3::NAND::SmcConfig;

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

} // namespace

int main() {
    bool passed = true;
    passed = test_fresh_blocks_are_not_bad() && passed;
    passed = test_big_block_sequence_layout() && passed;
    passed = test_block_type_masks_ecc_bits() && passed;
    passed = test_flash_image_reads_cross_page_config() && passed;
    passed = test_flash_image_reassembles_latest_mobile_data() && passed;
    passed = test_writes_reject_out_of_range_data() && passed;
    passed = test_flash_image_rejects_oversized_smc() && passed;
    return passed ? 0 : 1;
}
