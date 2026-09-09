#include "nand/objects/FlashFileSystem.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

using namespace gxbuild3::NAND;
using Bytes = std::vector<uint8_t>;

namespace {
    bool check(bool condition, const char* message) {
        if (!condition) std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    void put16(Bytes& bytes, size_t offset, uint16_t value) {
        bytes[offset] = static_cast<uint8_t>(value >> 8);
        bytes[offset + 1] = static_cast<uint8_t>(value);
    }

    void put32(Bytes& bytes, size_t offset, uint32_t value) {
        put16(bytes, offset, static_cast<uint16_t>(value >> 16));
        put16(bytes, offset + 2, static_cast<uint16_t>(value));
    }

    size_t map_offset(size_t cluster) {
        return (cluster / 256) * 1024 + (cluster % 256) * 2;
    }

    bool test_load_independent_big_block_layout() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        Bytes root(0x4000, 0);
        // The on-disk map has 4096 16 KiB clusters, despite only 512 erase blocks.
        for (size_t cluster = 0; cluster < 4096; ++cluster) {
            put16(root, map_offset(cluster), BlockMapStatus::Free);
        }
        put16(root, map_offset(988), 999);
        put16(root, map_offset(999), BlockMapStatus::EndOfChain);
        std::memcpy(root.data() + 512, "secdata.bin", 12);
        put16(root, 512 + 22, 988);
        put32(root, 512 + 24, 0x4003);
        Bytes expected(0x4003, 0x31);
        expected[0x4000] = 0x42;
        expected[0x4001] = 0x53;
        expected[0x4002] = 0x64;
        if (!driver.write_block(380, root) ||
            !driver.write_offset(988 * 0x4000, std::span(expected).first(0x4000)) ||
            !driver.write_offset(999 * 0x4000, std::span(expected).subspan(0x4000))) {
            return check(false, "independent fixture writes succeed");
        }
        FlashFileSystem fs;
        if (!check(fs.load(driver, 380), "independent big-block root loads") ||
            !check(fs.get_file("secdata.bin") == expected,
                   "big-block file chains use 16 KiB cluster addresses and lengths")) return false;
        put16(root, map_offset(988), BlockMapStatus::EndOfChain);
        if (!driver.write_block(380, root)) return false;
        FlashFileSystem truncated;
        return check(!truncated.load(driver, 380),
                     "a truncated chain must not be cached as a successfully read file");
    }

    bool test_big_block_writer_uses_clusters() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        FlashFileSystem fs;
        fs.set_driver(&driver);
        if (!check(fs.format(driver.block_count(), 380), "big-block filesystem formats"))
            return false;
        const Bytes first(0x4003, 0x31);
        const Bytes second(1024, 0x42);
        if (!fs.add_file("first.bin", first) || !fs.add_file("second.bin", second))
            return check(false, "big-block files allocate");
        const auto first_entry = fs.stat("first.bin");
        const auto second_entry = fs.stat("second.bin");
        if (!check(!fs.is_block_free(first_entry->block_number / 8),
                   "physical allocation sees every occupied subcluster") ||
            !check(!fs.set_root_block(first_entry->block_number / 8),
                   "root cannot overwrite an occupied physical block") ||
            !check(fs.reserve_blocks(200, 1), "physical block reservation succeeds") ||
            !check(std::all_of(fs.blockmap().begin() + 200 * 8,
                               fs.blockmap().begin() + 201 * 8,
                               [](uint16_t value) { return value == BlockMapStatus::Reserved; }),
                   "physical reservation covers all eight clusters") ||
            !check(fs.set_root_block(300) && fs.is_block_free(380) && !fs.is_block_free(300),
                   "root relocation reserves and releases whole erase blocks")) return false;
        if (!check(fs.get_chain(first_entry->block_number).size() == 2,
                   "a 16 KiB plus three byte file requires two clusters") ||
            !check(fs.save(), "big-block files save")) return false;
        const auto first_address = static_cast<size_t>(first_entry->block_number) * 0x4000;
        const auto second_address = static_cast<size_t>(second_entry->block_number) * 0x4000;
        return check(driver.read_clean(first_address, first.size()) == first,
                     "writer uses on-disk 16 KiB addresses") &&
               check(driver.read_clean(second_address, second.size()) == second,
                     "writing a neighboring cluster preserves earlier file data");
    }
}

int main() {
    bool passed = test_load_independent_big_block_layout();
    passed = test_big_block_writer_uses_clusters() && passed;
    return passed ? 0 : 1;
}
