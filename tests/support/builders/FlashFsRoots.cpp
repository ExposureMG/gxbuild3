#include "FlashFsRoots.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace gxbuild3::test::flashfs {

    using Bytes = std::vector<uint8_t>;
    using nand::BlockMapStatus;
    using nand::Driver;
    using nand::FlashFileSystem;
    using nand::kCleanBlockSize;
    using nand::kEntriesPerPage;
    using nand::kMaxFilenameLength;

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

    size_t slot_offset(size_t slot) {
        return (1 + 2 * (slot / kEntriesPerPage)) * 512 + (slot % kEntriesPerPage) * 32;
    }

    void put_entry(Bytes& root, size_t slot, std::string_view name, uint16_t relative_block,
                   uint32_t length) {
        const size_t at = slot_offset(slot);
        std::fill(root.begin() + static_cast<std::ptrdiff_t>(at),
                  root.begin() + static_cast<std::ptrdiff_t>(at + kMaxFilenameLength), 0);
        std::memcpy(root.data() + at, name.data(), std::min(name.size(), kMaxFilenameLength));
        put16(root, at + 22, relative_block);
        put32(root, at + 24, length);
        put32(root, at + 28, 0x5D444AC2);
    }

    Bytes small_root() {
        Bytes root(kCleanBlockSize, 0);
        for (size_t cluster = 0; cluster < 0x400; ++cluster) {
            put16(root, map_offset(cluster), BlockMapStatus::Free);
        }
        put16(root, map_offset(0x3E0), BlockMapStatus::Table);
        for (uint16_t cluster = 0x60; cluster < 0x64; ++cluster) {
            put16(root, map_offset(cluster), BlockMapStatus::EndOfChain);
        }
        return root;
    }

    std::string outcome(const Result<>& result) {
        return result ? std::string{"ok"} : std::format("err={}", to_string(result.error().code));
    }

    std::string load_pin(const char* name, Driver& driver, const Bytes& root, uint16_t root_block,
                         FlashFileSystem& fs, Result<>& result) {
        const size_t ratio = driver.block_size_clean() / kCleanBlockSize;
        if (!driver.write_offset(static_cast<size_t>(root_block) * ratio * kCleanBlockSize, root))
            return std::format("[load {}] fixture write failed\n", name);
        result = fs.load(driver, root_block);
        std::string text = std::format("[load {}] {}", name, outcome(result));
        if (result) {
            text += " entries=";
            for (size_t i = 0; i < fs.entries().size(); ++i) {
                text += std::format("{}{}@0x{:X}", i ? "," : "",
                                    std::string_view{fs.entries()[i].filename},
                                    fs.entries()[i].block_number);
            }
        }
        return text + '\n';
    }

    std::string slot_name(const Bytes& root, size_t slot) {
        const char* at = reinterpret_cast<const char*>(root.data() + slot_offset(slot));
        return std::string(at, strnlen(at, kMaxFilenameLength));
    }

} // namespace gxbuild3::test::flashfs
