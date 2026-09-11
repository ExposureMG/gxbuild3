#include <Commons.hpp>
#include <Endian.hpp>
#include <FileTableParser.hpp>
#include <span>
#include <stdexcept>
#include <vector>

namespace stfs {

    std::vector<FileEntry> parseFileListing(std::span<const std::byte> data) {
        std::vector<FileEntry> entries;
        constexpr std::size_t entry_size = 0x40;

        if (data.size() % entry_size != 0) {
            throw std::runtime_error("File listing size not aligned to entry size");
        }

        std::size_t entry_count = data.size() / entry_size;
        const auto* base = data.data();

        for (std::size_t i = 0; i < entry_count; ++i) {
            const auto* ptr = base + i * entry_size;

            bool all_zero = true;
            for (std::size_t b = 0; b < entry_size; ++b) {
                if (ptr[b] != std::byte{0}) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero) {
                break;
            }

            FileEntry entry;

            std::uint8_t flags = static_cast<std::uint8_t>(ptr[0x28]);
            std::uint8_t name_length = flags & 0x3F;

            entry.name.assign(reinterpret_cast<const char*>(ptr), name_length);
            entry.flags = flags;

            entry.blocks_allocated = readUInt24LE(ptr + 0x29);
            entry.blocks_allocated_copy = readUInt24LE(ptr + 0x2C);
            entry.starting_block = readUInt24LE(ptr + 0x2F);
            entry.path_indicator = static_cast<std::int16_t>(readBE16(ptr + 0x32));
            entry.file_size = readBE32(ptr + 0x34);
            entry.update_timestamp = readBE32(ptr + 0x38);
            entry.access_timestamp = readBE32(ptr + 0x3C);

            entries.push_back(std::move(entry));
        }

        return entries;
    }

} // namespace stfs