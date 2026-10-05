#include "stfs/FileTableParser.hpp"

#include "Endian.hpp"
#include "stfs/Commons.hpp"

#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace stfs {

    std::vector<FileEntry> parseFileListing(std::span<const std::byte> data) {
        std::vector<FileEntry> entries;
        constexpr std::size_t entry_size = 0x40;
        constexpr std::size_t name_field_size = 0x28;

        if (data.size() % entry_size != 0) {
            throw std::runtime_error("File listing size not aligned to entry size");
        }

        std::size_t entry_count = data.size() / entry_size;
        const auto* base = data.data();

        for (std::size_t i = 0; i < entry_count; ++i) {
            const auto* ptr = base + i * entry_size;

            std::uint8_t flags = static_cast<std::uint8_t>(ptr[0x28]);
            std::uint8_t name_length = flags & 0x3F;

            // The listing ends with an all-zero entry. An entry with no name length cannot name
            // a file either, so it ends the listing as well: skipping it instead would shift the
            // table positions that later entries' parent indexes refer to.
            if (name_length == 0) {
                break;
            }
            if (name_length > name_field_size) {
                throw std::runtime_error("File table entry " + std::to_string(i) +
                                         " has a name longer than its 40-byte field");
            }

            // Names are not NUL-terminated, but tolerate NUL padding inside the stated length.
            std::string_view name(reinterpret_cast<const char*>(ptr), name_length);
            name = name.substr(0, name.find('\0'));
            if (name.empty()) {
                throw std::runtime_error("File table entry " + std::to_string(i) +
                                         " has an empty name");
            }
            if (name.find_first_of("/\\") != std::string_view::npos) {
                throw std::runtime_error("File table entry " + std::to_string(i) +
                                         " has a path separator in its name");
            }

            FileEntry entry;
            entry.name.assign(name);
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