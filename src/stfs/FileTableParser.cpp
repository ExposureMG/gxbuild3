#include "stfs/FileTableParser.hpp"

#include "Endian.hpp"
#include "stfs/Commons.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::stfs {

    Result<std::vector<FileEntry>> parse_file_listing(std::span<const std::byte> data) {
        std::vector<FileEntry> entries;
        constexpr std::size_t entry_size = 0x40;
        constexpr std::size_t name_field_size = 0x28;

        if (data.size() % entry_size != 0) {
            return fail(ErrorCode::Malformed,
                        "file listing size 0x{:X} is not aligned to entry size", data.size());
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
                return fail(ErrorCode::Malformed,
                            "file table entry {} has a name longer than its 40-byte field", i);
            }

            // Names are not NUL-terminated, but tolerate NUL padding inside the stated length.
            std::string_view name(reinterpret_cast<const char*>(ptr), name_length);
            name = name.substr(0, name.find('\0'));
            if (name.empty()) {
                return fail(ErrorCode::Malformed, "file table entry {} has an empty name", i);
            }
            if (name.find_first_of("/\\") != std::string_view::npos) {
                return fail(ErrorCode::Malformed,
                            "file table entry {} has a path separator in its name", i);
            }

            FileEntry entry;
            entry.name.assign(name);
            entry.flags = flags;

            entry.blocks_allocated = read_le24(ptr + 0x29);
            entry.blocks_allocated_copy = read_le24(ptr + 0x2C);
            entry.starting_block = read_le24(ptr + 0x2F);
            entry.path_indicator = static_cast<std::int16_t>(read_be16(ptr + 0x32));
            entry.file_size = read_be32(ptr + 0x34);
            entry.update_timestamp = read_be32(ptr + 0x38);
            entry.access_timestamp = read_be32(ptr + 0x3C);

            entries.push_back(std::move(entry));
        }

        return entries;
    }

} // namespace gxbuild3::stfs