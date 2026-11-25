#include "stfs/FileTableParser.hpp"

#include "core/Wire.hpp"
#include "stfs/Commons.hpp"
#include "stfs/Layout.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild::stfs {

    Result<std::vector<FileEntry>> parse_file_listing(std::span<const std::byte> data) {
        std::vector<FileEntry> entries;
        constexpr std::size_t entry_size = sizeof(stfs_file_table_entry);
        constexpr std::size_t name_field_size = sizeof(stfs_file_table_entry::name);

        if (data.size() % entry_size != 0) {
            return fail(ErrorCode::Malformed,
                        "file listing size 0x{:X} is not aligned to entry size", data.size());
        }

        const std::size_t entry_count = data.size() / entry_size;
        wire::Cursor cursor(wire::as_u8(data));

        for (std::size_t i = 0; i < entry_count; ++i) {
            const auto taken = cursor.take<stfs_file_table_entry>("STFS file table entry");
            if (!taken) {
                return std::unexpected(taken.error());
            }
            const stfs_file_table_entry& e = *taken;

            const std::uint8_t flags = e.flags;
            const std::uint8_t name_length = flags & 0x3F;

            // stops parsing the file table as soon as it hits an entry with a zero name length
            if (name_length == 0) {
                break;
            }
            if (name_length > name_field_size) {
                return fail(ErrorCode::Malformed,
                            "file table entry {} has a name longer than its 40-byte field", i);
            }

            std::string_view name(e.name, name_length);
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

            entry.blocks_allocated = e.blocks_allocated.get();
            entry.blocks_allocated_copy = e.blocks_allocated_copy.get();
            entry.starting_block = e.starting_block.get();
            entry.path_indicator = static_cast<std::int16_t>(e.path_indicator.get());
            entry.file_size = e.file_size.get();
            entry.update_timestamp = e.update_timestamp.get();
            entry.access_timestamp = e.access_timestamp.get();

            entries.push_back(std::move(entry));
        }

        return entries;
    }

} // namespace gxbuild::stfs