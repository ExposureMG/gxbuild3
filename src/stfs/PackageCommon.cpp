#include "PackageCommon.hpp"

#include <FileExtractor.hpp>
#include <cstdint>
#include <stdexcept>

namespace stfs::detail {

    std::vector<std::byte> readFileTable(std::span<const std::byte> package,
                                         std::uint32_t header_size,
                                         const StfsVolumeDescriptor& descriptor) {
        // Bit 0 set marks the read-only layout (one hash table per level), which is what system
        // update and other Microsoft-signed packages use. The writable layout keeps two tables
        // per level and places blocks differently; it is not implemented.
        if ((descriptor.block_separation & 0x01) == 0) {
            throw std::runtime_error(
                "STFS packages with block_separation bit 0 clear are not supported");
        }
        if (descriptor.file_table_block_count <= 0 || descriptor.file_table_block_number < 0) {
            throw std::runtime_error("STFS package has an invalid file table descriptor");
        }

        constexpr std::size_t kBlockSize = 0x1000;
        FileEntry table_entry{};
        table_entry.name = "$filetable";
        table_entry.flags = 0; // follow the hash chain
        table_entry.blocks_allocated =
            static_cast<std::uint32_t>(descriptor.file_table_block_count);
        table_entry.blocks_allocated_copy = table_entry.blocks_allocated;
        table_entry.starting_block = static_cast<std::uint32_t>(descriptor.file_table_block_number);
        table_entry.path_indicator = -1;
        table_entry.file_size =
            table_entry.blocks_allocated * static_cast<std::uint32_t>(kBlockSize);

        return extractFile(package, table_entry, Magic::PIRS, header_size);
    }

    std::vector<std::filesystem::path> buildEntryPaths(const std::vector<FileEntry>& entries) {
        constexpr std::uint16_t kRootIndicator = 0xFFFF;

        std::vector<std::filesystem::path> paths;
        paths.reserve(entries.size());

        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            std::filesystem::path path{entry.name};

            const auto parent = static_cast<std::uint16_t>(entry.path_indicator);
            if (parent != kRootIndicator) {
                if (parent >= i) {
                    throw std::runtime_error("STFS file table references an invalid parent index");
                }
                path = paths[parent] / path;
            }

            paths.push_back(std::move(path));
        }

        return paths;
    }

    std::filesystem::path safeJoin(const std::filesystem::path& parent,
                                   const std::filesystem::path& relative) {
        if (relative.is_absolute() || relative.has_root_path() || relative.has_root_name()) {
            throw std::runtime_error("STFS entry uses an absolute path");
        }

        const auto normalized = relative.lexically_normal();
        for (const auto& part : normalized) {
            if (part == "..") {
                throw std::runtime_error("STFS entry escapes the target directory");
            }
        }
        if (normalized.empty() || normalized == ".") {
            throw std::runtime_error("STFS entry has an empty path");
        }

        return parent / normalized;
    }

} // namespace stfs::detail
