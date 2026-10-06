#include "ContainerDetail.hpp"

#include "stfs/FileExtractor.hpp"

#include <cstdint>
#include <fstream>
#include <utility>

namespace gxbuild3::stfs::detail {

    Result<std::vector<std::byte>> read_file_table(std::span<const std::byte> package,
                                                   std::uint32_t header_size,
                                                   const StfsVolumeDescriptor& descriptor) {
        // Bit 0 set marks the read-only layout (one hash table per level), which is what system
        // update and other Microsoft-signed packages use. The writable layout keeps two tables
        // per level and places blocks differently; it is not implemented.
        if ((descriptor.block_separation & 0x01) == 0) {
            return fail(ErrorCode::Unsupported,
                        "STFS packages with block_separation bit 0 clear are not supported");
        }
        if (descriptor.file_table_block_count <= 0 || descriptor.file_table_block_number < 0) {
            return fail(ErrorCode::Malformed, "STFS package has an invalid file table descriptor");
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

        return with_context(extract_file(package, table_entry, Magic::PIRS, header_size),
                            "reading the STFS file table");
    }

    Result<void> write_file(const std::filesystem::path& path, std::span<const std::byte> data) {
        std::ofstream out(path, std::ios::binary);
        if (!out) {
            return fail(ErrorCode::IoError, "cannot open output file {}", path.string());
        }

        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        out.close();
        if (!out) {
            return fail(ErrorCode::IoError, "failed to write output file {}", path.string());
        }
        return {};
    }

    Result<std::vector<std::filesystem::path>>
    build_entry_paths(const std::vector<FileEntry>& entries) {
        constexpr std::uint16_t kRootIndicator = 0xFFFF;

        std::vector<std::filesystem::path> paths;
        paths.reserve(entries.size());

        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            std::filesystem::path path{entry.name};

            const auto parent = static_cast<std::uint16_t>(entry.path_indicator);
            if (parent != kRootIndicator) {
                if (parent >= i) {
                    return fail(ErrorCode::Malformed,
                                "STFS file table entry {} references an invalid parent index {}", i,
                                parent);
                }
                path = paths[parent] / path;
            }

            paths.push_back(std::move(path));
        }

        return paths;
    }

    Result<std::filesystem::path> safe_join(const std::filesystem::path& parent,
                                            const std::filesystem::path& relative) {
        if (relative.is_absolute() || relative.has_root_path() || relative.has_root_name()) {
            return fail(ErrorCode::InvalidArgument, "STFS entry {} uses an absolute path",
                        relative.string());
        }

        const auto normalized = relative.lexically_normal();
        for (const auto& part : normalized) {
            if (part == "..") {
                return fail(ErrorCode::InvalidArgument,
                            "STFS entry {} escapes the target directory", relative.string());
            }
        }
        if (normalized.empty() || normalized == ".") {
            return fail(ErrorCode::InvalidArgument, "STFS entry {} has an empty path",
                        relative.string());
        }

        return parent / normalized;
    }

    Result<std::vector<std::filesystem::path>>
    plan_destinations(const std::vector<FileEntry>& entries,
                      const std::filesystem::path& target_dir) {
        const auto relative_paths = build_entry_paths(entries);
        if (!relative_paths) {
            return std::unexpected(relative_paths.error());
        }
        std::vector<std::filesystem::path> destinations;
        destinations.reserve(relative_paths->size());
        for (const auto& relative : *relative_paths) {
            auto destination = safe_join(target_dir, relative);
            if (!destination) {
                return std::unexpected(std::move(destination).error());
            }
            destinations.push_back(std::move(*destination));
        }
        return destinations;
    }

} // namespace gxbuild3::stfs::detail
