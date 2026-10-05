#pragma once

// Internal helpers shared by stfs::Package and Stfs::StfsContainer.

#include <Commons.hpp>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace stfs::detail {

    // Reads the file table through its hash chain after checking that the volume descriptor
    // describes a layout this reader supports.
    [[nodiscard]] std::vector<std::byte> readFileTable(std::span<const std::byte> package,
                                                       std::uint32_t header_size,
                                                       const StfsVolumeDescriptor& descriptor);

    // Writes `data` to `path`, throwing if the file cannot be opened, written or closed.
    void writeFile(const std::filesystem::path& path, std::span<const std::byte> data);

    // Relative path of every file-table entry, built from the path_indicator links. A parent
    // must precede its child in the table, which also rules out cycles.
    [[nodiscard]] std::vector<std::filesystem::path>
    buildEntryPaths(const std::vector<FileEntry>& entries);

    // Joins an entry path under `parent`, rejecting absolute, rooted or drive-relative paths and
    // any path that escapes `parent` after normalisation.
    [[nodiscard]] std::filesystem::path safeJoin(const std::filesystem::path& parent,
                                                 const std::filesystem::path& relative);

} // namespace stfs::detail
