#pragma once

// Internal helpers used by stfs::StfsContainer.

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace gxbuild3::stfs::detail {

    // Reads the file table through its hash chain after checking that the volume descriptor
    // describes a layout this reader supports.
    [[nodiscard]] Result<std::vector<std::byte>>
    read_file_table(std::span<const std::byte> package, std::uint32_t header_size,
                    const StfsVolumeDescriptor& descriptor);

    // Writes `data` to `path`; fails with IoError if the file cannot be opened, written or closed.
    [[nodiscard]] Result<void> write_file(const std::filesystem::path& path,
                                          std::span<const std::byte> data);

    // Relative path of every file-table entry, built from the path_indicator links. A parent
    // must precede its child in the table, which also rules out cycles.
    [[nodiscard]] Result<std::vector<std::filesystem::path>>
    build_entry_paths(const std::vector<FileEntry>& entries);

    // Joins an entry path under `parent`, rejecting absolute, rooted or drive-relative paths and
    // any path that escapes `parent` after normalisation (InvalidArgument).
    [[nodiscard]] Result<std::filesystem::path> safe_join(const std::filesystem::path& parent,
                                                          const std::filesystem::path& relative);

    // Destination of every file-table entry under `target_dir`, in table order: the
    // build_entry_paths result joined through safe_join. Fails on the first bad entry, before
    // anything is written.
    [[nodiscard]] Result<std::vector<std::filesystem::path>>
    plan_destinations(const std::vector<FileEntry>& entries,
                      const std::filesystem::path& target_dir);

} // namespace gxbuild3::stfs::detail
