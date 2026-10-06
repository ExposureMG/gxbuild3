#pragma once

// Internal helpers shared by stfs::Package and stfs::StfsContainer.

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <utility>
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

    // TODO(parsing): Package still reports failures by throwing. It unwraps the
    // Result-returning helpers through this shim until the parsing phase converts it.
    template <class T> [[nodiscard]] T value_or_throw(Result<T>&& result) {
        if (!result) {
            throw std::runtime_error(result.error().describe());
        }
        return std::move(*result);
    }

    inline void value_or_throw(Result<void>&& result) {
        if (!result) {
            throw std::runtime_error(result.error().describe());
        }
    }

} // namespace gxbuild3::stfs::detail
