#pragma once

// Internal helpers shared by stfs::Package and Stfs::StfsContainer.

#include <Commons.hpp>
#include <filesystem>
#include <vector>

namespace stfs::detail {

    // Relative path of every file-table entry, built from the path_indicator links. A parent
    // must precede its child in the table, which also rules out cycles.
    [[nodiscard]] std::vector<std::filesystem::path>
    buildEntryPaths(const std::vector<FileEntry>& entries);

    // Joins an entry path under `parent`, rejecting absolute, rooted or drive-relative paths and
    // any path that escapes `parent` after normalisation.
    [[nodiscard]] std::filesystem::path safeJoin(const std::filesystem::path& parent,
                                                 const std::filesystem::path& relative);

} // namespace stfs::detail
