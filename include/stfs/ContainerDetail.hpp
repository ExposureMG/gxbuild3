#pragma once

#include "gxbuild/Error.hpp"
#include "stfs/Commons.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace gxbuild::stfs::detail {

    [[nodiscard]] Result<std::vector<std::byte>>
    read_file_table(std::span<const std::byte> package, std::uint32_t header_size,
                    const StfsVolumeDescriptor& descriptor);

    [[nodiscard]] Result<void> write_file(const std::filesystem::path& path,
                                          std::span<const std::byte> data);

    [[nodiscard]] Result<std::vector<std::filesystem::path>>
    build_entry_paths(const std::vector<FileEntry>& entries);

    [[nodiscard]] Result<std::filesystem::path> safe_join(const std::filesystem::path& parent,
                                                          const std::filesystem::path& relative);

    [[nodiscard]] Result<std::vector<std::filesystem::path>>
    plan_destinations(const std::vector<FileEntry>& entries,
                      const std::filesystem::path& target_dir);

} // namespace gxbuild::stfs::detail
