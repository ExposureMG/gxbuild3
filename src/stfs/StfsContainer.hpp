#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace gxbuild3::stfs {

    using ExtractedFiles = std::unordered_map<std::string, std::vector<std::byte>>;

    // A read-only PIRS system-update package. The container keeps a view of `data`, which
    // must outlive it.
    class StfsContainer {
      public:
        // Parses the header, metadata and file table. Fails for anything but an STFS PIRS
        // package (Malformed, Unsupported) and for a file table that cannot be read.
        [[nodiscard]] static Result<StfsContainer> open(std::span<const std::byte> data);

        // Validates every destination before writing anything. A failed write can leave the
        // files written before it in place.
        [[nodiscard]] Result<void> extract_all(const std::filesystem::path& target_dir) const;

        // Exclusions use the same lowercase, $flash_-stripped names as the result.
        // Excluded entries are skipped before their file contents are extracted.
        [[nodiscard]] Result<ExtractedFiles>
        extract_to_memory(std::span<const std::string> excluded_names = {}) const;
        [[nodiscard]] bool contains_file_by_name(std::string_view name) const;
        // Fails with NotFound when no file has that name.
        [[nodiscard]] Result<std::vector<std::byte>>
        extract_file_by_name(std::string_view name) const;

      private:
        StfsContainer(std::span<const std::byte> data, std::uint32_t header_size,
                      std::vector<FileEntry> entries);

        std::span<const std::byte> data_;
        std::uint32_t header_size_;
        std::vector<FileEntry> entries_;
    };

} // namespace gxbuild3::stfs
