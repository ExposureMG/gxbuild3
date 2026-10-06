#pragma once

#include "Error.hpp"
#include "stfs/Commons.hpp"

#include <array>
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
        // Whether extraction checks every data block against the hash tables up to the
        // volume descriptor's top hash.
        enum class Verify : bool {
            No,
            Yes
        };

        // Parses the header, metadata and file table. Fails for anything but an STFS PIRS
        // package (Malformed, Unsupported) and for a file table that cannot be read.
        [[nodiscard]] static Result<StfsContainer> open(std::span<const std::byte> data);
        // The container would view a temporary that dies at the end of the call.
        static Result<StfsContainer> open(std::vector<std::byte>&&) = delete;

        // The file table, in on-disk order.
        [[nodiscard]] const std::vector<FileEntry>& entries() const { return entries_; }
        [[nodiscard]] std::uint32_t header_size() const { return header_size_; }

        // Contents of one file-table entry (empty for a directory or an empty file).
        [[nodiscard]] Result<std::vector<std::byte>> extract(const FileEntry& entry,
                                                             Verify verify = Verify::No) const;

        // Validates every destination before writing anything. A failed write can leave the
        // files written before it in place.
        [[nodiscard]] Result<void> extract_all(const std::filesystem::path& target_dir,
                                               Verify verify = Verify::No) const;

        // Exclusions use the same lowercase, $flash_-stripped names as the result.
        // Excluded entries are skipped before their file contents are extracted. When two
        // files share a name the first one in the table wins.
        [[nodiscard]] Result<ExtractedFiles>
        extract_to_memory(std::span<const std::string> excluded_names = {}) const;
        [[nodiscard]] bool contains_file_by_name(std::string_view name) const;
        // Fails with NotFound when no file has that name.
        [[nodiscard]] Result<std::vector<std::byte>>
        extract_file_by_name(std::string_view name) const;

      private:
        StfsContainer(std::span<const std::byte> data, std::uint32_t header_size,
                      const StfsVolumeDescriptor& descriptor, std::vector<FileEntry> entries);

        std::span<const std::byte> data_;
        std::uint32_t header_size_;
        std::array<std::byte, 0x14> top_hash_;
        std::uint32_t total_blocks_;
        std::vector<FileEntry> entries_;
        // Lookup key of each entry: the name with any $flash_ prefix stripped, then lowercased.
        std::vector<std::string> keys_;
    };

} // namespace gxbuild3::stfs
