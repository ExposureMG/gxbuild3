#pragma once

#include "gxbuild/Error.hpp"
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

namespace gxbuild::stfs {

    using ExtractedFiles = std::unordered_map<std::string, std::vector<std::byte>>;

    class StfsContainer {
      public:
        enum class Verify : bool {
            No,
            Yes
        };

        [[nodiscard]] static Result<StfsContainer> open(std::span<const std::byte> data);
        static Result<StfsContainer> open(std::vector<std::byte>&&) = delete;

        [[nodiscard]] const std::vector<FileEntry>& entries() const { return entries_; }
        [[nodiscard]] std::uint32_t header_size() const { return header_size_; }

        [[nodiscard]] Result<std::vector<std::byte>> extract(const FileEntry& entry,
                                                             Verify verify = Verify::No) const;

        [[nodiscard]] Result<void> extract_all(const std::filesystem::path& target_dir,
                                               Verify verify = Verify::No) const;

        [[nodiscard]] Result<ExtractedFiles>
        extract_to_memory(std::span<const std::string> excluded_names = {}) const;
        [[nodiscard]] bool contains_file_by_name(std::string_view name) const;
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
        // lowercased entry names with any leading "$flash_" prefix stripped off
        std::vector<std::string> keys_;
    };

} // namespace gxbuild::stfs
