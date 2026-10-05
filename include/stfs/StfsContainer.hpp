#pragma once

#include "stfs/Commons.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Stfs {

    using ExtractedFiles = std::unordered_map<std::string, std::vector<std::byte>>;

    class StfsContainer {
      public:
        explicit StfsContainer(std::span<const std::byte> data);

        void extractAll(const std::filesystem::path& target_dir) const;

        // Exclusions use the same lowercase, $flash_-stripped names as the result.
        // Excluded entries are skipped before their file contents are extracted.
        [[nodiscard]] ExtractedFiles
        extractToMemory(std::span<const std::string> excluded_names = {}) const;
        [[nodiscard]] bool containsFileByName(std::string_view name) const;
        [[nodiscard]] std::vector<std::byte> extractFileByName(std::string_view name) const;

      private:
        std::span<const std::byte> data_;
        std::uint32_t header_size_;
        std::vector<::stfs::FileEntry> entries_;
    };

} // namespace Stfs
