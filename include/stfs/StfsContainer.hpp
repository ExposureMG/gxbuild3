#pragma once

#include <Commons.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Stfs {

    struct XboxupdRawParts {
        std::vector<std::byte> cf_raw;
        std::vector<std::byte> cg_raw;
    };

    using ExtractedFiles = std::unordered_map<std::string, std::vector<std::byte>>;

    [[nodiscard]] XboxupdRawParts splitXboxupdRaw(std::span<const std::byte> xboxupd_bytes);

    class StfsContainer {
      public:
        explicit StfsContainer(std::span<const std::byte> data);

        void extractAll(const std::filesystem::path& target_dir) const;

        [[nodiscard]] ExtractedFiles extractToMemory() const;
        [[nodiscard]] std::vector<std::byte> extractFileByName(std::string_view name) const;

      private:
        struct EntryView {
            std::size_t index;
            std::filesystem::path path;
        };

        [[nodiscard]] std::vector<EntryView> buildEntryViews() const;

        std::span<const std::byte> data_;
        std::uint32_t header_size_;
        std::vector<::stfs::FileEntry> entries_;
    };

    [[nodiscard]] XboxupdRawParts extractXboxupdRaw(std::span<const std::byte> pirs_data);

} // namespace Stfs
