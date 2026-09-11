#pragma once

#include <Commons.hpp>
#include <filesystem>
#include <span>
#include <vector>

namespace stfs {

    class Package {
      public:
        [[nodiscard]] static Package open(const std::filesystem::path& path);
        [[nodiscard]] static Package fromData(std::vector<std::byte> data);

        [[nodiscard]] const Header& header() const { return header_; }
        [[nodiscard]] const Metadata& metadata() const { return metadata_; }
        [[nodiscard]] const std::vector<FileEntry>& files() const { return files_; }

        [[nodiscard]] std::vector<std::byte> extractFile(const FileEntry& entry,
                                                         bool verify = false) const;

        void extractFileToDisk(const FileEntry& entry, const std::filesystem::path& output_path,
                               bool verify = false) const;

        void extractAll(const std::filesystem::path& output_dir, bool verify = false) const;

      private:
        Package(std::vector<std::byte> data, Header header, Metadata metadata,
                std::vector<FileEntry> files);

        std::vector<std::byte> data_;
        Header header_;
        Metadata metadata_;
        std::vector<FileEntry> files_;
    };

} // namespace stfs
