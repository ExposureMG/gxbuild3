#pragma once

#include "stfs/Commons.hpp"

#include <filesystem>
#include <span>
#include <vector>

namespace gxbuild3::stfs {

    class Package {
      public:
        [[nodiscard]] static Package open(const std::filesystem::path& path);
        [[nodiscard]] static Package from_data(std::vector<std::byte> data);

        [[nodiscard]] const Header& header() const { return header_; }
        [[nodiscard]] const Metadata& metadata() const { return metadata_; }
        [[nodiscard]] const std::vector<FileEntry>& files() const { return files_; }

        [[nodiscard]] std::vector<std::byte> extract_file(const FileEntry& entry,
                                                          bool verify = false) const;

        void extract_file_to_disk(const FileEntry& entry, const std::filesystem::path& output_path,
                                  bool verify = false) const;

        void extract_all(const std::filesystem::path& output_dir, bool verify = false) const;

      private:
        Package(std::vector<std::byte> data, Header header, Metadata metadata,
                std::vector<FileEntry> files);

        std::vector<std::byte> data_;
        Header header_;
        Metadata metadata_;
        std::vector<FileEntry> files_;
    };

} // namespace gxbuild3::stfs
