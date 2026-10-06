#include "stfs/Package.hpp"

#include "PackageCommon.hpp"
#include "stfs/BlockParser.hpp"
#include "stfs/Commons.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/FileTableParser.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/MetadataParser.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>

// TODO(parsing): Package reports failures by throwing std::runtime_error. It is test-only (no
// src caller) and is allowlisted in tests/ErrorConventionGuard.cmake until the parsing phase
// replaces it with a Result-returning reader.

namespace gxbuild3::stfs {

    namespace {

        std::vector<FileEntry> build_file_listing(std::span<const std::byte> package,
                                                  const Metadata& meta) {
            const auto* vd = std::get_if<StfsVolumeDescriptor>(&meta.volume_descriptor);
            if (!vd) {
                throw std::runtime_error("SVOD packages are not supported for file listing");
            }

            const auto table_data =
                detail::value_or_throw(detail::read_file_table(package, meta.header_size, *vd));
            return detail::value_or_throw(parse_file_listing(table_data));
        }

        const std::array<std::byte, 0x14>*
        top_hash_pointer(const StfsVolumeDescriptor* vd) noexcept {
            return vd ? &vd->top_hash_table_hash : nullptr;
        }

    } // namespace

    Package::Package(std::vector<std::byte> data, Header header, Metadata metadata,
                     std::vector<FileEntry> files)
        : data_(std::move(data)), header_(std::move(header)), metadata_(std::move(metadata)),
          files_(std::move(files)) {}

    Package Package::open(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + path.string());
        }

        auto size = static_cast<std::size_t>(file.tellg());
        file.seekg(0);

        std::vector<std::byte> data(size);
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
        if (!file) {
            throw std::runtime_error("Failed to read file: " + path.string());
        }

        return from_data(std::move(data));
    }

    Package Package::from_data(std::vector<std::byte> data) {
        std::span<const std::byte> view(data);

        auto header = detail::value_or_throw(parse_header(view));
        auto metadata = detail::value_or_throw(parse_metadata(view));
        auto files = build_file_listing(view, metadata);

        return Package(std::move(data), std::move(header), std::move(metadata), std::move(files));
    }

    std::vector<std::byte> Package::extract_file(const FileEntry& entry, bool verify) const {
        const auto* vd = std::get_if<StfsVolumeDescriptor>(&metadata_.volume_descriptor);
        auto total_blocks = vd ? static_cast<std::uint32_t>(vd->total_allocated_block_count) : 0u;

        return detail::value_or_throw(stfs::extract_file(data_, entry, header_.magic,
                                                         metadata_.header_size, verify,
                                                         top_hash_pointer(vd), total_blocks));
    }

    void Package::extract_file_to_disk(const FileEntry& entry,
                                       const std::filesystem::path& output_path,
                                       bool verify) const {
        const auto* vd = std::get_if<StfsVolumeDescriptor>(&metadata_.volume_descriptor);
        auto total_blocks = vd ? static_cast<std::uint32_t>(vd->total_allocated_block_count) : 0u;

        detail::value_or_throw(
            stfs::extract_file_to_disk(data_, entry, header_.magic, metadata_.header_size,
                                       output_path, verify, top_hash_pointer(vd), total_blocks));
    }

    void Package::extract_all(const std::filesystem::path& output_dir, bool verify) const {
        // Validate every destination before writing anything.
        const auto relative_paths = detail::value_or_throw(detail::build_entry_paths(files_));
        std::vector<std::filesystem::path> destinations;
        destinations.reserve(relative_paths.size());
        for (const auto& relative : relative_paths) {
            destinations.push_back(detail::value_or_throw(detail::safe_join(output_dir, relative)));
        }

        for (std::size_t i = 0; i < files_.size(); ++i) {
            const auto& entry = files_[i];
            const auto& dest = destinations[i];

            if (entry.is_directory()) {
                std::filesystem::create_directories(dest);
            } else {
                std::filesystem::create_directories(dest.parent_path());
                extract_file_to_disk(entry, dest, verify);
            }
        }
    }

} // namespace gxbuild3::stfs
