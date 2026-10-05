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

namespace gxbuild3::stfs {

    namespace {

        std::vector<FileEntry> buildFileListing(std::span<const std::byte> package,
                                                const Metadata& meta) {
            const auto* vd = std::get_if<StfsVolumeDescriptor>(&meta.volume_descriptor);
            if (!vd) {
                throw std::runtime_error("SVOD packages are not supported for file listing");
            }

            auto table_data = detail::readFileTable(package, meta.header_size, *vd);
            return parseFileListing(table_data);
        }

        const std::array<std::byte, 0x14>* topHashPointer(const StfsVolumeDescriptor* vd) noexcept {
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

        return fromData(std::move(data));
    }

    Package Package::fromData(std::vector<std::byte> data) {
        std::span<const std::byte> view(data);

        auto header = parseHeader(view);
        auto metadata = parseMetadata(view);
        auto files = buildFileListing(view, metadata);

        return Package(std::move(data), std::move(header), std::move(metadata), std::move(files));
    }

    std::vector<std::byte> Package::extractFile(const FileEntry& entry, bool verify) const {
        const auto* vd = std::get_if<StfsVolumeDescriptor>(&metadata_.volume_descriptor);
        auto total_blocks = vd ? static_cast<std::uint32_t>(vd->total_allocated_block_count) : 0u;

        return stfs::extractFile(data_, entry, header_.magic, metadata_.header_size, verify,
                                 topHashPointer(vd), total_blocks);
    }

    void Package::extractFileToDisk(const FileEntry& entry,
                                    const std::filesystem::path& output_path, bool verify) const {
        const auto* vd = std::get_if<StfsVolumeDescriptor>(&metadata_.volume_descriptor);
        auto total_blocks = vd ? static_cast<std::uint32_t>(vd->total_allocated_block_count) : 0u;

        stfs::extractFileToDisk(data_, entry, header_.magic, metadata_.header_size, output_path,
                                verify, topHashPointer(vd), total_blocks);
    }

    void Package::extractAll(const std::filesystem::path& output_dir, bool verify) const {
        // Validate every destination before writing anything.
        const auto relative_paths = detail::buildEntryPaths(files_);
        std::vector<std::filesystem::path> destinations;
        destinations.reserve(relative_paths.size());
        for (const auto& relative : relative_paths) {
            destinations.push_back(detail::safeJoin(output_dir, relative));
        }

        for (std::size_t i = 0; i < files_.size(); ++i) {
            const auto& entry = files_[i];
            const auto& dest = destinations[i];

            if (entry.isDirectory()) {
                std::filesystem::create_directories(dest);
            } else {
                std::filesystem::create_directories(dest.parent_path());
                extractFileToDisk(entry, dest, verify);
            }
        }
    }

} // namespace gxbuild3::stfs
