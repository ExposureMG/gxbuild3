#include <BlockParser.hpp>
#include <Commons.hpp>
#include <FileExtractor.hpp>
#include <FileTableParser.hpp>
#include <HeaderParser.hpp>
#include <MetadataParser.hpp>
#include <Package.hpp>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace stfs {

    namespace {

        constexpr std::size_t kBlockSize = 0x1000;

        std::vector<std::byte> readFileTableData(std::span<const std::byte> package,
                                                 const StfsVolumeDescriptor& vd,
                                                 std::uint32_t header_size) {
            std::vector<std::byte> table_data;
            table_data.reserve(static_cast<std::size_t>(vd.file_table_block_count) * kBlockSize);

            for (std::int16_t i = 0; i < vd.file_table_block_count; ++i) {
                auto logical = static_cast<std::uint32_t>(vd.file_table_block_number + i);
                std::uint32_t data_block = computeDataBlockNumber(logical);
                std::uint32_t offset = blockToOffset(data_block, header_size);

                if (offset + kBlockSize > package.size()) {
                    throw std::runtime_error("File table block out of bounds");
                }

                const auto* ptr = package.data() + offset;
                table_data.insert(table_data.end(), ptr, ptr + kBlockSize);
            }

            return table_data;
        }

        std::vector<FileEntry> buildFileListing(std::span<const std::byte> package,
                                                const Metadata& meta) {
            const auto* vd = std::get_if<StfsVolumeDescriptor>(&meta.volume_descriptor);
            if (!vd) {
                throw std::runtime_error("SVOD packages are not supported for file listing");
            }

            auto table_data = readFileTableData(package, *vd, meta.header_size);
            return parseFileListing(table_data);
        }

        std::filesystem::path resolveEntryPath(const std::vector<FileEntry>& files,
                                               const FileEntry& entry) {
            if (entry.path_indicator == -1) {
                return entry.name;
            }

            std::filesystem::path path = entry.name;
            std::int16_t parent = entry.path_indicator;

            while (parent != -1) {
                if (parent < 0 || static_cast<std::size_t>(parent) >= files.size()) {
                    throw std::runtime_error("Invalid path_indicator in file entry");
                }
                const FileEntry& dir = files[static_cast<std::size_t>(parent)];
                path = std::filesystem::path(dir.name) / path;
                parent = dir.path_indicator;
            }

            return path;
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
        for (const auto& entry : files_) {
            auto relative = resolveEntryPath(files_, entry);
            auto dest = output_dir / relative;

            if (entry.isDirectory()) {
                std::filesystem::create_directories(dest);
            } else {
                std::filesystem::create_directories(dest.parent_path());
                extractFileToDisk(entry, dest, verify);
            }
        }
    }

} // namespace stfs
