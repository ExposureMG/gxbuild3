#include "stfs/StfsContainer.hpp"

#include <BlockParser.hpp>
#include <FileExtractor.hpp>
#include <FileTableParser.hpp>
#include <HeaderParser.hpp>
#include <MetadataParser.hpp>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <variant>

namespace Stfs {
    namespace {

        constexpr std::size_t kBlockSize = 0x1000;
        constexpr std::size_t kBootloaderHeaderSize = 0x10;

        [[nodiscard]] std::uint16_t readBe16(std::span<const std::byte> data, std::size_t offset) {
            if (offset + 2 > data.size())
                throw std::runtime_error("Unexpected end of buffer while reading u16");

            return (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset])) << 8) |
                   static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset + 1]));
        }

        [[nodiscard]] std::uint32_t readBe32(std::span<const std::byte> data, std::size_t offset) {
            if (offset + 4 > data.size())
                throw std::runtime_error("Unexpected end of buffer while reading u32");

            return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset])) << 24) |
                   (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + 1]))
                    << 16) |
                   (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + 2]))
                    << 8) |
                   static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + 3]));
        }

        [[nodiscard]] bool startsWithPirs(std::span<const std::byte> data) {
            return data.size() >= 4 && data[0] == std::byte{static_cast<unsigned char>('P')} &&
                   data[1] == std::byte{static_cast<unsigned char>('I')} &&
                   data[2] == std::byte{static_cast<unsigned char>('R')} &&
                   data[3] == std::byte{static_cast<unsigned char>('S')};
        }

        [[nodiscard]] std::string lowerAscii(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            return value;
        }

        [[nodiscard]] std::string stripFlashPrefix(std::string name) {
            constexpr std::string_view prefix = "$flash_";
            if (name.size() >= prefix.size() &&
                lowerAscii(name.substr(0, prefix.size())) == prefix) {
                name.erase(0, prefix.size());
            }
            return name;
        }

        [[nodiscard]] std::filesystem::path safeJoin(const std::filesystem::path& parent,
                                                     std::string_view child) {
            std::filesystem::path child_path{std::string{child}};
            if (child_path.is_absolute()) {
                throw std::runtime_error("STFS entry uses an absolute path");
            }

            const auto normalized = child_path.lexically_normal();
            for (const auto& part : normalized) {
                if (part == "..") {
                    throw std::runtime_error("STFS entry escapes the target directory");
                }
            }

            return parent / normalized;
        }

        [[nodiscard]] std::vector<std::byte> readFileTable(std::span<const std::byte> data,
                                                           std::uint32_t header_size,
                                                           const stfs::StfsVolumeDescriptor& vd) {
            stfs::FileEntry table_entry{};
            table_entry.name = "$filetable";
            table_entry.flags = 0;
            table_entry.blocks_allocated = static_cast<std::uint32_t>(vd.file_table_block_count);
            table_entry.blocks_allocated_copy = table_entry.blocks_allocated;
            table_entry.starting_block = static_cast<std::uint32_t>(vd.file_table_block_number);
            table_entry.file_size = table_entry.blocks_allocated * kBlockSize;

            return stfs::extractFile(data, table_entry, stfs::Magic::PIRS, header_size);
        }

        void writeFile(const std::filesystem::path& path, std::span<const std::byte> data) {
            std::ofstream out(path, std::ios::binary);
            if (!out) {
                throw std::runtime_error("Cannot open output file: " + path.string());
            }

            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }

    } // namespace

    XboxupdRawParts splitXboxupdRaw(std::span<const std::byte> xboxupd_bytes) {
        if (xboxupd_bytes.size() < 0x20) {
            throw std::runtime_error("xboxupd buffer too small to split");
        }

        if (xboxupd_bytes[0] != std::byte{static_cast<unsigned char>('C')} ||
            xboxupd_bytes[1] != std::byte{static_cast<unsigned char>('F')}) {
            throw std::runtime_error("Invalid xboxupd magic: expected CF");
        }

        const std::uint32_t cf_size = readBe32(xboxupd_bytes, 0x0C);
        if (cf_size < kBootloaderHeaderSize || xboxupd_bytes.size() < cf_size) {
            throw std::runtime_error("xboxupd buffer too small to contain full CF");
        }

        const std::uint32_t cg_size = readBe32(xboxupd_bytes, 0x1C);
        const std::size_t cg_offset = cf_size;
        if (cg_size < kBootloaderHeaderSize || xboxupd_bytes.size() < cg_offset + cg_size) {
            throw std::runtime_error("xboxupd buffer too small to contain full CG");
        }

        const std::uint16_t cg_magic = readBe16(xboxupd_bytes.subspan(cg_offset), 0);
        if ((cg_magic & 0x0FFF) != 0x347) {
            throw std::runtime_error("CG header not found. invalid xboxupd.bin?");
        }

        XboxupdRawParts parts;
        parts.cf_raw.assign(xboxupd_bytes.begin(), xboxupd_bytes.begin() + cf_size);
        parts.cg_raw.assign(xboxupd_bytes.begin() + cg_offset,
                            xboxupd_bytes.begin() + cg_offset + cg_size);
        return parts;
    }

    StfsContainer::StfsContainer(std::span<const std::byte> data) : data_(data) {
        if (!startsWithPirs(data_)) {
            throw std::runtime_error("Invalid STFS signature: expected PIRS");
        }

        const auto header = stfs::parseHeader(data_);
        if (header.magic != stfs::Magic::PIRS) {
            throw std::runtime_error("Invalid STFS signature: expected PIRS");
        }

        const auto metadata = stfs::parseMetadata(data_);
        if (metadata.descriptor_type != stfs::DescriptorType::Stfs) {
            throw std::runtime_error("SVOD packages are not supported for PIRS extraction");
        }

        const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&metadata.volume_descriptor);
        if (vd == nullptr) {
            throw std::runtime_error("PIRS package is missing an STFS volume descriptor");
        }

        if (vd->file_table_block_count <= 0 || vd->file_table_block_number < 0) {
            throw std::runtime_error("PIRS package has an invalid file table descriptor");
        }

        header_size_ = metadata.header_size;

        const auto file_table = readFileTable(data_, header_size_, *vd);
        entries_ = stfs::parseFileListing(file_table);
    }

    std::vector<StfsContainer::EntryView> StfsContainer::buildEntryViews() const {
        std::vector<EntryView> views;
        views.reserve(entries_.size());

        for (std::size_t i = 0; i < entries_.size(); ++i) {
            const auto& entry = entries_[i];
            std::filesystem::path path{entry.name};

            if (entry.path_indicator >= 0) {
                const auto parent_index = static_cast<std::size_t>(entry.path_indicator);
                if (parent_index >= views.size()) {
                    throw std::runtime_error("STFS file table references an invalid parent index");
                }
                path = views[parent_index].path / path;
            }

            views.push_back(EntryView{i, path.lexically_normal()});
        }

        return views;
    }

    void StfsContainer::extractAll(const std::filesystem::path& target_dir) const {
        std::filesystem::create_directories(target_dir);

        for (const auto& view : buildEntryViews()) {
            const auto& entry = entries_[view.index];
            const auto full_path = safeJoin(target_dir, view.path.string());

            if (entry.isDirectory()) {
                std::filesystem::create_directories(full_path);
                continue;
            }

            std::filesystem::create_directories(full_path.parent_path());
            const auto file_data = stfs::extractFile(data_, entry, stfs::Magic::PIRS, header_size_);
            writeFile(full_path, file_data);
        }
    }

    ExtractedFiles StfsContainer::extractToMemory() const {
        ExtractedFiles results;

        for (const auto& entry : entries_) {
            if (entry.isDirectory()) {
                continue;
            }

            auto name = stripFlashPrefix(entry.name);
            name = lowerAscii(std::move(name));
            results.emplace(std::move(name),
                            stfs::extractFile(data_, entry, stfs::Magic::PIRS, header_size_));
        }

        return results;
    }

    std::vector<std::byte> StfsContainer::extractFileByName(std::string_view name) const {
        const auto wanted = lowerAscii(std::string{name});

        for (const auto& entry : entries_) {
            if (entry.isDirectory()) {
                continue;
            }

            auto entry_name = stripFlashPrefix(entry.name);
            entry_name = lowerAscii(std::move(entry_name));
            if (entry_name == wanted) {
                return stfs::extractFile(data_, entry, stfs::Magic::PIRS, header_size_);
            }
        }

        throw std::runtime_error("STFS file not found: " + std::string{name});
    }

    XboxupdRawParts extractXboxupdRaw(std::span<const std::byte> pirs_data) {
        const StfsContainer container{pirs_data};
        return splitXboxupdRaw(container.extractFileByName("xboxupd.bin"));
    }

} // namespace Stfs
