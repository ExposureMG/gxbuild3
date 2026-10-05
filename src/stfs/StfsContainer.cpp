#include "stfs/StfsContainer.hpp"

#include "PackageCommon.hpp"
#include "stfs/BlockParser.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/FileTableParser.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/MetadataParser.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <variant>

namespace gxbuild3::stfs {
    namespace {

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

    } // namespace

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

        header_size_ = metadata.header_size;

        const auto file_table = stfs::detail::readFileTable(data_, header_size_, *vd);
        entries_ = stfs::parseFileListing(file_table);
        Log::Debug("Opened STFS container ({} entries, header size 0x{:X})", entries_.size(),
                   header_size_);
    }

    void StfsContainer::extractAll(const std::filesystem::path& target_dir) const {
        // Validate every destination before writing anything.
        const auto relative_paths = stfs::detail::buildEntryPaths(entries_);
        std::vector<std::filesystem::path> destinations;
        destinations.reserve(relative_paths.size());
        for (const auto& relative : relative_paths) {
            destinations.push_back(stfs::detail::safeJoin(target_dir, relative));
        }

        std::filesystem::create_directories(target_dir);

        for (std::size_t i = 0; i < entries_.size(); ++i) {
            const auto& entry = entries_[i];
            const auto& full_path = destinations[i];

            if (entry.isDirectory()) {
                std::filesystem::create_directories(full_path);
                continue;
            }

            std::filesystem::create_directories(full_path.parent_path());
            const auto file_data = stfs::extractFile(data_, entry, stfs::Magic::PIRS, header_size_);
            stfs::detail::writeFile(full_path, file_data);
        }
    }

    ExtractedFiles
    StfsContainer::extractToMemory(std::span<const std::string> excluded_names) const {
        ExtractedFiles results;

        for (const auto& entry : entries_) {
            if (entry.isDirectory()) {
                continue;
            }

            auto name = stripFlashPrefix(entry.name);
            name = lowerAscii(std::move(name));
            if (std::find(excluded_names.begin(), excluded_names.end(), name) !=
                excluded_names.end()) {
                continue;
            }
            results.emplace(std::move(name),
                            stfs::extractFile(data_, entry, stfs::Magic::PIRS, header_size_));
        }

        return results;
    }

    bool StfsContainer::containsFileByName(std::string_view name) const {
        const auto wanted = lowerAscii(std::string{name});

        return std::any_of(entries_.begin(), entries_.end(), [&](const auto& entry) {
            if (entry.isDirectory()) {
                return false;
            }
            auto entry_name = stripFlashPrefix(entry.name);
            return lowerAscii(std::move(entry_name)) == wanted;
        });
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

} // namespace gxbuild3::stfs
