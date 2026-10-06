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

        [[nodiscard]] bool starts_with_pirs(std::span<const std::byte> data) {
            return data.size() >= 4 && data[0] == std::byte{static_cast<unsigned char>('P')} &&
                   data[1] == std::byte{static_cast<unsigned char>('I')} &&
                   data[2] == std::byte{static_cast<unsigned char>('R')} &&
                   data[3] == std::byte{static_cast<unsigned char>('S')};
        }

        [[nodiscard]] std::string lower_ascii(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            return value;
        }

        [[nodiscard]] std::string strip_flash_prefix(std::string name) {
            constexpr std::string_view prefix = "$flash_";
            if (name.size() >= prefix.size() &&
                lower_ascii(name.substr(0, prefix.size())) == prefix) {
                name.erase(0, prefix.size());
            }
            return name;
        }

    } // namespace

    StfsContainer::StfsContainer(std::span<const std::byte> data) : data_(data) {
        if (!starts_with_pirs(data_)) {
            throw std::runtime_error("Invalid STFS signature: expected PIRS");
        }

        const auto header = detail::value_or_throw(stfs::parse_header(data_));
        if (header.magic != stfs::Magic::PIRS) {
            throw std::runtime_error("Invalid STFS signature: expected PIRS");
        }

        const auto metadata = detail::value_or_throw(stfs::parse_metadata(data_));
        if (metadata.descriptor_type != stfs::DescriptorType::Stfs) {
            throw std::runtime_error("SVOD packages are not supported for PIRS extraction");
        }

        const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&metadata.volume_descriptor);
        if (vd == nullptr) {
            throw std::runtime_error("PIRS package is missing an STFS volume descriptor");
        }

        header_size_ = metadata.header_size;

        const auto file_table =
            detail::value_or_throw(detail::read_file_table(data_, header_size_, *vd));
        entries_ = detail::value_or_throw(stfs::parse_file_listing(file_table));
        Log::Debug("Opened STFS container ({} entries, header size 0x{:X})", entries_.size(),
                   header_size_);
    }

    void StfsContainer::extract_all(const std::filesystem::path& target_dir) const {
        // Validate every destination before writing anything.
        const auto relative_paths = detail::value_or_throw(detail::build_entry_paths(entries_));
        std::vector<std::filesystem::path> destinations;
        destinations.reserve(relative_paths.size());
        for (const auto& relative : relative_paths) {
            destinations.push_back(detail::value_or_throw(detail::safe_join(target_dir, relative)));
        }

        std::filesystem::create_directories(target_dir);

        for (std::size_t i = 0; i < entries_.size(); ++i) {
            const auto& entry = entries_[i];
            const auto& full_path = destinations[i];

            if (entry.is_directory()) {
                std::filesystem::create_directories(full_path);
                continue;
            }

            std::filesystem::create_directories(full_path.parent_path());
            const auto file_data = detail::value_or_throw(
                stfs::extract_file(data_, entry, stfs::Magic::PIRS, header_size_));
            detail::value_or_throw(detail::write_file(full_path, file_data));
        }
    }

    ExtractedFiles
    StfsContainer::extract_to_memory(std::span<const std::string> excluded_names) const {
        ExtractedFiles results;

        for (const auto& entry : entries_) {
            if (entry.is_directory()) {
                continue;
            }

            auto name = strip_flash_prefix(entry.name);
            name = lower_ascii(std::move(name));
            if (std::find(excluded_names.begin(), excluded_names.end(), name) !=
                excluded_names.end()) {
                continue;
            }
            results.emplace(std::move(name), detail::value_or_throw(stfs::extract_file(
                                                 data_, entry, stfs::Magic::PIRS, header_size_)));
        }

        return results;
    }

    bool StfsContainer::contains_file_by_name(std::string_view name) const {
        const auto wanted = lower_ascii(std::string{name});

        return std::any_of(entries_.begin(), entries_.end(), [&](const auto& entry) {
            if (entry.is_directory()) {
                return false;
            }
            auto entry_name = strip_flash_prefix(entry.name);
            return lower_ascii(std::move(entry_name)) == wanted;
        });
    }

    std::vector<std::byte> StfsContainer::extract_file_by_name(std::string_view name) const {
        const auto wanted = lower_ascii(std::string{name});

        for (const auto& entry : entries_) {
            if (entry.is_directory()) {
                continue;
            }

            auto entry_name = strip_flash_prefix(entry.name);
            entry_name = lower_ascii(std::move(entry_name));
            if (entry_name == wanted) {
                return detail::value_or_throw(
                    stfs::extract_file(data_, entry, stfs::Magic::PIRS, header_size_));
            }
        }

        throw std::runtime_error("STFS file not found: " + std::string{name});
    }

} // namespace gxbuild3::stfs
