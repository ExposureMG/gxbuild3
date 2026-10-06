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
#include <string_view>
#include <system_error>
#include <utility>
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

    StfsContainer::StfsContainer(std::span<const std::byte> data, std::uint32_t header_size,
                                 std::vector<FileEntry> entries)
        : data_(data), header_size_(header_size), entries_(std::move(entries)) {}

    Result<StfsContainer> StfsContainer::open(std::span<const std::byte> data) {
        if (!starts_with_pirs(data)) {
            return fail(ErrorCode::Malformed, "Invalid STFS signature: expected PIRS");
        }

        const auto header = stfs::parse_header(data);
        if (!header) {
            return std::unexpected(header.error());
        }
        if (header->magic != stfs::Magic::PIRS) {
            return fail(ErrorCode::Malformed, "Invalid STFS signature: expected PIRS");
        }

        const auto metadata = stfs::parse_metadata(data);
        if (!metadata) {
            return std::unexpected(metadata.error());
        }
        if (metadata->descriptor_type != stfs::DescriptorType::Stfs) {
            return fail(ErrorCode::Unsupported,
                        "SVOD packages are not supported for PIRS extraction");
        }

        const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&metadata->volume_descriptor);
        if (vd == nullptr) {
            return fail(ErrorCode::Malformed, "PIRS package is missing an STFS volume descriptor");
        }

        const auto header_size = metadata->header_size;
        const auto file_table = detail::read_file_table(data, header_size, *vd);
        if (!file_table) {
            return std::unexpected(file_table.error());
        }
        auto entries = stfs::parse_file_listing(*file_table);
        if (!entries) {
            return std::unexpected(std::move(entries).error());
        }
        Log::Debug("Opened STFS container ({} entries, header size 0x{:X})", entries->size(),
                   header_size);
        return StfsContainer(data, header_size, std::move(*entries));
    }

    Result<void> StfsContainer::extract_all(const std::filesystem::path& target_dir) const {
        // Validate every destination before writing anything.
        const auto relative_paths = detail::build_entry_paths(entries_);
        if (!relative_paths) {
            return std::unexpected(relative_paths.error());
        }
        std::vector<std::filesystem::path> destinations;
        destinations.reserve(relative_paths->size());
        for (const auto& relative : *relative_paths) {
            auto destination = detail::safe_join(target_dir, relative);
            if (!destination) {
                return std::unexpected(std::move(destination).error());
            }
            destinations.push_back(std::move(*destination));
        }

        std::error_code error;
        std::filesystem::create_directories(target_dir, error);
        if (error) {
            return from_error_code(error, target_dir);
        }

        for (std::size_t i = 0; i < entries_.size(); ++i) {
            const auto& entry = entries_[i];
            const auto& full_path = destinations[i];

            const auto directory = entry.is_directory() ? full_path : full_path.parent_path();
            std::filesystem::create_directories(directory, error);
            if (error) {
                return from_error_code(error, directory);
            }
            if (entry.is_directory()) {
                continue;
            }

            const auto file_data =
                stfs::extract_file(data_, entry, stfs::Magic::PIRS, header_size_);
            if (!file_data) {
                return std::unexpected(file_data.error());
            }
            if (auto written = detail::write_file(full_path, *file_data); !written) {
                return written;
            }
        }
        return {};
    }

    Result<ExtractedFiles>
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
            auto file_data = stfs::extract_file(data_, entry, stfs::Magic::PIRS, header_size_);
            if (!file_data) {
                return std::unexpected(std::move(file_data).error());
            }
            results.emplace(std::move(name), std::move(*file_data));
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

    Result<std::vector<std::byte>>
    StfsContainer::extract_file_by_name(std::string_view name) const {
        const auto wanted = lower_ascii(std::string{name});

        for (const auto& entry : entries_) {
            if (entry.is_directory()) {
                continue;
            }

            auto entry_name = strip_flash_prefix(entry.name);
            entry_name = lower_ascii(std::move(entry_name));
            if (entry_name == wanted) {
                return stfs::extract_file(data_, entry, stfs::Magic::PIRS, header_size_);
            }
        }

        return fail(ErrorCode::NotFound, "STFS file not found: {}", name);
    }

} // namespace gxbuild3::stfs
