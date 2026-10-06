#include "stfs/MetadataParser.hpp"

#include "Wire.hpp"
#include "stfs/Commons.hpp"
#include "stfs/Layout.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace gxbuild3::stfs {

    namespace {

        void append_utf8(std::u8string& out, char32_t cp) {
            if (cp < 0x80) {
                out += static_cast<char8_t>(cp);
            } else if (cp < 0x800) {
                out += static_cast<char8_t>(0xC0 | (cp >> 6));
                out += static_cast<char8_t>(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                out += static_cast<char8_t>(0xE0 | (cp >> 12));
                out += static_cast<char8_t>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char8_t>(0x80 | (cp & 0x3F));
            } else {
                out += static_cast<char8_t>(0xF0 | (cp >> 18));
                out += static_cast<char8_t>(0x80 | ((cp >> 12) & 0x3F));
                out += static_cast<char8_t>(0x80 | ((cp >> 6) & 0x3F));
                out += static_cast<char8_t>(0x80 | (cp & 0x3F));
            }
        }

        // Decodes a NUL-terminated UTF-16BE string held in `bytes` to UTF-8.
        // Unpaired surrogates become U+FFFD; a trailing odd byte is ignored.
        std::u8string read_locale_string(std::span<const std::uint8_t> bytes) {
            constexpr char32_t kReplacement = 0xFFFD;
            const std::size_t units = bytes.size() / 2;
            const auto unit = [bytes](std::size_t i) -> char32_t {
                return (static_cast<char32_t>(bytes[2 * i]) << 8) |
                       static_cast<char32_t>(bytes[2 * i + 1]);
            };

            std::u8string out;
            for (std::size_t i = 0; i < units; ++i) {
                char32_t cp = unit(i);
                if (cp == 0) {
                    break;
                }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    const char32_t low = i + 1 < units ? unit(i + 1) : 0;
                    if (low >= 0xDC00 && low <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        ++i;
                    } else {
                        cp = kReplacement;
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = kReplacement;
                }
                append_utf8(out, cp);
            }
            return out;
        }

        // Thumbnail sizes are signed on disk; negative sizes mean no image.
        std::size_t thumbnail_size(std::int32_t size) {
            constexpr std::int32_t kMaxThumbnailSize = 0x4000;
            return size <= 0 ? 0 : static_cast<std::size_t>(std::min(size, kMaxThumbnailSize));
        }

        // Copies an on-disk byte field into the model's std::byte array of the same size.
        template <std::size_t N>
        [[nodiscard]] std::array<std::byte, N> to_array(const std::uint8_t (&field)[N]) {
            return std::bit_cast<std::array<std::byte, N>>(field);
        }

        [[nodiscard]] Result<StfsVolumeDescriptor>
        parse_stfs_volume_descriptor(std::span<const std::uint8_t> bytes) {
            auto disk = wire::read<stfs_volume_descriptor_disk>(bytes, 0, "STFS volume descriptor");
            if (!disk) {
                return std::unexpected(std::move(disk.error()));
            }

            StfsVolumeDescriptor vd;
            vd.size = disk->size;
            vd.block_separation = disk->block_separation;
            vd.file_table_block_count =
                static_cast<std::int16_t>(disk->file_table_block_count.get());
            vd.file_table_block_number =
                static_cast<std::int32_t>(disk->file_table_block_number.get());
            vd.top_hash_table_hash = to_array(disk->top_hash_table_hash);
            vd.total_allocated_block_count =
                static_cast<std::int32_t>(disk->total_allocated_block_count.get());
            vd.total_unallocated_block_count =
                static_cast<std::int32_t>(disk->total_unallocated_block_count.get());
            return vd;
        }

        [[nodiscard]] Result<SvodVolumeDescriptor>
        parse_svod_volume_descriptor(std::span<const std::uint8_t> bytes) {
            auto disk = wire::read<svod_volume_descriptor_disk>(bytes, 0, "SVOD volume descriptor");
            if (!disk) {
                return std::unexpected(std::move(disk.error()));
            }

            SvodVolumeDescriptor vd;
            vd.size = disk->size;
            vd.block_cache_element_count = disk->block_cache_element_count;
            vd.worker_thread_processor = disk->worker_thread_processor;
            vd.worker_thread_priority = disk->worker_thread_priority;
            vd.hash = to_array(disk->hash);
            vd.device_features = disk->device_features;
            vd.data_block_count = disk->data_block_count.get();
            vd.data_block_offset = disk->data_block_offset.get();
            return vd;
        }

        [[nodiscard]] Result<VolumeDescriptor>
        parse_volume_descriptor(DescriptorType type, std::span<const std::uint8_t> bytes) {
            if (type == DescriptorType::Svod) {
                return parse_svod_volume_descriptor(bytes);
            }
            return parse_stfs_volume_descriptor(bytes);
        }

        std::vector<LicenseEntry> parse_license_entries(const stfs_metadata_disk& md) {
            std::vector<LicenseEntry> entries;
            for (const stfs_license_entry& disk : md.license) {
                const std::uint64_t license_id = disk.id;
                if (license_id == 0) {
                    continue;
                }

                LicenseEntry entry;
                entry.license_id = static_cast<std::int64_t>(license_id);
                entry.license_bits = static_cast<std::int32_t>(disk.bits.get());
                entry.license_flags = static_cast<std::int32_t>(disk.flags.get());
                entries.push_back(entry);
            }
            return entries;
        }
    } // namespace

    Result<Metadata> parse_metadata(std::span<const std::byte> data) {
        if (data.size() < kMinMetadataSize) {
            return fail(ErrorCode::Truncated,
                        "STFS metadata needs 0x{:X} bytes (v1 assumed), got 0x{:X}",
                        kMinMetadataSize, data.size());
        }

        const auto disk =
            wire::read<stfs_metadata_disk>(wire::as_u8(data), kMetadataOffset, "STFS metadata");
        if (!disk) {
            return std::unexpected(disk.error());
        }
        const stfs_metadata_disk& md = *disk;

        Metadata meta;
        meta.header_size = md.header_size;
        // Every header holds at least the v1 metadata parsed here (real packages use 0x971A or
        // 0xAD0E); a header approaching 1 MiB is not a real STFS header.
        constexpr std::uint32_t kMaxHeaderSize = 0xFFFF0;
        if (meta.header_size < kMinMetadataSize || meta.header_size > kMaxHeaderSize) {
            return fail(ErrorCode::Malformed, "STFS header size 0x{:X} is out of range",
                        meta.header_size);
        }

        meta.license_entries = parse_license_entries(md);
        meta.header_sha1 = to_array(md.header_sha1);
        meta.content_type = static_cast<ContentType>(md.content_type.get());
        meta.metadata_version = static_cast<std::int32_t>(md.metadata_version.get());
        meta.content_size = static_cast<std::int64_t>(md.content_size.get());
        meta.media_id = md.media_id;
        meta.version = static_cast<std::int32_t>(md.version.get());
        meta.base_version = static_cast<std::int32_t>(md.base_version.get());
        meta.title_id = md.title_id;
        meta.platform = static_cast<Platform>(md.platform);
        meta.executable_type = md.executable_type;
        meta.disc_number = md.disc_number;
        meta.disc_in_set = md.disc_in_set;
        meta.save_game_id = md.save_game_id;
        meta.console_id = to_array(md.console_id);
        meta.profile_id = to_array(md.profile_id);

        meta.descriptor_type = static_cast<DescriptorType>(md.descriptor_type.get());
        auto volume_descriptor =
            parse_volume_descriptor(meta.descriptor_type, std::span(md.volume_descriptor));
        if (!volume_descriptor) {
            return std::unexpected(std::move(volume_descriptor.error()));
        }
        meta.volume_descriptor = std::move(*volume_descriptor);

        meta.data_file_count = static_cast<std::int32_t>(md.data_file_count.get());
        meta.data_file_combined_size = static_cast<std::int64_t>(md.data_file_combined_size.get());

        if (meta.metadata_version == 2) {
            MetadataV2Extra extra;
            extra.series_id = to_array(md.series_id);
            extra.season_id = to_array(md.season_id);
            extra.season_number = static_cast<std::int16_t>(md.season_number.get());
            extra.episode_number = static_cast<std::int16_t>(md.episode_number.get());
            meta.v2_extra = extra;
        }

        meta.device_id = to_array(md.device_id);

        meta.display_name = read_locale_string(md.display_name);
        meta.display_description = read_locale_string(md.display_description);
        meta.publisher_name = read_locale_string(md.publisher_name);
        meta.title_name = read_locale_string(md.title_name);

        meta.transfer_flags = md.transfer_flags;
        meta.thumbnail_image_size = static_cast<std::int32_t>(md.thumbnail_image_size.get());
        meta.title_thumbnail_image_size =
            static_cast<std::int32_t>(md.title_thumbnail_image_size.get());

        const auto thumbnail =
            data.subspan(kThumbnailOffset, thumbnail_size(meta.thumbnail_image_size));
        meta.thumbnail_image.assign(thumbnail.begin(), thumbnail.end());

        const auto title_thumbnail =
            data.subspan(kTitleThumbnailOffset, thumbnail_size(meta.title_thumbnail_image_size));
        meta.title_thumbnail_image.assign(title_thumbnail.begin(), title_thumbnail.end());

        return meta;
    }
} // namespace gxbuild3::stfs
