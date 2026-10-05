#include "stfs/MetadataParser.hpp"

#include "Endian.hpp"
#include "stfs/Commons.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <stdexcept>

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

        // Decodes a NUL-terminated UTF-16BE string of at most `max_bytes` bytes to UTF-8.
        // Unpaired surrogates become U+FFFD; a trailing odd byte is ignored.
        std::u8string read_locale_string(const std::byte* ptr, std::size_t max_bytes) {
            constexpr char32_t kReplacement = 0xFFFD;
            const std::size_t units = max_bytes / 2;
            const auto unit = [ptr](std::size_t i) -> char32_t {
                return (static_cast<char32_t>(ptr[2 * i]) << 8) |
                       static_cast<char32_t>(ptr[2 * i + 1]);
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

        StfsVolumeDescriptor parse_stfs_volume_descriptor(const std::byte* ptr) {
            StfsVolumeDescriptor vd;
            vd.size = static_cast<std::uint8_t>(ptr[0x00]);
            vd.block_separation = static_cast<std::uint8_t>(ptr[0x02]);
            vd.file_table_block_count = static_cast<std::int16_t>(read_le16(ptr + 0x03));
            vd.file_table_block_number = static_cast<std::int32_t>(read_le24(ptr + 0x05));
            std::memcpy(vd.top_hash_table_hash.data(), ptr + 0x08, 0x14);
            vd.total_allocated_block_count = static_cast<std::int32_t>(read_be32(ptr + 0x1C));
            vd.total_unallocated_block_count = static_cast<std::int32_t>(read_be32(ptr + 0x20));
            return vd;
        }

        SvodVolumeDescriptor parse_svod_volume_descriptor(const std::byte* ptr) {
            SvodVolumeDescriptor vd;
            vd.size = static_cast<std::uint8_t>(ptr[0x00]);
            vd.block_cache_element_count = static_cast<std::uint8_t>(ptr[0x01]);
            vd.worker_thread_processor = static_cast<std::uint8_t>(ptr[0x02]);
            vd.worker_thread_priority = static_cast<std::uint8_t>(ptr[0x03]);
            std::memcpy(vd.hash.data(), ptr + 0x04, 0x14);
            vd.device_features = static_cast<std::uint8_t>(ptr[0x18]);
            vd.data_block_count = read_be24(ptr + 0x19);
            vd.data_block_offset = read_be24(ptr + 0x1C);
            return vd;
        }

        std::vector<LicenseEntry> parse_license_entries(const std::byte* ptr) {
            std::vector<LicenseEntry> entries;
            constexpr std::size_t entry_size = 0x10;
            constexpr std::size_t entry_count = 0x100 / entry_size;

            for (std::size_t i = 0; i < entry_count; ++i) {
                const auto* entry_ptr = ptr + i * entry_size;
                std::uint64_t license_id = read_be64(entry_ptr + 0x0);

                if (license_id == 0) {
                    continue;
                }

                LicenseEntry entry;
                entry.license_id = static_cast<std::int64_t>(license_id);
                entry.license_bits = static_cast<std::int32_t>(read_be32(entry_ptr + 0x8));
                entry.license_flags = static_cast<std::int32_t>(read_be32(entry_ptr + 0xC));
                entries.push_back(entry);
            }

            return entries;
        }
    } // namespace

    Metadata parse_metadata(std::span<const std::byte> data) {
        if (data.size() < 0x571A + 0x4000) {
            throw std::runtime_error("Insufficient data for metadata parsing (v1 assumed)");
        }

        const auto* base = data.data();
        Metadata meta;

        meta.license_entries = parse_license_entries(base + 0x022C);

        std::memcpy(meta.header_sha1.data(), base + 0x032C, 0x14);
        meta.header_size = read_be32(base + 0x0340);
        // Every header holds at least the v1 metadata parsed here (real packages use 0x971A or
        // 0xAD0E); a header approaching 1 MiB is not a real STFS header.
        constexpr std::uint32_t kMinHeaderSize = 0x971A;
        constexpr std::uint32_t kMaxHeaderSize = 0xFFFF0;
        if (meta.header_size < kMinHeaderSize || meta.header_size > kMaxHeaderSize) {
            throw std::runtime_error("STFS header size is out of range");
        }
        meta.content_type = static_cast<ContentType>(read_be32(base + 0x0344));
        meta.metadata_version = static_cast<std::int32_t>(read_be32(base + 0x0348));
        meta.content_size = static_cast<std::int64_t>(read_be64(base + 0x034C));
        meta.media_id = read_be32(base + 0x0354);
        meta.version = static_cast<std::int32_t>(read_be32(base + 0x0358));
        meta.base_version = static_cast<std::int32_t>(read_be32(base + 0x035C));
        meta.title_id = read_be32(base + 0x0360);
        meta.platform = static_cast<Platform>(static_cast<std::uint8_t>(base[0x0364]));
        meta.executable_type = static_cast<std::uint8_t>(base[0x0365]);
        meta.disc_number = static_cast<std::uint8_t>(base[0x0366]);
        meta.disc_in_set = static_cast<std::uint8_t>(base[0x0367]);
        meta.save_game_id = read_be32(base + 0x0368);

        std::memcpy(meta.console_id.data(), base + 0x036C, 5);
        std::memcpy(meta.profile_id.data(), base + 0x0371, 8);

        auto descriptor_type_raw = read_be32(base + 0x03A9);
        meta.descriptor_type = static_cast<DescriptorType>(descriptor_type_raw);

        if (meta.descriptor_type == DescriptorType::Svod) {
            meta.volume_descriptor = parse_svod_volume_descriptor(base + 0x0379);
        } else {
            meta.volume_descriptor = parse_stfs_volume_descriptor(base + 0x0379);
        }

        meta.data_file_count = static_cast<std::int32_t>(read_be32(base + 0x039D));
        meta.data_file_combined_size = static_cast<std::int64_t>(read_be64(base + 0x03A1));

        if (meta.metadata_version == 2) {
            MetadataV2Extra extra;
            std::memcpy(extra.series_id.data(), base + 0x03B1, 0x10);
            std::memcpy(extra.season_id.data(), base + 0x03C1, 0x10);
            extra.season_number = static_cast<std::int16_t>(read_be16(base + 0x03D1));
            extra.episode_number = static_cast<std::int16_t>(read_be16(base + 0x03D3));
            meta.v2_extra = extra;
        }

        std::memcpy(meta.device_id.data(), base + 0x03FD, 0x14);

        meta.display_name = read_locale_string(base + 0x0411, 0x900);
        meta.display_description = read_locale_string(base + 0x0D11, 0x900);
        meta.publisher_name = read_locale_string(base + 0x1611, 0x80);
        meta.title_name = read_locale_string(base + 0x1691, 0x80);

        meta.transfer_flags = static_cast<std::uint8_t>(base[0x1711]);
        meta.thumbnail_image_size = static_cast<std::int32_t>(read_be32(base + 0x1712));
        meta.title_thumbnail_image_size = static_cast<std::int32_t>(read_be32(base + 0x1716));

        const auto thumb_size = thumbnail_size(meta.thumbnail_image_size);
        meta.thumbnail_image.assign(base + 0x171A, base + 0x171A + thumb_size);

        const auto title_thumb_size = thumbnail_size(meta.title_thumbnail_image_size);
        meta.title_thumbnail_image.assign(base + 0x571A, base + 0x571A + title_thumb_size);

        return meta;
    }
} // namespace gxbuild3::stfs