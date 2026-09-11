#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace stfs {

    enum class Magic {
        CON,
        PIRS,
        LIVE
    };

    struct ConSignature {
        std::uint16_t public_key_certificate_size;
        std::array<std::byte, 5> certificate_owner_console_id;
        std::array<char, 0x14> certificate_owner_console_part_number;
        std::uint8_t certificate_owner_console_type;
        std::array<char, 8> certificate_date_of_generation;
        std::array<std::byte, 4> public_exponent;
        std::array<std::byte, 0x80> public_modulus;
        std::array<std::byte, 0x100> certificate_signature;
        std::array<std::byte, 0x80> signature;
    };

    struct LiveSignature {
        std::array<std::byte, 0x100> package_signature;
        std::array<std::byte, 0x128> padding;
    };

    using Signature = std::variant<ConSignature, LiveSignature>;

    struct Header {
        Magic magic;
        Signature signature;
    };

    enum class ContentType : std::uint32_t {
        SavedGame = 0x0000001,
        MarketplaceContent = 0x0000002,
        Publisher = 0x0000003,
        XboxTitle = 0x0001000,
        IptvPauseBuffer = 0x0002000,
        InstalledGame = 0x0004000,
        XboxOriginalGame = 0x0005000,
        GameOnDemand = 0x0007000,
        AvatarItem = 0x0009000,
        Profile = 0x0010000,
        GamerPicture = 0x0020000,
        Theme = 0x0030000,
        CacheFile = 0x0040000,
        StorageDownload = 0x0050000,
        XboxSavedGame = 0x0060000,
        XboxDownload = 0x0070000,
        GameDemo = 0x0080000,
        Video = 0x0090000,
        GameTitle = 0x00A0000,
        Installer = 0x00B0000,
        GameTrailer = 0x00C0000,
        ArcadeTitle = 0x00D0000,
        Xna = 0x00E0000,
        LicenseStore = 0x00F0000,
        Movie = 0x0100000,
        Tv = 0x0200000,
        MusicVideo = 0x0300000,
        GameVideo = 0x0400000,
        PodcastVideo = 0x0500000,
        ViralVideo = 0x0600000,
        CommunityGame = 0x2000000,
    };

    enum class DescriptorType : std::uint32_t {
        Stfs = 0,
        Svod = 1
    };

    enum class Platform : std::uint8_t {
        Xbox360 = 2,
        Pc = 4
    };

    struct LicenseEntry {
        std::int64_t license_id;
        std::int32_t license_bits;
        std::int32_t license_flags;
    };

    struct StfsVolumeDescriptor {
        std::uint8_t size;
        std::uint8_t block_separation;
        std::int16_t file_table_block_count;
        std::int32_t file_table_block_number;
        std::array<std::byte, 0x14> top_hash_table_hash;
        std::int32_t total_allocated_block_count;
        std::int32_t total_unallocated_block_count;
    };

    struct SvodVolumeDescriptor {
        std::uint8_t size;
        std::uint8_t block_cache_element_count;
        std::uint8_t worker_thread_processor;
        std::uint8_t worker_thread_priority;
        std::array<std::byte, 0x14> hash;
        std::uint8_t device_features;
        std::uint32_t data_block_count;
        std::uint32_t data_block_offset;
    };

    using VolumeDescriptor = std::variant<StfsVolumeDescriptor, SvodVolumeDescriptor>;

    struct MetadataV2Extra {
        std::array<std::byte, 0x10> series_id;
        std::array<std::byte, 0x10> season_id;
        std::int16_t season_number;
        std::int16_t episode_number;
    };

    struct Metadata {
        std::vector<LicenseEntry> license_entries;
        std::array<std::byte, 0x14> header_sha1;
        std::uint32_t header_size;
        ContentType content_type;
        std::int32_t metadata_version;
        std::int64_t content_size;
        std::uint32_t media_id;
        std::int32_t version;
        std::int32_t base_version;
        std::uint32_t title_id;
        Platform platform;
        std::uint8_t executable_type;
        std::uint8_t disc_number;
        std::uint8_t disc_in_set;
        std::uint32_t save_game_id;
        std::array<std::byte, 5> console_id;
        std::array<std::byte, 8> profile_id;
        VolumeDescriptor volume_descriptor;
        std::int32_t data_file_count;
        std::int64_t data_file_combined_size;
        DescriptorType descriptor_type;
        std::array<std::byte, 0x14> device_id;
        std::u8string display_name;
        std::u8string display_description;
        std::u8string publisher_name;
        std::u8string title_name;
        std::uint8_t transfer_flags;
        std::int32_t thumbnail_image_size;
        std::int32_t title_thumbnail_image_size;
        std::vector<std::byte> thumbnail_image;
        std::vector<std::byte> title_thumbnail_image;
        std::optional<MetadataV2Extra> v2_extra;
    };

    struct FileEntry {
        std::string name;
        std::uint8_t flags;
        std::uint32_t blocks_allocated;
        std::uint32_t blocks_allocated_copy;
        std::uint32_t starting_block;
        std::int16_t path_indicator;
        std::uint32_t file_size;
        std::uint32_t update_timestamp;
        std::uint32_t access_timestamp;

        bool isDirectory() const { return (flags & 0x80) == 0x80; }
        bool isConsecutiveBlocks() const { return (flags & 0x40) == 0x40; }

        std::uint8_t nameLength() const { return flags & 0x3F; }
    };

    std::vector<FileEntry> parseFileListing(std::span<const std::byte> data);

    Header parseHeader(std::span<const std::byte> data);
    Header readHeaderFromFile(const std::filesystem::path& path);

    Metadata parseMetadata(std::span<const std::byte> data);

} // namespace stfs