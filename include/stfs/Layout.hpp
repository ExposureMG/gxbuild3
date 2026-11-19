#pragma once

#include "Error.hpp"
#include "Wire.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace gxbuild3::stfs {

    // STFS geometry. Blocks are 4 KiB; block numbers are 24 bits wide.
    inline constexpr std::size_t kBlockSize = 0x1000;
    inline constexpr std::uint32_t kMaxBlockNumber = 0xFFFFFF;

    // The next-block field of the last hash entry in a chain.
    inline constexpr std::uint32_t kChainTerminator = kMaxBlockNumber;

    // A hash table block holds 0xAA entries of 0x18 bytes (SHA-1, status, next block).
    inline constexpr std::size_t kHashEntrySize = 0x18;

    // Data blocks covered by one hash table at level 0, 1 and 2.
    inline constexpr std::array<std::uint32_t, 3> kDataBlocksPerHashLevel = {0xAA, 0x70E4,
                                                                             0x4AF768};

    // CON signatures end at 0x22C (0x1AC + 0x80); LIVE/PIRS signatures end at 0x22C as well
    // (0x004 + 0x100 + 0x128). Every header variant needs this many bytes.
    inline constexpr std::size_t kHeaderRegionSize = 0x22C;

    // Offset of the signature block that follows the 4-byte magic.
    inline constexpr std::size_t kSignatureOffset = 0x004;

    // The CON (console-signed) signature block at kSignatureOffset: the console certificate
    // followed by the package signature. Offsets below are relative to kSignatureOffset.
    struct con_signature_disk {
        wire::be16 public_key_certificate_size;
        std::uint8_t console_id[5];
        char part_number[0x14];
        std::uint8_t console_type;
        char date[8];
        std::uint8_t exponent[4];
        std::uint8_t modulus[0x80];
        std::uint8_t certificate_signature[0x100];
        std::uint8_t signature[0x80];
    };
    static_assert(wire::WireLayout<con_signature_disk>);
    static_assert(sizeof(con_signature_disk) == 0x228);
    static_assert(offsetof(con_signature_disk, console_id) == 0x02);
    static_assert(offsetof(con_signature_disk, part_number) == 0x07);
    static_assert(offsetof(con_signature_disk, console_type) == 0x1B);
    static_assert(offsetof(con_signature_disk, date) == 0x1C);
    static_assert(offsetof(con_signature_disk, exponent) == 0x24);
    static_assert(offsetof(con_signature_disk, modulus) == 0x28);
    static_assert(offsetof(con_signature_disk, certificate_signature) == 0xA8);
    static_assert(offsetof(con_signature_disk, signature) == 0x1A8);

    // The LIVE/PIRS (Microsoft-signed) signature block at kSignatureOffset.
    struct live_signature_disk {
        std::uint8_t package_signature[0x100];
        std::uint8_t padding[0x128];
    };
    static_assert(wire::WireLayout<live_signature_disk>);
    static_assert(sizeof(live_signature_disk) == 0x228);
    static_assert(offsetof(live_signature_disk, padding) == 0x100);

    static_assert(kSignatureOffset + sizeof(con_signature_disk) == kHeaderRegionSize);
    static_assert(kSignatureOffset + sizeof(live_signature_disk) == kHeaderRegionSize);

    // Bytes of the v1 metadata parsed by parse_metadata; every header holds at least this much.
    inline constexpr std::uint32_t kMinMetadataSize = 0x971A;

    // One 0x10-byte license table entry. An all-zero id marks an unused slot.
    struct stfs_license_entry {
        wire::be64 id;
        wire::be32 bits;
        wire::be32 flags;
    };
    static_assert(wire::WireLayout<stfs_license_entry>);
    static_assert(sizeof(stfs_license_entry) == 0x10);
    static_assert(offsetof(stfs_license_entry, bits) == 0x08);
    static_assert(offsetof(stfs_license_entry, flags) == 0x0C);

    // The STFS volume descriptor (descriptor type 0). The file table block count and number are
    // little-endian; the block counts are big-endian.
    struct stfs_volume_descriptor_disk {
        std::uint8_t size;
        std::uint8_t reserved;
        std::uint8_t block_separation;
        wire::le16 file_table_block_count;
        wire::le24 file_table_block_number;
        std::uint8_t top_hash_table_hash[0x14];
        wire::be32 total_allocated_block_count;
        wire::be32 total_unallocated_block_count;
    };
    static_assert(wire::WireLayout<stfs_volume_descriptor_disk>);
    static_assert(sizeof(stfs_volume_descriptor_disk) == 0x24);
    static_assert(offsetof(stfs_volume_descriptor_disk, block_separation) == 0x02);
    static_assert(offsetof(stfs_volume_descriptor_disk, file_table_block_count) == 0x03);
    static_assert(offsetof(stfs_volume_descriptor_disk, file_table_block_number) == 0x05);
    static_assert(offsetof(stfs_volume_descriptor_disk, top_hash_table_hash) == 0x08);
    static_assert(offsetof(stfs_volume_descriptor_disk, total_allocated_block_count) == 0x1C);
    static_assert(offsetof(stfs_volume_descriptor_disk, total_unallocated_block_count) == 0x20);

    // The SVOD volume descriptor (descriptor type 1). The 24-bit block fields are read
    // big-endian; that byte order has not been checked against a real SVOD package.
    struct svod_volume_descriptor_disk {
        std::uint8_t size;
        std::uint8_t block_cache_element_count;
        std::uint8_t worker_thread_processor;
        std::uint8_t worker_thread_priority;
        std::uint8_t hash[0x14];
        std::uint8_t device_features;
        wire::be24 data_block_count;
        wire::be24 data_block_offset;
        std::uint8_t reserved[5];
    };
    static_assert(wire::WireLayout<svod_volume_descriptor_disk>);
    static_assert(sizeof(svod_volume_descriptor_disk) == 0x24);
    static_assert(offsetof(svod_volume_descriptor_disk, hash) == 0x04);
    static_assert(offsetof(svod_volume_descriptor_disk, device_features) == 0x18);
    static_assert(offsetof(svod_volume_descriptor_disk, data_block_count) == 0x19);
    static_assert(offsetof(svod_volume_descriptor_disk, data_block_offset) == 0x1C);
    static_assert(offsetof(svod_volume_descriptor_disk, reserved) == 0x1F);

    // The metadata that follows the signature block, from kMetadataOffset up to the thumbnails.
    // The volume descriptor stays raw bytes: its layout depends on descriptor_type, which follows
    // it. The four strings are NUL-terminated UTF-16BE. series_id .. episode_number are only
    // meaningful when metadata_version is 2.
    inline constexpr std::size_t kMetadataOffset = kHeaderRegionSize;

    struct stfs_metadata_disk {
        stfs_license_entry license[0x10];
        std::uint8_t header_sha1[0x14];
        wire::be32 header_size;
        wire::be32 content_type;
        wire::be32 metadata_version;
        wire::be64 content_size;
        wire::be32 media_id;
        wire::be32 version;
        wire::be32 base_version;
        wire::be32 title_id;
        std::uint8_t platform;
        std::uint8_t executable_type;
        std::uint8_t disc_number;
        std::uint8_t disc_in_set;
        wire::be32 save_game_id;
        std::uint8_t console_id[5];
        std::uint8_t profile_id[8];
        std::uint8_t volume_descriptor[0x24];
        wire::be32 data_file_count;
        wire::be64 data_file_combined_size;
        wire::be32 descriptor_type;
        std::uint8_t reserved[4];
        std::uint8_t series_id[0x10];
        std::uint8_t season_id[0x10];
        wire::be16 season_number;
        wire::be16 episode_number;
        std::uint8_t reserved2[0x28];
        std::uint8_t device_id[0x14];
        std::uint8_t display_name[0x900];
        std::uint8_t display_description[0x900];
        std::uint8_t publisher_name[0x80];
        std::uint8_t title_name[0x80];
        std::uint8_t transfer_flags;
        wire::be32 thumbnail_image_size;
        wire::be32 title_thumbnail_image_size;
    };
    static_assert(wire::WireLayout<stfs_metadata_disk>);
    static_assert(sizeof(stfs_metadata_disk) == 0x14EE);

    // Absolute offsets in the package header.
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, license) == 0x022C);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, header_sha1) == 0x032C);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, header_size) == 0x0340);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, content_type) == 0x0344);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, metadata_version) == 0x0348);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, content_size) == 0x034C);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, media_id) == 0x0354);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, version) == 0x0358);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, base_version) == 0x035C);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, title_id) == 0x0360);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, platform) == 0x0364);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, executable_type) == 0x0365);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, disc_number) == 0x0366);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, disc_in_set) == 0x0367);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, save_game_id) == 0x0368);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, console_id) == 0x036C);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, profile_id) == 0x0371);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, volume_descriptor) == 0x0379);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, data_file_count) == 0x039D);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, data_file_combined_size) ==
                  0x03A1);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, descriptor_type) == 0x03A9);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, reserved) == 0x03AD);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, series_id) == 0x03B1);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, season_id) == 0x03C1);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, season_number) == 0x03D1);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, episode_number) == 0x03D3);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, reserved2) == 0x03D5);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, device_id) == 0x03FD);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, display_name) == 0x0411);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, display_description) == 0x0D11);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, publisher_name) == 0x1611);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, title_name) == 0x1691);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, transfer_flags) == 0x1711);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, thumbnail_image_size) == 0x1712);
    static_assert(kMetadataOffset + offsetof(stfs_metadata_disk, title_thumbnail_image_size) ==
                  0x1716);

    static_assert(sizeof(stfs_volume_descriptor_disk) ==
                  sizeof(stfs_metadata_disk::volume_descriptor));
    static_assert(sizeof(svod_volume_descriptor_disk) ==
                  sizeof(stfs_metadata_disk::volume_descriptor));

    // The two thumbnails follow the metadata, each in a slot of kThumbnailSlotSize bytes.
    inline constexpr std::size_t kThumbnailOffset = kMetadataOffset + sizeof(stfs_metadata_disk);
    inline constexpr std::size_t kThumbnailSlotSize = 0x4000;
    inline constexpr std::size_t kTitleThumbnailOffset = kThumbnailOffset + kThumbnailSlotSize;
    static_assert(kThumbnailOffset == 0x171A);
    static_assert(kTitleThumbnailOffset == 0x571A);
    static_assert(kTitleThumbnailOffset + kThumbnailSlotSize == kMinMetadataSize);

    // One 0x40-byte file table entry as the container stores it. Block counts and the starting
    // block are 24-bit little-endian; the rest is big-endian. The name is not NUL-terminated and
    // its length is the low six bits of flags.
    struct stfs_file_table_entry {
        char name[0x28];
        std::uint8_t flags;
        wire::le24 blocks_allocated;
        wire::le24 blocks_allocated_copy;
        wire::le24 starting_block;
        wire::be16 path_indicator;
        wire::be32 file_size;
        wire::be32 update_timestamp;
        wire::be32 access_timestamp;
    };
    static_assert(wire::WireLayout<stfs_file_table_entry>);
    static_assert(sizeof(stfs_file_table_entry) == 0x40);
    static_assert(offsetof(stfs_file_table_entry, flags) == 0x28);
    static_assert(offsetof(stfs_file_table_entry, blocks_allocated) == 0x29);
    static_assert(offsetof(stfs_file_table_entry, blocks_allocated_copy) == 0x2C);
    static_assert(offsetof(stfs_file_table_entry, starting_block) == 0x2F);
    static_assert(offsetof(stfs_file_table_entry, path_indicator) == 0x32);
    static_assert(offsetof(stfs_file_table_entry, file_size) == 0x34);
    static_assert(offsetof(stfs_file_table_entry, update_timestamp) == 0x38);
    static_assert(offsetof(stfs_file_table_entry, access_timestamp) == 0x3C);

    // One 0x18-byte hash table entry: the SHA-1 of the block it covers, the block's status and,
    // at level 0, the next block of the file's chain (24-bit big-endian; kChainTerminator ends it).
    struct stfs_hash_entry {
        std::uint8_t sha1[0x14];
        std::uint8_t status;
        wire::be24 next_block;
    };
    static_assert(wire::WireLayout<stfs_hash_entry>);
    static_assert(sizeof(stfs_hash_entry) == kHashEntrySize);
    static_assert(offsetof(stfs_hash_entry, status) == 0x14);
    static_assert(offsetof(stfs_hash_entry, next_block) == 0x15);

    // Byte offset of the level-`level` hash entry for logical block `block`: the entry's index in
    // the hash table block that covers it, scaled by kHashEntrySize, added to that table block's
    // offset. Fails like compute_level_n_hash_block_number and block_to_offset.
    [[nodiscard]] Result<std::uint64_t> hash_entry_offset(std::uint32_t block, int level,
                                                          std::uint32_t header_size);

} // namespace gxbuild3::stfs
