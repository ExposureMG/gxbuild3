// tests/golden/stfs_su20076000_entries.txt and stfs_su20076000_metadata.txt: HEAD behaviour of
// the tracked system update package 17559/su20076000_00000000, compared whole.
//   - entries: its 31 file-table entries with the SHA-1 of every file
//     StfsContainer::extract_to_memory() returns, and whether the hash-verified extract agrees;
//   - metadata: every header and metadata field through stfs::parse_header and
//     stfs::parse_metadata.
// The renderers and their format strings are the old StfsTests.cpp ones, verbatim; a failed
// precondition is now an Error the render returns. The package is read once per process.
// GXBUILD3_STFS_SUPPORT overrides the support directory, for mutation checks against scratch
// copies only.

#include "Error.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/MetadataParser.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "support/golden/Golden.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <gtest/gtest.h>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace gxbuild3::snapshots {
    namespace {

        constexpr std::string_view kEntriesGolden = "stfs_su20076000_entries";
        constexpr std::string_view kMetadataGolden = "stfs_su20076000_metadata";
        constexpr const char* kSupportOverride = "GXBUILD3_STFS_SUPPORT";

        using Verify = stfs::StfsContainer::Verify;

        std::string bytes_hex(std::span<const std::byte> data) {
            return test::hex({reinterpret_cast<const std::uint8_t*>(data.data()), data.size()});
        }

        // Printable ASCII is kept; quotes, backslashes and every other byte are escaped.
        std::string escaped_text(std::string_view text) {
            std::string out = "\"";
            for (const char ch : text) {
                const auto byte = static_cast<unsigned char>(ch);
                if (ch == '"' || ch == '\\')
                    out += std::format("\\{}", ch);
                else if (byte >= 0x20 && byte < 0x7F)
                    out += ch;
                else
                    out += std::format("\\x{:02x}", byte);
            }
            return out + "\"";
        }

        std::string escaped_text(const std::u8string& text) {
            return escaped_text(
                std::string_view(reinterpret_cast<const char*>(text.data()), text.size()));
        }

        // The extract_to_memory key of an entry: a leading "$flash_" in any case is dropped and
        // the rest lower-cased.
        std::string normalised_name(std::string name) {
            if (name.size() >= 7) {
                std::string prefix = name.substr(0, 7);
                std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (prefix == "$flash_")
                    name.erase(0, 7);
            }
            std::transform(name.begin(), name.end(), name.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return name;
        }

        std::size_t line_count(std::string_view text) {
            return static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n'));
        }

        Result<test::Bytes> read_system_update_fixture() {
            if (test::support_dir(kSupportOverride) != test::support_dir()) {
                std::cerr << "  note: support directory overridden by GXBUILD3_STFS_SUPPORT\n";
            }
            const auto path = test::support_dir(kSupportOverride) / "17559" / "su20076000_00000000";
            auto bytes = test::read_file(path);
            if (bytes && bytes->empty()) {
                return fail(ErrorCode::Truncated, "fixture {} is readable", path.string());
            }
            return with_context(std::move(bytes), "fixture " + path.string() + " is readable");
        }

        // Read once per process and shared by the four cases and both renderers.
        const Result<test::Bytes>& system_update_package() {
            static const Result<test::Bytes> package = read_system_update_fixture();
            return package;
        }

        struct EntrySnapshot {
            std::string text;
            std::size_t entries = 0;
            std::size_t hashed = 0;
            std::size_t files = 0;
        };

        Result<EntrySnapshot> render_entry_snapshot(std::span<const std::byte> bytes) {
            const auto container =
                with_context(stfs::StfsContainer::open(bytes), "StfsContainer opens the fixture");
            if (!container) {
                return std::unexpected(container.error());
            }
            const auto in_memory = with_context(container->extract_to_memory(),
                                                "StfsContainer extracts the fixture to memory");
            if (!in_memory) {
                return std::unexpected(in_memory.error());
            }

            EntrySnapshot snapshot;
            std::string& out = snapshot.text;
            const auto& entries = container->entries();
            out += std::format("entries {}\n", entries.size());
            out += std::format("extract_to_memory files {}\n", in_memory->size());
            for (std::size_t i = 0; i < entries.size(); ++i) {
                const auto& entry = entries[i];
                out += std::format("[{:02}] name={} flags=0x{:02X} blocks_allocated=0x{:06X} "
                                   "blocks_allocated_copy=0x{:06X} starting_block=0x{:06X} "
                                   "path_indicator={} file_size=0x{:08X} update_timestamp=0x{:08X} "
                                   "access_timestamp=0x{:08X}\n",
                                   i, escaped_text(entry.name), entry.flags, entry.blocks_allocated,
                                   entry.blocks_allocated_copy, entry.starting_block,
                                   entry.path_indicator, entry.file_size, entry.update_timestamp,
                                   entry.access_timestamp);
                ++snapshot.entries;
                if (entry.is_directory()) {
                    out += std::format("[{:02}] directory\n", i);
                    continue;
                }
                ++snapshot.files;
                const auto key = normalised_name(entry.name);
                const auto found = in_memory->find(key);
                if (found == in_memory->end()) {
                    out += std::format("[{:02}] key={} missing from extract_to_memory\n", i,
                                       escaped_text(key));
                    continue;
                }
                // The hash-verified extraction must agree with the unverified extract_to_memory
                // bytes; a verification failure is rendered so the golden diff names the entry.
                const auto checked = container->extract(entry, Verify::Yes);
                const std::string verified =
                    !checked ? "verify-failed" : (*checked == found->second ? "yes" : "no");
                out += std::format("[{:02}] key={} size=0x{:08X} sha1={} verified_equal={}\n", i,
                                   escaped_text(key), found->second.size(),
                                   test::sha1_hex(found->second), verified);
                ++snapshot.hashed;
            }
            return snapshot;
        }

        Result<EntrySnapshot> entry_snapshot() {
            const auto& package = system_update_package();
            if (!package) {
                return std::unexpected(package.error());
            }
            return render_entry_snapshot(std::as_bytes(std::span{*package}));
        }

        struct MetadataSnapshot {
            std::string text;
            std::size_t fields = 0;
        };

        Result<MetadataSnapshot> render_metadata_snapshot(std::span<const std::byte> bytes) {
            const auto header =
                with_context(stfs::parse_header(bytes), "parse_header accepts the fixture");
            if (!header) {
                return std::unexpected(header.error());
            }
            const auto meta =
                with_context(stfs::parse_metadata(bytes), "parse_metadata accepts the fixture");
            if (!meta) {
                return std::unexpected(meta.error());
            }

            MetadataSnapshot snapshot;
            const auto field = [&snapshot](std::string_view name, const std::string& value) {
                snapshot.text += std::format("{} {}\n", name, value);
                ++snapshot.fields;
            };
            const auto hex32 = [](std::uint64_t value) { return std::format("0x{:08X}", value); };
            using test::sha1_hex;

            constexpr std::string_view magic_names[] = {"CON", "PIRS", "LIVE"};
            field("magic", std::string(magic_names[static_cast<std::size_t>(header->magic)]));
            if (const auto* live = std::get_if<stfs::LiveSignature>(&header->signature)) {
                field("signature", "live");
                field("signature.package_signature.sha1", sha1_hex(live->package_signature));
                field("signature.padding.sha1", sha1_hex(live->padding));
            } else {
                const auto& con = std::get<stfs::ConSignature>(header->signature);
                field("signature", "con");
                field("signature.public_key_certificate_size",
                      std::to_string(con.public_key_certificate_size));
                field("signature.signature.sha1", sha1_hex(con.signature));
            }

            field("license_entries.count", std::to_string(meta->license_entries.size()));
            for (std::size_t i = 0; i < meta->license_entries.size(); ++i) {
                const auto& license = meta->license_entries[i];
                field(std::format("license_entries[{}]", i),
                      std::format("id=0x{:016X} bits=0x{:08X} flags=0x{:08X}",
                                  static_cast<std::uint64_t>(license.license_id),
                                  static_cast<std::uint32_t>(license.license_bits),
                                  static_cast<std::uint32_t>(license.license_flags)));
            }
            field("header_sha1.sha1", sha1_hex(meta->header_sha1));
            field("header_size", hex32(meta->header_size));
            field("content_type", hex32(static_cast<std::uint32_t>(meta->content_type)));
            field("metadata_version", std::to_string(meta->metadata_version));
            field("content_size",
                  std::format("0x{:016X}", static_cast<std::uint64_t>(meta->content_size)));
            field("media_id", hex32(meta->media_id));
            field("version", hex32(static_cast<std::uint32_t>(meta->version)));
            field("base_version", hex32(static_cast<std::uint32_t>(meta->base_version)));
            field("title_id", hex32(meta->title_id));
            field("platform", std::to_string(static_cast<unsigned>(meta->platform)));
            field("executable_type", std::to_string(meta->executable_type));
            field("disc_number", std::to_string(meta->disc_number));
            field("disc_in_set", std::to_string(meta->disc_in_set));
            field("save_game_id", hex32(meta->save_game_id));
            field("console_id", bytes_hex(meta->console_id));
            field("profile_id", bytes_hex(meta->profile_id));
            field("descriptor_type",
                  std::to_string(static_cast<std::uint32_t>(meta->descriptor_type)));
            if (const auto* vd =
                    std::get_if<stfs::StfsVolumeDescriptor>(&meta->volume_descriptor)) {
                field("stfs.size", std::format("0x{:02X}", vd->size));
                field("stfs.block_separation", std::format("0x{:02X}", vd->block_separation));
                field("stfs.file_table_block_count", std::to_string(vd->file_table_block_count));
                field("stfs.file_table_block_number", std::to_string(vd->file_table_block_number));
                field("stfs.top_hash_table_hash", bytes_hex(vd->top_hash_table_hash));
                field("stfs.total_allocated_block_count",
                      std::to_string(vd->total_allocated_block_count));
                field("stfs.total_unallocated_block_count",
                      std::to_string(vd->total_unallocated_block_count));
            } else {
                field("volume_descriptor", "svod");
            }
            field("data_file_count", std::to_string(meta->data_file_count));
            field("data_file_combined_size",
                  std::format("0x{:016X}",
                              static_cast<std::uint64_t>(meta->data_file_combined_size)));
            field("v2_extra", meta->v2_extra ? "present" : "absent");
            if (meta->v2_extra) {
                field("v2_extra.series_id", bytes_hex(meta->v2_extra->series_id));
                field("v2_extra.season_id", bytes_hex(meta->v2_extra->season_id));
                field("v2_extra.season_number", std::to_string(meta->v2_extra->season_number));
                field("v2_extra.episode_number", std::to_string(meta->v2_extra->episode_number));
            }
            field("device_id.sha1", sha1_hex(meta->device_id));
            field("display_name", escaped_text(meta->display_name));
            field("display_description", escaped_text(meta->display_description));
            field("publisher_name", escaped_text(meta->publisher_name));
            field("title_name", escaped_text(meta->title_name));
            field("transfer_flags", std::format("0x{:02X}", meta->transfer_flags));
            field("thumbnail_image_size", std::to_string(meta->thumbnail_image_size));
            field("title_thumbnail_image_size", std::to_string(meta->title_thumbnail_image_size));
            field("thumbnail_image",
                  std::format("size=0x{:X} sha1={}", meta->thumbnail_image.size(),
                              sha1_hex(meta->thumbnail_image)));
            field("title_thumbnail_image",
                  std::format("size=0x{:X} sha1={}", meta->title_thumbnail_image.size(),
                              sha1_hex(meta->title_thumbnail_image)));
            return snapshot;
        }

        Result<MetadataSnapshot> metadata_snapshot() {
            const auto& package = system_update_package();
            if (!package) {
                return std::unexpected(package.error());
            }
            return render_metadata_snapshot(std::as_bytes(std::span{*package}));
        }

        // The whole-file renderers the registry re-renders under --update.
        Result<std::string> render_entries_golden() {
            return entry_snapshot().transform([](EntrySnapshot s) { return std::move(s.text); });
        }

        Result<std::string> render_metadata_golden() {
            return metadata_snapshot().transform(
                [](MetadataSnapshot s) { return std::move(s.text); });
        }

        GX_GOLDEN(kEntriesGolden, render_entries_golden);
        GX_GOLDEN(kMetadataGolden, render_metadata_golden);

        TEST(StfsSystemUpdateGolden, EntriesMatchGolden) {
            ASSERT_OK_AND_ASSIGN(const EntrySnapshot first, entry_snapshot());
            ASSERT_OK_AND_ASSIGN(const EntrySnapshot second, entry_snapshot());
            EXPECT_EQ(first.text, second.text) << kEntriesGolden << ": two renderings differ";
            EXPECT_TRUE(test::matches_golden(kEntriesGolden, first.text))
                << kEntriesGolden << ".txt does not match HEAD output";
        }

        TEST(StfsSystemUpdateGolden, EveryOneOf31EntriesIsHashed) {
            ASSERT_OK_AND_ASSIGN(const EntrySnapshot snapshot, entry_snapshot());
            EXPECT_EQ(snapshot.entries, 31u) << "fixture lists 31 entries";
            EXPECT_EQ(snapshot.hashed, snapshot.files) << "every file entry is hashed";
        }

        TEST(StfsSystemUpdateGolden, MetadataMatchesGolden) {
            ASSERT_OK_AND_ASSIGN(const MetadataSnapshot first, metadata_snapshot());
            ASSERT_OK_AND_ASSIGN(const MetadataSnapshot second, metadata_snapshot());
            EXPECT_EQ(first.text, second.text) << kMetadataGolden << ": two renderings differ";
            EXPECT_TRUE(test::matches_golden(kMetadataGolden, first.text))
                << kMetadataGolden << ".txt does not match HEAD output";
        }

        TEST(StfsSystemUpdateGolden, MetadataFieldsAreRendered) {
            ASSERT_OK_AND_ASSIGN(const MetadataSnapshot snapshot, metadata_snapshot());
            EXPECT_GT(snapshot.fields, 0u) << "metadata fields rendered";
            EXPECT_EQ(snapshot.fields, line_count(snapshot.text)) << "one line per field";
        }

    } // namespace
} // namespace gxbuild3::snapshots
