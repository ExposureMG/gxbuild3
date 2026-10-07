// Legacy STFS golden snapshots, kept until the golden binary owns them: the two snapshot cases
// pin HEAD behaviour of the tracked 17559/su20076000_00000000:
//   - its 31 file-table entries with the SHA-1 of every file StfsContainer::extract_to_memory()
//     returns (tests/golden/stfs_su20076000_entries.txt);
//   - every header and metadata field through stfs::parse_header and stfs::parse_metadata
//     (tests/golden/stfs_su20076000_metadata.txt).
// The behavioural cases and the exact-ErrorCode table moved to gxbuild3_stfs_tests (tests/stfs).
// --update rewrites the two goldens (CTest never passes it). GXBUILD3_STFS_SUPPORT overrides the
// support directory of the snapshot cases, for mutation checks against scratch copies only.

#include "Error.hpp"
#include "GoldenSnapshot.hpp"
#include "excrypt.h"
#include "stfs/HeaderParser.hpp"
#include "stfs/MetadataParser.hpp"
#include "stfs/StfsContainer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {
    namespace fs = std::filesystem;
    namespace stfs = gxbuild3::stfs;
    using Bytes = std::vector<std::byte>;

    // Set by main(); the golden snapshot cases compare against (or, with --update, rewrite)
    // tests/golden/<name>.txt.
    std::optional<gxbuild3::test::GoldenOptions> g_golden;

    void require(bool condition, std::string_view message) {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    using Verify = gxbuild3::stfs::StfsContainer::Verify;

    // --- HEAD snapshots of the tracked system update package -------------------------------

    std::string sha1_hex(std::span<const std::byte> data) {
        std::uint8_t digest[0x14]{};
        ExCryptSha(reinterpret_cast<const std::uint8_t*>(data.data()),
                   static_cast<std::uint32_t>(data.size()), nullptr, 0, nullptr, 0, digest,
                   sizeof(digest));
        std::string hex;
        for (const auto byte : digest)
            hex += std::format("{:02x}", byte);
        return hex;
    }

    std::string bytes_hex(std::span<const std::byte> data) {
        std::string hex;
        for (const auto byte : data)
            hex += std::format("{:02x}", std::to_integer<unsigned>(byte));
        return hex;
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

    fs::path snapshot_support_dir() {
        if (const char* dir = std::getenv("GXBUILD3_STFS_SUPPORT");
            dir != nullptr && *dir != '\0') {
            std::cerr << "  note: support directory overridden by GXBUILD3_STFS_SUPPORT\n";
            return dir;
        }
        return GXBUILD3_SUPPORT_DIR;
    }

    Bytes read_system_update_fixture() {
        const auto path = snapshot_support_dir() / "17559" / "su20076000_00000000";
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw(std::istreambuf_iterator<char>(in), {});
        require(!raw.empty(), "fixture " + path.string() + " is readable");
        Bytes bytes(raw.size());
        std::transform(raw.begin(), raw.end(), bytes.begin(),
                       [](char c) { return static_cast<std::byte>(c); });
        return bytes;
    }

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

    // Compares `text` with tests/golden/<name>.txt and prints a compared N/M line counter.
    void require_golden(std::string_view name, const std::string& text,
                        const std::string& second_render) {
        require(text == second_render, std::string(name) + ": two renderings differ");
        require(g_golden.has_value(), "golden options are set");
        const bool matched = gxbuild3::test::check_golden(*g_golden, name, text);
        const auto lines = line_count(text);
        std::cout << "  compared " << (matched ? lines : 0) << "/" << lines << " lines against "
                  << name << ".txt\n";
        require(matched, std::string(name) + ".txt does not match HEAD output (see diff above)");
    }

    struct EntrySnapshot {
        std::string text;
        std::size_t entries = 0;
        std::size_t hashed = 0;
        std::size_t files = 0;
    };

    EntrySnapshot render_entry_snapshot(const Bytes& bytes) {
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "StfsContainer opens the fixture");
        const auto in_memory = container->extract_to_memory();
        require(in_memory.has_value(), "StfsContainer extracts the fixture to memory");

        EntrySnapshot snapshot;
        std::string& out = snapshot.text;
        const auto& entries = container->entries();
        out += std::format("entries {}\n", entries.size());
        out += std::format("extract_to_memory files {}\n", in_memory->size());
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            out +=
                std::format("[{:02}] name={} flags=0x{:02X} blocks_allocated=0x{:06X} "
                            "blocks_allocated_copy=0x{:06X} starting_block=0x{:06X} "
                            "path_indicator={} file_size=0x{:08X} update_timestamp=0x{:08X} "
                            "access_timestamp=0x{:08X}\n",
                            i, escaped_text(entry.name), entry.flags, entry.blocks_allocated,
                            entry.blocks_allocated_copy, entry.starting_block, entry.path_indicator,
                            entry.file_size, entry.update_timestamp, entry.access_timestamp);
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
            // The hash-verified extraction must agree with the unverified extract_to_memory bytes;
            // a verification failure is rendered so the golden diff names the entry.
            const auto checked = container->extract(entry, Verify::Yes);
            const std::string verified =
                !checked ? "verify-failed" : (*checked == found->second ? "yes" : "no");
            out += std::format("[{:02}] key={} size=0x{:08X} sha1={} verified_equal={}\n", i,
                               escaped_text(key), found->second.size(), sha1_hex(found->second),
                               verified);
            ++snapshot.hashed;
        }
        return snapshot;
    }

    void test_system_update_fixture_entry_snapshot() {
        const auto bytes = read_system_update_fixture();
        const auto first = render_entry_snapshot(bytes);
        const auto second = render_entry_snapshot(bytes);
        std::cout << "  entries " << first.entries << "/31, files hashed " << first.hashed << "/"
                  << first.files << '\n';
        require(first.entries == 31, "fixture lists 31 entries");
        require(first.hashed == first.files, "every file entry is hashed");
        require_golden("stfs_su20076000_entries", first.text, second.text);
    }

    struct MetadataSnapshot {
        std::string text;
        std::size_t fields = 0;
    };

    MetadataSnapshot render_metadata_snapshot(const Bytes& bytes) {
        const auto header = stfs::parse_header(bytes);
        require(header.has_value(), "parse_header accepts the fixture");
        const auto meta = stfs::parse_metadata(bytes);
        require(meta.has_value(), "parse_metadata accepts the fixture");

        MetadataSnapshot snapshot;
        const auto field = [&snapshot](std::string_view name, const std::string& value) {
            snapshot.text += std::format("{} {}\n", name, value);
            ++snapshot.fields;
        };
        const auto hex32 = [](std::uint64_t value) { return std::format("0x{:08X}", value); };

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
        field("descriptor_type", std::to_string(static_cast<std::uint32_t>(meta->descriptor_type)));
        if (const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&meta->volume_descriptor)) {
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
              std::format("0x{:016X}", static_cast<std::uint64_t>(meta->data_file_combined_size)));
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
        field("thumbnail_image", std::format("size=0x{:X} sha1={}", meta->thumbnail_image.size(),
                                             sha1_hex(meta->thumbnail_image)));
        field("title_thumbnail_image",
              std::format("size=0x{:X} sha1={}", meta->title_thumbnail_image.size(),
                          sha1_hex(meta->title_thumbnail_image)));
        return snapshot;
    }

    void test_system_update_fixture_metadata_snapshot() {
        const auto bytes = read_system_update_fixture();
        const auto first = render_metadata_snapshot(bytes);
        const auto second = render_metadata_snapshot(bytes);
        std::cout << "  metadata fields rendered " << first.fields << '\n';
        require_golden("stfs_su20076000_metadata", first.text, second.text);
    }

} // namespace

int main(int argc, char** argv) {
    const auto golden = gxbuild3::test::golden_options(argc, argv);
    if (!golden)
        return 2;
    g_golden = *golden;

    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"system update fixture entry snapshot", test_system_update_fixture_entry_snapshot},
        {"system update fixture metadata snapshot", test_system_update_fixture_metadata_snapshot},
    };
    int failed = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch (const std::exception& e) {
            std::cerr << "FAIL: " << name << ": " << e.what() << '\n';
            ++failed;
        }
    }
    return failed == 0 ? 0 : 1;
}
