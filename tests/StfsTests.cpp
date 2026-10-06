// STFS reader tests. Besides the behavioural cases, three snapshot cases pin HEAD behaviour
// before the parsing phase migrates this code:
//   - the 31 file-table entries of the tracked 17559/su20076000_00000000 with the SHA-1 of every
//     file StfsContainer::extract_to_memory() returns (tests/golden/stfs_su20076000_entries.txt);
//   - every header and metadata field of that package through stfs::parse_header and
//     stfs::parse_metadata (tests/golden/stfs_su20076000_metadata.txt);
//   - the exact ErrorCode of every malformed-container case (an inline table).
// --update rewrites the two goldens (CTest never passes it). GXBUILD3_STFS_SUPPORT overrides the
// support directory of the snapshot cases, for mutation checks against scratch copies only.

#include "Error.hpp"
#include "GoldenSnapshot.hpp"
#include "excrypt.h"
#include "stfs/BlockParser.hpp"
#include "stfs/ContainerDetail.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/HashVerifier.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/MetadataParser.hpp"
#include "stfs/StfsContainer.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
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

    template <typename R> bool fails_with(const R& result, gxbuild3::ErrorCode code) {
        return !result && result.error().code == code;
    }

    using Verify = gxbuild3::stfs::StfsContainer::Verify;

    // Synthetic read-only (block_separation bit 0 set) PIRS layout:
    //   header_size 0xA000, one level-0 hash table at 0xA000,
    //   logical block N stored at 0xB000 + N * 0x1000.
    // Logical block 0 holds the file table; files follow in consecutive blocks.
    constexpr std::size_t kBlockSize = 0x1000;
    constexpr std::size_t kHeaderSize = 0xA000;
    constexpr std::size_t kHashTable = 0xA000;
    constexpr std::size_t kVolumeDescriptor = 0x379;

    std::size_t data_offset(std::uint32_t logical) {
        return kHashTable + (logical + 1) * kBlockSize;
    }
    std::size_t hash_offset(std::uint32_t logical) {
        return kHashTable + logical * 0x18;
    }
    std::size_t entry_offset(std::size_t index) {
        return data_offset(0) + index * 0x40;
    }

    void put_be(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i)
            bytes.at(offset + i) = static_cast<std::byte>(value >> (8 * (width - 1 - i)));
    }
    void put_le(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i)
            bytes.at(offset + i) = static_cast<std::byte>(value >> (8 * i));
    }

    void sha1(const Bytes& bytes, std::size_t offset, std::size_t size, Bytes& out,
              std::size_t out_offset) {
        require(offset + size <= bytes.size() && out_offset + 0x14 <= out.size(),
                "SHA-1 range fits");
        std::uint8_t digest[0x14]{};
        ExCryptSha(reinterpret_cast<const std::uint8_t*>(bytes.data() + offset),
                   static_cast<std::uint32_t>(size), nullptr, 0, nullptr, 0, digest,
                   sizeof(digest));
        for (std::size_t i = 0; i < sizeof(digest); ++i)
            out[out_offset + i] = static_cast<std::byte>(digest[i]);
    }

    std::uint32_t total_blocks(const Bytes& package) {
        std::uint32_t total = 0;
        for (std::size_t i = 0; i < 4; ++i)
            total = (total << 8) | std::to_integer<std::uint32_t>(package[0x395 + i]);
        return total;
    }

    // Recomputes the level-0 data hashes and the top hash so verification passes.
    void seal(Bytes& package) {
        const auto total = total_blocks(package);
        for (std::uint32_t block = 0; block < total; ++block)
            sha1(package, data_offset(block), kBlockSize, package, hash_offset(block));
        sha1(package, kHashTable, kBlockSize, package, kVolumeDescriptor + 0x08);
    }

    struct SynthFile {
        std::string name;
        Bytes data;
        bool consecutive = true;
        std::int16_t parent = -1;
        bool directory = false;
    };

    Bytes make_package(const std::vector<SynthFile>& files) {
        require(files.size() <= 64, "fixture fits in one file table block");

        std::vector<std::uint32_t> first_block;
        std::vector<std::uint32_t> block_count;
        std::uint32_t total = 1; // file table
        for (const auto& file : files) {
            const auto blocks =
                static_cast<std::uint32_t>((file.data.size() + kBlockSize - 1) / kBlockSize);
            first_block.push_back(blocks == 0 ? 0 : total);
            block_count.push_back(blocks);
            total += blocks;
        }
        require(total <= 0xAA, "fixture fits under one level-0 hash table");

        Bytes package(data_offset(total), std::byte{0});
        for (std::size_t i = 0; i < 4; ++i)
            package[i] = static_cast<std::byte>("PIRS"[i]);
        put_be(package, 0x340, kHeaderSize, 4);
        package[kVolumeDescriptor] = std::byte{0x24};
        package[kVolumeDescriptor + 0x02] = std::byte{0x01}; // block_separation: read-only
        put_le(package, kVolumeDescriptor + 0x03, 1, 2);     // file table block count
        put_le(package, kVolumeDescriptor + 0x05, 0, 3);     // file table block number
        put_be(package, kVolumeDescriptor + 0x1C, total, 4); // total allocated blocks

        package[hash_offset(0) + 0x14] = std::byte{0x80};
        put_be(package, hash_offset(0) + 0x15, 0xFFFFFF, 3);

        for (std::size_t i = 0; i < files.size(); ++i) {
            const auto& file = files[i];
            require(file.name.size() <= 0x28, "fixture name fits");
            const auto entry = entry_offset(i);
            std::copy_n(reinterpret_cast<const std::byte*>(file.name.data()), file.name.size(),
                        package.begin() + static_cast<std::ptrdiff_t>(entry));
            package[entry + 0x28] = static_cast<std::byte>(
                file.name.size() | (file.consecutive ? 0x40 : 0) | (file.directory ? 0x80 : 0));
            put_le(package, entry + 0x29, block_count[i], 3);
            put_le(package, entry + 0x2C, block_count[i], 3);
            put_le(package, entry + 0x2F, first_block[i], 3);
            put_be(package, entry + 0x32, static_cast<std::uint16_t>(file.parent), 2);
            put_be(package, entry + 0x34, file.data.size(), 4);

            std::copy(file.data.begin(), file.data.end(),
                      package.begin() + static_cast<std::ptrdiff_t>(data_offset(first_block[i])));
            for (std::uint32_t b = 0; b < block_count[i]; ++b) {
                const auto block = first_block[i] + b;
                package[hash_offset(block) + 0x14] = std::byte{0x80};
                put_be(package, hash_offset(block) + 0x15,
                       b + 1 == block_count[i] ? 0xFFFFFF : block + 1, 3);
            }
        }

        seal(package);
        return package;
    }

    void write_entry(Bytes& bytes, std::size_t offset, std::string_view name, std::uint8_t flags,
                     std::uint32_t blocks, std::uint32_t start, std::uint32_t size) {
        std::fill_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), 0x40, std::byte{0});
        std::copy_n(reinterpret_cast<const std::byte*>(name.data()), name.size(),
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        bytes[offset + 0x28] = static_cast<std::byte>(flags | name.size());
        put_le(bytes, offset + 0x29, blocks, 3);
        put_le(bytes, offset + 0x2C, blocks, 3);
        put_le(bytes, offset + 0x2F, start, 3);
        put_be(bytes, offset + 0x32, 0xFFFF, 2);
        put_be(bytes, offset + 0x34, size, 4);
    }

    Bytes pattern(std::size_t size, std::uint8_t seed) {
        Bytes data(size);
        for (std::size_t i = 0; i < size; ++i)
            data[i] = static_cast<std::byte>((i * 7 + seed) & 0xFF);
        return data;
    }

    void write_bytes(const fs::path& path, const Bytes& data) {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        require(out.good(), "fixture file must be writable");
    }

    struct TempDir {
        fs::path root;

        TempDir() {
            static unsigned counter = 0;
            root = fs::current_path() /
                   ("stfs-test-" +
                    std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                    "-" + std::to_string(counter++));
            require(fs::create_directory(root), "fixture directory must be new");
        }

        ~TempDir() {
            std::error_code ec;
            if (root.filename().string().starts_with("stfs-test-"))
                fs::remove_all(root, ec);
        }
    };

    // --- Header parsing --------------------------------------------------------------------

    void test_parse_header_rejects_short_buffer() {
        Bytes data(0x1B0, std::byte{0});
        for (std::size_t i = 0; i < 4; ++i)
            data[i] = static_cast<std::byte>("PIRS"[i]);
        require(fails_with(stfs::parse_header(data), gxbuild3::ErrorCode::Truncated),
                "a 0x1B0-byte PIRS header must be rejected, not over-read");

        data.resize(0x22C);
        const auto header = stfs::parse_header(data);
        require(header && header->magic == stfs::Magic::PIRS, "a full 0x22C-byte header parses");
    }

    void test_read_header_from_file_requires_full_header() {
        TempDir dir;
        Bytes data(0x1B0, std::byte{0});
        for (std::size_t i = 0; i < 4; ++i)
            data[i] = static_cast<std::byte>("PIRS"[i]);
        write_bytes(dir.root / "short", data);
        require(fails_with(stfs::read_header_from_file(dir.root / "short"),
                           gxbuild3::ErrorCode::Truncated),
                "a short header file must be rejected");

        write_bytes(dir.root / "full", make_package({{"a.bin", pattern(10, 1)}}));
        const auto header = stfs::read_header_from_file(dir.root / "full");
        require(header && header->magic == stfs::Magic::PIRS,
                "a full package header reads from file");
    }

    // --- Extraction paths ------------------------------------------------------------------

    // Opens and extracts a package, returning the describe() of whichever of open or
    // extract_all fails (empty if both succeed).
    std::string extract_error(const Bytes& bytes, const fs::path& out) {
        const auto container = stfs::StfsContainer::open(bytes);
        if (!container)
            return container.error().describe();
        if (const auto extracted = container->extract_all(out); !extracted)
            return extracted.error().describe();
        return {};
    }

    void test_container_rejects_relative_escape() {
        TempDir dir;
        // A ".." directory entry passes the name checks but escapes once joined.
        const auto dotdot = make_package({{"good.bin", pattern(10, 1)},
                                          {"..", {}, true, -1, true},
                                          {"escaped", pattern(10, 2), true, 1}});
        require(extract_error(dotdot, dir.root / "out").find("escapes") != std::string::npos,
                "a .. entry path is rejected by StfsContainer::extract_all");
        require(!fs::exists(dir.root / "escaped"), "nothing is written outside output_dir");
        require(!fs::exists(dir.root / "out" / "good.bin"),
                "destinations are validated before anything is written");

        const auto slash = make_package({{"../escaped", pattern(10, 2)}});
        require(!extract_error(slash, dir.root / "out").empty(),
                "a ../ entry name is rejected by StfsContainer");
        require(!fs::exists(dir.root / "escaped"), "a ../ name writes nothing outside");

        const auto nested =
            make_package({{"sub", {}, true, -1, true}, {"../../escaped", pattern(10, 3), true, 0}});
        require(!extract_error(nested, dir.root / "out").empty(),
                "a ../ entry under a directory is rejected");
        require(!fs::exists(dir.root / "escaped"), "nested escape writes nothing outside");
    }

    void test_container_rejects_absolute_name() {
        TempDir dir;
        const auto bytes = make_package({{"/stfs-absolute-escape", pattern(10, 1)}});
        const auto message = extract_error(bytes, dir.root / "out");
        require(message.find("absolute") != std::string::npos ||
                    message.find("separator") != std::string::npos,
                "an absolute entry name is rejected by StfsContainer");
        require(!fs::exists("/stfs-absolute-escape"), "nothing is written at the absolute path");
    }

    void test_container_rejects_escape() {
        TempDir dir;
        const auto bytes =
            make_package({{"..", {}, true, -1, true}, {"escaped", pattern(10, 2), true, 0}});
        const auto container = stfs::StfsContainer::open(bytes);
        require(container && !container->extract_all(dir.root / "out"),
                "StfsContainer rejects a .. entry path");
        require(!fs::exists(dir.root / "escaped"), "container writes nothing outside");
    }

    void test_safe_join() {
        const fs::path out = "out";
        require(stfs::detail::safe_join(out, "a/./b") == out / "a/b", "safe paths are kept");
        constexpr auto rejected = gxbuild3::ErrorCode::InvalidArgument;
        require(fails_with(stfs::detail::safe_join(out, "/abs"), rejected),
                "absolute paths are rejected");
        require(fails_with(stfs::detail::safe_join(out, "a/../../b"), rejected),
                "escaping paths are rejected");
        require(fails_with(stfs::detail::safe_join(out, "a/.."), rejected),
                "paths that collapse to the target itself are rejected");
#ifdef _WIN32
        require(fails_with(stfs::detail::safe_join(out, "C:foo"), rejected),
                "drive-relative paths are rejected");
        require(fails_with(stfs::detail::safe_join(out, "\\\\server\\share"), rejected),
                "UNC paths are rejected");
#endif
    }

    void test_parent_cycle_rejected() {
        TempDir dir;
        // Entry 0 names itself as its parent.
        const auto self_bytes = make_package({{"a.bin", pattern(10, 1), true, 0}});
        const auto self = stfs::StfsContainer::open(self_bytes);
        require(self.has_value(), "a self-parented entry opens");
        require(fails_with(self->extract_all(dir.root / "out"), gxbuild3::ErrorCode::Malformed),
                "an entry that is its own parent is rejected");

        // Entry 0 refers forward to entry 1, which refers back to entry 0.
        const auto loop_bytes = make_package({{"a", {}, true, 1, true}, {"b", {}, true, 0, true}});
        const auto loop = stfs::StfsContainer::open(loop_bytes);
        require(loop.has_value(), "a forward-parented entry opens");
        require(fails_with(loop->extract_all(dir.root / "out"), gxbuild3::ErrorCode::Malformed),
                "a parent cycle through a later entry is rejected");

        const auto bytes = make_package({{"a", {}, true, 1, true}, {"b", {}, true, 0, true}});
        const auto container = stfs::StfsContainer::open(bytes);
        require(container && !container->extract_all(dir.root / "out"),
                "StfsContainer rejects a forward parent reference");
    }

    void test_nested_extraction() {
        TempDir dir;
        const auto data = pattern(5000, 9);
        const auto bytes =
            make_package({{"sub", {}, true, -1, true}, {"inner.bin", data, true, 0}});
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "a nested package opens");
        require(container->extract_all(dir.root / "out", Verify::Yes).has_value(),
                "a nested package extracts with verification");
        std::ifstream in(dir.root / "out" / "sub" / "inner.bin", std::ios::binary);
        Bytes read(data.size() + 1);
        in.read(reinterpret_cast<char*>(read.data()), static_cast<std::streamsize>(read.size()));
        read.resize(static_cast<std::size_t>(in.gcount()));
        require(read == data, "a nested file extracts with verification");
    }

    // --- File extraction -------------------------------------------------------------------

    void test_truncated_chain_fails() {
        // A chained (non-consecutive) two-block file whose chain ends after the first block.
        auto bytes = make_package({{"a.bin", pattern(0x1800, 1), false}});
        put_be(bytes, hash_offset(1) + 0x15, 0xFFFFFF, 3);
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "a package with a truncated chain opens");
        require(fails_with(container->extract(container->entries().at(0)),
                           gxbuild3::ErrorCode::Truncated),
                "a chain shorter than file_size must fail, not return a short buffer");
    }

    void test_longer_chain_is_cut_at_file_size() {
        // The chain may be longer than needed; extraction stops at file_size.
        const auto data = pattern(0x1800, 4);
        auto bytes = make_package({{"a.bin", data, false}, {"b.bin", pattern(0x10, 5), false}});
        put_be(bytes, hash_offset(2) + 0x15, 3, 3); // a.bin's last block links on into b.bin
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "a package with a longer chain opens");
        require(container->extract(container->entries().at(0)) == data,
                "a longer chain yields exactly file_size bytes");
    }

    void test_zero_size_file_skips_chain() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}, {"empty.bin", {}}});
        put_le(bytes, entry_offset(1) + 0x2F, 3000, 3); // starting block far out of range
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "a package with an empty file opens");
        const auto extracted = container->extract(container->entries().at(1));
        require(extracted.has_value() && extracted->empty(),
                "a zero-size file returns no bytes without walking its chain");
    }

    // --- Offsets and header size -----------------------------------------------------------

    void test_block_offsets_are_64_bit() {
        require(stfs::block_to_offset(0, 0xAD0E) == 0xB000, "0xAD0E rounds up to 0xB000");
        require(stfs::block_to_offset(0, 0x971A) == 0xA000, "0x971A rounds up to 0xA000");
        require(stfs::block_to_offset(2, 0x1F000) == 0x21000, "header sizes above 0xFFFF are kept");
        require(stfs::block_to_offset(0xFFFFFF, 0xAD0E) == 0xB000 + 0xFFFFFF000ull,
                "the largest block number does not wrap");
        require(
            fails_with(stfs::block_to_offset(0x1000000, 0xAD0E), gxbuild3::ErrorCode::OutOfRange),
            "block numbers above 24 bits are rejected");
    }

    void test_header_size_out_of_range_rejected() {
        for (const std::uint32_t header_size : {0x100u, 0x100000u, 0xFFFFF000u}) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            put_be(bytes, 0x340, header_size, 4);
            require(fails_with(stfs::StfsContainer::open(bytes), gxbuild3::ErrorCode::Malformed),
                    "an absurd header_size is rejected");
        }
    }

    void test_invalid_hash_status_message_is_hex() {
        auto bytes = make_package({{"a.bin", pattern(10, 1), false}});
        bytes[hash_offset(1) + 0x14] = std::byte{0xAB};
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "a package with a bad hash status opens");
        const auto extracted = container->extract(container->entries().at(0));
        require(fails_with(extracted, gxbuild3::ErrorCode::Malformed),
                "an invalid hash entry status is malformed");
        require(extracted.error().describe().find("(0xAB)") != std::string::npos,
                "the hash entry status is printed in hex");
    }

    // --- Consecutive files -----------------------------------------------------------------

    void test_consecutive_file_ignores_hash_chain() {
        const auto data = pattern(0x2800, 6);
        auto consecutive = make_package({{"a.bin", data, true}});
        auto chained = make_package({{"a.bin", data, false}});
        for (auto* bytes : {&consecutive, &chained}) {
            for (std::uint32_t block = 1; block <= 3; ++block)
                put_be(*bytes, hash_offset(block) + 0x15, 0xFFFFFF, 3); // break the chain
            seal(*bytes);
        }

        const auto container = stfs::StfsContainer::open(consecutive);
        require(container.has_value(), "a consecutive package opens");
        require(container->extract(container->entries().at(0)) == data,
                "a consecutive file is read from starting_block without its chain");
        require(container->extract(container->entries().at(0), Verify::Yes) == data,
                "a consecutive file still verifies block by block");

        const auto chained_container = stfs::StfsContainer::open(chained);
        require(chained_container.has_value(), "a chained package opens");
        require(fails_with(chained_container->extract(chained_container->entries().at(0)),
                           gxbuild3::ErrorCode::Truncated),
                "a non-consecutive file still follows (and trusts) its chain");
    }

    void test_consecutive_file_bounds() {
        auto short_allocation = make_package({{"a.bin", pattern(0x2800, 6), true}});
        put_le(short_allocation, entry_offset(0) + 0x29, 2, 3); // 2 blocks for 0x2800 bytes
        const auto container = stfs::StfsContainer::open(short_allocation);
        require(container.has_value(), "a short allocation opens");
        require(fails_with(container->extract(container->entries().at(0)),
                           gxbuild3::ErrorCode::Malformed),
                "blocks_allocated too small for file_size is rejected");

        auto past_end = make_package({{"a.bin", pattern(0x2800, 6), true}});
        put_le(past_end, entry_offset(0) + 0x2F, 0xFFFFFE, 3);
        const auto past_end_container = stfs::StfsContainer::open(past_end);
        require(past_end_container.has_value(), "a starting block near the end opens");
        require(fails_with(past_end_container->extract(past_end_container->entries().at(0)),
                           gxbuild3::ErrorCode::OutOfRange),
                "consecutive blocks past the last block number are rejected");

        auto huge = make_package({{"a.bin", pattern(0x10, 6), true}});
        put_le(huge, entry_offset(0) + 0x29, 0xFFFFFF, 3);
        put_be(huge, entry_offset(0) + 0x34, 0xFFFFFFFF, 4);
        const auto huge_container = stfs::StfsContainer::open(huge);
        require(huge_container.has_value(), "a huge consecutive file entry opens");
        require(fails_with(huge_container->extract(huge_container->entries().at(0)),
                           gxbuild3::ErrorCode::OutOfRange),
                "a consecutive file larger than the package is rejected");
    }

    // --- File table and volume descriptor --------------------------------------------------

    void test_file_table_follows_hash_chain() {
        // Logical block 0 is the first table block; a.bin lives in block 1 and the second table
        // block is block 2, linked 0 -> 2 through the hash chain.
        const auto data = pattern(10, 1);
        auto bytes = make_package({{"a.bin", data}, {"spare", pattern(kBlockSize, 2)}});
        for (std::size_t i = 1; i < 64; ++i)
            write_entry(bytes, entry_offset(i), "e" + std::to_string(i), 0x40, 0, 0, 0);
        std::fill_n(bytes.begin() + static_cast<std::ptrdiff_t>(data_offset(2)), kBlockSize,
                    std::byte{0});
        write_entry(bytes, data_offset(2), "second.bin", 0x40, 1, 1, 10);
        put_le(bytes, kVolumeDescriptor + 0x03, 2, 2);
        put_be(bytes, hash_offset(0) + 0x15, 2, 3);
        seal(bytes);

        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "a package with a two-block file table opens");
        require(container->entries().size() == 65 &&
                    container->entries().back().name == "second.bin",
                "StfsContainer reads the file table through its hash chain");
        require(container->extract(container->entries().back(), Verify::Yes) == data,
                "an entry from the second table block extracts");
        require(container->extract_file_by_name("second.bin") == data,
                "StfsContainer finds the entry from the second table block by name");
    }

    void test_invalid_file_table_descriptor_rejected() {
        auto empty = make_package({{"a.bin", pattern(10, 1)}});
        put_le(empty, kVolumeDescriptor + 0x03, 0, 2);
        require(fails_with(stfs::StfsContainer::open(empty), gxbuild3::ErrorCode::Malformed),
                "StfsContainer rejects a zero file table block count");

        auto negative = make_package({{"a.bin", pattern(10, 1)}});
        put_le(negative, kVolumeDescriptor + 0x03, 0x8000, 2);
        require(fails_with(stfs::StfsContainer::open(negative), gxbuild3::ErrorCode::Malformed),
                "StfsContainer rejects a negative file table block count");
    }

    void test_short_file_table_chain_rejected() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        put_le(bytes, kVolumeDescriptor + 0x03, 2, 2); // claims two blocks, chain has one
        require(fails_with(stfs::StfsContainer::open(bytes), gxbuild3::ErrorCode::Truncated),
                "a file table chain shorter than its block count is rejected");
    }

    void test_writable_layout_rejected() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        bytes[kVolumeDescriptor + 0x02] = std::byte{0x00}; // block_separation bit 0 clear
        require(fails_with(stfs::StfsContainer::open(bytes), gxbuild3::ErrorCode::Unsupported),
                "StfsContainer rejects block_separation bit 0 clear");

        bytes[kVolumeDescriptor + 0x02] = std::byte{0x03};
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value() && container->entries().size() == 1,
                "other block_separation bits do not matter");
    }

    // --- File table names ------------------------------------------------------------------

    void test_name_length_beyond_field_rejected() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        bytes[entry_offset(0) + 0x28] = std::byte{0x40 | 0x29};
        require(fails_with(stfs::StfsContainer::open(bytes), gxbuild3::ErrorCode::Malformed),
                "name_length 0x29 is rejected");
        bytes[entry_offset(0) + 0x28] = std::byte{0x40 | 0x3F};
        require(fails_with(stfs::StfsContainer::open(bytes), gxbuild3::ErrorCode::Malformed),
                "name_length 0x3F is rejected");

        const std::string longest(0x28, 'n');
        const auto full_bytes = make_package({{longest, pattern(10, 1)}});
        const auto full = stfs::StfsContainer::open(full_bytes);
        require(full.has_value() && full->entries().at(0).name == longest,
                "a 40-byte name is accepted");
    }

    void test_nameless_entry_ends_listing() {
        auto bytes = make_package(
            {{"a.bin", pattern(10, 1)}, {"b.bin", pattern(10, 2)}, {"c.bin", pattern(10, 3)}});
        bytes[entry_offset(1) + 0x28] = std::byte{0x40}; // name_length 0, other bytes set
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value() && container->entries().size() == 1 &&
                    container->entries().at(0).name == "a.bin",
                "an entry without a name length ends the listing");
    }

    void test_entry_name_contents() {
        auto padded = make_package({{"a.bin", pattern(10, 1)}});
        padded[entry_offset(0) + 0x28] = std::byte{0x40 | 0x08}; // "a.bin\0\0\0"
        const auto padded_container = stfs::StfsContainer::open(padded);
        require(padded_container.has_value() && padded_container->entries().at(0).name == "a.bin",
                "NUL padding inside name_length is trimmed");

        auto empty = make_package({{"a.bin", pattern(10, 1)}});
        empty[entry_offset(0)] = std::byte{0};
        require(fails_with(stfs::StfsContainer::open(empty), gxbuild3::ErrorCode::Malformed),
                "a name that starts with NUL is rejected");

        for (const auto* name : {"a/b", "a\\b"}) {
            const auto bytes = make_package({{name, pattern(10, 1)}});
            require(fails_with(stfs::StfsContainer::open(bytes), gxbuild3::ErrorCode::Malformed),
                    "a name with a path separator is rejected");
        }

        const auto plain_bytes = make_package(
            {{"$flash_dash.xex", pattern(10, 1)}, {"$flash_SegoeXbox-Light.xtt", pattern(10, 2)}});
        const auto plain = stfs::StfsContainer::open(plain_bytes);
        require(plain.has_value() && plain->entries().size() == 2 &&
                    plain->entries().at(1).name == "$flash_SegoeXbox-Light.xtt",
                "system update names are accepted");
    }

    // --- Writing ---------------------------------------------------------------------------

    void test_write_failure_is_reported() {
        const fs::path full = "/dev/full";
        if (!fs::exists(full)) {
            std::cout << "  (skipped: no /dev/full)\n";
            return;
        }
        const auto bytes = make_package({{"a.bin", pattern(10, 1)}});

        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "the package opens");
        const auto& entry = container->entries().at(0);
        require(fails_with(stfs::extract_file_to_disk(bytes, entry, stfs::Magic::PIRS,
                                                      container->header_size(), full),
                           gxbuild3::ErrorCode::IoError),
                "extract_file_to_disk reports a failed write");

        // StfsContainer::extract_all writing through a planted link to /dev/full.
        TempDir dir;
        fs::create_directories(dir.root / "out");
        fs::create_symlink(full, dir.root / "out" / "a.bin");
        require(!container->extract_all(dir.root / "out"),
                "StfsContainer::extract_all reports a failed write");

        require(
            fails_with(stfs::extract_file_to_disk(bytes, entry, stfs::Magic::PIRS,
                                                  container->header_size(), dir.root / "no/dir/x"),
                       gxbuild3::ErrorCode::IoError),
            "an unopenable output path is reported");
    }

    // --- Hash verification -----------------------------------------------------------------

    std::string sha1_hex(const Bytes& data) {
        Bytes digest(0x14);
        sha1(data, 0, data.size(), digest, 0);
        std::string hex;
        for (const auto byte : digest) {
            constexpr std::string_view digits = "0123456789abcdef";
            hex += digits[std::to_integer<unsigned>(byte) >> 4];
            hex += digits[std::to_integer<unsigned>(byte) & 0xF];
        }
        return hex;
    }

    void test_verify_requires_total_blocks() {
        const auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "the package opens");
        const auto& entry = container->entries().at(0);
        const auto meta = stfs::parse_metadata(bytes);
        require(meta.has_value(), "parse_metadata accepts the package");
        const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&meta->volume_descriptor);
        require(vd != nullptr, "synthetic package has an STFS descriptor");

        require(fails_with(stfs::extract_file(bytes, entry, stfs::Magic::PIRS, 0xA000, true,
                                              &vd->top_hash_table_hash, 0),
                           gxbuild3::ErrorCode::InvalidArgument),
                "extract_file with verify and total_blocks 0 fails");
        TempDir dir;
        require(fails_with(stfs::extract_file_to_disk(bytes, entry, stfs::Magic::PIRS, 0xA000,
                                                      dir.root / "a", true,
                                                      &vd->top_hash_table_hash, 0),
                           gxbuild3::ErrorCode::InvalidArgument),
                "extract_file_to_disk with verify and total_blocks 0 fails");

        require(stfs::extract_file(bytes, entry, stfs::Magic::PIRS, 0xA000, true,
                                   &vd->top_hash_table_hash, 2) == pattern(10, 1),
                "verification passes with total_blocks set");
    }

    void test_verify_detects_corruption() {
        auto data_corrupt = make_package({{"a.bin", pattern(10, 1)}});
        data_corrupt[data_offset(1) + 0x800] ^= std::byte{0x01}; // past file_size, still hashed
        const auto container = stfs::StfsContainer::open(data_corrupt);
        require(container.has_value(), "the corrupted package opens");
        require(container->extract(container->entries().at(0)) == pattern(10, 1),
                "unverified extraction ignores the hash");
        require(fails_with(container->extract(container->entries().at(0), Verify::Yes),
                           gxbuild3::ErrorCode::HashMismatch),
                "a corrupted data block fails verification");
        const auto meta = stfs::parse_metadata(data_corrupt);
        require(meta.has_value(), "parse_metadata accepts the corrupted package");
        const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&meta->volume_descriptor);
        require(vd != nullptr, "synthetic package has an STFS descriptor");
        require(
            fails_with(stfs::verify_data_block(data_corrupt, 1, 0xA000, vd->top_hash_table_hash, 2),
                       gxbuild3::ErrorCode::HashMismatch),
            "a corrupted data block is a hash mismatch");
        require(fails_with(stfs::verify_data_block(data_corrupt, 0x100, 0xA000,
                                                   vd->top_hash_table_hash, 2),
                           gxbuild3::ErrorCode::OutOfRange),
                "a block outside the package is out of range, not a hash mismatch");

        auto table_corrupt = make_package({{"a.bin", pattern(10, 1)}});
        table_corrupt[hash_offset(5) + 0x3] ^= std::byte{0x01}; // unused hash slot
        const auto table_container = stfs::StfsContainer::open(table_corrupt);
        require(table_container.has_value(), "the package with a corrupted hash table opens");
        require(fails_with(table_container->extract(table_container->entries().at(0), Verify::Yes),
                           gxbuild3::ErrorCode::HashMismatch),
                "a corrupted hash table fails the top hash");
    }

    // The tracked system update package: two hash levels, 31 consecutive files.
    void test_system_update_fixture() {
        const fs::path path = fs::path(GXBUILD3_SUPPORT_DIR) / "17559" / "su20076000_00000000";
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw(std::istreambuf_iterator<char>(in), {});
        require(!raw.empty(), "fixture su20076000_00000000 is readable");
        Bytes bytes(raw.size());
        std::transform(raw.begin(), raw.end(), bytes.begin(),
                       [](char c) { return static_cast<std::byte>(c); });

        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "StfsContainer opens the fixture");
        require(container->entries().size() == 31, "fixture lists 31 files");
        const auto meta = stfs::parse_metadata(bytes);
        require(meta.has_value(), "parse_metadata accepts the fixture");
        const auto& display_name = meta->display_name;
        require(std::string(display_name.begin(), display_name.end()) == "System Update",
                "fixture display_name decodes from UTF-16BE");

        const auto in_memory = container->extract_to_memory();
        require(in_memory.has_value(), "StfsContainer extracts the fixture to memory");
        const auto verified_bytes = [&](const stfs::FileEntry& entry) {
            auto verified = container->extract(entry, Verify::Yes);
            require(verified.has_value(), "StfsContainer verifies " + entry.name);
            return std::move(*verified);
        };
        for (const auto& entry : container->entries()) {
            const auto verified = verified_bytes(entry);
            std::string key = entry.name;
            if (key.starts_with("$flash_"))
                key.erase(0, 7);
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            require(in_memory->at(key) == verified,
                    "verified extract and extract_to_memory return identical bytes");
        }

        const auto find = [&](std::string_view name) -> const stfs::FileEntry& {
            for (const auto& entry : container->entries())
                if (entry.name == name)
                    return entry;
            throw std::runtime_error("fixture entry missing");
        };
        require(sha1_hex(verified_bytes(find("xboxupd.bin"))) ==
                    "ea7666ebe2799812270581538b342b8143397ab9",
                "xboxupd.bin extracts byte-identically");
        require(sha1_hex(verified_bytes(find("$flash_dash.xex"))) ==
                    "3d44ef57781c20669705cd687e3b62b1c2f1ff6b",
                "$flash_dash.xex extracts byte-identically");
    }

    // StfsContainer::extract with Verify::Yes checks the hash tables up to the top hash and
    // returns the same bytes as the unverified extract_to_memory path.
    void test_container_verified_extract() {
        const fs::path path = fs::path(GXBUILD3_SUPPORT_DIR) / "17559" / "su20076000_00000000";
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw(std::istreambuf_iterator<char>(in), {});
        require(!raw.empty(), "fixture su20076000_00000000 is readable");
        Bytes bytes(raw.size());
        std::transform(raw.begin(), raw.end(), bytes.begin(),
                       [](char c) { return static_cast<std::byte>(c); });

        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "StfsContainer opens the fixture");
        require(container->entries().size() == 31, "StfsContainer lists 31 entries");
        require(container->header_size() == 0xAD0E, "StfsContainer reports header size 0xAD0E");
        const auto in_memory = container->extract_to_memory();
        require(in_memory.has_value(), "StfsContainer extracts the fixture to memory");

        std::size_t files = 0;
        for (const auto& entry : container->entries()) {
            if (entry.is_directory())
                continue;
            const auto verified = container->extract(entry, stfs::StfsContainer::Verify::Yes);
            require(verified.has_value(), "StfsContainer verifies " + entry.name);
            std::string key = entry.name;
            if (key.starts_with("$flash_"))
                key.erase(0, 7);
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            require(in_memory->at(key) == *verified,
                    "verified extract equals extract_to_memory for " + entry.name);
            ++files;
        }
        require(files == in_memory->size(), "every in-memory file was verified");

        TempDir dir;
        require(
            container->extract_all(dir.root / "out", stfs::StfsContainer::Verify::Yes).has_value(),
            "StfsContainer verified extract_all succeeds on the fixture");

        auto data_corrupt = make_package({{"a.bin", pattern(10, 1)}});
        data_corrupt[data_offset(1) + 0x800] ^= std::byte{0x01}; // past file_size, still hashed
        const auto corrupt = stfs::StfsContainer::open(data_corrupt);
        require(corrupt.has_value(), "StfsContainer opens the corrupted package");
        const auto& entry = corrupt->entries().at(0);
        require(corrupt->extract(entry) == pattern(10, 1),
                "unverified container extraction ignores the hash");
        require(fails_with(corrupt->extract(entry, stfs::StfsContainer::Verify::Yes),
                           gxbuild3::ErrorCode::HashMismatch),
                "verified container extraction fails the hash");
        TempDir corrupt_dir;
        require(fails_with(corrupt->extract_all(corrupt_dir.root / "out",
                                                stfs::StfsContainer::Verify::Yes),
                           gxbuild3::ErrorCode::HashMismatch),
                "verified container extract_all fails the hash");
    }

    // --- Metadata strings ------------------------------------------------------------------

    void put_utf16be(Bytes& bytes, std::size_t offset, std::u16string_view text) {
        for (std::size_t i = 0; i < text.size(); ++i)
            put_be(bytes, offset + 2 * i, text[i], 2);
    }

    std::string as_string(const std::u8string& text) {
        return {text.begin(), text.end()};
    }

    void test_locale_strings_decode_utf16be() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        put_utf16be(bytes, 0x411, u"System Update");
        put_utf16be(bytes, 0xD11, u"caf\u00e9 \u20ac \U0001F600"); // 2-, 3- and 4-byte UTF-8
        put_utf16be(bytes, 0x1611, u"Pub\xD800x");                 // unpaired high surrogate
        put_utf16be(bytes, 0x1691, std::u16string(0x40, u'T'));    // fills the whole field
        bytes[0x1691 + 0x80] = std::byte{0x41};                    // next field, not part of it

        const auto meta = stfs::parse_metadata(bytes);
        require(meta.has_value(), "parse_metadata accepts the package");
        require(as_string(meta->display_name) == "System Update", "display_name decodes");
        require(as_string(meta->display_description) == "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80",
                "non-ASCII and surrogate pairs decode to UTF-8");
        require(as_string(meta->publisher_name) == "Pub\xEF\xBF\xBDx",
                "unpaired surrogates become U+FFFD");
        require(as_string(meta->title_name) == std::string(0x40, 'T'),
                "a field without a terminator stops at its size");
    }

    void test_negative_thumbnail_size_is_empty() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        put_be(bytes, 0x1712, 0xFFFFFFFF, 4);
        put_be(bytes, 0x1716, 0x80000000, 4);
        const auto meta = stfs::parse_metadata(bytes);
        require(meta.has_value(), "parse_metadata accepts negative thumbnail sizes");
        require(meta->thumbnail_image.empty() && meta->title_thumbnail_image.empty(),
                "negative thumbnail sizes yield no image");

        put_be(bytes, 0x1712, 0x20, 4);
        put_be(bytes, 0x1716, 0x7FFFFFFF, 4);
        const auto sized = stfs::parse_metadata(bytes);
        require(sized.has_value(), "parse_metadata accepts positive thumbnail sizes");
        require(sized->thumbnail_image.size() == 0x20 &&
                    sized->title_thumbnail_image.size() == 0x4000,
                "positive sizes are kept and clamped to 0x4000");
    }

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

    // --- Exact error codes -----------------------------------------------------------------

    using ErrorCode = gxbuild3::ErrorCode;

    template <typename R> std::optional<gxbuild3::Error> error_of(const R& result) {
        if (result)
            return std::nullopt;
        return result.error();
    }

    // The container keeps a view of `bytes`; it is dropped before this returns.
    std::optional<gxbuild3::Error> open_error(const Bytes& bytes) {
        return error_of(stfs::StfsContainer::open(bytes));
    }

    gxbuild3::Error open_failed(const gxbuild3::Error& error) {
        return {ErrorCode::Internal, "open unexpectedly failed: " + error.describe()};
    }

    std::optional<gxbuild3::Error> extract_by_name_error(const Bytes& bytes,
                                                         std::string_view name) {
        const auto container = stfs::StfsContainer::open(bytes);
        if (!container)
            return open_failed(container.error());
        return error_of(container->extract_file_by_name(name));
    }

    std::optional<gxbuild3::Error> extract_all_error(const Bytes& bytes) {
        const auto container = stfs::StfsContainer::open(bytes);
        if (!container)
            return open_failed(container.error());
        TempDir dir;
        return error_of(container->extract_all(dir.root / "out"));
    }

    Bytes with_magic(Bytes bytes, std::string_view magic) {
        for (std::size_t i = 0; i < 4; ++i)
            bytes[i] = static_cast<std::byte>(magic[i]);
        return bytes;
    }

    Bytes pirs_buffer(std::size_t size) {
        return with_magic(Bytes(size, std::byte{0}), "PIRS");
    }

    struct ErrorCase {
        std::string name;
        ErrorCode expected;
        std::function<std::optional<gxbuild3::Error>()> run;
        std::string_view must_contain = {};
        bool needs_dev_full = false;
    };

    std::vector<ErrorCase> error_cases() {
        const auto one_file = [] { return make_package({{"a.bin", pattern(10, 1)}}); };
        const auto patched = [one_file](std::size_t offset, std::uint64_t value, std::size_t width,
                                        bool big_endian) {
            auto bytes = one_file();
            if (big_endian)
                put_be(bytes, offset, value, width);
            else
                put_le(bytes, offset, value, width);
            return bytes;
        };
        const auto free_extract = [](const Bytes& bytes, stfs::Magic magic, bool verify) {
            const auto container = stfs::StfsContainer::open(bytes);
            require(container.has_value(), "the synthetic package opens");
            const auto meta = stfs::parse_metadata(bytes);
            require(meta.has_value(), "parse_metadata accepts the synthetic package");
            const auto* vd = std::get_if<stfs::StfsVolumeDescriptor>(&meta->volume_descriptor);
            require(vd != nullptr, "synthetic package has an STFS descriptor");
            return error_of(stfs::extract_file(bytes, container->entries().at(0), magic, 0xA000,
                                               verify, &vd->top_hash_table_hash,
                                               total_blocks(bytes)));
        };
        const auto free_to_disk = [](const Bytes& bytes, const fs::path& path) {
            const auto container = stfs::StfsContainer::open(bytes);
            require(container.has_value(), "the synthetic package opens");
            return error_of(stfs::extract_file_to_disk(bytes, container->entries().at(0),
                                                       stfs::Magic::PIRS, 0xA000, path));
        };

        std::vector<ErrorCase> cases;
        // Open-time.
        cases.push_back({"open: CON magic, full-size buffer", ErrorCode::Malformed,
                         [=] { return open_error(with_magic(one_file(), "CON ")); }});
        cases.push_back({"open: LIVE magic, full-size buffer", ErrorCode::Malformed,
                         [=] { return open_error(with_magic(one_file(), "LIVE")); }});
        cases.push_back({"open: 0x100-byte non-PIRS buffer", ErrorCode::Malformed,
                         [] { return open_error(Bytes(0x100, std::byte{0x5A})); }});
        cases.push_back({"open: 0x100-byte PIRS buffer", ErrorCode::Truncated,
                         [] { return open_error(pirs_buffer(0x100)); }});
        cases.push_back({"open: 0x1000-byte PIRS buffer", ErrorCode::Truncated,
                         [] { return open_error(pirs_buffer(0x1000)); }});
        for (const std::uint32_t header_size : {0x100u, 0x100000u, 0xFFFFF000u}) {
            cases.push_back({std::format("open: header_size 0x{:X}", header_size),
                             ErrorCode::Malformed,
                             [=] { return open_error(patched(0x340, header_size, 4, true)); }});
        }
        for (const std::uint32_t type : {1u, 2u}) {
            cases.push_back({std::format("open: descriptor_type {}", type), ErrorCode::Unsupported,
                             [=] { return open_error(patched(0x3A9, type, 4, true)); }});
        }
        for (const std::uint32_t count : {0u, 0x8000u}) {
            cases.push_back(
                {std::format("open: file table block count 0x{:X}", count), ErrorCode::Malformed,
                 [=] { return open_error(patched(kVolumeDescriptor + 0x03, count, 2, false)); }});
        }
        cases.push_back({"open: block_separation bit 0 clear", ErrorCode::Unsupported, [=] {
                             auto bytes = one_file();
                             bytes[kVolumeDescriptor + 0x02] = std::byte{0x00};
                             return open_error(bytes);
                         }});
        cases.push_back({"open: table count 2 with a 1-block chain", ErrorCode::Truncated, [=] {
                             return open_error(patched(kVolumeDescriptor + 0x03, 2, 2, false));
                         }});
        for (const std::uint8_t length : {std::uint8_t{0x29}, std::uint8_t{0x3F}}) {
            cases.push_back(
                {std::format("open: name_length 0x{:02X}", length), ErrorCode::Malformed, [=] {
                     auto bytes = one_file();
                     bytes[entry_offset(0) + 0x28] = static_cast<std::byte>(0x40 | length);
                     return open_error(bytes);
                 }});
        }
        cases.push_back({"open: name starting with NUL", ErrorCode::Malformed, [=] {
                             auto bytes = one_file();
                             bytes[entry_offset(0)] = std::byte{0};
                             return open_error(bytes);
                         }});
        for (const std::string name : {"a/b", "a\\b", "../escaped"}) {
            cases.push_back({std::format("open: name {}", escaped_text(name)), ErrorCode::Malformed,
                             [=] { return open_error(make_package({{name, pattern(10, 1)}})); }});
        }

        // Extraction-time.
        cases.push_back({"extract_file_by_name: broken 2-block chain", ErrorCode::Truncated, [] {
                             auto bytes = make_package({{"a.bin", pattern(0x1800, 1), false}});
                             put_be(bytes, hash_offset(1) + 0x15, 0xFFFFFF, 3);
                             return extract_by_name_error(bytes, "a.bin");
                         }});
        cases.push_back({"extract_file_by_name: hash status 0xAB", ErrorCode::Malformed,
                         [] {
                             auto bytes = make_package({{"a.bin", pattern(10, 1), false}});
                             bytes[hash_offset(1) + 0x14] = std::byte{0xAB};
                             return extract_by_name_error(bytes, "a.bin");
                         },
                         "(0xAB)"});
        cases.push_back({"extract_file_by_name: consecutive blocks_allocated too small",
                         ErrorCode::Malformed, [] {
                             auto bytes = make_package({{"a.bin", pattern(0x2800, 6), true}});
                             put_le(bytes, entry_offset(0) + 0x29, 2, 3);
                             return extract_by_name_error(bytes, "a.bin");
                         }});
        cases.push_back({"extract_file_by_name: consecutive starting_block 0xFFFFFE",
                         ErrorCode::OutOfRange, [] {
                             auto bytes = make_package({{"a.bin", pattern(0x2800, 6), true}});
                             put_le(bytes, entry_offset(0) + 0x2F, 0xFFFFFE, 3);
                             return extract_by_name_error(bytes, "a.bin");
                         }});
        cases.push_back({"extract_file_by_name: consecutive 0xFFFFFF blocks, size 0xFFFFFFFF",
                         ErrorCode::OutOfRange, [] {
                             auto bytes = make_package({{"a.bin", pattern(0x10, 6), true}});
                             put_le(bytes, entry_offset(0) + 0x29, 0xFFFFFF, 3);
                             put_be(bytes, entry_offset(0) + 0x34, 0xFFFFFFFF, 4);
                             return extract_by_name_error(bytes, "a.bin");
                         }});
        cases.push_back(
            {"extract_all: parent self-reference", ErrorCode::Malformed,
             [] { return extract_all_error(make_package({{"a.bin", pattern(10, 1), true, 0}})); }});
        cases.push_back({"extract_all: parent forward reference", ErrorCode::Malformed, [] {
                             return extract_all_error(make_package(
                                 {{"a", {}, true, 1, true}, {"b", {}, true, 0, true}}));
                         }});
        cases.push_back(
            {"extract_all: .. directory", ErrorCode::InvalidArgument,
             [] {
                 return extract_all_error(make_package(
                     {{"..", {}, true, -1, true}, {"escaped", pattern(10, 2), true, 0}}));
             },
             "escapes"});
        cases.push_back({"free extract_file: Magic::CON", ErrorCode::Unsupported,
                         [=] { return free_extract(one_file(), stfs::Magic::CON, false); }});
        cases.push_back(
            {"free extract_file: verify, corrupt data block", ErrorCode::HashMismatch, [=] {
                 auto bytes = one_file();
                 bytes[data_offset(1) + 0x800] ^= std::byte{0x01};
                 return free_extract(bytes, stfs::Magic::PIRS, true);
             }});
        cases.push_back(
            {"free extract_file: verify, corrupt hash table", ErrorCode::HashMismatch, [=] {
                 auto bytes = one_file();
                 bytes[hash_offset(5) + 0x3] ^= std::byte{0x01};
                 return free_extract(bytes, stfs::Magic::PIRS, true);
             }});
        cases.push_back({"free extract_file_to_disk: /dev/full",
                         ErrorCode::IoError,
                         [=] { return free_to_disk(one_file(), "/dev/full"); },
                         {},
                         true});
        cases.push_back({"free extract_file_to_disk: unopenable path", ErrorCode::IoError, [=] {
                             TempDir dir;
                             return free_to_disk(one_file(), dir.root / "no" / "dir" / "x");
                         }});
        return cases;
    }

    void test_error_codes_are_pinned() {
        const bool have_dev_full = fs::exists("/dev/full");
        std::size_t pinned = 0;
        std::size_t skipped = 0;
        std::vector<std::string> failures;
        const auto cases = error_cases();
        for (const auto& item : cases) {
            if (item.needs_dev_full && !have_dev_full) {
                std::cout << "  not compared: " << item.name << " (no /dev/full)\n";
                ++skipped;
                continue;
            }
            const auto error = item.run();
            if (!error) {
                failures.push_back(item.name + ": succeeded, expected " +
                                   std::string(gxbuild3::to_string(item.expected)));
                continue;
            }
            if (error->code != item.expected) {
                failures.push_back(item.name + ": got " +
                                   std::string(gxbuild3::to_string(error->code)) + ", expected " +
                                   std::string(gxbuild3::to_string(item.expected)) + " (" +
                                   error->describe() + ")");
                continue;
            }
            if (!item.must_contain.empty() &&
                error->describe().find(item.must_contain) == std::string::npos) {
                failures.push_back(item.name + ": message lacks '" +
                                   std::string(item.must_contain) + "': " + error->describe());
                continue;
            }
            ++pinned;
        }
        for (const auto& failure : failures)
            std::cerr << "  error case FAIL: " << failure << '\n';
        std::cout << "  error codes pinned " << pinned << "/" << (cases.size() - skipped) << " ("
                  << skipped << " not compared)\n";
        require(failures.empty(), std::format("{} error case(s) differ", failures.size()));
    }

} // namespace

int main(int argc, char** argv) {
    const auto golden = gxbuild3::test::golden_options(argc, argv);
    if (!golden)
        return 2;
    g_golden = *golden;

    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"parse_header rejects short buffer", test_parse_header_rejects_short_buffer},
        {"read_header_from_file requires full header",
         test_read_header_from_file_requires_full_header},
        {"container rejects relative escape", test_container_rejects_relative_escape},
        {"container rejects absolute name", test_container_rejects_absolute_name},
        {"StfsContainer rejects escape", test_container_rejects_escape},
        {"safe_join", test_safe_join},
        {"parent cycle rejected", test_parent_cycle_rejected},
        {"nested extraction", test_nested_extraction},
        {"truncated chain fails", test_truncated_chain_fails},
        {"longer chain is cut at file_size", test_longer_chain_is_cut_at_file_size},
        {"zero-size file skips chain", test_zero_size_file_skips_chain},
        {"block offsets are 64-bit", test_block_offsets_are_64_bit},
        {"header_size out of range rejected", test_header_size_out_of_range_rejected},
        {"invalid hash status message is hex", test_invalid_hash_status_message_is_hex},
        {"consecutive file ignores hash chain", test_consecutive_file_ignores_hash_chain},
        {"consecutive file bounds", test_consecutive_file_bounds},
        {"file table follows hash chain", test_file_table_follows_hash_chain},
        {"invalid file table descriptor rejected", test_invalid_file_table_descriptor_rejected},
        {"short file table chain rejected", test_short_file_table_chain_rejected},
        {"writable layout rejected", test_writable_layout_rejected},
        {"name_length beyond field rejected", test_name_length_beyond_field_rejected},
        {"nameless entry ends listing", test_nameless_entry_ends_listing},
        {"entry name contents", test_entry_name_contents},
        {"write failure is reported", test_write_failure_is_reported},
        {"verify requires total_blocks", test_verify_requires_total_blocks},
        {"verify detects corruption", test_verify_detects_corruption},
        {"system update fixture", test_system_update_fixture},
        {"StfsContainer verified extract", test_container_verified_extract},
        {"locale strings decode UTF-16BE", test_locale_strings_decode_utf16be},
        {"negative thumbnail size is empty", test_negative_thumbnail_size_is_empty},
        {"system update fixture entry snapshot", test_system_update_fixture_entry_snapshot},
        {"system update fixture metadata snapshot", test_system_update_fixture_metadata_snapshot},
        {"error codes are pinned", test_error_codes_are_pinned},
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
