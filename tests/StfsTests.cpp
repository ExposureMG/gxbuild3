#include "Error.hpp"
#include "excrypt.h"
#include "stfs/BlockParser.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/HashVerifier.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/Package.hpp"
#include "stfs/PackageCommon.hpp"
#include "stfs/StfsContainer.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
    namespace fs = std::filesystem;
    namespace stfs = gxbuild3::stfs;
    using Bytes = std::vector<std::byte>;

    void require(bool condition, std::string_view message) {
        if (!condition)
            throw std::runtime_error(std::string(message));
    }

    template <typename F> std::string thrown_message(F&& action) {
        try {
            action();
        } catch (const std::exception& e) {
            return e.what();
        }
        throw std::runtime_error("expected an exception");
    }

    template <typename R> bool fails_with(const R& result, gxbuild3::ErrorCode code) {
        return !result && result.error().code == code;
    }

    template <typename F> void require_throws(F&& action, std::string_view message) {
        bool threw = false;
        try {
            action();
        } catch (const std::exception&) {
            threw = true;
        }
        require(threw, message);
    }

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

    // Opens and extracts a package, returning the error message (empty if nothing threw).
    std::string extract_error(const Bytes& bytes, const fs::path& out) {
        try {
            stfs::Package::from_data(bytes).extract_all(out);
        } catch (const std::exception& e) {
            return e.what();
        }
        return {};
    }

    void test_package_rejects_relative_escape() {
        TempDir dir;
        // A ".." directory entry passes the name checks but escapes once joined.
        const auto dotdot = make_package({{"good.bin", pattern(10, 1)},
                                          {"..", {}, true, -1, true},
                                          {"escaped", pattern(10, 2), true, 1}});
        require(extract_error(dotdot, dir.root / "out").find("escapes") != std::string::npos,
                "a .. entry path is rejected by Package::extract_all");
        require(!fs::exists(dir.root / "escaped"), "nothing is written outside output_dir");
        require(!fs::exists(dir.root / "out" / "good.bin"),
                "destinations are validated before anything is written");

        const auto slash = make_package({{"../escaped", pattern(10, 2)}});
        require(!extract_error(slash, dir.root / "out").empty(),
                "a ../ entry name is rejected by Package");
        require(!fs::exists(dir.root / "escaped"), "a ../ name writes nothing outside");

        const auto nested =
            make_package({{"sub", {}, true, -1, true}, {"../../escaped", pattern(10, 3), true, 0}});
        require(!extract_error(nested, dir.root / "out").empty(),
                "a ../ entry under a directory is rejected");
        require(!fs::exists(dir.root / "escaped"), "nested escape writes nothing outside");
    }

    void test_package_rejects_absolute_name() {
        TempDir dir;
        const auto bytes = make_package({{"/stfs-absolute-escape", pattern(10, 1)}});
        const auto message = extract_error(bytes, dir.root / "out");
        require(message.find("absolute") != std::string::npos ||
                    message.find("separator") != std::string::npos,
                "an absolute entry name is rejected by Package");
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
        const auto self =
            stfs::Package::from_data(make_package({{"a.bin", pattern(10, 1), true, 0}}));
        require_throws([&] { self.extract_all(dir.root / "out"); },
                       "an entry that is its own parent is rejected");

        // Entry 0 refers forward to entry 1, which refers back to entry 0.
        const auto loop = stfs::Package::from_data(
            make_package({{"a", {}, true, 1, true}, {"b", {}, true, 0, true}}));
        require_throws([&] { loop.extract_all(dir.root / "out"); },
                       "a parent cycle through a later entry is rejected");

        const auto bytes = make_package({{"a", {}, true, 1, true}, {"b", {}, true, 0, true}});
        const auto container = stfs::StfsContainer::open(bytes);
        require(container && !container->extract_all(dir.root / "out"),
                "StfsContainer rejects a forward parent reference");
    }

    void test_nested_extraction() {
        TempDir dir;
        const auto data = pattern(5000, 9);
        const auto package = stfs::Package::from_data(
            make_package({{"sub", {}, true, -1, true}, {"inner.bin", data, true, 0}}));
        package.extract_all(dir.root / "out", true);
        std::ifstream in(dir.root / "out" / "sub" / "inner.bin", std::ios::binary);
        Bytes read(data.size() + 1);
        in.read(reinterpret_cast<char*>(read.data()), static_cast<std::streamsize>(read.size()));
        read.resize(static_cast<std::size_t>(in.gcount()));
        require(read == data, "a nested file extracts with verification");
    }

    // --- File extraction -------------------------------------------------------------------

    void test_truncated_chain_throws() {
        // A chained (non-consecutive) two-block file whose chain ends after the first block.
        auto bytes = make_package({{"a.bin", pattern(0x1800, 1), false}});
        put_be(bytes, hash_offset(1) + 0x15, 0xFFFFFF, 3);
        const auto package = stfs::Package::from_data(bytes);
        require_throws([&] { (void) package.extract_file(package.files().at(0)); },
                       "a chain shorter than file_size must throw, not return a short buffer");
    }

    void test_longer_chain_is_cut_at_file_size() {
        // The chain may be longer than needed; extraction stops at file_size.
        const auto data = pattern(0x1800, 4);
        auto bytes = make_package({{"a.bin", data, false}, {"b.bin", pattern(0x10, 5), false}});
        put_be(bytes, hash_offset(2) + 0x15, 3, 3); // a.bin's last block links on into b.bin
        const auto package = stfs::Package::from_data(bytes);
        require(package.extract_file(package.files().at(0)) == data,
                "a longer chain yields exactly file_size bytes");
    }

    void test_zero_size_file_skips_chain() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}, {"empty.bin", {}}});
        put_le(bytes, entry_offset(1) + 0x2F, 3000, 3); // starting block far out of range
        const auto package = stfs::Package::from_data(bytes);
        require(package.extract_file(package.files().at(1)).empty(),
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
            require_throws([&] { (void) stfs::Package::from_data(bytes); },
                           "an absurd header_size is rejected");
        }
    }

    void test_invalid_hash_status_message_is_hex() {
        auto bytes = make_package({{"a.bin", pattern(10, 1), false}});
        bytes[hash_offset(1) + 0x14] = std::byte{0xAB};
        const auto package = stfs::Package::from_data(bytes);
        const auto message =
            thrown_message([&] { (void) package.extract_file(package.files().at(0)); });
        require(message.find("(0xAB)") != std::string::npos,
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

        const auto package = stfs::Package::from_data(consecutive);
        require(package.extract_file(package.files().at(0)) == data,
                "a consecutive file is read from starting_block without its chain");
        require(package.extract_file(package.files().at(0), true) == data,
                "a consecutive file still verifies block by block");

        const auto chained_package = stfs::Package::from_data(chained);
        require_throws([&] { (void) chained_package.extract_file(chained_package.files().at(0)); },
                       "a non-consecutive file still follows (and trusts) its chain");
    }

    void test_consecutive_file_bounds() {
        auto short_allocation = make_package({{"a.bin", pattern(0x2800, 6), true}});
        put_le(short_allocation, entry_offset(0) + 0x29, 2, 3); // 2 blocks for 0x2800 bytes
        const auto package = stfs::Package::from_data(short_allocation);
        require_throws([&] { (void) package.extract_file(package.files().at(0)); },
                       "blocks_allocated too small for file_size is rejected");

        auto past_end = make_package({{"a.bin", pattern(0x2800, 6), true}});
        put_le(past_end, entry_offset(0) + 0x2F, 0xFFFFFE, 3);
        const auto past_end_package = stfs::Package::from_data(past_end);
        require_throws(
            [&] { (void) past_end_package.extract_file(past_end_package.files().at(0)); },
            "consecutive blocks past the last block number are rejected");

        auto huge = make_package({{"a.bin", pattern(0x10, 6), true}});
        put_le(huge, entry_offset(0) + 0x29, 0xFFFFFF, 3);
        put_be(huge, entry_offset(0) + 0x34, 0xFFFFFFFF, 4);
        const auto huge_package = stfs::Package::from_data(huge);
        require_throws([&] { (void) huge_package.extract_file(huge_package.files().at(0)); },
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

        const auto package = stfs::Package::from_data(bytes);
        require(package.files().size() == 65 && package.files().back().name == "second.bin",
                "Package reads the file table through its hash chain");
        require(package.extract_file(package.files().back(), true) == data,
                "an entry from the second table block extracts");

        const auto container = stfs::StfsContainer::open(bytes);
        require(container && container->extract_file_by_name("second.bin") == data,
                "StfsContainer reads the same file table");
    }

    void test_invalid_file_table_descriptor_rejected() {
        auto empty = make_package({{"a.bin", pattern(10, 1)}});
        put_le(empty, kVolumeDescriptor + 0x03, 0, 2);
        require_throws([&] { (void) stfs::Package::from_data(empty); },
                       "Package rejects a zero file table block count");

        auto negative = make_package({{"a.bin", pattern(10, 1)}});
        put_le(negative, kVolumeDescriptor + 0x03, 0x8000, 2);
        require_throws([&] { (void) stfs::Package::from_data(negative); },
                       "Package rejects a negative file table block count");
    }

    void test_short_file_table_chain_rejected() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        put_le(bytes, kVolumeDescriptor + 0x03, 2, 2); // claims two blocks, chain has one
        require_throws([&] { (void) stfs::Package::from_data(bytes); },
                       "a file table chain shorter than its block count is rejected");
    }

    void test_writable_layout_rejected() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        bytes[kVolumeDescriptor + 0x02] = std::byte{0x00}; // block_separation bit 0 clear
        require_throws([&] { (void) stfs::Package::from_data(bytes); },
                       "Package rejects block_separation bit 0 clear");
        require(!stfs::StfsContainer::open(bytes),
                "StfsContainer rejects block_separation bit 0 clear");

        bytes[kVolumeDescriptor + 0x02] = std::byte{0x03};
        require(stfs::Package::from_data(bytes).files().size() == 1,
                "other block_separation bits do not matter");
    }

    // --- File table names ------------------------------------------------------------------

    void test_name_length_beyond_field_rejected() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        bytes[entry_offset(0) + 0x28] = std::byte{0x40 | 0x29};
        require_throws([&] { (void) stfs::Package::from_data(bytes); },
                       "name_length 0x29 is rejected");
        bytes[entry_offset(0) + 0x28] = std::byte{0x40 | 0x3F};
        require_throws([&] { (void) stfs::Package::from_data(bytes); },
                       "name_length 0x3F is rejected");

        const std::string longest(0x28, 'n');
        const auto full = stfs::Package::from_data(make_package({{longest, pattern(10, 1)}}));
        require(full.files().at(0).name == longest, "a 40-byte name is accepted");
    }

    void test_nameless_entry_ends_listing() {
        auto bytes = make_package(
            {{"a.bin", pattern(10, 1)}, {"b.bin", pattern(10, 2)}, {"c.bin", pattern(10, 3)}});
        bytes[entry_offset(1) + 0x28] = std::byte{0x40}; // name_length 0, other bytes set
        const auto package = stfs::Package::from_data(bytes);
        require(package.files().size() == 1 && package.files().at(0).name == "a.bin",
                "an entry without a name length ends the listing");
    }

    void test_entry_name_contents() {
        auto padded = make_package({{"a.bin", pattern(10, 1)}});
        padded[entry_offset(0) + 0x28] = std::byte{0x40 | 0x08}; // "a.bin\0\0\0"
        require(stfs::Package::from_data(padded).files().at(0).name == "a.bin",
                "NUL padding inside name_length is trimmed");

        auto empty = make_package({{"a.bin", pattern(10, 1)}});
        empty[entry_offset(0)] = std::byte{0};
        require_throws([&] { (void) stfs::Package::from_data(empty); },
                       "a name that starts with NUL is rejected");

        for (const auto* name : {"a/b", "a\\b"}) {
            const auto bytes = make_package({{name, pattern(10, 1)}});
            require_throws([&] { (void) stfs::Package::from_data(bytes); },
                           "a name with a path separator is rejected");
        }

        const auto plain = stfs::Package::from_data(make_package(
            {{"$flash_dash.xex", pattern(10, 1)}, {"$flash_SegoeXbox-Light.xtt", pattern(10, 2)}}));
        require(plain.files().size() == 2 &&
                    plain.files().at(1).name == "$flash_SegoeXbox-Light.xtt",
                "system update names are accepted");
    }

    // --- Writing ---------------------------------------------------------------------------

    void test_write_failure_throws() {
        const fs::path full = "/dev/full";
        if (!fs::exists(full)) {
            std::cout << "  (skipped: no /dev/full)\n";
            return;
        }
        const auto bytes = make_package({{"a.bin", pattern(10, 1)}});

        const auto package = stfs::Package::from_data(bytes);
        require_throws([&] { package.extract_file_to_disk(package.files().at(0), full); },
                       "Package::extract_file_to_disk reports a failed write");

        // StfsContainer::extract_all writing through a planted link to /dev/full.
        TempDir dir;
        fs::create_directories(dir.root / "out");
        fs::create_symlink(full, dir.root / "out" / "a.bin");
        const auto container = stfs::StfsContainer::open(bytes);
        require(container && !container->extract_all(dir.root / "out"),
                "StfsContainer::extract_all reports a failed write");

        require_throws(
            [&] { package.extract_file_to_disk(package.files().at(0), dir.root / "no/dir/x"); },
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
        const auto package = stfs::Package::from_data(bytes);
        const auto& entry = package.files().at(0);
        const auto* vd =
            std::get_if<stfs::StfsVolumeDescriptor>(&package.metadata().volume_descriptor);
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
        const auto package = stfs::Package::from_data(data_corrupt);
        require(package.extract_file(package.files().at(0)) == pattern(10, 1),
                "unverified extraction ignores the hash");
        require_throws([&] { (void) package.extract_file(package.files().at(0), true); },
                       "a corrupted data block fails verification");
        const auto* vd =
            std::get_if<stfs::StfsVolumeDescriptor>(&package.metadata().volume_descriptor);
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
        const auto table_package = stfs::Package::from_data(table_corrupt);
        require_throws(
            [&] { (void) table_package.extract_file(table_package.files().at(0), true); },
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

        const auto package = stfs::Package::from_data(bytes);
        require(package.files().size() == 31, "fixture lists 31 files");
        const auto& display_name = package.metadata().display_name;
        require(std::string(display_name.begin(), display_name.end()) == "System Update",
                "fixture display_name decodes from UTF-16BE");

        const auto container = stfs::StfsContainer::open(bytes);
        require(container.has_value(), "StfsContainer opens the fixture");
        const auto in_memory = container->extract_to_memory();
        require(in_memory.has_value(), "StfsContainer extracts the fixture to memory");
        for (const auto& entry : package.files()) {
            const auto verified = package.extract_file(entry, true);
            std::string key = entry.name;
            if (key.starts_with("$flash_"))
                key.erase(0, 7);
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            require(in_memory->at(key) == verified,
                    "Package (verified) and StfsContainer extract identical bytes");
        }

        const auto find = [&](std::string_view name) -> const stfs::FileEntry& {
            for (const auto& entry : package.files())
                if (entry.name == name)
                    return entry;
            throw std::runtime_error("fixture entry missing");
        };
        require(sha1_hex(package.extract_file(find("xboxupd.bin"), true)) ==
                    "ea7666ebe2799812270581538b342b8143397ab9",
                "xboxupd.bin extracts byte-identically");
        require(sha1_hex(package.extract_file(find("$flash_dash.xex"), true)) ==
                    "3d44ef57781c20669705cd687e3b62b1c2f1ff6b",
                "$flash_dash.xex extracts byte-identically");
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

        const auto package = stfs::Package::from_data(bytes);
        const auto& meta = package.metadata();
        require(as_string(meta.display_name) == "System Update", "display_name decodes");
        require(as_string(meta.display_description) == "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80",
                "non-ASCII and surrogate pairs decode to UTF-8");
        require(as_string(meta.publisher_name) == "Pub\xEF\xBF\xBDx",
                "unpaired surrogates become U+FFFD");
        require(as_string(meta.title_name) == std::string(0x40, 'T'),
                "a field without a terminator stops at its size");
    }

    void test_negative_thumbnail_size_is_empty() {
        auto bytes = make_package({{"a.bin", pattern(10, 1)}});
        put_be(bytes, 0x1712, 0xFFFFFFFF, 4);
        put_be(bytes, 0x1716, 0x80000000, 4);
        const auto package = stfs::Package::from_data(bytes);
        const auto& meta = package.metadata();
        require(meta.thumbnail_image.empty() && meta.title_thumbnail_image.empty(),
                "negative thumbnail sizes yield no image");

        put_be(bytes, 0x1712, 0x20, 4);
        put_be(bytes, 0x1716, 0x7FFFFFFF, 4);
        const auto sized_package = stfs::Package::from_data(bytes);
        const auto& sized = sized_package.metadata();
        require(sized.thumbnail_image.size() == 0x20 &&
                    sized.title_thumbnail_image.size() == 0x4000,
                "positive sizes are kept and clamped to 0x4000");
    }

} // namespace

int main() {
    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"parse_header rejects short buffer", test_parse_header_rejects_short_buffer},
        {"read_header_from_file requires full header",
         test_read_header_from_file_requires_full_header},
        {"Package rejects relative escape", test_package_rejects_relative_escape},
        {"Package rejects absolute name", test_package_rejects_absolute_name},
        {"StfsContainer rejects escape", test_container_rejects_escape},
        {"safe_join", test_safe_join},
        {"parent cycle rejected", test_parent_cycle_rejected},
        {"nested extraction", test_nested_extraction},
        {"truncated chain throws", test_truncated_chain_throws},
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
        {"write failure throws", test_write_failure_throws},
        {"verify requires total_blocks", test_verify_requires_total_blocks},
        {"verify detects corruption", test_verify_detects_corruption},
        {"system update fixture", test_system_update_fixture},
        {"locale strings decode UTF-16BE", test_locale_strings_decode_utf16be},
        {"negative thumbnail size is empty", test_negative_thumbnail_size_is_empty},
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
