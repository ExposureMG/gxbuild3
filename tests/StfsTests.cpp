#include "excrypt.h"
#include "stfs/FileExtractor.hpp"
#include "stfs/HeaderParser.hpp"
#include "stfs/Package.hpp"
#include "stfs/StfsContainer.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
    namespace fs = std::filesystem;
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
        require_throws([&] { (void) stfs::parseHeader(data); },
                       "a 0x1B0-byte PIRS header must be rejected, not over-read");

        data.resize(0x22C);
        const auto header = stfs::parseHeader(data);
        require(header.magic == stfs::Magic::PIRS, "a full 0x22C-byte header parses");
    }

    void test_read_header_from_file_requires_full_header() {
        TempDir dir;
        Bytes data(0x1B0, std::byte{0});
        for (std::size_t i = 0; i < 4; ++i)
            data[i] = static_cast<std::byte>("PIRS"[i]);
        write_bytes(dir.root / "short", data);
        require_throws([&] { (void) stfs::readHeaderFromFile(dir.root / "short"); },
                       "a short header file must be rejected");

        write_bytes(dir.root / "full", make_package({{"a.bin", pattern(10, 1)}}));
        const auto header = stfs::readHeaderFromFile(dir.root / "full");
        require(header.magic == stfs::Magic::PIRS, "a full package header reads from file");
    }

} // namespace

int main() {
    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"parseHeader rejects short buffer", test_parse_header_rejects_short_buffer},
        {"readHeaderFromFile requires full header",
         test_read_header_from_file_requires_full_header},
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
