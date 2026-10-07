#include "PirsPackage.hpp"

#include "excrypt.h"

#include <algorithm>
#include <gtest/gtest.h>

namespace gxbuild3::stfs::pirs {

    namespace {
        // SHA-1 of bytes[offset, offset + size) written to out[out_offset, out_offset + 0x14).
        void sha1(const Bytes& bytes, std::size_t offset, std::size_t size, Bytes& out,
                  std::size_t out_offset) {
            if (offset + size > bytes.size() || out_offset + 0x14 > out.size()) {
                ADD_FAILURE() << "SHA-1 range fits";
                return;
            }
            std::uint8_t digest[0x14]{};
            ExCryptSha(reinterpret_cast<const std::uint8_t*>(bytes.data() + offset),
                       static_cast<std::uint32_t>(size), nullptr, 0, nullptr, 0, digest,
                       sizeof(digest));
            for (std::size_t i = 0; i < sizeof(digest); ++i) {
                out[out_offset + i] = static_cast<std::byte>(digest[i]);
            }
        }
    } // namespace

    void put_be(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) {
            bytes.at(offset + i) = static_cast<std::byte>(value >> (8 * (width - 1 - i)));
        }
    }

    void put_le(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) {
            bytes.at(offset + i) = static_cast<std::byte>(value >> (8 * i));
        }
    }

    std::uint32_t total_blocks(const Bytes& package) {
        std::uint32_t total = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            total = (total << 8) | std::to_integer<std::uint32_t>(package[0x395 + i]);
        }
        return total;
    }

    void seal(Bytes& package) {
        const auto total = total_blocks(package);
        for (std::uint32_t block = 0; block < total; ++block) {
            sha1(package, data_offset(block), kBlockSize, package, hash_offset(block));
        }
        sha1(package, kHashTable, kBlockSize, package, kVolumeDescriptor + 0x08);
    }

    Bytes make_package(const std::vector<SynthFile>& files) {
        if (files.size() > 64) {
            ADD_FAILURE() << "fixture fits in one file table block";
            return {};
        }

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
        if (total > 0xAA) {
            ADD_FAILURE() << "fixture fits under one level-0 hash table";
            return {};
        }

        Bytes package(data_offset(total), std::byte{0});
        for (std::size_t i = 0; i < 4; ++i) {
            package[i] = static_cast<std::byte>("PIRS"[i]);
        }
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
            if (file.name.size() > 0x28) {
                ADD_FAILURE() << "fixture name fits";
                return {};
            }
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
        for (std::size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>((i * 7 + seed) & 0xFF);
        }
        return data;
    }

    std::span<const std::uint8_t> as_u8(const Bytes& bytes) {
        return {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};
    }

} // namespace gxbuild3::stfs::pirs
