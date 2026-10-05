#pragma once

#include "stfs/Commons.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace gxbuild3::stfs {

    [[nodiscard]] std::vector<std::uint32_t> follow_block_chain(std::span<const std::byte> package,
                                                                std::uint32_t starting_block,
                                                                std::uint32_t header_size);

    [[nodiscard]] std::vector<std::byte>
    extract_file(std::span<const std::byte> package, const FileEntry& entry, Magic magic,
                 std::uint32_t header_size, bool verify = false,
                 const std::array<std::byte, 0x14>* top_hash = nullptr,
                 std::uint32_t total_blocks = 0);

    void extract_file_to_disk(std::span<const std::byte> package, const FileEntry& entry,
                              Magic magic, std::uint32_t header_size,
                              const std::filesystem::path& output_path, bool verify = false,
                              const std::array<std::byte, 0x14>* top_hash = nullptr,
                              std::uint32_t total_blocks = 0);

} // namespace gxbuild3::stfs