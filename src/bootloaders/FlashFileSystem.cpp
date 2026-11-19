// FlashFileSystem implementation
// Modern C++23 implementation of Xbox 360 NAND flash filesystem

#include "bootloaders/FlashFileSystem.hpp"

#include "Utils.hpp"
#include "utils/FlashBlockDriver.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string_view>

namespace gxbuild3::bootloaders {

    namespace {

        uint32_t ceil_div_u32(uint32_t value, uint32_t divisor) {
            if (divisor == 0) {
                return 0;
            }
            return value / divisor + ((value % divisor) != 0 ? 1U : 0U);
        }

    } // namespace

    // Construction and initialization

    FlashFileSystem::FlashFileSystem(
        std::shared_ptr<gxbuild3::utils::FlashBlockDriver> block_driver)
        : m_block_driver(std::move(block_driver)),
          m_corona_data(std::make_shared<XeCoronaFsData>()), m_version(0), m_start_block_idx(0) {
        Log::Trace("FlashFileSystem: constructed with block driver");
    }

    FlashFileSystem::FlashFileSystem(
        std::shared_ptr<gxbuild3::utils::FlashBlockDriver> block_driver,
        std::shared_ptr<XeCoronaFsData> corona_data)
        : m_block_driver(std::move(block_driver)), m_corona_data(std::move(corona_data)),
          m_version(0), m_start_block_idx(0) {
        Log::Trace("FlashFileSystem: constructed with block driver and corona data");
    }

    bool FlashFileSystem::create_defaults(uint16_t block_idx, uint32_t version,
                                          uint32_t sys_update_addr, bool reserve_config_blocks) {
        if (!m_block_driver) {
            Log::Error("create_defaults: no block driver available");
            return false;
        }

        const uint32_t lil_block_count = m_block_driver->lil_block_count();
        const uint32_t lil_block_length = m_block_driver->lil_block_length();
        if (lil_block_count == 0 || lil_block_length == 0 || block_idx >= lil_block_count) {
            Log::Error("create_defaults: invalid filesystem geometry or root block 0x{:x}",
                       block_idx);
            return false;
        }

        m_start_block_idx = block_idx;
        m_version = version;
        m_entries.clear();
        m_blockmap.assign(lil_block_count, 0x1ffe);
        m_blockmap[block_idx] = 0x1fff;
        m_block_driver->reserve_logical_block(block_idx);

        const auto& alloc_table = m_block_driver->allocated_blocks();
        for (size_t i = 0; i < alloc_table.size() && i < lil_block_count; ++i) {
            if (alloc_table[i] && i != block_idx) {
                m_blockmap[i] = 0x1ffb;
            }
        }

        const uint32_t fs_start_block = std::max(static_cast<uint32_t>(block_idx), ceil_div_u32(sys_update_addr + 0x20000U, lil_block_length));
        for (uint32_t i = 0; i < std::min(fs_start_block, lil_block_count); ++i) {
            if (i != block_idx) {
                m_blockmap[i] = 0x1ffb;
                m_block_driver->reserve_logical_block(i);
            }
        }

        if (reserve_config_blocks) {
            const uint32_t config_block_idx = m_block_driver->config_block_idx();
            if (config_block_idx < lil_block_count) {
                for (uint32_t i = 0; i < 5 && (config_block_idx + i) < lil_block_count; ++i) {
                    m_blockmap[config_block_idx + i] = 0x1ffb;
                    m_block_driver->reserve_logical_block(config_block_idx + i);
                }
            }
        }

        if (m_corona_data) {
            m_corona_data->fs_version = version;
            m_corona_data->fs_block_idx = block_idx;
        }

        return true;
    }

    ChainAllocationResult FlashFileSystem::allocate_block() {
        return allocate_blocks(1, 0);
    }

    ChainAllocationResult FlashFileSystem::allocate_blocks(uint16_t blocks_needed,
                                                           uint16_t min_block) {
        if (!m_block_driver) {
            Log::Error("allocate_blocks: no block driver available");
            return {false, 0};
        }

        const uint32_t lil_block_count = m_block_driver->lil_block_count();

        for (uint32_t i = min_block; i < lil_block_count; i++) {
            bool contiguous_available = true;

            for (uint16_t x = 0; x < blocks_needed; x++) {
                if (i + x >= m_blockmap.size()) {
                    contiguous_available = false;
                    break;
                }
                if ((m_blockmap[i + x] & 0x7fff) != 0x1ffe) {
                    contiguous_available = false;
                    break;
                }
            }

            if (!contiguous_available) {
                continue;
            }

            for (uint16_t x = 0; x < blocks_needed; x++) {
                m_block_driver->reserve_logical_block(i + x);
                if (x + 1 < blocks_needed) {
                    m_blockmap[i + x] = static_cast<uint16_t>(i + x + 1);
                } else {
                    m_blockmap[i + x] = 0x1fff;
                }
            }
            return {true, static_cast<uint16_t>(i)};
        }

        Log::Error("allocate_blocks: failed to find {} contiguous blocks starting from {}",
                   blocks_needed, min_block);
        return {false, 0};
    }

    std::optional<std::vector<uint16_t>>
    FlashFileSystem::get_chain_from_start(uint16_t start_block, size_t& chain_length) const {
        uint16_t start_blk = 0;
        uint16_t curr_blk = start_block;

        do {
            start_blk = curr_blk;
            curr_blk = get_previous_block(curr_blk);
        } while (curr_blk > 0);

        if (start_blk == 0) {
            chain_length = 0;
            return std::nullopt;
        }

        return get_chain(start_blk, chain_length);
    }

    uint16_t FlashFileSystem::get_previous_block(uint16_t block_idx) const {
        for (size_t i = 0; i < m_blockmap.size(); i++) {
            if (m_blockmap[i] == block_idx) {
                return static_cast<uint16_t>(i);
            }
        }
        return 0;
    }

    void FlashFileSystem::free_chain(uint16_t start_block) {
        size_t chain_length = 0;
        auto chain = get_chain(start_block, chain_length);
        if (!chain) {
            Log::Error("free_chain: failed to get chain for block {}", start_block);
            return;
        }

        for (size_t i = 0; i < chain_length; i++) {
            if ((*chain)[i] < m_blockmap.size()) {
                m_blockmap[(*chain)[i]] = 0x1ffe; // Mark as free
            }
        }
    }

    std::optional<std::vector<uint16_t>> FlashFileSystem::get_chain(uint16_t start_block,
                                                                    size_t& chain_length) const {
        return get_chain(start_block, 0x600, chain_length); // Default limit
    }

    std::optional<std::vector<uint16_t>> FlashFileSystem::get_chain(uint16_t start_block,
                                                                    size_t max_length,
                                                                    size_t& chain_length) const {
        // First, get the length of this chain
        int num = 1;
        uint16_t block = start_block;

        while (true) {
            if (block >= m_blockmap.size()) {
                Log::Error("get_chain: block index {} out of bounds", block);
                chain_length = 0;
                return std::nullopt;
            }

            block = static_cast<uint16_t>(m_blockmap[block] & 0x7fff);
            if (block >= 0x1ffb || num == static_cast<int>(max_length)) {
                break;
            }
            num++;
        }

        if (num == static_cast<int>(max_length)) {
            Log::Error("get_chain: reached maximum length {}", max_length);
            chain_length = 0;
            return std::nullopt;
        }

        // Now build the chain
        std::vector<uint16_t> chain(num);
        block = start_block;
        for (int i = 0; i < num; i++) {
            chain[i] = block;
            if (block >= m_blockmap.size()) {
                Log::Error("get_chain: block index {} out of bounds during chain building", block);
                chain_length = 0;
                return std::nullopt;
            }
            block = static_cast<uint16_t>(m_blockmap[block] & 0x7fff);
            if (block >= 0x1ffb || i + 1 >= num) {
                break;
            }
        }

        chain_length = num;
        return chain;
    }

    size_t FlashFileSystem::set_chain_data(uint16_t start_block, std::span<const uint8_t> data) {
        if (!m_block_driver) {
            Log::Error("set_chain_data: no block driver available");
            return 0;
        }

        size_t chain_length = 0;
        auto chain = get_chain(start_block, chain_length);
        if (!chain) {
            Log::Error("set_chain_data: failed to get chain for block {}", start_block);
            return 0;
        }

        const size_t data_size = data.size();
        const size_t lil_block_length = m_block_driver->lil_block_length();
        const uint32_t blocks_needed = static_cast<uint32_t>(
            data_size / lil_block_length + ((data_size % lil_block_length) > 0 ? 1 : 0));

        size_t wrote = 0;

        // Check if we have enough blocks
        if (chain_length == blocks_needed) {
            // write data to existing blocks
            for (uint32_t i = 0; i < blocks_needed && i < chain_length; i++) {
                size_t to_write = lil_block_length;
                if (i + 1 == blocks_needed) {
                    to_write = data_size - wrote;
                }

                const uint32_t target_block = (*chain)[i] + m_block_driver->fs_offset();
                if (!m_block_driver->write_lil_block(target_block, data.data() + wrote, to_write)) {
                    Log::Error("set_chain_data: failed to write block {}", target_block);
                    return wrote;
                }
                wrote += to_write;
            }
            return wrote;
        }

        if (chain_length < blocks_needed) {
            // Need to allocate more blocks
            const uint16_t blocks_to_alloc = static_cast<uint16_t>(blocks_needed - chain_length);
            uint16_t current_blk = (*chain)[chain_length - 1];

            for (uint16_t x = 0; x < blocks_to_alloc; x++) {
                auto alloc_result = allocate_blocks(1, current_blk);
                if (!alloc_result.success) {
                    Log::Error("set_chain_data: failed to allocate additional block");
                    return wrote;
                }
                // Link old tail to new block, then advance current to the new block
                if (current_blk < m_blockmap.size()) {
                    m_blockmap[current_blk] = alloc_result.block_index;
                }
                current_blk = alloc_result.block_index;
            }

            // Recursively call to write data with updated chain
            return set_chain_data(start_block, data);
        }

        // Too many blocks, free excess and resize
        if (chain_length > blocks_needed) {
            // Free blocks after the amount we need
            free_chain((*chain)[blocks_needed]);

            // Set last block to 0x1fff (end of chain)
            if (blocks_needed > 0 && blocks_needed - 1 < chain_length) {
                m_blockmap[(*chain)[blocks_needed - 1]] = 0x1fff;
            }

            // Recursively call to write data with resized chain
            return set_chain_data(start_block, data);
        }

        return wrote;
    }

    // File operations

    const FlashFileSystemEntry* FlashFileSystem::find_file(std::string_view filename) const {
        return find_entry_internal(filename);
    }

    std::optional<std::vector<uint8_t>>
    FlashFileSystem::get_file_data(const FlashFileSystemEntry& entry) const {
        if (!m_block_driver) {
            Log::Error("get_file_data: no block driver available");
            return std::nullopt;
        }

        if (entry.block_number == 0) {
            Log::Error("get_file_data: entry has no block number");
            return std::nullopt;
        }

        size_t chain_length = 0;
        auto chain = get_chain(entry.block_number, chain_length);
        if (!chain) {
            Log::Error("get_file_data: failed to get chain for block {}", entry.block_number);
            return std::nullopt;
        }

        std::vector<uint8_t> buffer(entry.length);
        auto result =
            m_block_driver->read_lil_block_chain(chain->data(), chain_length, entry.length);
        if (!result) {
            Log::Error("get_file_data: failed to read chain data");
            return std::nullopt;
        }

        if (result->size() != entry.length) {
            Log::Warn("get_file_data: read {} bytes, expected {}", result->size(), entry.length);
            // Resize to match expected length
            buffer.resize(result->size());
            std::memcpy(buffer.data(), result->data(), result->size());
        } else {
            std::memcpy(buffer.data(), result->data(), entry.length);
        }

        return buffer;
    }

    bool FlashFileSystem::set_file_data(FlashFileSystemEntry& entry,
                                        std::span<const uint8_t> data) {
        if (entry.block_number == 0) {
            // Allocate a block for this entry
            auto alloc_result = allocate_block();
            if (!alloc_result.success) {
                Log::Error("set_file_data: failed to allocate block for entry");
                return false;
            }
            entry.block_number = alloc_result.block_index;
        }

        const size_t bytes_written = set_chain_data(entry.block_number, data);
        if (bytes_written != data.size()) {
            Log::Error("set_file_data: failed to write all data (wrote {} of {})", bytes_written,
                       data.size());
            return false;
        }

        entry.length = static_cast<uint32_t>(data.size());
        return true;
    }

    bool FlashFileSystem::add_file(std::string_view filename, FlashFileSystemEntry*& entry) {
        std::string_view clean_filename = filename;
        auto pos = clean_filename.find_last_of("/\\");
        if (pos != std::string_view::npos) {
            clean_filename = clean_filename.substr(pos + 1);
        }

        if (clean_filename.empty()) {
            Log::Error("add_file: empty filename after sanitization from '{}'", filename);
            return false;
        }

        // Check if file already exists
        if (find_entry_internal(clean_filename) != nullptr) {
            Log::Error("add_file: file '{}' already exists", clean_filename);
            return false;
        }

        Log::Info("add_file: adding file '{}'...", clean_filename);

        // Create new entry
        m_entries.emplace_back();
        auto& new_entry = m_entries.back();

        // Initialize entry
        std::memset(new_entry.filename, 0, kMaxFilenameLength);
        const size_t filename_len = std::min(clean_filename.length(), kMaxFilenameLength - 1);
        std::memcpy(new_entry.filename, clean_filename.data(), filename_len);
        new_entry.filename[filename_len] = '\0';

        // Allocate a block for the new entry
        auto alloc_result = allocate_block();
        if (!alloc_result.success) {
            Log::Error("add_file: failed to allocate block for new entry");
            m_entries.pop_back();
            return false;
        }

        new_entry.block_number = alloc_result.block_index;
        entry = &new_entry;
        return true;
    }

    const FlashFileSystemEntry* FlashFileSystem::search_file(std::string_view filename) const {
        return find_file(filename);
    }

    // Filesystem I/O

    bool FlashFileSystem::load(uint16_t block_idx) {
        if (!m_block_driver) {
            Log::Error("load: no block driver available");
            return false;
        }

        Log::Info("load: loading filesystem from block 0x{:x}...", block_idx);

        // Set version from Corona data or spare data
        if (!m_corona_data || m_corona_data->fs_version == 0) {
            // Read spare data to get version
            auto spare = m_block_driver->read_lil_block_spare(block_idx);
            if (spare) {
                m_version = m_block_driver->get_spare_seq_field(spare->data());
            } else if (m_block_driver->flash_config() == gxbuild3::utils::FlashConfig::Corona4GB) {
                m_version = 1;
                Log::Info("load: no spare available on Corona eMMC, using version {}", m_version);
            } else {
                Log::Error("load: failed to read spare data");
                return false;
            }
        } else {
            m_version = m_corona_data->fs_version;
        }

        // Read block data
        const size_t lil_block_length = m_block_driver->lil_block_length();
        auto block_data = m_block_driver->read_lil_block(block_idx, lil_block_length);
        if (!block_data) {
            Log::Error("load: failed to read block data");
            return false;
        }

        // Calculate page count in a little block
        const size_t page_count = lil_block_length / 512;
        std::vector<uint32_t> blk_map_pages;
        std::vector<uint32_t> f_entry_pages;

        // Separate pages: even indices for blockmap, odd indices for file entries
        for (size_t i = 0; i < page_count; i++) {
            if (i % 2 == 0) {
                blk_map_pages.push_back(static_cast<uint32_t>(i));
            } else {
                f_entry_pages.push_back(static_cast<uint32_t>(i));
            }
        }

        // Load blockmap data
        const size_t blk_map_count = blk_map_pages.size();
        const size_t existing_blockmap_size = m_blockmap.size();
        std::vector<uint16_t> new_blockmap(existing_blockmap_size +
                                           (blk_map_count * kMaxBlocksPerPage));

        // Copy existing blockmap first (old data at the start)
        if (!m_blockmap.empty()) {
            std::memcpy(new_blockmap.data(), m_blockmap.data(),
                        existing_blockmap_size * sizeof(uint16_t));
        }

        Log::Info("load: loading blockmap...");

        // Append new blockmap pages after the existing data
        for (size_t i = 0; i < blk_map_count; i++) {
            const size_t page_idx = blk_map_pages[i];
            const uint8_t* bmap_data = block_data->data() + (page_idx * 0x200);

            for (size_t y = 0; y < kMaxBlocksPerPage; y++) {
                const size_t dest_idx =
                    y + ((i + existing_blockmap_size / kMaxBlocksPerPage) * kMaxBlocksPerPage);
                if (dest_idx >= new_blockmap.size()) {
                    break;
                }
                const uint16_t* src = reinterpret_cast<const uint16_t*>(bmap_data + (y * 2));
                // Byte swap from little endian to host endian
                new_blockmap[dest_idx] = bswap16(*src);
            }
        }

        m_blockmap = std::move(new_blockmap);

        // Load file entries
        const size_t fs_page_count = f_entry_pages.size();
        std::vector<FlashFileSystemEntry> new_entries;
        new_entries.reserve(m_entries.size() + (fs_page_count * kMaxEntriesPerPage));

        // Copy existing entries
        new_entries = m_entries;

        Log::Info("load: loading file entries...");

        for (size_t i = 0; i < fs_page_count; i++) {
            const size_t page_idx = f_entry_pages[i];
            const uint8_t* fs_data = block_data->data() + (page_idx * 0x200);

            for (size_t y = 0; y < kMaxEntriesPerPage; y++) {
                new_entries.emplace_back();

                const uint8_t* src = fs_data + (y * sizeof(FlashFileSystemEntry));
                FlashFileSystemEntry& entry = new_entries.back();

                // Copy raw data
                std::memcpy(&entry, src, sizeof(FlashFileSystemEntry));

                // Byte swap fields from little endian to host endian
                entry.length = bswap32(entry.length);
                entry.timestamp = bswap32(entry.timestamp);
                entry.block_number = bswap16(entry.block_number);
            }
        }

        m_entries = std::move(new_entries);

        // Validate and count only the newly loaded entries (existing ones were already validated).
        // first_new_idx is the number of entries that existed before this load() call;
        // new raw slots start immediately after.
        Log::Info("load: validating file entries...");
        size_t valid_new_entries = 0;
        const size_t first_new_idx = m_entries.size() - (fs_page_count * kMaxEntriesPerPage);

        for (size_t i = first_new_idx; i < m_entries.size(); i++) {
            if (!m_entries[i].is_valid()) {
                continue;
            }

            m_entries[first_new_idx + valid_new_entries] = m_entries[i];
            valid_new_entries++;
        }

        // Resize to keep only pre-existing valid entries plus the newly validated ones
        m_entries.resize(first_new_idx + valid_new_entries);

        // Check if this block is part of a chain
        if (block_idx < m_blockmap.size()) {
            const uint16_t bmap = m_blockmap[block_idx];
            if ((bmap & 0x7fff) < 0x1ffb) {
                // This block is part of a chain, load the next block
                return load(bmap);
            }
        }

        Log::Info("load: completed successfully, loaded {} entries", m_entries.size());
        return true;
    }

    bool FlashFileSystem::save(uint16_t block_idx) {
        if (!m_block_driver) {
            Log::Error("save: no block driver available");
            return false;
        }

        Log::Info("save: saving filesystem to block 0x{:x}...", block_idx);

        // Get the filesystem chain
        size_t chain_length = 0;
        auto fschain = get_chain_from_start(block_idx, chain_length);
        if (!fschain) {
            Log::Error("save: failed to get filesystem chain");
            return false;
        }

        const size_t lil_block_length = m_block_driver->lil_block_length();
        const size_t page_count = lil_block_length / 512;

        std::vector<uint32_t> blk_map_pages;
        std::vector<uint32_t> f_entry_pages;

        for (size_t i = 0; i < page_count; i++) {
            if (i % 2 == 0) {
                blk_map_pages.push_back(static_cast<uint32_t>(i));
            } else {
                f_entry_pages.push_back(static_cast<uint32_t>(i));
            }
        }

        auto spare = m_block_driver->read_lil_block_spare(block_idx);
        if (spare) {
            std::vector<uint8_t> spare_data = *spare;
            m_block_driver->set_spare_seq_field(spare_data.data(), m_version);
            m_block_driver->set_spare_block_type_field(spare_data.data(), 0x30);
            m_block_driver->write_lil_block_spare_all_pages(block_idx, spare_data.data());
        }

        // Process each block in the chain
        for (size_t y = 0; y < (*fschain).size(); y++) {
            const uint16_t current_block = (*fschain)[y];

            std::vector<uint8_t> blk_data(lil_block_length, 0);
            const size_t bl_num = blk_map_pages.size();
            const size_t fs_num = f_entry_pages.size();

            Log::Trace("save: writing blockmap...");

            // Write blockmap data
            for (size_t i = 0; i < bl_num; i++) {
                const size_t page_idx = blk_map_pages[i];
                uint8_t* bmap_data = blk_data.data() + (page_idx * 0x200);

                for (size_t z = 0; z < kMaxBlocksPerPage; z++) {
                    const size_t blockmap_idx = z + (i * kMaxBlocksPerPage) + (y * 0x1000);
                    if (blockmap_idx >= m_blockmap.size()) {
                        break;
                    }

                    // Byte swap to little endian
                    uint16_t swapped = bswap16(m_blockmap[blockmap_idx]);
                    std::memcpy(bmap_data + (z * 2), &swapped, sizeof(uint16_t));
                }
            }

            Log::Trace("save: writing file entries...");

            // Write file entries data
            for (size_t i = 0; i < fs_num; i++) {
                const size_t page_idx = f_entry_pages[i];
                uint8_t* fs_data = blk_data.data() + (page_idx * 0x200);

                for (size_t z = 0; z < kMaxEntriesPerPage; z++) {
                    const size_t entry_idx = (y * 0x100) + (i * kMaxEntriesPerPage) + z;
                    if (entry_idx >= m_entries.size()) {
                        break;
                    }

                    // Make a copy for byte swapping
                    FlashFileSystemEntry entry = m_entries[entry_idx];

                    // Byte swap to little endian
                    entry.length = bswap32(entry.length);
                    entry.timestamp = bswap32(entry.timestamp);
                    entry.block_number = bswap16(entry.block_number);

                    std::memcpy(fs_data + (z * sizeof(FlashFileSystemEntry)), &entry,
                                sizeof(FlashFileSystemEntry));
                }
            }

            // Write the block
            if (!m_block_driver->write_lil_block(current_block, blk_data.data(),
                                                 lil_block_length)) {
                Log::Error("save: failed to write block {}", current_block);
                return false;
            }
        }

        Log::Info("save: filesystem saved successfully");
        return true;
    }

    // Internal helpers

    FlashFileSystemEntry* FlashFileSystem::find_entry_internal(std::string_view filename) {
        std::string_view clean_filename = filename;
        auto pos = clean_filename.find_last_of("/\\");
        if (pos != std::string_view::npos) {
            clean_filename = clean_filename.substr(pos + 1);
        }
        for (auto& entry : m_entries) {
            if (entry.filename_matches(clean_filename)) {
                return &entry;
            }
        }
        return nullptr;
    }

    const FlashFileSystemEntry*
    FlashFileSystem::find_entry_internal(std::string_view filename) const {
        std::string_view clean_filename = filename;
        auto pos = clean_filename.find_last_of("/\\");
        if (pos != std::string_view::npos) {
            clean_filename = clean_filename.substr(pos + 1);
        }
        for (const auto& entry : m_entries) {
            if (entry.filename_matches(clean_filename)) {
                return &entry;
            }
        }
        return nullptr;
    }

} // namespace gxbuild3::bootloaders
