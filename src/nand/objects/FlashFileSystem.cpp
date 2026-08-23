#include "nand/objects/FlashFileSystem.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_set>

namespace gxbuild3::NAND {

    void FlashFileSystem::set_driver(Driver* driver) {
        m_driver = driver;
    }

    bool FlashFileSystemEntry::is_valid() const noexcept {
        if (block_number == 0 || block_number == 0xFFFF) {
            return false;
        }
        if (length == 0 || length == 0xFFFFFFFF) {
            return false;
        }
        const uint8_t first = static_cast<uint8_t>(filename[0]);
        if (first == '\0' || first == 0xFF || first == 0x05) {
            return false;
        }
        for (size_t i = 0; i < kMaxFilenameLength && filename[i] != '\0'; ++i) {
            const uint8_t c = static_cast<uint8_t>(filename[i]);
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
        }
        return true;
    }

    bool FlashFileSystemEntry::matches(std::string_view name) const noexcept {
        std::string_view self{filename};
        if (self.size() != name.size()) {
            return false;
        }
        for (size_t i = 0; i < self.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(self[i])) !=
                std::tolower(static_cast<unsigned char>(name[i]))) {
                return false;
            }
        }
        return true;
    }

    bool FlashFileSystem::format(size_t total_blocks, uint16_t root_block, uint32_t version,
                                 uint32_t reserved_boundary) {
        if (total_blocks == 0 || root_block >= total_blocks) {
            Log::Error("Invalid parameters for FlashFS format: total_blocks={}, root_block={}",
                       total_blocks, root_block);
            return false;
        }

        m_version = version;
        m_root_block = root_block;
        m_entries.clear();
        m_file_data.clear();
        m_blockmap.assign(total_blocks, BlockMapStatus::Free);

        Log::Debug("Formatted Flash File System: total_blocks={}, root_block={}, version={}",
                   total_blocks, root_block, version);

        const size_t bound = std::min(total_blocks, static_cast<size_t>(reserved_boundary));
        for (size_t i = 0; i < bound; ++i) {
            m_blockmap[i] = BlockMapStatus::Reserved;
        }

        m_blockmap[root_block] = BlockMapStatus::EndOfChain;
        return true;
    }

    bool FlashFileSystem::set_root_block(uint16_t root_block) {
        if (root_block >= m_blockmap.size()) {
            return false;
        }
        if (root_block == m_root_block) {
            return true;
        }
        if (m_blockmap[root_block] != BlockMapStatus::Free) {
            return false;
        }

        if (m_root_block < m_blockmap.size() &&
            m_blockmap[m_root_block] == BlockMapStatus::EndOfChain) {
            m_blockmap[m_root_block] = BlockMapStatus::Free;
        }
        m_root_block = root_block;
        m_blockmap[m_root_block] = BlockMapStatus::EndOfChain;
        return true;
    }

    bool FlashFileSystem::reserve_blocks(size_t start_block, size_t block_count) {
        if (block_count == 0 || start_block >= m_blockmap.size() ||
            block_count > m_blockmap.size() - start_block) {
            return false;
        }

        for (size_t block = start_block; block < start_block + block_count; ++block) {
            if (m_blockmap[block] != BlockMapStatus::Free &&
                m_blockmap[block] != BlockMapStatus::Reserved) {
                return false;
            }
        }
        for (size_t block = start_block; block < start_block + block_count; ++block) {
            m_blockmap[block] = BlockMapStatus::Reserved;
        }
        return true;
    }

    std::vector<uint16_t> FlashFileSystem::get_chain(uint16_t start_block) const {
        std::vector<uint16_t> chain;
        std::unordered_set<uint16_t> visited;
        uint16_t current = start_block & 0x7FFF;

        while (current < (BlockMapStatus::Reserved & 0x7FFF) && current < m_blockmap.size() &&
               visited.insert(current).second) {
            chain.push_back(current);
            uint16_t next = m_blockmap[current] & 0x7FFF;
            if (next >= (BlockMapStatus::Reserved & 0x7FFF)) {
                break;
            }
            current = next;
        }

        return chain;
    }

    std::vector<uint16_t> FlashFileSystem::get_all_file_blocks() const {
        std::vector<uint16_t> blocks;
        for (const auto& entry : m_entries) {
            if (!entry.is_valid()) {
                continue;
            }
            auto chain = get_chain(entry.block_number);
            blocks.insert(blocks.end(), chain.begin(), chain.end());
        }
        return blocks;
    }

    std::optional<uint16_t> FlashFileSystem::allocate_chain(size_t bytes_needed) {
        size_t blocks_needed = (bytes_needed + kCleanBlockSize - 1) / kCleanBlockSize;
        if (blocks_needed == 0) {
            blocks_needed = 1;
        }

        std::vector<uint16_t> allocated;
        allocated.reserve(blocks_needed);

        for (size_t i = 0; i < m_blockmap.size() && allocated.size() < blocks_needed; ++i) {
            if ((m_blockmap[i] & 0x7FFF) == BlockMapStatus::Free || m_blockmap[i] == BlockMapStatus::Free) {
                allocated.push_back(static_cast<uint16_t>(i));
            }
        }

        if (allocated.size() < blocks_needed) {
            Log::Error("FlashFS out of space: needed {} blocks, only {} free blocks available (out of {} total blocks)",
                       blocks_needed, allocated.size(), m_blockmap.size());
            return std::nullopt;
        }

        for (size_t i = 0; i < allocated.size(); ++i) {
            if (i + 1 < allocated.size()) {
                m_blockmap[allocated[i]] = allocated[i + 1];
            } else {
                m_blockmap[allocated[i]] = BlockMapStatus::EndOfChain;
            }
        }

        return allocated.front();
    }

    void FlashFileSystem::free_chain(uint16_t start_block) {
        auto chain = get_chain(start_block);
        for (uint16_t blk : chain) {
            if (blk < m_blockmap.size()) {
                m_blockmap[blk] = BlockMapStatus::Free;
            }
        }
    }

    bool FlashFileSystem::add_file(std::string_view filename, std::span<const uint8_t> data,
                                   uint32_t timestamp) {
        std::string_view clean_name = filename;
        auto pos = clean_name.find_last_of("/\\");
        if (pos != std::string_view::npos) {
            clean_name = clean_name.substr(pos + 1);
        }

        if (clean_name.empty() || clean_name.size() >= kMaxFilenameLength) {
            Log::Error("Invalid filename '{}' for FlashFS (length must be 1-{} chars)",
                       clean_name, kMaxFilenameLength - 1);
            return false;
        }

        if (exists(clean_name)) {
            delete_file(clean_name);
        }

        auto chain_start = allocate_chain(data.size());
        if (!chain_start) {
            Log::Error("FlashFS out of space: failed to allocate blocks for '{}' ({} bytes)",
                       clean_name, data.size());
            return false;
        }

        FlashFileSystemEntry entry{};
        std::memcpy(entry.filename, clean_name.data(), clean_name.size());
        entry.filename[clean_name.size()] = '\0';
        entry.block_number = *chain_start;
        entry.length = static_cast<uint32_t>(data.size());
        entry.timestamp = timestamp;

        m_entries.push_back(entry);
        m_file_data[std::string(clean_name)] = std::vector<uint8_t>(data.begin(), data.end());
        return true;
    }

    std::optional<std::vector<uint8_t>> FlashFileSystem::get_file(
        std::string_view filename) const {
        std::string_view clean_name = filename;
        auto pos = clean_name.find_last_of("/\\");
        if (pos != std::string_view::npos) {
            clean_name = clean_name.substr(pos + 1);
        }

        auto it = m_file_data.find(std::string(clean_name));
        if (it != m_file_data.end()) {
            return it->second;
        }

        const auto* entry = find_entry(clean_name);
        if (!entry) {
            return std::nullopt;
        }

        auto chain = get_chain(entry->block_number);
        if (chain.empty()) {
            return std::nullopt;
        }

        if (!m_driver) {
            return std::nullopt;
        }

        std::vector<uint8_t> data;
        data.reserve(entry->length);

        for (uint16_t blk : chain) {
            if (data.size() >= entry->length) {
                break;
            }
            auto blk_data = m_driver->read_block(blk);
            size_t to_copy = std::min<size_t>(entry->length - data.size(), blk_data.size());
            data.insert(data.end(), blk_data.begin(), blk_data.begin() + to_copy);
        }

        return data;
    }

    bool FlashFileSystem::delete_file(std::string_view filename) {
        std::string_view clean_name = filename;
        auto pos = clean_name.find_last_of("/\\");
        if (pos != std::string_view::npos) {
            clean_name = clean_name.substr(pos + 1);
        }

        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            if (it->matches(clean_name)) {
                free_chain(it->block_number);
                m_file_data.erase(std::string(clean_name));
                m_entries.erase(it);
                return true;
            }
        }
        return false;
    }

    bool FlashFileSystem::exists(std::string_view filename) const {
        return find_entry(filename) != nullptr;
    }

    std::vector<std::string> FlashFileSystem::list_files() const {
        std::vector<std::string> result;
        result.reserve(m_entries.size());
        for (const auto& entry : m_entries) {
            if (entry.is_valid()) {
                result.emplace_back(entry.filename);
            }
        }
        return result;
    }

    std::optional<FlashFileSystemEntry> FlashFileSystem::stat(std::string_view filename) const {
        const auto* entry = find_entry(filename);
        if (!entry) {
            return std::nullopt;
        }
        return *entry;
    }

    std::vector<uint8_t> FlashFileSystem::serialize_root_block() const {
        std::vector<uint8_t> root_block(kCleanBlockSize, 0);

        size_t bm_written = 0;
        for (size_t page = 0; page < 32 && bm_written < m_blockmap.size(); page += 2) {
            uint8_t* page_ptr = root_block.data() + (page * 512);
            for (size_t entry = 0; entry < kBlocksPerPage && bm_written < m_blockmap.size();
                 ++entry) {
                uint16_t val = bswap16(m_blockmap[bm_written++]);
                std::memcpy(page_ptr + (entry * sizeof(uint16_t)), &val, sizeof(uint16_t));
            }
        }

        size_t entry_written = 0;
        for (size_t page = 1; page < 32 && entry_written < m_entries.size(); page += 2) {
            uint8_t* page_ptr = root_block.data() + (page * 512);
            for (size_t slot = 0; slot < kEntriesPerPage && entry_written < m_entries.size();
                 ++slot) {
                FlashFileSystemEntry raw = m_entries[entry_written++];
                raw.block_number = bswap16(raw.block_number);
                raw.length = bswap32(raw.length);
                raw.timestamp = bswap32(raw.timestamp);
                std::memcpy(page_ptr + (slot * sizeof(FlashFileSystemEntry)), &raw,
                            sizeof(FlashFileSystemEntry));
            }
        }

        return root_block;
    }

    bool FlashFileSystem::save() {
        if (!m_driver) {
            return false;
        }

        auto root_data = serialize_root_block();
        if (!m_driver->write_block(m_root_block, root_data)) {
            return false;
        }

        BlockMetadata root_meta{};
        root_meta.logical_block_id = m_root_block;
        root_meta.sequence = m_version;
        root_meta.block_type = 0x30;
        root_meta.page_count = 0;
        root_meta.is_bad = false;
        m_driver->write_block_metadata(m_root_block, root_meta);

        for (const auto& entry : m_entries) {
            if (!entry.is_valid()) {
                continue;
            }

            auto it = m_file_data.find(std::string(entry.filename));
            if (it == m_file_data.end()) {
                continue;
            }

            const auto& file_bytes = it->second;
            auto chain = get_chain(entry.block_number);
            size_t bytes_written = 0;

            for (uint16_t blk : chain) {
                if (bytes_written >= file_bytes.size()) {
                    break;
                }

                size_t chunk_len =
                    std::min<size_t>(file_bytes.size() - bytes_written, kCleanBlockSize);
                std::span<const uint8_t> chunk(file_bytes.data() + bytes_written, chunk_len);
                if (!m_driver->write_block(blk, chunk)) {
                    return false;
                }

                // Metadata already written by allocate_block(); update page_count only
                BlockMetadata file_meta{};
                file_meta.logical_block_id = blk;
                file_meta.sequence = m_version;
                file_meta.block_type = 0x01;
                file_meta.page_count = static_cast<uint8_t>((chunk_len + 511) / 512);
                file_meta.is_bad = false;
                m_driver->write_block_metadata(blk, file_meta);

                bytes_written += chunk_len;
            }
        }

        return true;
    }

    bool FlashFileSystem::load(Driver& driver, uint16_t root_block) {
        m_driver = &driver;
        m_root_block = root_block;
        auto root_meta = driver.interpret_block(root_block);
        m_version = root_meta.sequence;

        auto root_data = driver.read_block(root_block);
        if (root_data.size() < kCleanBlockSize) {
            return false;
        }

        m_blockmap.assign(driver.block_count(), BlockMapStatus::Free);
        size_t bm_read = 0;

        for (size_t page = 0; page < 32 && bm_read < m_blockmap.size(); page += 2) {
            const uint8_t* page_ptr = root_data.data() + (page * 512);
            for (size_t entry = 0; entry < kBlocksPerPage && bm_read < m_blockmap.size();
                 ++entry) {
                uint16_t val = 0;
                std::memcpy(&val, page_ptr + (entry * sizeof(uint16_t)), sizeof(uint16_t));
                m_blockmap[bm_read++] = bswap16(val);
            }
        }

        m_entries.clear();
        m_file_data.clear();

        for (size_t page = 1; page < 32; page += 2) {
            const uint8_t* page_ptr = root_data.data() + (page * 512);
            for (size_t slot = 0; slot < kEntriesPerPage; ++slot) {
                FlashFileSystemEntry raw{};
                std::memcpy(&raw, page_ptr + (slot * sizeof(FlashFileSystemEntry)),
                            sizeof(FlashFileSystemEntry));
                raw.block_number = bswap16(raw.block_number);
                raw.length = bswap32(raw.length);
                raw.timestamp = bswap32(raw.timestamp);

                if (raw.is_valid()) {
                    m_entries.push_back(raw);
                }
            }
        }

        for (const auto& entry : m_entries) {
            auto chain = get_chain(entry.block_number);
            std::vector<uint8_t> file_bytes;
            file_bytes.reserve(entry.length);

            for (uint16_t blk : chain) {
                if (file_bytes.size() >= entry.length) {
                    break;
                }
                auto blk_data = driver.read_block(blk);
                size_t to_copy = std::min<size_t>(entry.length - file_bytes.size(), blk_data.size());
                file_bytes.insert(file_bytes.end(), blk_data.begin(), blk_data.begin() + to_copy);
            }

            m_file_data[std::string(entry.filename)] = std::move(file_bytes);
        }

        return true;
    }

    const std::vector<uint16_t>& FlashFileSystem::blockmap() const {
        return m_blockmap;
    }

    const std::vector<FlashFileSystemEntry>& FlashFileSystem::entries() const {
        return m_entries;
    }

    uint32_t FlashFileSystem::version() const {
        return m_version;
    }

    uint16_t FlashFileSystem::root_block() const {
        return m_root_block;
    }

    FlashFileSystemEntry* FlashFileSystem::find_entry(std::string_view filename) {
        for (auto& entry : m_entries) {
            if (entry.matches(filename)) {
                return &entry;
            }
        }
        return nullptr;
    }

    const FlashFileSystemEntry* FlashFileSystem::find_entry(std::string_view filename) const {
        for (const auto& entry : m_entries) {
            if (entry.matches(filename)) {
                return &entry;
            }
        }
        return nullptr;
    }

} // namespace gxbuild3::NAND
