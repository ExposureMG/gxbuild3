#include "nand/objects/FlashFileSystem.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <unordered_set>

namespace gxbuild3::nand {

    namespace {
        // An on-disk name fills all kMaxFilenameLength bytes when it has no terminator.
        std::string_view entry_name(const FlashFileSystemEntry& entry) {
            const char* end = std::find(entry.filename, entry.filename + kMaxFilenameLength, '\0');
            return {entry.filename, static_cast<size_t>(end - entry.filename)};
        }

        // The name a path names: what follows its last '/' or '\\'.
        std::string_view clean_name(std::string_view filename) {
            if (const auto pos = filename.find_last_of("/\\"); pos != std::string_view::npos) {
                return filename.substr(pos + 1);
            }
            return filename;
        }

        constexpr size_t kMapLinks = kRootDirectoryPages * kBlocksPerPage;
        constexpr size_t kPagesPerCluster = kCleanBlockSize / 512;

        // Link `index` of the block map, counted from the filesystem's base cluster.
        wire::be16& map_link(flashfs_root_cluster& root, size_t index) {
            return root.pairs[index / kBlocksPerPage].map.links[index % kBlocksPerPage];
        }

        const wire::be16& map_link(const flashfs_root_cluster& root, size_t index) {
            return root.pairs[index / kBlocksPerPage].map.links[index % kBlocksPerPage];
        }

        flashfs_disk_entry& dir_slot(flashfs_root_cluster& root, size_t index) {
            return root.pairs[index / kEntriesPerPage].dir.entries[index % kEntriesPerPage];
        }

        const flashfs_disk_entry& dir_slot(const flashfs_root_cluster& root, size_t index) {
            return root.pairs[index / kEntriesPerPage].dir.entries[index % kEntriesPerPage];
        }

        // States every cluster from `base` on, rebased to it; a withheld cluster states what
        // `stated` names for it.
        Result<void> encode_block_map(const std::vector<uint16_t>& blockmap,
                                      const std::map<size_t, uint16_t>& stated, size_t base,
                                      flashfs_root_cluster& root) {
            for (size_t index = 0; index < kMapLinks && base + index < blockmap.size(); ++index) {
                const size_t cluster = base + index;
                uint16_t val = blockmap[cluster];
                if (const auto withheld = stated.find(cluster); withheld != stated.end()) {
                    val = withheld->second;
                } else if ((val & 0x7FFF) < BlockMapStatus::BadBlock) {
                    if ((val & 0x7FFF) < base) {
                        return fail(ErrorCode::Malformed,
                                    "FlashFS cluster 0x{:X} links below the filesystem base 0x{:X}",
                                    cluster, base);
                    }
                    val = static_cast<uint16_t>((val & 0x8000) | ((val & 0x7FFF) - base));
                }
                map_link(root, index) = val;
            }
            return {};
        }

        Result<void> encode_directory(const std::vector<FlashFileSystemEntry>& entries, size_t base,
                                      flashfs_root_cluster& root) {
            for (size_t index = 0; index < entries.size() && index < kMaxDirectoryEntries;
                 ++index) {
                const FlashFileSystemEntry& entry = entries[index];
                if (entry.block_number < base) {
                    return fail(ErrorCode::Malformed,
                                "FlashFS file '{}' starts below the filesystem base 0x{:X}",
                                entry_name(entry), base);
                }
                flashfs_disk_entry& disk = dir_slot(root, index);
                std::ranges::copy(entry.filename, disk.filename);
                disk.block_number = static_cast<uint16_t>(entry.block_number - base);
                disk.length = entry.length;
                disk.timestamp = entry.timestamp;
            }
            return {};
        }

        // Fills `blockmap` from `base` on, rebasing every link; the clusters before `base` and
        // past the root's map keep what they hold.
        Result<void> decode_block_map(const flashfs_root_cluster& root, size_t base,
                                      std::vector<uint16_t>& blockmap) {
            for (size_t index = 0; index < kMapLinks && base + index < blockmap.size(); ++index) {
                const size_t cluster = base + index;
                uint16_t val = map_link(root, index);
                if ((val & 0x7FFF) < BlockMapStatus::BadBlock) {
                    if ((val & 0x7FFF) + base >= blockmap.size()) {
                        return fail(ErrorCode::Malformed,
                                    "FlashFS cluster 0x{:X} links past the map to 0x{:X}", cluster,
                                    (val & 0x7FFF) + base);
                    }
                    val = static_cast<uint16_t>((val & 0x8000) | ((val & 0x7FFF) + base));
                }
                blockmap[cluster] = val;
            }
            return {};
        }

        // Appends every valid entry, rebased to physical clusters; an unused slot (block 0xFFFF)
        // is skipped before rebasing.
        Result<void> decode_directory(const flashfs_root_cluster& root, size_t base,
                                      size_t map_size, std::vector<FlashFileSystemEntry>& entries) {
            for (size_t index = 0; index < kMaxDirectoryEntries; ++index) {
                const flashfs_disk_entry& disk = dir_slot(root, index);
                const uint16_t relative_block = disk.block_number;
                if (relative_block == 0xFFFF) {
                    continue;
                }
                const size_t physical_cluster = relative_block + base;
                FlashFileSystemEntry entry{};
                std::ranges::copy(disk.filename, entry.filename);
                entry.block_number = static_cast<uint16_t>(physical_cluster);
                entry.length = disk.length;
                entry.timestamp = disk.timestamp;

                if (entry.is_valid()) {
                    if (physical_cluster >= map_size) {
                        return fail(ErrorCode::Malformed,
                                    "FlashFS file '{}' starts past the map at 0x{:X}",
                                    entry_name(entry), physical_cluster);
                    }
                    entries.push_back(entry);
                }
            }
            return {};
        }
    } // namespace

    void FlashFileSystem::set_driver(Driver* driver) {
        m_driver = driver;
    }

    size_t FlashFileSystem::clusters_per_block() const {
        return m_driver ? m_driver->block_size_clean() / kCleanBlockSize : 1;
    }

    size_t FlashFileSystem::base_cluster() const {
        if (!m_driver || m_driver->driver_mode() != Driver::DriverMode::Big) {
            return 0;
        }
        return m_larger ? 0x2E0 : 0xAE0;
    }

    bool FlashFileSystem::is_block_free(size_t physical_block) const {
        const size_t ratio = clusters_per_block();
        if (physical_block >= m_blockmap.size() / ratio) {
            return false;
        }
        const auto first = m_blockmap.begin() + physical_block * ratio;
        return std::all_of(first, first + ratio,
                           [](uint16_t value) { return value == BlockMapStatus::Free; });
    }

    bool FlashFileSystemEntry::is_valid() const noexcept {
        if (block_number == 0 || block_number == 0xFFFF) {
            return false;
        }
        if (length == 0xFFFFFFFF) {
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

    Result<void> FlashFileSystem::format(size_t total_blocks, uint16_t root_block, uint32_t version,
                                         uint32_t reserved_boundary) {
        const bool defer_root = (root_block == kDeferRoot);
        const size_t ratio = clusters_per_block();
        constexpr size_t map_capacity = kRootDirectoryPages * kBlocksPerPage;
        if (total_blocks == 0 || total_blocks > map_capacity / ratio ||
            (!defer_root && (root_block >= total_blocks || root_block * ratio < base_cluster()))) {
            return fail(ErrorCode::InvalidArgument,
                        "invalid FlashFS format parameters: total_blocks={}, root_block=0x{:X}",
                        total_blocks, root_block);
        }

        m_version = version;
        m_root_cluster_offset = 0;
        m_root_reserved_clusters = ratio;
        m_entries.clear();
        m_file_data.clear();
        m_stated.clear();
        m_blockmap.assign(total_blocks * ratio, BlockMapStatus::Free);

        const size_t bound = std::max(
            base_cluster(), std::min(total_blocks, static_cast<size_t>(reserved_boundary)) * ratio);
        for (size_t i = 0; i < bound; ++i) {
            m_blockmap[i] = BlockMapStatus::Reserved;
        }

        if (defer_root) {
            // serialize allocates the root once, last, from the same free pool the files
            // and mobile data draw from, so no block is pre-consumed for it here
            m_root_placed = false;
            Log::Debug("Formatted Flash File System: total_blocks={}, root_block=deferred, "
                       "version={}",
                       total_blocks, version);
        } else {
            place_root(root_block);
            Log::Debug("Formatted Flash File System: total_blocks={}, root_block={}, version={}",
                       total_blocks, root_block, version);
        }
        return {};
    }

    // The root takes the first cluster of its erase block, which the table states as itself;
    // the rest of that block is kept from allocation and stated free, as xeBuild states it.
    void FlashFileSystem::place_root(uint16_t root_block) {
        const size_t ratio = clusters_per_block();
        const size_t first = static_cast<size_t>(root_block) * ratio;
        m_root_block = root_block;
        m_root_cluster_offset = 0;
        m_root_reserved_clusters = ratio;
        m_blockmap[first] = BlockMapStatus::Table;
        for (size_t cluster = first + 1; cluster < first + ratio; ++cluster) {
            m_blockmap[cluster] = BlockMapStatus::Reserved;
            m_stated[cluster] = BlockMapStatus::Free;
        }
        m_root_placed = true;
    }

    void FlashFileSystem::release_root() {
        if (!m_root_placed) {
            return;
        }
        const size_t first =
            static_cast<size_t>(m_root_block) * clusters_per_block() + m_root_cluster_offset;
        for (size_t cluster = first;
             cluster < first + m_root_reserved_clusters && cluster < m_blockmap.size(); ++cluster) {
            m_blockmap[cluster] = BlockMapStatus::Free;
            m_stated.erase(cluster);
        }
        m_root_placed = false;
    }

    Result<void> FlashFileSystem::set_root_block(uint16_t root_block) {
        const size_t ratio = clusters_per_block();
        if (root_block >= m_blockmap.size() / ratio || root_block * ratio < base_cluster()) {
            return fail(ErrorCode::OutOfRange,
                        "FlashFS root block 0x{:X} is outside the filesystem", root_block);
        }
        if (m_root_placed && root_block == m_root_block) {
            return {};
        }
        if (!is_block_free(root_block)) {
            return fail(ErrorCode::InvalidArgument, "FlashFS root block 0x{:X} is not free",
                        root_block);
        }

        release_root();
        place_root(root_block);
        return {};
    }

    Result<void> FlashFileSystem::reserve_blocks(size_t start_block, size_t block_count) {
        const size_t ratio = clusters_per_block();
        const size_t physical_blocks = m_blockmap.size() / ratio;
        if (block_count == 0 || start_block >= physical_blocks ||
            block_count > physical_blocks - start_block) {
            return fail(ErrorCode::OutOfRange, "cannot reserve {} FlashFS blocks from 0x{:X} of {}",
                        block_count, start_block, physical_blocks);
        }

        start_block *= ratio;
        block_count *= ratio;

        for (size_t block = start_block; block < start_block + block_count; ++block) {
            if (m_blockmap[block] != BlockMapStatus::Free &&
                m_blockmap[block] != BlockMapStatus::Reserved) {
                return fail(ErrorCode::InvalidArgument,
                            "FlashFS cluster 0x{:X} is in use and cannot be reserved", block);
            }
        }
        for (size_t block = start_block; block < start_block + block_count; ++block) {
            m_blockmap[block] = BlockMapStatus::Reserved;
            m_stated.erase(block);
        }
        return {};
    }

    Result<void> FlashFileSystem::withhold_clusters(size_t first_cluster, size_t cluster_count,
                                                    uint16_t stated) {
        if (cluster_count == 0 || first_cluster >= m_blockmap.size() ||
            cluster_count > m_blockmap.size() - first_cluster) {
            return fail(ErrorCode::OutOfRange,
                        "cannot withhold {} FlashFS clusters from 0x{:X} of {}", cluster_count,
                        first_cluster, m_blockmap.size());
        }
        for (size_t cluster = first_cluster; cluster < first_cluster + cluster_count; ++cluster) {
            if (m_blockmap[cluster] != BlockMapStatus::Free &&
                !(m_blockmap[cluster] == BlockMapStatus::Reserved && m_stated.contains(cluster))) {
                return fail(ErrorCode::InvalidArgument,
                            "FlashFS cluster 0x{:X} is in use and cannot be withheld", cluster);
            }
        }
        for (size_t cluster = first_cluster; cluster < first_cluster + cluster_count; ++cluster) {
            m_blockmap[cluster] = BlockMapStatus::Reserved;
            m_stated[cluster] = stated;
        }
        return {};
    }

    Result<void> FlashFileSystem::withhold_blocks(size_t start_block, size_t block_count,
                                                  uint16_t stated) {
        const size_t ratio = clusters_per_block();
        if (block_count == 0 || start_block >= m_blockmap.size() / ratio ||
            block_count > m_blockmap.size() / ratio - start_block) {
            return fail(ErrorCode::OutOfRange,
                        "cannot withhold {} FlashFS blocks from 0x{:X} of {}", block_count,
                        start_block, m_blockmap.size() / ratio);
        }
        return withhold_clusters(start_block * ratio, block_count * ratio, stated);
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

    std::optional<size_t> FlashFileSystem::checked_block_count(size_t bytes_needed,
                                                               size_t clean_block_size) {
        if (clean_block_size == 0) {
            return std::nullopt;
        }
        if (bytes_needed == 0) {
            return 1;
        }
        return bytes_needed / clean_block_size + (bytes_needed % clean_block_size != 0);
    }

    std::optional<uint16_t> FlashFileSystem::allocate_chain(size_t bytes_needed) {
        const auto blocks_needed = checked_block_count(bytes_needed, kCleanBlockSize);
        if (!blocks_needed) {
            return std::nullopt;
        }
        const size_t block_count = *blocks_needed;
        if (block_count > m_blockmap.size()) {
            return std::nullopt;
        }

        std::vector<uint16_t> allocated;
        allocated.reserve(block_count);

        for (size_t i = 0; i < m_blockmap.size() && allocated.size() < block_count; ++i) {
            if ((m_blockmap[i] & 0x7FFF) == BlockMapStatus::Free ||
                m_blockmap[i] == BlockMapStatus::Free) {
                allocated.push_back(static_cast<uint16_t>(i));
            }
        }

        if (allocated.size() < block_count) {
            Log::Debug("FlashFS out of space: needed {} clusters, only {} of {} are free",
                       block_count, allocated.size(), m_blockmap.size());
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

    Result<void> FlashFileSystem::add_file(std::string_view filename, std::span<const uint8_t> data,
                                           std::optional<uint32_t> timestamp) {
        const std::string_view name = clean_name(filename);
        if (name.empty() || name.size() >= kMaxFilenameLength) {
            return fail(ErrorCode::InvalidArgument,
                        "invalid FlashFS filename '{}' (length must be 1-{} chars)", name,
                        kMaxFilenameLength - 1);
        }

        const bool replacing_existing_file = exists(name);
        if (!replacing_existing_file && m_entries.size() >= kMaxDirectoryEntries) {
            return fail(ErrorCode::Exhausted, "FlashFS directory is full (maximum {} entries)",
                        kMaxDirectoryEntries);
        }

        if (replacing_existing_file) {
            if (auto deleted = delete_file(name); !deleted) {
                return deleted;
            }
        }

        auto chain_start = allocate_chain(data.size());
        if (!chain_start) {
            return fail(ErrorCode::Exhausted, "FlashFS out of space for '{}' ({} bytes)", name,
                        data.size());
        }

        FlashFileSystemEntry entry{};
        std::ranges::copy(name, entry.filename);
        entry.filename[name.size()] = '\0';
        entry.block_number = *chain_start;
        entry.length = static_cast<uint32_t>(data.size());
        entry.timestamp = timestamp.value_or(m_timestamp);

        m_entries.push_back(entry);
        m_file_data[std::string(name)] = std::vector<uint8_t>(data.begin(), data.end());
        return {};
    }

    Result<void> FlashFileSystem::insert_file(size_t position, std::string_view filename,
                                              std::span<const uint8_t> data,
                                              std::optional<uint32_t> timestamp) {
        const std::string_view inserted_name = clean_name(filename);
        // The data may be a view of the file being replaced, which deleting it frees.
        const std::vector<uint8_t> inserted(data.begin(), data.end());
        for (size_t index = 0; index < m_entries.size(); ++index) {
            if (m_entries[index].matches(inserted_name)) {
                if (index < position) {
                    --position;
                }
                if (auto deleted = delete_file(inserted_name); !deleted) {
                    return deleted;
                }
                break;
            }
        }
        position = std::min(position, m_entries.size());

        struct Moved {
            std::string name;
            std::vector<uint8_t> data;
            uint32_t timestamp;
        };
        std::vector<Moved> moved;
        for (auto it = m_entries.begin() + static_cast<std::ptrdiff_t>(position);
             it != m_entries.end(); ++it) {
            free_chain(it->block_number);
            const std::string name{it->filename};
            auto data_it = m_file_data.find(name);
            if (data_it == m_file_data.end()) {
                return fail(ErrorCode::Internal, "FlashFS file '{}' has no data to lay again",
                            name);
            }
            moved.push_back({name, std::move(data_it->second), it->timestamp});
            m_file_data.erase(data_it);
        }
        m_entries.erase(m_entries.begin() + static_cast<std::ptrdiff_t>(position), m_entries.end());

        if (auto added = add_file(inserted_name, inserted, timestamp); !added) {
            return added;
        }
        for (const auto& file : moved) {
            if (auto added = add_file(file.name, file.data, file.timestamp); !added) {
                return with_context(std::move(added), std::format("laying '{}' again", file.name));
            }
        }
        return {};
    }

    std::optional<std::vector<uint8_t>> FlashFileSystem::get_file(std::string_view filename) const {
        const std::string_view name = clean_name(filename);
        auto it = m_file_data.find(std::string(name));
        if (it != m_file_data.end()) {
            return it->second;
        }

        const auto* entry = find_entry(name);
        if (!entry) {
            return std::nullopt;
        }

        if (get_chain(entry->block_number).empty() || !m_driver) {
            return std::nullopt;
        }

        auto data = read_chain(*m_driver, *entry);
        if (data.size() != entry->length) {
            return std::nullopt;
        }
        return data;
    }

    std::vector<uint8_t> FlashFileSystem::read_chain(const Driver& driver,
                                                     const FlashFileSystemEntry& entry) const {
        std::vector<uint8_t> data;
        data.reserve(entry.length);

        for (uint16_t blk : get_chain(entry.block_number)) {
            if (data.size() >= entry.length) {
                break;
            }
            auto blk_data =
                driver.read_clean(static_cast<size_t>(blk) * kCleanBlockSize, kCleanBlockSize);
            size_t to_copy = std::min<size_t>(entry.length - data.size(), blk_data.size());
            data.insert(data.end(), blk_data.begin(), blk_data.begin() + to_copy);
        }
        return data;
    }

    Result<void> FlashFileSystem::delete_file(std::string_view filename) {
        const std::string_view name = clean_name(filename);
        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            if (it->matches(name)) {
                free_chain(it->block_number);
                m_file_data.erase(std::string(name));
                m_entries.erase(it);
                return {};
            }
        }
        return fail(ErrorCode::NotFound, "FlashFS has no file '{}'", name);
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

    Result<std::vector<uint8_t>> FlashFileSystem::serialize_root_block() const {
        if (!m_root_placed) {
            return fail(ErrorCode::InvalidArgument, "FlashFS root block is not placed");
        }
        if (m_entries.size() > kMaxDirectoryEntries) {
            return fail(ErrorCode::OutOfRange, "FlashFS directory holds {} entries; at most {} fit",
                        m_entries.size(), kMaxDirectoryEntries);
        }
        // The map is encoded before the directory, so its errors take precedence.
        flashfs_root_cluster root{};
        if (auto encoded = encode_block_map(m_blockmap, m_stated, base_cluster(), root); !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        if (auto encoded = encode_directory(m_entries, base_cluster(), root); !encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        const auto image = wire::bytes_of(root);
        return std::vector<uint8_t>(image.begin(), image.end());
    }

    Result<size_t> FlashFileSystem::write_root_cluster() {
        auto root_data = serialize_root_block();
        if (!root_data) {
            return std::unexpected(std::move(root_data.error()).add_context("saving FlashFS"));
        }
        const size_t root_cluster = m_root_block * clusters_per_block() + m_root_cluster_offset;
        if (!m_driver->write_offset(root_cluster * kCleanBlockSize, *root_data)) {
            return fail(ErrorCode::OutOfRange, "FlashFS root cluster 0x{:X} is outside the NAND",
                        root_cluster);
        }
        return root_cluster;
    }

    // Small-block data blocks are plain type 0x00 blocks with no size or page count; big-block
    // ones carry type 0x2A and the constant reference stamp, as the big-block root does.
    BlockMetadata FlashFileSystem::fs_metadata(BlockKind kind, uint32_t sequence,
                                               uint16_t block_id) const {
        const bool big_block = m_driver->driver_mode() == Driver::DriverMode::Big;
        BlockMetadata meta{};
        meta.logical_block_id = block_id;
        meta.sequence = sequence;
        if (kind == BlockKind::Root) {
            meta.block_type =
                big_block ? FlashFsMetadata::kRootTypeBig : FlashFsMetadata::kRootTypeSmall;
        } else {
            meta.block_type =
                big_block ? FlashFsMetadata::kDataTypeBig : FlashFsMetadata::kDataTypeSmall;
        }
        meta.fs_size = big_block ? big_fs_size() : 0;
        meta.page_count = big_block ? FlashFsMetadata::kBigPageCount : 0;
        meta.is_bad = false;
        return meta;
    }

    Result<void> FlashFileSystem::write_file_chain(const FlashFileSystemEntry& entry,
                                                   const std::string& name,
                                                   std::span<const uint8_t> bytes,
                                                   ClusterPages& clusters) {
        const bool big_block = m_driver->driver_mode() == Driver::DriverMode::Big;
        size_t bytes_written = 0;
        for (uint16_t blk : get_chain(entry.block_number)) {
            if (bytes_written >= bytes.size()) {
                break;
            }

            // The last cluster of a file is zero-padded to its end, so every page of a file
            // cluster is programmed.
            const size_t chunk_len =
                std::min<size_t>(bytes.size() - bytes_written, kCleanBlockSize);
            const auto chunk = bytes.subspan(bytes_written, chunk_len);
            const size_t cluster_offset = static_cast<size_t>(blk) * kCleanBlockSize;
            if (!m_driver->write_offset(cluster_offset, chunk)) {
                return fail(ErrorCode::OutOfRange,
                            "FlashFS cluster 0x{:X} of '{}' is outside the NAND", blk, name);
            }
            if (chunk_len < kCleanBlockSize) {
                const std::vector<uint8_t> padding(kCleanBlockSize - chunk_len, 0);
                if (!m_driver->write_offset(cluster_offset + chunk_len, padding)) {
                    return fail(ErrorCode::OutOfRange,
                                "FlashFS cluster 0x{:X} of '{}' is outside the NAND", blk, name);
                }
            }

            // A big-block file of one cluster states its spare on the pages its bytes reach;
            // the zero padding after them keeps erased fields (xeBuild 1.21).
            size_t pages = kPagesPerCluster;
            if (big_block && bytes.size() <= kCleanBlockSize) {
                pages = std::max<size_t>(1, (chunk_len + 511) / 512);
            }
            clusters[blk] = pages;

            bytes_written += chunk_len;
        }
        if (bytes_written != bytes.size()) {
            return fail(ErrorCode::Truncated,
                        "FlashFS chain of '{}' holds 0x{:X} of its 0x{:X} bytes", name,
                        bytes_written, bytes.size());
        }
        return {};
    }

    // File data blocks carry FS sequence 0. Only the 16 KiB clusters holding file data are
    // stamped: the rest of a big block stays erased, as xeBuild leaves it, and so do the pages
    // of a cluster past those its spare reaches.
    void FlashFileSystem::stamp_file_clusters(const ClusterPages& clusters) {
        const std::vector<uint8_t> erased_spare(16, 0xFF);
        for (const auto& [cluster, pages] : clusters) {
            const BlockMetadata file_meta = fs_metadata(
                BlockKind::Data, 0, static_cast<uint16_t>(cluster / clusters_per_block()));
            m_driver->write_page_metadata(cluster * kPagesPerCluster, pages, file_meta);
            for (size_t page = pages; page < kPagesPerCluster; ++page) {
                m_driver->write_page_spare(cluster * kPagesPerCluster + page, erased_spare);
            }
        }
    }

    // Driver writes go in this order: the root bytes, every file's bytes in directory order,
    // the file spares, and the root spare last.
    Result<void> FlashFileSystem::save() {
        if (!m_driver) {
            return fail(ErrorCode::InvalidArgument, "FlashFS save needs an attached driver");
        }
        auto root_cluster = write_root_cluster();
        if (!root_cluster) {
            return std::unexpected(std::move(root_cluster.error()));
        }

        ClusterPages file_clusters;
        for (const auto& entry : m_entries) {
            if (!entry.is_valid()) {
                continue;
            }
            auto it = m_file_data.find(std::string(entry.filename));
            if (it == m_file_data.end()) {
                continue;
            }
            if (auto written = write_file_chain(entry, it->first, it->second, file_clusters);
                !written) {
                return written;
            }
        }

        stamp_file_clusters(file_clusters);
        m_driver->write_cluster_metadata(*root_cluster,
                                         fs_metadata(BlockKind::Root, m_version, m_root_block));
        return {};
    }

    Result<void> FlashFileSystem::load(Driver& driver, uint16_t root_block,
                                       size_t cluster_in_block) {
        // Read into a staged filesystem that carries only this one's settings, and commit it
        // whole on success, so a failed load leaves this filesystem as it was.
        FlashFileSystem staged;
        staged.m_larger = m_larger;
        staged.m_big_system_blocks = m_big_system_blocks;
        staged.m_timestamp = m_timestamp;
        if (auto loaded = staged.read_root(driver, root_block, cluster_in_block); !loaded) {
            return loaded;
        }
        *this = std::move(staged);
        return {};
    }

    Result<void> FlashFileSystem::read_root(Driver& driver, uint16_t root_block,
                                            size_t cluster_in_block) {
        m_driver = &driver;
        m_root_block = root_block;
        if (cluster_in_block >= clusters_per_block()) {
            return fail(ErrorCode::OutOfRange, "FlashFS root cluster {} is past its erase block",
                        cluster_in_block);
        }
        m_root_cluster_offset = cluster_in_block;
        m_root_reserved_clusters = 1;
        const size_t root_cluster = root_block * clusters_per_block() + cluster_in_block;
        auto root_meta = driver.interpret_cluster(root_cluster);
        m_version = root_meta.sequence;

        auto root_data = driver.read_clean(root_cluster * kCleanBlockSize, kCleanBlockSize);
        if (root_data.size() < kCleanBlockSize) {
            return fail(ErrorCode::Truncated, "FlashFS root cluster 0x{:X} reads 0x{:X} bytes",
                        root_cluster, root_data.size());
        }
        m_root_placed = true;
        m_stated.clear();

        auto root = wire::read<flashfs_root_cluster>(root_data, 0, "FlashFS root");
        if (!root) {
            return std::unexpected(std::move(root.error()));
        }

        const size_t cluster_count = driver.block_count() * clusters_per_block();
        m_blockmap.assign(std::min(cluster_count, kRootDirectoryPages * kBlocksPerPage),
                          BlockMapStatus::Reserved);
        if (auto decoded = decode_block_map(*root, base_cluster(), m_blockmap); !decoded) {
            return decoded;
        }

        m_entries.clear();
        m_file_data.clear();
        if (auto decoded = decode_directory(*root, base_cluster(), m_blockmap.size(), m_entries);
            !decoded) {
            return decoded;
        }

        return read_files(driver);
    }

    Result<void> FlashFileSystem::read_files(const Driver& driver) {
        for (const auto& entry : m_entries) {
            auto file_bytes = read_chain(driver, entry);
            if (file_bytes.size() != entry.length) {
                return fail(ErrorCode::Truncated,
                            "FlashFS file '{}' is truncated: expected {} bytes, read {}",
                            entry.filename, entry.length, file_bytes.size());
            }
            m_file_data[std::string(entry.filename)] = std::move(file_bytes);
        }

        return {};
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

} // namespace gxbuild3::nand
