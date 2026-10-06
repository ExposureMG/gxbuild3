#pragma once

#include "Error.hpp"
#include "Wire.hpp"
#include "nand/FlashDriver.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::nand {

    struct FlashFileSystemTestAccess;

    inline constexpr size_t kMaxFilenameLength = 0x16;
    inline constexpr size_t kEntriesPerPage = 16;
    inline constexpr size_t kRootDirectoryPages = 16;
    inline constexpr size_t kMaxDirectoryEntries = kRootDirectoryPages * kEntriesPerPage;
    inline constexpr size_t kBlocksPerPage = 256;
    inline constexpr size_t kCleanBlockSize = 0x4000;

    struct BlockMapStatus {
        static constexpr uint16_t Free = 0x1FFE;
        static constexpr uint16_t EndOfChain = 0x1FFF;
        static constexpr uint16_t Reserved = 0x1FFB;
        static constexpr uint16_t BadBlock = 0x1FF0;
        // The cluster the root (the table itself) occupies.
        static constexpr uint16_t Table = 0x1FFD;
        // A cluster the table never names: the remap pool past the reserved settings blocks,
        // and the clusters a big-block build steps over to start the settings blobs on an
        // erase block.
        static constexpr uint16_t Unnamed = 0x0000;
    };

    // A directory entry in host order: the block number is the physical cluster, rebased from
    // the on-disk number by the filesystem's base cluster.
    struct FlashFileSystemEntry {
        char filename[kMaxFilenameLength]{};
        uint16_t block_number{};
        uint32_t length{};
        uint32_t timestamp{};

        [[nodiscard]] bool is_valid() const noexcept;
        [[nodiscard]] bool matches(std::string_view name) const noexcept;
    };

    // ---- On-disk root cluster (big-endian) --------------------------------------------------
    // The root is one 0x4000-byte cluster of 32 pages of 0x200 bytes: even pages hold the block
    // map, odd pages the directory. Block numbers and links count from the filesystem's base
    // cluster.

    struct flashfs_disk_entry {
        // NUL-terminated unless it fills all kMaxFilenameLength bytes.
        char filename[kMaxFilenameLength];
        wire::be16 block_number;
        wire::be32 length;
        wire::be32 timestamp;
    };
    static_assert(sizeof(flashfs_disk_entry) == 0x20);
    static_assert(offsetof(flashfs_disk_entry, filename) == 0x00);
    static_assert(offsetof(flashfs_disk_entry, block_number) == 0x16);
    static_assert(offsetof(flashfs_disk_entry, length) == 0x18);
    static_assert(offsetof(flashfs_disk_entry, timestamp) == 0x1C);

    struct flashfs_map_page {
        wire::be16 links[kBlocksPerPage];
    };
    static_assert(sizeof(flashfs_map_page) == 0x200);

    struct flashfs_dir_page {
        flashfs_disk_entry entries[kEntriesPerPage];
    };
    static_assert(sizeof(flashfs_dir_page) == 0x200);

    // One even map page and the odd directory page after it.
    struct flashfs_root_pair {
        flashfs_map_page map;
        flashfs_dir_page dir;
    };
    static_assert(sizeof(flashfs_root_pair) == 0x400);
    static_assert(offsetof(flashfs_root_pair, dir) == 0x200);

    struct flashfs_root_cluster {
        flashfs_root_pair pairs[kRootDirectoryPages];
    };
    static_assert(sizeof(flashfs_root_cluster) == kCleanBlockSize);
    static_assert(wire::WireLayout<flashfs_root_cluster>);

    class FlashFileSystem {
      public:
        FlashFileSystem() = default;

        // Sentinel root_block for format(): defer root placement so serialize can
        // allocate the root once, last, from the same free pool as files/mobile data.
        static constexpr uint16_t kDeferRoot = 0xFFFF;

        void set_driver(Driver* driver);

        // The larger filesystem a big-block devkit image takes (xeBuild 1.21 "extended size
        // FFS"): its block numbers count from cluster 0x2E0 instead of 0xAE0. Small-block and
        // eMMC filesystems count from zero either way.
        void set_larger_filesystem(bool larger) noexcept { m_larger = larger; }

        // The system area a big-block filesystem's spare states, in 0x20000-byte blocks: 0x10 on
        // every image but a retail one, whose system area ends with its update slots (xeBuild
        // 1.21: 6 on a jasperbb retail image).
        void set_big_system_blocks(uint8_t blocks) noexcept { m_big_system_blocks = blocks; }

        // The fs_size stamp its root and data blocks carry on big block: the system area in
        // byte 7 and the filesystem's size over 32 blocks in byte 8.
        [[nodiscard]] uint16_t big_fs_size() const noexcept {
            const uint16_t stamp =
                m_larger ? FlashFsMetadata::kBigFsSizeLarger : FlashFsMetadata::kBigFsSize;
            if (!m_big_system_blocks) {
                return stamp;
            }
            return static_cast<uint16_t>((stamp & 0xFF00) | *m_big_system_blocks);
        }

        // The stamp a directory entry gets when add_file or insert_file is given none.
        void set_timestamp(uint32_t timestamp) noexcept { m_timestamp = timestamp; }
        [[nodiscard]] uint32_t timestamp() const noexcept { return m_timestamp; }

        // Attach the driver before formatting. These allocation boundaries and root
        // locations are physical NAND blocks; directory entries/blockmap use 16 KiB clusters.
        [[nodiscard]] Result<void> format(size_t total_blocks, uint16_t root_block = 0x3E0,
                                          uint32_t version = 1, uint32_t reserved_boundary = 0x50);
        // Reads the root at `root_block` (and `cluster_in_block` within it) and every file it
        // lists. Transactional: on failure the filesystem, its driver included, is unchanged.
        [[nodiscard]] Result<void> load(Driver& driver, uint16_t root_block = 0x3E0,
                                        size_t cluster_in_block = 0);
        [[nodiscard]] Result<void> save();
        [[nodiscard]] Result<void> set_root_block(uint16_t root_block);
        [[nodiscard]] Result<void> reserve_blocks(size_t start_block, size_t block_count);
        // Keeps free clusters from allocation while the table states them as `stated`: Free
        // for the settings blobs, which xeBuild leaves free in the table, or Unnamed.
        [[nodiscard]] Result<void> withhold_clusters(size_t first_cluster, size_t cluster_count,
                                                     uint16_t stated);
        [[nodiscard]] Result<void> withhold_blocks(size_t start_block, size_t block_count,
                                                   uint16_t stated);
        [[nodiscard]] bool is_block_free(size_t physical_block) const;

        [[nodiscard]] Result<void> add_file(std::string_view filename,
                                            std::span<const uint8_t> data,
                                            std::optional<uint32_t> timestamp = std::nullopt);
        // Lists the file at `position` in the directory: it and every file after it are laid
        // again in directory order, from the first free block, so a filesystem whose files sit
        // back to back stays that way. A file of the same name is replaced.
        [[nodiscard]] Result<void> insert_file(size_t position, std::string_view filename,
                                               std::span<const uint8_t> data,
                                               std::optional<uint32_t> timestamp = std::nullopt);
        [[nodiscard]] std::optional<std::vector<uint8_t>> get_file(std::string_view filename) const;
        // Fails with NotFound when no file has that name.
        [[nodiscard]] Result<void> delete_file(std::string_view filename);
        [[nodiscard]] bool exists(std::string_view filename) const;
        [[nodiscard]] std::vector<std::string> list_files() const;
        [[nodiscard]] std::optional<FlashFileSystemEntry> stat(std::string_view filename) const;

        [[nodiscard]] Result<std::vector<uint8_t>> serialize_root_block() const;
        [[nodiscard]] const std::vector<uint16_t>& blockmap() const;
        [[nodiscard]] const std::vector<FlashFileSystemEntry>& entries() const;
        [[nodiscard]] uint32_t version() const;
        [[nodiscard]] uint16_t root_block() const;
        [[nodiscard]] bool has_root() const noexcept { return m_root_placed; }

        [[nodiscard]] std::vector<uint16_t> get_chain(uint16_t start_block) const;
        [[nodiscard]] std::vector<uint16_t> get_all_file_blocks() const;
        // Empty when the free clusters cannot hold `bytes_needed`; nothing is allocated then.
        [[nodiscard]] std::optional<uint16_t> allocate_chain(size_t bytes_needed);
        void free_chain(uint16_t start_block);

      private:
        friend struct FlashFileSystemTestAccess;

        Driver* m_driver = nullptr;
        uint32_t m_version = 1;
        uint16_t m_root_block = 0x3E0;
        bool m_root_placed = false;
        bool m_larger = false;
        std::optional<uint8_t> m_big_system_blocks;
        uint32_t m_timestamp = 0;
        size_t m_root_cluster_offset = 0;
        size_t m_root_reserved_clusters = 1;
        std::vector<uint16_t> m_blockmap;
        std::vector<FlashFileSystemEntry> m_entries;
        std::map<std::string, std::vector<uint8_t>> m_file_data;
        // Withheld clusters and what the table states for each; the block map holds them
        // Reserved so nothing allocates them.
        std::map<size_t, uint16_t> m_stated;

        [[nodiscard]] size_t clusters_per_block() const;
        [[nodiscard]] size_t base_cluster() const;
        void place_root(uint16_t root_block);
        void release_root();
        // load() into a freshly staged filesystem; load() commits it only on success.
        [[nodiscard]] Result<void> read_root(Driver& driver, uint16_t root_block,
                                             size_t cluster_in_block);
        // Reads every listed file through its chain into m_file_data; Truncated when a chain
        // holds fewer bytes than the entry states.
        [[nodiscard]] Result<void> read_files(const Driver& driver);
        // The entry's chain read up to its stated length; shorter when the chain runs out.
        [[nodiscard]] std::vector<uint8_t> read_chain(const Driver& driver,
                                                      const FlashFileSystemEntry& entry) const;

        enum class BlockKind {
            Root,
            Data
        };
        // Each file cluster and how many of its pages carry the file's spare.
        using ClusterPages = std::map<size_t, size_t>;

        // save()'s stages. Writes the encoded root bytes and returns the root cluster.
        [[nodiscard]] Result<size_t> write_root_cluster();
        // The spare stamp of a root or data block.
        [[nodiscard]] BlockMetadata fs_metadata(BlockKind kind, uint32_t sequence,
                                                uint16_t block_id) const;
        // Writes the file's bytes through its chain, zero-padding the last cluster, and states
        // in `clusters` how many pages of each cluster carry the file's spare.
        [[nodiscard]] Result<void> write_file_chain(const FlashFileSystemEntry& entry,
                                                    const std::string& name,
                                                    std::span<const uint8_t> bytes,
                                                    ClusterPages& clusters);
        // Stamps the data spare on each cluster's stated pages and erases the rest.
        void stamp_file_clusters(const ClusterPages& clusters);

        [[nodiscard]] static std::optional<size_t> checked_block_count(size_t bytes_needed,
                                                                       size_t clean_block_size);

        [[nodiscard]] FlashFileSystemEntry* find_entry(std::string_view filename);
        [[nodiscard]] const FlashFileSystemEntry* find_entry(std::string_view filename) const;
    };

} // namespace gxbuild3::nand
