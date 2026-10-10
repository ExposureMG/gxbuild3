#pragma once

#include "nand/FlashDriver.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::NAND {

    struct FlashFileSystemTestAccess;

    inline constexpr size_t kMaxFilenameLength = 0x16;
    inline constexpr size_t kEntriesPerPage = 16;
    inline constexpr size_t kRootDirectoryPages = 16;
    inline constexpr size_t kMaxDirectoryEntries = kRootDirectoryPages * kEntriesPerPage;
    inline constexpr size_t kBlocksPerPage = 256;
    inline constexpr size_t kCleanBlockSize = 0x4000;

    namespace BlockMapStatus {
        inline constexpr uint16_t Free = 0x1FFE;
        inline constexpr uint16_t EndOfChain = 0x1FFF;
        inline constexpr uint16_t Reserved = 0x1FFB;
        inline constexpr uint16_t BadBlock = 0x1FF0;
        // The cluster the root (the table itself) occupies.
        inline constexpr uint16_t Table = 0x1FFD;
        // A cluster the table never names: the remap pool past the reserved settings blocks,
        // and the clusters a big-block build steps over to start the settings blobs on an
        // erase block.
        inline constexpr uint16_t Unnamed = 0x0000;
    } // namespace BlockMapStatus

#pragma pack(push, 1)
    struct FlashFileSystemEntry {
        char filename[kMaxFilenameLength]{};
        uint16_t block_number{};
        uint32_t length{};
        uint32_t timestamp{};

        [[nodiscard]] bool is_valid() const noexcept;
        [[nodiscard]] bool matches(std::string_view name) const noexcept;
        [[nodiscard]] std::string_view name() const noexcept;
    };
    static_assert(sizeof(FlashFileSystemEntry) == 32);
#pragma pack(pop)

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
        bool format(size_t total_blocks, uint16_t root_block = 0x3E0, uint32_t version = 1,
                    uint32_t reserved_boundary = 0x50);
        bool load(Driver& driver, uint16_t root_block = 0x3E0, size_t cluster_in_block = 0);
        bool save();
        bool set_root_block(uint16_t root_block);
        bool reserve_blocks(size_t start_block, size_t block_count);
        // Keeps free clusters from allocation while the table states them as `stated`: Free
        // for the settings blobs, which xeBuild leaves free in the table, or Unnamed.
        bool withhold_clusters(size_t first_cluster, size_t cluster_count, uint16_t stated);
        bool withhold_blocks(size_t start_block, size_t block_count, uint16_t stated);
        [[nodiscard]] bool is_block_free(size_t physical_block) const;

        bool add_file(std::string_view filename, std::span<const uint8_t> data,
                      std::optional<uint32_t> timestamp = std::nullopt);
        // Lists the file at `position` in the directory: it and every file after it are laid
        // again in directory order, from the first free block, so a filesystem whose files sit
        // back to back stays that way. A file of the same name is replaced.
        bool insert_file(size_t position, std::string_view filename, std::span<const uint8_t> data,
                         std::optional<uint32_t> timestamp = std::nullopt);
        [[nodiscard]] std::optional<std::vector<uint8_t>> get_file(std::string_view filename) const;
        bool delete_file(std::string_view filename);
        [[nodiscard]] bool exists(std::string_view filename) const;
        [[nodiscard]] std::vector<std::string> list_files() const;
        [[nodiscard]] std::optional<FlashFileSystemEntry> stat(std::string_view filename) const;

        [[nodiscard]] std::vector<uint8_t> serialize_root_block() const;
        [[nodiscard]] const std::vector<uint16_t>& blockmap() const;
        [[nodiscard]] const std::vector<FlashFileSystemEntry>& entries() const;
        [[nodiscard]] uint32_t version() const;
        [[nodiscard]] uint16_t root_block() const;
        [[nodiscard]] bool has_root() const noexcept { return m_root_placed; }

        [[nodiscard]] std::vector<uint16_t> get_chain(uint16_t start_block) const;
        [[nodiscard]] std::vector<uint16_t> get_all_file_blocks() const;
        std::optional<uint16_t> allocate_chain(size_t bytes_needed);
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

        [[nodiscard]] static std::optional<size_t> checked_block_count(size_t bytes_needed,
                                                                       size_t clean_block_size);

        [[nodiscard]] FlashFileSystemEntry* find_entry(std::string_view filename);
        [[nodiscard]] const FlashFileSystemEntry* find_entry(std::string_view filename) const;
    };

} // namespace gxbuild3::NAND
