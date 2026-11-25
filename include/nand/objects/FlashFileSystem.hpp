#pragma once

#include "gxbuild/Error.hpp"
#include "core/Wire.hpp"
#include "nand/FlashDriver.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild::nand {

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
        static constexpr uint16_t Table = 0x1FFD;
        // cluster value 0x0000 used for the remap pool and alignment gaps that the blockmap ignores
        static constexpr uint16_t Unnamed = 0x0000;
    };

    struct FlashFileSystemEntry {
        char filename[kMaxFilenameLength]{};
        uint16_t block_number{};
        uint32_t length{};
        uint32_t timestamp{};

        [[nodiscard]] bool is_valid() const noexcept;
        [[nodiscard]] bool matches(std::string_view name) const noexcept;
    };

    struct flashfs_disk_entry {
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

    // the 16kb root cluster interleaves 512-byte blockmap pages (even) and directory pages (odd)
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
        explicit FlashFileSystem(const Driver& driver);

        static constexpr uint16_t kDeferRoot = 0xFFFF;

        void configure(const Driver& driver) noexcept;

        void set_larger_filesystem(bool larger) noexcept { m_larger = larger; }

        void set_big_system_blocks(uint8_t blocks) noexcept { m_big_system_blocks = blocks; }

        // packs the system area block count into the low byte and total filesystem blocks / 32 into the high byte
        [[nodiscard]] uint16_t big_fs_size() const noexcept {
            const uint16_t stamp =
                m_larger ? FlashFsMetadata::kBigFsSizeLarger : FlashFsMetadata::kBigFsSize;
            if (!m_big_system_blocks) {
                return stamp;
            }
            return static_cast<uint16_t>((stamp & 0xFF00) | *m_big_system_blocks);
        }

        void set_timestamp(uint32_t timestamp) noexcept { m_timestamp = timestamp; }
        [[nodiscard]] uint32_t timestamp() const noexcept { return m_timestamp; }

        [[nodiscard]] Result<void> format(size_t total_blocks, uint16_t root_block = 0x3E0,
                                          uint32_t version = 1, uint32_t reserved_boundary = 0x50);
        [[nodiscard]] Result<void> load(const Driver& driver, uint16_t root_block = 0x3E0,
                                        size_t cluster_in_block = 0);
        [[nodiscard]] Result<void> save(Driver& driver);
        [[nodiscard]] Result<void> set_root_block(uint16_t root_block);
        [[nodiscard]] Result<void> reserve_blocks(size_t start_block, size_t block_count);
        // marks clusters as reserved internally so nothing allocates them, but writes a custom status value to disk
        [[nodiscard]] Result<void> withhold_clusters(size_t first_cluster, size_t cluster_count,
                                                     uint16_t stated);
        [[nodiscard]] Result<void> withhold_blocks(size_t start_block, size_t block_count,
                                                   uint16_t stated);
        [[nodiscard]] bool is_block_free(size_t physical_block) const;

        [[nodiscard]] Result<void> add_file(std::string_view filename,
                                            std::span<const uint8_t> data,
                                            std::optional<uint32_t> timestamp = std::nullopt);
        [[nodiscard]] Result<void> insert_file(size_t position, std::string_view filename,
                                               std::span<const uint8_t> data,
                                               std::optional<uint32_t> timestamp = std::nullopt);
        [[nodiscard]] std::optional<std::vector<uint8_t>> get_file(std::string_view filename) const;
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
        [[nodiscard]] std::optional<uint16_t> allocate_chain(size_t bytes_needed);
        void free_chain(uint16_t start_block);

      private:
        friend struct FlashFileSystemTestAccess;

        Driver::DriverMode m_mode = Driver::DriverMode::Small;
        size_t m_clusters_per_block = 1;
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
        std::map<size_t, uint16_t> m_stated;

        [[nodiscard]] size_t clusters_per_block() const;
        [[nodiscard]] size_t base_cluster() const;
        void place_root(uint16_t root_block);
        void release_root();
        [[nodiscard]] Result<void> read_root(const Driver& driver, uint16_t root_block,
                                             size_t cluster_in_block);
        [[nodiscard]] Result<void> read_files(const Driver& driver);
        [[nodiscard]] std::vector<uint8_t> read_chain(const Driver& driver,
                                                      const FlashFileSystemEntry& entry) const;

        enum class BlockKind {
            Root,
            Data
        };
        using ClusterPages = std::map<size_t, size_t>;

        [[nodiscard]] Result<size_t> write_root_cluster(Driver& driver);
        [[nodiscard]] BlockMetadata fs_metadata(const Driver& driver, BlockKind kind,
                                                uint32_t sequence, uint16_t block_id) const;
        [[nodiscard]] Result<void> write_file_chain(Driver& driver,
                                                    const FlashFileSystemEntry& entry,
                                                    const std::string& name,
                                                    std::span<const uint8_t> bytes,
                                                    ClusterPages& clusters);
        void stamp_file_clusters(Driver& driver, const ClusterPages& clusters);

        [[nodiscard]] static std::optional<size_t> checked_block_count(size_t bytes_needed,
                                                                       size_t clean_block_size);

        [[nodiscard]] FlashFileSystemEntry* find_entry(std::string_view filename);
        [[nodiscard]] const FlashFileSystemEntry* find_entry(std::string_view filename) const;
    };

} // namespace gxbuild::nand
