#pragma once

#include "NandTypes.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

    struct BlockMetadata {
        uint16_t logical_block_id = 0;
        uint32_t sequence = 0;
        uint8_t block_type = 0;
        uint8_t page_count = 0;
        uint16_t fs_size = 0;
        bool is_bad = false;
    };

    // FlashFS spare metadata values. Big-block images use a distinct block-type space
    // (0x2C root, 0x2A data) and carry a constant fs_size/page_count stamp on every root
    // and data block; small/new-small images keep 0x30/0x01 and per-file sizes. The big
    // constants were derived byte-for-byte from retail and xeBuild big-block references,
    // whose filesystem the stock kernel only mounts when these values are present.
    namespace FlashFsMetadata {
        inline constexpr uint8_t kRootTypeSmall = 0x30;
        inline constexpr uint8_t kRootTypeBig = 0x2C;
        inline constexpr uint8_t kDataTypeSmall = 0x01;
        inline constexpr uint8_t kDataTypeBig = 0x2A;
        inline constexpr uint16_t kBigFsSize = 0x2006;
        inline constexpr uint8_t kBigPageCount = 0x04;
    } // namespace FlashFsMetadata

    struct BlockRange {
        size_t start_block = 0;
        size_t block_count = 0;

        [[nodiscard]] bool contains(size_t block) const noexcept {
            return block >= start_block && block - start_block < block_count;
        }
    };

    class Driver {
      public:
        enum DriverMode {
            Small,
            NewSmall,
            Big,
            Emmc
        };

        enum ImageSize {
            Smallblock,
            Emmcblock,
            Bigordevkit,
        };

        Driver() : Driver(ImageSize::Smallblock, DriverMode::Small) {}
        Driver(ImageSize size, DriverMode mode);
        explicit Driver(std::vector<uint8_t> image);

        static ImageSize detect_image_size(size_t size);
        static ImageSize detect_image_size(std::span<const uint8_t> image);
        static DriverMode detect_driver_mode(std::span<const uint8_t> image);

        DriverMode driver_mode() const;
        ImageSize image_size() const;
        size_t page_size() const;
        size_t pages_per_block() const;
        size_t block_count() const;
        size_t block_size_clean() const;
        size_t block_size_raw() const;
        size_t data_block_limit() const;
        [[nodiscard]] std::optional<BlockRange> block_range_for_byte_interval(size_t offset,
                                                                              size_t length) const;

        void set_layout(NandLayout layout);
        const NandLayout& layout() const;

        void input(std::vector<uint8_t> image);

        std::span<const uint8_t> read_page(size_t page) const;
        std::span<uint8_t> read_page(size_t page);
        void write_page(size_t page, std::span<const uint8_t> data);

        void write_data(size_t start_page, std::span<const uint8_t> data);
        std::vector<uint8_t> read_data(size_t start_page, size_t num_pages) const;

        std::span<const uint8_t> read_page_raw(size_t page, size_t length = 1) const;
        std::span<uint8_t> read_page_raw(size_t page, size_t length = 1);
        void write_page_raw(size_t page, std::span<const uint8_t> data);

        std::span<const uint8_t> read_page_spare(size_t page) const;
        std::span<uint8_t> read_page_spare(size_t page);
        void write_page_spare(size_t page, std::span<const uint8_t> spare);

        std::vector<uint8_t> read_block(size_t block_idx) const;
        bool write_block(size_t block_idx, std::span<const uint8_t> data);

        std::span<const uint8_t> read_block_raw(size_t block_idx) const;
        std::span<uint8_t> read_block_raw(size_t block_idx);
        void write_block_raw(size_t block_idx, std::span<const uint8_t> data);

        BlockMetadata interpret_block(size_t block_idx) const;
        BlockMetadata interpret_cluster(size_t cluster_idx) const;
        void write_cluster_metadata(size_t cluster_idx, const BlockMetadata& meta);
        bool is_bad_block(size_t block_idx) const;
        void mark_bad_block(size_t block_idx);
        void write_block_metadata(size_t block_idx, const BlockMetadata& meta);

        bool is_block_free(size_t block_idx) const;
        std::optional<size_t> find_next_free_block(size_t start_block = 0) const;
        std::optional<size_t> allocate_block(size_t start_block = 0, uint8_t block_type = 0x01,
                                             uint32_t sequence = 0);

        std::span<const uint8_t> read_offset(size_t offset, size_t length = 1) const;
        std::span<uint8_t> read_offset(size_t offset, size_t length = 1);
        std::vector<uint8_t> read_clean(size_t offset, size_t length) const;
        bool write_offset(size_t offset, std::span<const uint8_t> data);

        std::vector<uint8_t>& serialize();
        const std::vector<uint8_t>& serialize() const;
        void clean();

      private:
        BlockMetadata interpret_page_metadata(size_t first_page) const;
        void write_page_metadata_range(size_t first_page, size_t page_count,
                                       const BlockMetadata& meta);
        std::vector<uint8_t> m_nand_image;
        DriverMode m_driver_mode;
        ImageSize m_image_size;
        size_t m_page_size;
        NandLayout m_layout;
        mutable std::vector<uint8_t> m_offset_scratch;
    };

} // namespace gxbuild3::NAND
