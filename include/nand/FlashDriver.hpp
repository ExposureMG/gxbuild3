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
        void write_block(size_t block_idx, std::span<const uint8_t> data);

        std::span<const uint8_t> read_block_raw(size_t block_idx) const;
        std::span<uint8_t> read_block_raw(size_t block_idx);
        void write_block_raw(size_t block_idx, std::span<const uint8_t> data);

        BlockMetadata interpret_block(size_t block_idx) const;
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
        void write_offset(size_t offset, std::span<const uint8_t> data);

        std::vector<uint8_t>& serialize();
        const std::vector<uint8_t>& serialize() const;
        void clean();

      private:
        std::vector<uint8_t> m_nand_image;
        DriverMode m_driver_mode;
        ImageSize m_image_size;
        size_t m_page_size;
        NandLayout m_layout;
    };

} // namespace gxbuild3::NAND