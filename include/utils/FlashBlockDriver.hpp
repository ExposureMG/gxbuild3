#pragma once

#include <Log.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace gxbuild3::utils {

    /// @brief Enum for spare data types (small block, big block on small, big block, etc.)
    enum class SpareType : uint32_t {
        SmallBlock = 0,
        BigBlockOnSmall = 1,
        BigBlock = 2,
        Corona4GB = 3,
        OldSmallBlock = 4
    };

    /// @brief Flash configuration constants
    namespace FlashConfig {
        inline constexpr uint32_t AllOther16M = 0x01198010;
        inline constexpr uint32_t Jasper16M_NewSB = 0x00023010;
        inline constexpr uint32_t Trinity16MB = 0x00023010;
        inline constexpr uint32_t AllOther64M = 0x01198030;
        inline constexpr uint32_t Jasper64M_NewSB = 0x00023010;
        inline constexpr uint32_t Jasper256_512_LargeBlock = 0x00AA3020;
        inline constexpr uint32_t Corona256M = 0x008A3020;
        inline constexpr uint32_t Corona512M = 0x00AA3020;
        inline constexpr uint32_t Corona4GB = 0x00060000;
    } // namespace FlashConfig

    /// @brief Flash block driver for managing Xbox 360 NAND image operations
    /// Handles reading/writing blocks, pages, spare data, ECC calculation, and flash configuration
    class FlashBlockDriver {
      public:
        FlashBlockDriver();
        explicit FlashBlockDriver(std::vector<uint8_t>&& image_data);

        // Image creation and file I/O
        std::optional<std::vector<uint8_t>> create_image(size_t length, uint32_t flash_config);
        std::optional<std::vector<uint8_t>> open_image(const std::string& path);
        bool save_image(const std::string& path);

        // Spare data field manipulation
        uint32_t get_spare_seq_field(const uint8_t* spare_buff) const;
        uint16_t get_spare_index_field(const uint8_t* spare_buff) const;
        uint8_t get_spare_block_type_field(const uint8_t* spare_buff) const;
        uint16_t get_spare_size_field(const uint8_t* spare_buff) const;
        uint8_t get_spare_page_count_field(const uint8_t* spare_buff) const;

        void set_spare_page_count_field(uint8_t* spare_buff, uint8_t pg_count) const;
        void set_spare_block_type_field(uint8_t* spare_buff, uint8_t blk_type) const;
        void set_spare_seq_field(uint8_t* spare_buff, uint32_t sequence) const;
        void set_spare_index_field(uint8_t* spare_buff, uint16_t blk_index) const;
        void set_spare_size_field(uint8_t* spare_buff, uint16_t fs_size) const;
        void set_spare_bad_block(uint8_t* spare_buff, bool is_bad_block) const;

        bool is_spare_bad_block(const uint8_t* spare_buff) const;
        bool is_mobile_data(uint8_t block_type) const;

        // Read operations
        std::optional<std::vector<uint8_t>> read_page_spare(uint32_t page_idx) const;
        std::optional<std::vector<uint8_t>> read_block_spare(uint32_t block_idx) const;
        std::optional<std::vector<uint8_t>> read_lil_block_spare(uint32_t block_idx) const;
        std::optional<std::vector<uint8_t>> read_block(uint32_t blk_idx, size_t length) const;
        std::optional<std::vector<uint8_t>> read_lil_block(uint32_t blk_idx, size_t length) const;
        std::optional<std::vector<uint8_t>>
        read_lil_block_chain(const uint16_t* chain, size_t chain_length, size_t size) const;
        std::optional<std::vector<uint8_t>> read(size_t offset, size_t length) const;

        // Write operations
        bool write_page_spare(uint32_t page_idx, const uint8_t* spare_buff);
        bool write_block_spare(uint32_t block_idx, const uint8_t* spare_buff);
        bool write_lil_block_spare(uint32_t block_idx, const uint8_t* spare_buff);
        bool write_lil_block_spare_all_pages(uint32_t block_idx, const uint8_t* spare_buff);
        bool write_block(uint32_t blk_idx, const uint8_t* buffer, size_t length);
        bool write_lil_block(uint32_t blk_idx, const uint8_t* buffer, size_t length);
        bool write(size_t offset, const uint8_t* buffer, size_t length);

        void init_spare();
        SpareType detect_spare_type() const;
        void calculate_edc(uint32_t* data) const;
        void recalculate_all_ecc();
        bool load_flash_config(uint32_t flash_config = 0);
        bool open_continue(size_t length, uint32_t page_length);
        bool create_defaults(size_t img_len, uint32_t page_len, SpareType spare_type,
                             uint32_t flash_config, uint32_t fs_offset);

        void reserve_logical_block(uint32_t block_idx);
        void reserve_logical_blocks(uint32_t start_block_idx, uint32_t count);
        bool is_block_free(uint32_t block_idx) const;
        std::optional<uint32_t> allocate_logical_block(uint8_t block_type = 0,
                                                       uint32_t sequence = 0,
                                                       uint32_t min_block = 0);
        bool write_logical_block(uint32_t block_idx, const uint8_t* buffer, size_t length,
                                 uint8_t block_type = 0, uint32_t sequence = 0,
                                 uint16_t fs_size = 0);
        std::optional<std::vector<uint8_t>> read_logical_block(uint32_t block_idx) const;
        const std::vector<bool>& allocated_blocks() const { return m_allocated_blocks; }

        const std::vector<uint8_t>& image_data() const { return m_image_data; }
        std::vector<uint8_t>& image_data() { return m_image_data; }

        uint32_t spare_type() const { return static_cast<uint32_t>(m_spare_type); }
        uint32_t block_count() const { return m_block_count; }
        uint32_t block_length() const { return m_block_length; }
        uint32_t block_length_real() const { return m_block_length_real; }
        uint32_t lil_block_count() const { return m_lil_block_count; }
        uint32_t lil_block_length() const { return m_lil_block_length; }
        uint32_t lil_block_length_real() const { return m_lil_block_length_real; }
        uint32_t flash_config() const { return m_flash_config; }
        uint32_t page_length() const { return m_page_length; }
        uint32_t page_count() const { return m_page_count; }
        size_t image_length_real() const { return m_image_length_real; }
        size_t image_length_raw() const { return m_image_length_raw; }
        uint32_t fs_offset() const { return m_fs_offset; }
        uint32_t reserve_block_idx() const { return m_reserve_block_idx; }
        uint32_t config_block_idx() const { return m_config_block_idx; }
        uint32_t patch_slot_length() const { return m_patch_slot_length; }

      private:
        std::vector<uint8_t> m_image_data;
        std::vector<bool> m_allocated_blocks;

        SpareType m_spare_type = SpareType::SmallBlock;
        uint32_t m_block_count = 0;
        uint32_t m_block_length = 0;
        uint32_t m_block_length_real = 0;
        uint32_t m_lil_block_count = 0;
        uint32_t m_lil_block_length = 0;
        uint32_t m_lil_block_length_real = 0;
        uint32_t m_flash_config = 0;
        uint32_t m_page_length = 0;
        uint32_t m_page_count = 0;
        size_t m_image_length_real = 0;
        size_t m_image_length_raw = 0;
        uint32_t m_fs_offset = 0;
        uint32_t m_reserve_block_idx = 0;
        uint32_t m_config_block_idx = 0;
        uint32_t m_patch_slot_length = 0x10000;
    };

} // namespace gxbuild3::utils
