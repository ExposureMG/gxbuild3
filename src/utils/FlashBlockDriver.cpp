// FlashBlockDriver implementation
// Modern C++23 implementation of Xbox 360 NAND flash block driver

#include "utils/FlashBlockDriver.hpp"

#include "Utils.hpp"

#include <algorithm>
#include <cstring>
#include <memory>

namespace gxbuild3::utils {

    FlashBlockDriver::FlashBlockDriver() {
        m_fs_offset = 0;
        m_flash_config = 0;
        m_spare_type = SpareType::SmallBlock;
        m_block_count = 0;
        m_block_length = 0;
        m_page_length = 0;
        m_image_length_raw = 0;
        m_image_length_real = 0;
    }

    FlashBlockDriver::FlashBlockDriver(std::vector<uint8_t>&& image_data)
        : m_image_data(std::move(image_data)) {
        m_fs_offset = 0;
        m_flash_config = 0;
        m_spare_type = SpareType::SmallBlock;
        m_block_count = 0;
        m_block_length = 0;
        m_page_length = 0;
        m_image_length_raw = m_image_data.size();
        m_image_length_real = 0;
    }

    bool FlashBlockDriver::is_mobile_data(uint8_t block_type) const {
        if ((block_type & 0x30) != 0x30)
            return false;
        return (block_type >= 0x31 && block_type < 0x3A);
    }

    void FlashBlockDriver::set_spare_bad_block(uint8_t* spare_buff, bool is_bad_block) const {
        if (m_spare_type == SpareType::BigBlock) {
            spare_buff[0] = (is_bad_block ? 0x00 : 0xFF);
        } else {
            spare_buff[0x5] = (is_bad_block ? 0x00 : 0xFF);
        }
    }

    bool FlashBlockDriver::is_spare_bad_block(const uint8_t* spare_buff) const {
        if (m_spare_type == SpareType::BigBlock) {
            return spare_buff[0] != 0xFF;
        }
        return spare_buff[0x5] != 0xFF;
    }

    void FlashBlockDriver::set_spare_page_count_field(uint8_t* spare_buff, uint8_t pg_count) const {
        spare_buff[0x9] = pg_count;
    }

    void FlashBlockDriver::set_spare_block_type_field(uint8_t* spare_buff, uint8_t blk_type) const {
        spare_buff[0xC] = blk_type;
    }

    void FlashBlockDriver::set_spare_seq_field(uint8_t* spare_buff, uint32_t sequence) const {
        const uint8_t seq0 = static_cast<uint8_t>(sequence & 0xFF);
        const uint8_t seq1 = static_cast<uint8_t>((sequence >> 8) & 0xFF);
        const uint8_t seq2 = static_cast<uint8_t>((sequence >> 16) & 0xFF);
        const uint8_t seq3 = static_cast<uint8_t>((sequence >> 24) & 0xFF);

        switch (m_spare_type) {
            case SpareType::OldSmallBlock:
                spare_buff[0x2] = seq0;
                spare_buff[0x3] = seq1;
                spare_buff[0x4] = seq2;
                spare_buff[0x6] = seq3;
                break;
            case SpareType::SmallBlock:
                spare_buff[0x0] = seq0;
                spare_buff[0x3] = seq1;
                spare_buff[0x4] = seq2;
                spare_buff[0x6] = seq3;
                break;
            case SpareType::BigBlockOnSmall:
                spare_buff[0x0] = seq0;
                spare_buff[0x3] = seq1;
                spare_buff[0x4] = seq2;
                spare_buff[0x6] = seq3;
                break;
            case SpareType::BigBlock:
                spare_buff[0x5] = seq0;
                spare_buff[0x3] = seq1;
                spare_buff[0x4] = seq2;
                spare_buff[0x6] = seq3;
                break;
            case SpareType::Corona4GB:
                break;
        }
    }

    void FlashBlockDriver::set_spare_index_field(uint8_t* spare_buff, uint16_t blk_index) const {
        const uint8_t idx1 = static_cast<uint8_t>(blk_index & 0xFF);
        const uint8_t idx0 = static_cast<uint8_t>((blk_index >> 8) & 0xF);

        switch (m_spare_type) {
            case SpareType::OldSmallBlock:
                spare_buff[0x0] = idx1;
                spare_buff[0x1] = (spare_buff[0x1] & 0xF0) | idx0;
                break;
            case SpareType::SmallBlock:
                spare_buff[0x1] = idx1;
                spare_buff[0x2] = (spare_buff[0x2] & 0xF0) | idx0;
                break;
            case SpareType::BigBlockOnSmall:
            case SpareType::BigBlock:
            case SpareType::Corona4GB:
                spare_buff[0x1] = idx1;
                spare_buff[0x2] = (spare_buff[0x2] & 0xF0) | idx0;
                break;
        }
    }

    void FlashBlockDriver::set_spare_size_field(uint8_t* spare_buff, uint16_t fs_size) const {
        spare_buff[0x7] = static_cast<uint8_t>(fs_size & 0xFF);
        spare_buff[0x8] = static_cast<uint8_t>((fs_size >> 8) & 0xFF);
    }

    uint16_t FlashBlockDriver::get_spare_index_field(const uint8_t* spare_buff) const {
        uint8_t idx0 = 0;
        uint8_t idx1 = 0;

        switch (m_spare_type) {
            case SpareType::OldSmallBlock:
                idx0 = spare_buff[0x1] & 0xF;
                idx1 = spare_buff[0x0];
                break;
            case SpareType::SmallBlock:
                idx0 = spare_buff[0x2] & 0xF;
                idx1 = spare_buff[0x1];
                break;
            case SpareType::BigBlockOnSmall:
            case SpareType::BigBlock:
            case SpareType::Corona4GB:
                idx0 = spare_buff[0x2] & 0xF;
                idx1 = spare_buff[0x1];
                break;
        }

        return static_cast<uint16_t>((idx0 << 8) + idx1);
    }

    uint16_t FlashBlockDriver::get_spare_size_field(const uint8_t* spare_buff) const {
        return static_cast<uint16_t>((spare_buff[0x8] << 8) + spare_buff[0x7]);
    }

    uint8_t FlashBlockDriver::get_spare_page_count_field(const uint8_t* spare_buff) const {
        return spare_buff[0x9];
    }

    uint8_t FlashBlockDriver::get_spare_block_type_field(const uint8_t* spare_buff) const {
        return spare_buff[0xC];
    }

    uint32_t FlashBlockDriver::get_spare_seq_field(const uint8_t* spare_buff) const {
        uint8_t seq0 = 0, seq1 = 0, seq2 = 0, seq3 = 0;

        switch (m_spare_type) {
            case SpareType::OldSmallBlock:
                seq0 = spare_buff[0x2];
                seq1 = spare_buff[0x3];
                seq2 = spare_buff[0x4];
                seq3 = spare_buff[0x6];
                break;
            case SpareType::SmallBlock:
                seq0 = spare_buff[0x0];
                seq1 = spare_buff[0x3];
                seq2 = spare_buff[0x4];
                seq3 = spare_buff[0x6];
                break;
            case SpareType::BigBlockOnSmall:
                seq0 = spare_buff[0x0];
                seq1 = spare_buff[0x3];
                seq2 = spare_buff[0x4];
                seq3 = spare_buff[0x6];
                break;
            case SpareType::BigBlock:
                seq0 = spare_buff[0x5];
                seq1 = spare_buff[0x3];
                seq2 = spare_buff[0x4];
                seq3 = spare_buff[0x6];
                break;
            case SpareType::Corona4GB:
                break;
        }

        return (static_cast<uint32_t>(seq3) << 24) + (static_cast<uint32_t>(seq2) << 16) +
               (static_cast<uint32_t>(seq1) << 8) + seq0;
    }

    std::optional<std::vector<uint8_t>> FlashBlockDriver::read_page_spare(uint32_t page_idx) const {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            Log::Error("read_page_spare: spare not available");
            return std::nullopt;
        }

        const uint32_t raw_page_count =
            static_cast<uint32_t>(m_image_data.size() / m_page_length);
        if (page_idx >= raw_page_count) {
            Log::Error("read_page_spare: invalid page index {}", page_idx);
            return std::nullopt;
        }

        const size_t offset = page_idx * m_page_length + 0x200;
        if (offset + 0x10 > m_image_data.size()) {
            Log::Error("read_page_spare: spare data out of bounds");
            return std::nullopt;
        }

        std::vector<uint8_t> spare(0x10);
        std::memcpy(spare.data(), m_image_data.data() + offset, 0x10);
        return spare;
    }

    std::optional<std::vector<uint8_t>>
    FlashBlockDriver::read_block_spare(uint32_t block_idx) const {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            Log::Error("read_block_spare: spare not available");
            return std::nullopt;
        }

        if (block_idx >= m_block_count) {
            Log::Error("read_block_spare: invalid block index {}", block_idx);
            return std::nullopt;
        }

        const size_t offset = block_idx * m_block_length_real + 0x200;
        if (offset + 0x10 > m_image_data.size()) {
            Log::Error("read_block_spare: spare data out of bounds");
            return std::nullopt;
        }

        std::vector<uint8_t> spare(0x10);
        std::memcpy(spare.data(), m_image_data.data() + offset, 0x10);
        return spare;
    }

    std::optional<std::vector<uint8_t>>
    FlashBlockDriver::read_lil_block_spare(uint32_t block_idx) const {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            Log::Error("read_lil_block_spare: spare not available");
            return std::nullopt;
        }

        if (block_idx >= m_lil_block_count) {
            Log::Error("read_lil_block_spare: invalid lil block index {}", block_idx);
            return std::nullopt;
        }

        const size_t offset = block_idx * m_lil_block_length_real + 0x200;
        if (offset + 0x10 > m_image_data.size()) {
            Log::Error("read_lil_block_spare: spare data out of bounds");
            return std::nullopt;
        }

        std::vector<uint8_t> spare(0x10);
        std::memcpy(spare.data(), m_image_data.data() + offset, 0x10);
        return spare;
    }

    std::optional<std::vector<uint8_t>> FlashBlockDriver::read_block(uint32_t blk_idx,
                                                                     size_t length) const {
        return read(blk_idx * m_block_length, length);
    }

    std::optional<std::vector<uint8_t>> FlashBlockDriver::read_lil_block(uint32_t blk_idx,
                                                                         size_t length) const {
        return read(blk_idx * m_lil_block_length, length);
    }

    std::optional<std::vector<uint8_t>>
    FlashBlockDriver::read_lil_block_chain(const uint16_t* chain, size_t chain_length,
                                           size_t size) const {
        const size_t block_count =
            size / m_lil_block_length + (size % m_lil_block_length > 0 ? 1 : 0);

        if (block_count > chain_length) {
            Log::Error("read_lil_block_chain: chain too short");
            return std::nullopt;
        }

        std::vector<uint8_t> buffer(size);
        size_t total_read = 0;

        for (size_t i = 0; i < block_count && total_read < size; i++) {
            const uint32_t curr_block = chain[i] + m_fs_offset;
            const size_t read_size =
                std::min(size - total_read, static_cast<size_t>(m_lil_block_length));

            auto data = read_lil_block(curr_block, read_size);
            if (!data) {
                Log::Error("read_lil_block_chain: failed to read block {}", curr_block);
                return std::nullopt;
            }

            std::memcpy(buffer.data() + total_read, data->data(), data->size());
            total_read += data->size();
        }

        return buffer;
    }

    std::optional<std::vector<uint8_t>> FlashBlockDriver::read(size_t offset, size_t length) const {
        if (offset >= m_image_length_real || offset + length > m_image_length_real) {
            Log::Error("read: requested range [{:x}, {:x}) exceeds image size {:x}", offset,
                       offset + length, m_image_length_real);
            return std::nullopt;
        }

        size_t off_in_page = offset % 512;
        const size_t page_in_image = offset / 512;

        std::vector<uint8_t> buffer(length);
        size_t bytes_read = 0;
        size_t curr_page = 0;

        while (bytes_read < length) {
            const size_t bytes_to_read =
                std::min(length - bytes_read, static_cast<size_t>(512 - off_in_page));
            const size_t buffer_offset = bytes_read;
            const size_t image_offset = (page_in_image + curr_page) * m_page_length + off_in_page;

            if (image_offset + bytes_to_read > m_image_data.size()) {
                Log::Error("read: buffer overrun");
                return std::nullopt;
            }

            std::memcpy(buffer.data() + buffer_offset, m_image_data.data() + image_offset,
                        bytes_to_read);

            bytes_read += bytes_to_read;
            off_in_page = 0; // reset after first page so subsequent pages start at offset 0
            curr_page++;
        }

        return buffer;
    }

    bool FlashBlockDriver::write_page_spare(uint32_t page_idx, const uint8_t* spare_buff) {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            Log::Error("write_page_spare: spare not available");
            return false;
        }

        const uint32_t raw_page_count =
            static_cast<uint32_t>(m_image_data.size() / m_page_length);
        if (page_idx >= raw_page_count) {
            Log::Error("write_page_spare: invalid page index {}", page_idx);
            return false;
        }

        const size_t offset = page_idx * m_page_length + 0x200;
        if (offset + 0x10 > m_image_data.size()) {
            Log::Error("write_page_spare: spare data out of bounds");
            return false;
        }

        std::memcpy(m_image_data.data() + offset, spare_buff, 0x10);
        return true;
    }

    bool FlashBlockDriver::write_block_spare(uint32_t block_idx, const uint8_t* spare_buff) {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            Log::Error("write_block_spare: spare not available");
            return false;
        }

        if (block_idx >= m_block_count) {
            Log::Error("write_block_spare: invalid block index {}", block_idx);
            return false;
        }

        const size_t offset = block_idx * m_block_length_real + 0x200;
        if (offset + 0x10 > m_image_data.size()) {
            Log::Error("write_block_spare: spare data out of bounds");
            return false;
        }

        std::memcpy(m_image_data.data() + offset, spare_buff, 0x10);
        return true;
    }

    bool FlashBlockDriver::write_lil_block_spare(uint32_t block_idx, const uint8_t* spare_buff) {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            Log::Error("write_lil_block_spare: spare not available");
            return false;
        }

        if (block_idx >= m_lil_block_count) {
            Log::Error("write_lil_block_spare: invalid lil block index {}", block_idx);
            return false;
        }

        const size_t offset = block_idx * m_lil_block_length_real + 0x200;
        if (offset + 0x10 > m_image_data.size()) {
            Log::Error("write_lil_block_spare: spare data out of bounds");
            return false;
        }

        std::memcpy(m_image_data.data() + offset, spare_buff, 0x10);
        return true;
    }

    bool FlashBlockDriver::write_lil_block_spare_all_pages(uint32_t block_idx,
                                                           const uint8_t* spare_buff) {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            return false;
        }

        const uint32_t pages_per_block =
            (m_lil_block_length != 0) ? (m_lil_block_length / 512) : 32;
        const uint32_t start_page = block_idx * pages_per_block;
        const uint32_t raw_page_count =
            static_cast<uint32_t>(m_image_data.size() / m_page_length);

        for (uint32_t p = 0; p < pages_per_block; ++p) {
            const uint32_t page_idx = start_page + p;
            if (page_idx >= raw_page_count) {
                break;
            }
            if (!write_page_spare(page_idx, spare_buff)) {
                return false;
            }
        }
        return true;
    }

    bool FlashBlockDriver::write_block(uint32_t blk_idx, const uint8_t* buffer, size_t length) {
        return write(blk_idx * m_block_length, buffer, length);
    }

    bool FlashBlockDriver::write_lil_block(uint32_t blk_idx, const uint8_t* buffer, size_t length) {
        return write(blk_idx * m_lil_block_length, buffer, length);
    }

    bool FlashBlockDriver::write(size_t offset, const uint8_t* buffer, size_t length) {
        if (offset >= m_image_length_real || offset + length > m_image_length_real) {
            Log::Error("write: requested range [{:x}, {:x}) exceeds image size {:x}", offset,
                       offset + length, m_image_length_real);
            return false;
        }

        size_t off_in_page = offset % 512;
        const size_t page_in_image = offset / 512;
        size_t bytes_written = 0;
        size_t curr_page = 0;

        while (bytes_written < length) {
            const size_t bytes_to_write =
                std::min(length - bytes_written, static_cast<size_t>(512 - off_in_page));
            const uint8_t* copy_from = buffer + bytes_written;
            const size_t image_offset = (page_in_image + curr_page) * m_page_length + off_in_page;

            if (image_offset + bytes_to_write > m_image_data.size()) {
                Log::Error("write: buffer overrun");
                return false;
            }

            std::memcpy(m_image_data.data() + image_offset, copy_from, bytes_to_write);
            bytes_written += bytes_to_write;
            off_in_page = 0;
            curr_page++;
        }

        return true;
    }

    void FlashBlockDriver::init_spare() {
        if (m_page_length < 0x210) {
            return;
        }

        uint8_t spare[0x10] = {0};
        const uint32_t raw_page_count =
            static_cast<uint32_t>(m_image_data.size() / m_page_length);
        const uint32_t pages_per_block =
            (m_lil_block_length != 0) ? (m_lil_block_length / 512) : 32;

        for (uint32_t i = 0; i < raw_page_count; i++) {
            std::memset(spare, 0, 0x10);
            set_spare_bad_block(spare, false);
            const uint32_t blk_idx = (pages_per_block != 0) ? (i / pages_per_block) : 0;
            set_spare_index_field(spare, static_cast<uint16_t>(blk_idx));
            if (!write_page_spare(i, spare)) {
                Log::Error("init_spare: failed to write page spare for page {}", i);
                return;
            }
        }
    }

    SpareType FlashBlockDriver::detect_spare_type() const {
        if (m_image_data.size() < 0x4410) {
            return SpareType::SmallBlock; // Default
        }

        const uint8_t* spare = m_image_data.data() + 0x4400;

        // Check for old SFC small block layout (META_TYPE_0)
        uint16_t block_idx = static_cast<uint16_t>(((spare[0x1] & 0xF) << 8) | spare[0x0]);
        if (block_idx == 1 && spare[0x5] == 0xFF) {
            return SpareType::OldSmallBlock;
        }

        // Check for small block layout (META_TYPE_1)
        block_idx = static_cast<uint16_t>(((spare[0x2] & 0xF) << 8) | spare[0x1]);
        if (block_idx == 1 && spare[0x5] == 0xFF) {
            return SpareType::SmallBlock;
        }

        // Check for big-on-small layout
        block_idx = static_cast<uint16_t>(((spare[0x2] & 0xF) << 8) | spare[0x1]);
        if (block_idx == 1 && m_image_data[0x4400 + 0x5] == 0xFF) {
            return SpareType::BigBlockOnSmall;
        }

        // Check for big block layout
        if (m_image_data.size() >= 0x21210) {
            block_idx = static_cast<uint16_t>(((m_image_data[0x21200 + 0x2] & 0xF) << 8) |
                                              m_image_data[0x21200 + 0x1]);
            if (block_idx == 1 && m_image_data[0x21200 + 0x0] == 0xFF) {
                return SpareType::BigBlock;
            }
        }

        return SpareType::Corona4GB;
    }

    void FlashBlockDriver::calculate_edc(uint32_t* data) const {
        uint32_t i = 0, val = 0;
        unsigned char* edc = reinterpret_cast<unsigned char*>(data) + 0x200;
        uint32_t v = 0;

        for (i = 0; i < 0x1066; i++) {
            if (!(i & 31)) {
                v = ~bswap32(*data++);
            }
            val ^= v & 1;
            v >>= 1;
            if (val & 1) {
                val ^= 0x6954559;
            }
            val >>= 1;
        }

        val = ~val;

        edc[0xC] = static_cast<uint8_t>(((val << 6) | (edc[0xC] & 0x3F)) & 0xFF);
        edc[0xD] = static_cast<uint8_t>((val >> 2) & 0xFF);
        edc[0xE] = static_cast<uint8_t>((val >> 10) & 0xFF);
        edc[0xF] = static_cast<uint8_t>((val >> 18) & 0xFF);
    }

    void FlashBlockDriver::recalculate_all_ecc() {
        if (m_page_length < 0x210 || m_image_data.empty()) {
            return;
        }

        const uint32_t raw_page_count =
            static_cast<uint32_t>(m_image_data.size() / m_page_length);
        for (uint32_t i = 0; i < raw_page_count; i++) {
            const size_t page_offset = static_cast<size_t>(i) * m_page_length;
            if (page_offset + m_page_length <= m_image_data.size()) {
                calculate_edc(reinterpret_cast<uint32_t*>(m_image_data.data() + page_offset));
            }
        }
    }

    bool FlashBlockDriver::load_flash_config(uint32_t flash_config) {
        if (flash_config != 0) {
            m_flash_config = flash_config;
        }

        m_patch_slot_length = 0x10000;
        m_reserve_block_idx = 0x3E0;

        // Handle Corona 4GB separately
        if (m_flash_config == FlashConfig::Corona4GB) {
            m_block_length = 0x4000;
            m_block_count = 0xC00;
            m_reserve_block_idx = 0xC00;
            m_spare_type = SpareType::Corona4GB;

            // Calculate derived values
            m_config_block_idx = m_reserve_block_idx - 4;
            m_lil_block_length = 0x4000;
            m_lil_block_count = (m_block_count * m_block_length) / 0x4000;
            m_lil_block_length_real = m_lil_block_length;
            m_block_length_real = m_block_length;
            m_page_count = m_lil_block_count * 0x20;

            Log::Info("FlashBlockDriver::load_flash_config:");
            Log::Info("  page length:        0x{:04x}", m_page_length);
            Log::Info("  nand length:        0x{:08x}", m_image_length_real);
            Log::Info("  block length:       0x{:08x}", m_block_length_real);
            Log::Info("  block data length:  0x{:08x}", m_block_length);
            Log::Info("  lilblock length:    0x{:08x}", m_lil_block_length_real);
            Log::Info("  block count:        0x{:04x}", m_block_count);
            Log::Info("  lilblock count:     0x{:04x}", m_lil_block_count);
            Log::Info("  page count:         0x{:04x}", m_page_count);
            Log::Info("  flashconfig:        0x{:08x}", m_flash_config);
            Log::Info("  spare type:         {}", static_cast<int>(m_spare_type));

            return true;
        }

        // Parse flash config
        switch ((m_flash_config >> 17) & 3) {
            case 0:
                if (m_spare_type != SpareType::OldSmallBlock) {
                    m_spare_type = SpareType::SmallBlock;
                }
                switch ((m_flash_config >> 4) & 3) {
                    case 1:
                        m_block_length = 0x4000;
                        m_block_count = 0x400;
                        break;
                    case 3:
                        m_block_length = 0x4000;
                        m_block_count = 0x1000;
                        m_reserve_block_idx = 0xF80;
                        break;
                }
                break;

            case 1:
            case 2:
                switch ((m_flash_config >> 4) & 3) {
                    case 0:
                        m_block_length = 0x4000;
                        m_block_count = 0x400;
                        m_spare_type = SpareType::BigBlockOnSmall;
                        break;
                    case 1:
                        m_block_length = 0x4000;
                        m_block_count = 0x1000;
                        if (m_image_length_real == 16777216 || m_image_length_real == 17301504) {
                            m_block_count = 0x400;
                        }
                        m_spare_type = SpareType::BigBlockOnSmall;
                        break;
                    case 2:
                        m_block_length = 0x20000;
                        m_block_count = static_cast<uint32_t>(
                            m_image_length_real / ((m_block_length / 512) * m_page_length));
                        m_spare_type = SpareType::BigBlock;
                        m_patch_slot_length = 0x20000;
                        m_reserve_block_idx = 0x1E0;
                        break;
                }
                break;
        }

        // Calculate derived values
        m_config_block_idx = m_reserve_block_idx - 4;
        m_lil_block_length = 0x4000; // static
        m_lil_block_count = (m_block_count * m_block_length) / 0x4000;

        // Calculate real block lengths
        if (m_page_length > 512) {
            m_lil_block_length_real = (m_lil_block_length / 512) * 528;
            m_block_length_real = (m_block_length / 512) * 528;
        } else {
            m_lil_block_length_real = m_lil_block_length;
            m_block_length_real = m_block_length;
        }

        m_page_count = m_lil_block_count * 0x20;

        m_allocated_blocks.assign(m_lil_block_count, false);
        if (m_reserve_block_idx < m_lil_block_count) {
            for (uint32_t i = m_reserve_block_idx; i < m_lil_block_count; ++i) {
                m_allocated_blocks[i] = true;
            }
        }

        Log::Info("FlashBlockDriver::load_flash_config:");
        Log::Info("  page length:        0x{:04x}", m_page_length);
        Log::Info("  nand length:        0x{:08x}", m_image_length_real);
        Log::Info("  nand data length:   0x{:08x}", m_block_count * m_block_length);
        Log::Info("  block length:       0x{:08x}", m_block_length_real);
        Log::Info("  block data length:  0x{:08x}", m_block_length);
        Log::Info("  lilblock length:    0x{:08x}", m_lil_block_length_real);
        Log::Info("  lilblock data length: 0x{:08x}", m_lil_block_length);
        Log::Info("  block count:        0x{:04x}", m_block_count);
        Log::Info("  lilblock count:     0x{:04x}", m_lil_block_count);
        Log::Info("  page count:         0x{:04x}", m_page_count);
        Log::Info("  flashconfig:        0x{:08x}", m_flash_config);
        Log::Info("  spare type:         {}", static_cast<int>(m_spare_type));
        Log::Info("  config block index: 0x{}", m_config_block_idx);
        Log::Info("  reserve block index: 0x{}", m_reserve_block_idx);

        return true;
    }

    bool FlashBlockDriver::open_continue(size_t length, uint32_t page_length) {
        m_page_length = page_length;
        m_image_length_raw = length;
        m_image_length_real = (length / page_length) * 512;
        m_spare_type = detect_spare_type();

        if (m_flash_config == 0) {
            size_t real_len = (length / page_length) * 512;

            // Round up 16/64MB nands to nearest size
            if (real_len <= 16777216) {
                real_len = 16777216;
            } else if (real_len == 0x0aaaaa00) { // 4GB corona
                real_len = 0x3000000;
            } else if (real_len <= 67108864) {
                real_len = 67108864;
            }

            switch (real_len) {
                case 16777216: // 16MB
                    switch (m_spare_type) {
                        case SpareType::SmallBlock:
                        case SpareType::OldSmallBlock:
                            m_flash_config = FlashConfig::AllOther16M;
                            break;
                        case SpareType::BigBlockOnSmall:
                            m_flash_config = FlashConfig::Jasper16M_NewSB;
                            break;
                        case SpareType::BigBlock:
                            m_flash_config = FlashConfig::Jasper16M_NewSB;
                            break;
                        case SpareType::Corona4GB:
                            break;
                    }
                    break;

                case 67108864: // 64MB
                    switch (m_spare_type) {
                        case SpareType::SmallBlock:
                        case SpareType::OldSmallBlock:
                            m_flash_config = FlashConfig::AllOther64M;
                            break;
                        case SpareType::BigBlockOnSmall:
                            m_flash_config = FlashConfig::Jasper64M_NewSB;
                            break;
                        case SpareType::BigBlock:
                            m_flash_config = FlashConfig::Jasper256_512_LargeBlock;
                            break;
                        case SpareType::Corona4GB:
                            break;
                    }
                    break;

                case 268435456:
                case 268435456 - 0x80000:
                    m_fs_offset = 0x2E0;
                    m_flash_config = FlashConfig::Corona256M;
                    break;

                case 536870912:
                case 536870912 - 0x80000:
                    m_fs_offset = 0xAE0;
                    m_flash_config = FlashConfig::Corona512M;
                    break;

                case 0x3000000: // 4GB corona
                    m_fs_offset = 0;
                    m_flash_config = FlashConfig::Corona4GB;
                    m_page_length = 512;
                    break;

                default:
                    Log::Warn("open_continue: unknown NAND size, handling as 16MB!");
                    m_flash_config = FlashConfig::AllOther16M;
                    m_block_length = 0x4000;
                    m_block_count = 0x400;
                    break;
            }
        }

        return load_flash_config();
    }

    bool FlashBlockDriver::create_defaults(size_t img_len, uint32_t page_len, SpareType spare_type,
                                           uint32_t flash_config, uint32_t fs_offset) {
        m_page_length = page_len;
        m_image_length_raw = img_len;
        m_image_length_real = (img_len / page_len) * 512;
        m_image_data.resize(img_len, 0x00);
        m_spare_type = spare_type;
        m_flash_config = flash_config;
        m_fs_offset = fs_offset;

        if (!load_flash_config()) {
            return false;
        }

        // Initialize spare data for all pages
        uint8_t spare[0x10] = {0};
        for (uint32_t i = 0; i < m_page_count; i++) {
            set_spare_bad_block(spare, false);
            const uint32_t blk_idx = static_cast<uint32_t>(i / (m_lil_block_length / 0x200));
            set_spare_index_field(spare, static_cast<uint16_t>(blk_idx));
            if (!write_page_spare(i, spare)) {
                Log::Error("create_defaults: failed to write page spare for page {}", i);
                return false;
            }
        }

        return true;
    }

    std::optional<std::vector<uint8_t>> FlashBlockDriver::create_image(size_t length,
                                                                       uint32_t flash_config) {
        const uint32_t page_len = (flash_config == FlashConfig::Corona4GB) ? 512 : 528;
        const size_t page_count = (length / 512) + ((length % 512) != 0 ? 1 : 0);
        const size_t raw_length = page_count * page_len;

        m_image_data.assign(raw_length, 0x00);
        m_page_length = page_len;
        m_image_length_raw = raw_length;
        m_image_length_real = page_count * 512;
        m_flash_config = flash_config;

        if (!load_flash_config()) {
            return std::nullopt;
        }

        init_spare();
        return m_image_data;
    }

    std::optional<std::vector<uint8_t>> FlashBlockDriver::open_image(const std::string& path) {
        auto data = Utils::read_file(path);
        if (!data) {
            Log::Error("open_image: failed to read file: {}", path);
            return std::nullopt;
        }

        m_image_data = std::move(*data);
        return open_continue(m_image_data.size(), 528)
                   ? std::optional<std::vector<uint8_t>>(m_image_data)
                   : std::nullopt;
    }

    bool FlashBlockDriver::save_image(const std::string& path) {
        if (m_page_length >= 0x210) {
            for (uint32_t i = 0; i < m_page_count; i++) {
                const size_t page_offset = static_cast<size_t>(i) * m_page_length;
                if (page_offset + m_page_length <= m_image_data.size()) {
                    calculate_edc(reinterpret_cast<uint32_t*>(m_image_data.data() + page_offset));
                }
            }
        }

        return Utils::write_file(path, m_image_data);
    }

    void FlashBlockDriver::reserve_logical_block(uint32_t block_idx) {
        if (m_allocated_blocks.size() < m_lil_block_count) {
            m_allocated_blocks.resize(m_lil_block_count, false);
        }
        if (block_idx < m_allocated_blocks.size()) {
            m_allocated_blocks[block_idx] = true;
        }
    }

    void FlashBlockDriver::reserve_logical_blocks(uint32_t start_block_idx, uint32_t count) {
        for (uint32_t i = 0; i < count; ++i) {
            reserve_logical_block(start_block_idx + i);
        }
    }

    bool FlashBlockDriver::is_block_free(uint32_t block_idx) const {
        if (block_idx >= m_allocated_blocks.size()) {
            return block_idx < m_lil_block_count;
        }
        return !m_allocated_blocks[block_idx];
    }

    std::optional<uint32_t> FlashBlockDriver::allocate_logical_block(uint8_t block_type,
                                                                    uint32_t sequence,
                                                                    uint32_t min_block) {
        if (m_allocated_blocks.size() < m_lil_block_count) {
            m_allocated_blocks.resize(m_lil_block_count, false);
        }

        for (uint32_t i = min_block; i < m_lil_block_count; ++i) {
            if (!m_allocated_blocks[i]) {
                m_allocated_blocks[i] = true;

                if ((block_type != 0 || sequence != 0) && m_page_length >= 0x210) {
                    const uint32_t pages_per_block =
                        (m_lil_block_length != 0) ? (m_lil_block_length / 512) : 32;
                    const uint32_t start_page = i * pages_per_block;
                    const uint32_t raw_page_count =
                        static_cast<uint32_t>(m_image_data.size() / m_page_length);

                    for (uint32_t p = 0; p < pages_per_block; ++p) {
                        const uint32_t page_idx = start_page + p;
                        if (page_idx >= raw_page_count) break;

                        std::array<uint8_t, 16> spare{};
                        spare.fill(0xFF);
                        set_spare_bad_block(spare.data(), false);
                        set_spare_index_field(spare.data(), static_cast<uint16_t>(i));
                        if (block_type != 0) set_spare_block_type_field(spare.data(), block_type);
                        if (sequence != 0) set_spare_seq_field(spare.data(), sequence);
                        write_page_spare(page_idx, spare.data());
                    }
                }
                return i;
            }
        }
        return std::nullopt;
    }

    bool FlashBlockDriver::write_logical_block(uint32_t block_idx, const uint8_t* buffer,
                                               size_t length, uint8_t block_type,
                                               uint32_t sequence, uint16_t fs_size) {
        if (block_idx >= m_lil_block_count) {
            Log::Error("write_logical_block: block index {} exceeds block count {}", block_idx,
                       m_lil_block_count);
            return false;
        }

        reserve_logical_block(block_idx);

        if (!write_lil_block(block_idx, buffer, length)) {
            return false;
        }

        if (m_page_length >= 0x210) {
            const uint32_t pages_per_block =
                (m_lil_block_length != 0) ? (m_lil_block_length / 512) : 32;
            const uint32_t start_page = block_idx * pages_per_block;
            const uint32_t raw_page_count =
                static_cast<uint32_t>(m_image_data.size() / m_page_length);

            for (uint32_t p = 0; p < pages_per_block; ++p) {
                const uint32_t page_idx = start_page + p;
                if (page_idx >= raw_page_count) {
                    break;
                }

                std::array<uint8_t, 16> spare{};
                spare.fill(0xFF);
                set_spare_bad_block(spare.data(), false);
                set_spare_index_field(spare.data(), static_cast<uint16_t>(block_idx));

                if (block_type != 0) {
                    set_spare_block_type_field(spare.data(), block_type);
                }
                if (sequence != 0) {
                    set_spare_seq_field(spare.data(), sequence);
                }
                if (fs_size != 0) {
                    set_spare_size_field(spare.data(), fs_size);
                    const uint8_t fs_page_count =
                        static_cast<uint8_t>(pages_per_block - (p % pages_per_block));
                    set_spare_page_count_field(spare.data(), fs_page_count);
                }

                if (!write_page_spare(page_idx, spare.data())) {
                    return false;
                }
            }
        }

        return true;
    }

    std::optional<std::vector<uint8_t>>
    FlashBlockDriver::read_logical_block(uint32_t block_idx) const {
        return read_lil_block(block_idx, m_lil_block_length);
    }

} // namespace gxbuild3::utils
