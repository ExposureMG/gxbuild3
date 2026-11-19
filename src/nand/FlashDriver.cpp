#include "nand/FlashDriver.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstring>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

    Driver::Driver(ImageSize size, DriverMode mode) : m_driver_mode(mode), m_image_size(size) {
        switch (m_driver_mode) {
            case DriverMode::Small:
            case DriverMode::NewSmall:
            case DriverMode::Big:
                m_page_size = 528;
                break;
            case DriverMode::Emmc:
                m_page_size = 512;
                break;
        }

        size_t initial_size = 0;
        switch (m_image_size) {
            case ImageSize::Smallblock:
                initial_size = 17301504;
                break;
            case ImageSize::Emmcblock:
                initial_size = 49283072;
                break;
            case ImageSize::Bigordevkit:
                initial_size = 69206016;
                break;
        }

        m_nand_image.assign(initial_size, 0);
    }

    Driver::Driver(std::vector<uint8_t> image)
        : m_nand_image(std::move(image)), m_driver_mode(detect_driver_mode(m_nand_image)),
          m_image_size(detect_image_size(m_nand_image)),
          m_page_size((m_driver_mode == DriverMode::Emmc) ? 512 : 528) {
        Log::Debug("Initialized FlashDriver: size={} bytes, page_size={} bytes, blocks={}",
                   m_nand_image.size(), m_page_size, block_count());
    }

    Driver::ImageSize Driver::detect_image_size(size_t size) {
        if (size <= 17301504) {
            return ImageSize::Smallblock;
        }
        if (size <= 50331648) {
            return ImageSize::Emmcblock;
        }
        return ImageSize::Bigordevkit;
    }

    Driver::ImageSize Driver::detect_image_size(std::span<const uint8_t> image) {
        return detect_image_size(image.size());
    }

    Driver::DriverMode Driver::detect_driver_mode(std::span<const uint8_t> image) {
        if (image.size() < 0x4410 || image.size() % 528 != 0) {
            return DriverMode::Emmc;
        }

        const uint8_t* p20_spare = image.data() + 0x4400;

        // Step 1: Check XSB format (spare type 0)
        //   block_id: low byte at spare[0], high nibble at spare[1]
        //   bad block marker at spare[5]
        uint16_t xsb_block = static_cast<uint16_t>(p20_spare[0] | ((p20_spare[1] & 0x0F) << 8));
        if (xsb_block == 1 && p20_spare[5] == 0xFF) {
            return DriverMode::Small;
        }

        // Step 2: Check PSB/NewSmall format (spare type 1)
        //   block_id: low byte at spare[1], high nibble at spare[2]
        //   bad block marker at spare[5]
        uint16_t psb_block = static_cast<uint16_t>(p20_spare[1] | ((p20_spare[2] & 0x0F) << 8));
        if (psb_block == 1 && p20_spare[5] == 0xFF) {
            return DriverMode::NewSmall;
        }

        // Step 3: Check Big Block format (spare type 2)
        //   block_id: low byte at spare[1], high nibble at spare[2]
        //   bad block marker at spare[0]
        if (image.size() >= 0x21210) {
            const uint8_t* p100_spare = image.data() + 0x21200;
            uint16_t bb_block =
                static_cast<uint16_t>(p100_spare[1] | ((p100_spare[2] & 0x0F) << 8));
            if (bb_block == 1 && p100_spare[0] == 0xFF) {
                return DriverMode::Big;
            }
        }

        // Step 4: Fallback — if image is larger than 16MB, assume Big Block
        if (image.size() > 17301504) {
            return DriverMode::Big;
        }

        return DriverMode::Small;
    }

    Driver::DriverMode Driver::driver_mode() const {
        return m_driver_mode;
    }

    Driver::ImageSize Driver::image_size() const {
        return m_image_size;
    }

    size_t Driver::page_size() const {
        return m_page_size;
    }

    size_t Driver::pages_per_block() const {
        switch (m_driver_mode) {
            case DriverMode::Big:
                return 256;
            case DriverMode::Small:
            case DriverMode::NewSmall:
            case DriverMode::Emmc:
            default:
                return 32;
        }
    }

    size_t Driver::block_count() const {
        size_t raw_block_size = block_size_raw();
        if (raw_block_size == 0) {
            return 0;
        }
        return m_nand_image.size() / raw_block_size;
    }

    size_t Driver::block_size_clean() const {
        return pages_per_block() * 512;
    }

    size_t Driver::block_size_raw() const {
        return pages_per_block() * m_page_size;
    }

    void Driver::input(std::vector<uint8_t> image) {
        m_nand_image = std::move(image);
        m_driver_mode = detect_driver_mode(m_nand_image);
        m_image_size = detect_image_size(m_nand_image);
        m_page_size = (m_driver_mode == DriverMode::Emmc) ? 512 : 528;
    }

    std::span<const uint8_t> Driver::read_page(size_t page) const {
        size_t offset = page * m_page_size;
        if (offset + 512 > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, 512};
    }

    std::span<uint8_t> Driver::read_page(size_t page) {
        size_t offset = page * m_page_size;
        if (offset + 512 > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, 512};
    }

    void Driver::write_page(size_t page, std::span<const uint8_t> data) {
        size_t offset = page * m_page_size;
        if (offset + 512 > m_nand_image.size()) {
            return;
        }
        size_t write_len = std::min<size_t>(data.size(), 512);
        std::copy_n(data.data(), write_len, m_nand_image.data() + offset);
        if (write_len < 512) {
            std::fill_n(m_nand_image.data() + offset + write_len, 512 - write_len, 0);
        }
    }

    void Driver::write_data(size_t start_page, std::span<const uint8_t> data) {
        size_t bytes_written = 0;
        size_t current_page = start_page;

        while (bytes_written < data.size()) {
            size_t chunk_size =
                std::min<size_t>(data.size() - bytes_written, static_cast<size_t>(512));
            std::span<const uint8_t> chunk = data.subspan(bytes_written, chunk_size);
            write_page(current_page, chunk);
            bytes_written += chunk_size;
            current_page++;
        }
    }

    std::vector<uint8_t> Driver::read_data(size_t start_page, size_t num_pages) const {
        std::vector<uint8_t> result;
        result.reserve(num_pages * 512);

        for (size_t i = 0; i < num_pages; ++i) {
            auto page_span = read_page(start_page + i);
            if (page_span.empty()) {
                break;
            }
            result.insert(result.end(), page_span.begin(), page_span.end());
        }

        return result;
    }

    std::span<const uint8_t> Driver::read_page_raw(size_t page, size_t length) const {
        size_t offset = page * m_page_size;
        size_t size = length * m_page_size;
        if (offset + size > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, size};
    }

    std::span<uint8_t> Driver::read_page_raw(size_t page, size_t length) {
        size_t offset = page * m_page_size;
        size_t size = length * m_page_size;
        if (offset + size > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, size};
    }

    void Driver::write_page_raw(size_t page, std::span<const uint8_t> data) {
        size_t offset = page * m_page_size;
        if (offset + data.size() > m_nand_image.size()) {
            return;
        }
        std::copy(data.begin(), data.end(), m_nand_image.begin() + offset);
    }

    std::span<const uint8_t> Driver::read_page_spare(size_t page) const {
        if (m_driver_mode == DriverMode::Emmc) {
            return {};
        }
        size_t offset = (page * m_page_size) + 512;
        if (offset + 16 > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, 16};
    }

    std::span<uint8_t> Driver::read_page_spare(size_t page) {
        if (m_driver_mode == DriverMode::Emmc) {
            return {};
        }
        size_t offset = (page * m_page_size) + 512;
        if (offset + 16 > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, 16};
    }

    void Driver::write_page_spare(size_t page, std::span<const uint8_t> spare) {
        if (m_driver_mode == DriverMode::Emmc) {
            return;
        }
        size_t offset = (page * m_page_size) + 512;
        size_t write_len = std::min<size_t>(spare.size(), 16);
        if (offset + write_len > m_nand_image.size()) {
            return;
        }
        std::copy_n(spare.data(), write_len, m_nand_image.data() + offset);
    }

    std::vector<uint8_t> Driver::read_block(size_t block_idx) const {
        if (m_driver_mode == DriverMode::Emmc) {
            size_t offset = block_idx * 0x4000;
            if (offset + 0x4000 > m_nand_image.size()) {
                return {};
            }
            return {m_nand_image.begin() + offset, m_nand_image.begin() + offset + 0x4000};
        }
        size_t ppb = pages_per_block();
        return read_data(block_idx * ppb, ppb);
    }

    void Driver::write_block(size_t block_idx, std::span<const uint8_t> data) {
        if (m_driver_mode == DriverMode::Emmc) {
            size_t offset = block_idx * 0x4000;
            if (offset >= m_nand_image.size()) {
                return;
            }
            size_t write_len = std::min<size_t>(data.size(), std::min<size_t>(0x4000, m_nand_image.size() - offset));
            std::copy_n(data.data(), write_len, m_nand_image.data() + offset);
            if (write_len < 0x4000 && offset + 0x4000 <= m_nand_image.size()) {
                std::fill_n(m_nand_image.data() + offset + write_len, 0x4000 - write_len, 0);
            }
            return;
        }
        size_t ppb = pages_per_block();
        write_data(block_idx * ppb, data);
    }

    std::span<const uint8_t> Driver::read_block_raw(size_t block_idx) const {
        size_t ppb = pages_per_block();
        return read_page_raw(block_idx * ppb, ppb);
    }

    std::span<uint8_t> Driver::read_block_raw(size_t block_idx) {
        size_t ppb = pages_per_block();
        return read_page_raw(block_idx * ppb, ppb);
    }

    void Driver::write_block_raw(size_t block_idx, std::span<const uint8_t> data) {
        size_t raw_size = block_size_raw();
        size_t start_offset = block_idx * raw_size;
        if (start_offset + data.size() > m_nand_image.size()) {
            return;
        }
        std::copy(data.begin(), data.end(), m_nand_image.begin() + start_offset);
    }

    BlockMetadata Driver::interpret_block(size_t block_idx) const {
        BlockMetadata meta{};
        if (m_driver_mode == DriverMode::Emmc) {
            meta.logical_block_id = static_cast<uint16_t>(block_idx);
            meta.is_bad = false;
            return meta;
        }

        size_t first_page = block_idx * pages_per_block();
        auto spare = read_page_spare(first_page);
        if (spare.size() < 16) {
            return meta;
        }

        if (m_driver_mode == DriverMode::Big) {
            meta.is_bad = (spare[0] != 0xFF);
            if (!meta.is_bad && pages_per_block() > 1) {
                auto spare1 = read_page_spare(first_page + 1);
                if (spare1.size() >= 16 && spare1[0] != 0xFF) {
                    meta.is_bad = true;
                }
            }

            meta.logical_block_id = static_cast<uint16_t>(((spare[2] & 0x0F) << 8) | spare[1]);
            meta.sequence = static_cast<uint32_t>(spare[5] | (spare[3] << 8) | (spare[4] << 16) |
                                                  (spare[6] << 24));
            meta.fs_size = static_cast<uint16_t>(spare[7] | (spare[8] << 8));
            meta.block_type = spare[0xC];
            meta.page_count = spare[0x9];
        } else if (m_driver_mode == DriverMode::NewSmall) {
            // PSB/NewSmall layout (spare type 1):
            //   block_id: low byte at spare[1], high nibble at spare[2]
            //   sequence byte 0 at spare[0]
            //   bad block marker at spare[5]
            meta.is_bad = (spare[5] != 0xFF);
            if (!meta.is_bad && pages_per_block() > 1) {
                auto spare1 = read_page_spare(first_page + 1);
                if (spare1.size() >= 16 && spare1[5] != 0xFF) {
                    meta.is_bad = true;
                }
            }

            meta.logical_block_id = static_cast<uint16_t>(((spare[2] & 0x0F) << 8) | spare[1]);
            meta.sequence = static_cast<uint32_t>(spare[0] | (spare[3] << 8) | (spare[4] << 16) |
                                                  (spare[6] << 24));
            meta.fs_size = static_cast<uint16_t>(spare[7] | (spare[8] << 8));
            meta.block_type = spare[0xC];
            meta.page_count = spare[0x9];
        } else {
            // XSB/Small layout (spare type 0):
            //   block_id: low byte at spare[0], high nibble at spare[1]
            //   sequence byte 0 at spare[2]
            //   bad block marker at spare[5]
            meta.is_bad = (spare[5] != 0xFF);
            if (!meta.is_bad && pages_per_block() > 1) {
                auto spare1 = read_page_spare(first_page + 1);
                if (spare1.size() >= 16 && spare1[5] != 0xFF) {
                    meta.is_bad = true;
                }
            }

            meta.logical_block_id = static_cast<uint16_t>(((spare[1] & 0x0F) << 8) | spare[0]);
            meta.sequence = static_cast<uint32_t>(spare[2] | (spare[3] << 8) | (spare[4] << 16) |
                                                  (spare[6] << 24));
            meta.fs_size = static_cast<uint16_t>(spare[7] | (spare[8] << 8));
            meta.block_type = spare[0xC];
            meta.page_count = spare[0x9];
        }

        return meta;
    }

    bool Driver::is_bad_block(size_t block_idx) const {
        if (m_driver_mode == DriverMode::Emmc) {
            return false;
        }

        size_t first_page = block_idx * pages_per_block();
        auto spare0 = read_page_spare(first_page);
        if (spare0.size() < 16) {
            return false;
        }

        if (m_driver_mode == DriverMode::Big) {
            if (spare0[0] != 0xFF) {
                return true;
            }
            auto spare1 = read_page_spare(first_page + 1);
            return spare1.size() >= 16 && spare1[0] != 0xFF;
        } else {
            if (spare0[5] != 0xFF) {
                return true;
            }
            auto spare1 = read_page_spare(first_page + 1);
            return spare1.size() >= 16 && spare1[5] != 0xFF;
        }
    }

    void Driver::mark_bad_block(size_t block_idx) {
        if (m_driver_mode == DriverMode::Emmc) {
            return;
        }

        size_t ppb = pages_per_block();
        size_t first_page = block_idx * ppb;

        for (size_t p = 0; p < std::min<size_t>(ppb, 2); ++p) {
            auto spare = read_page_spare(first_page + p);
            if (spare.size() >= 16) {
                std::vector<uint8_t> updated_spare(spare.begin(), spare.end());
                if (m_driver_mode == DriverMode::Big) {
                    updated_spare[0] = 0x00;
                } else {
                    updated_spare[5] = 0x00;
                }
                write_page_spare(first_page + p, updated_spare);
            }
        }
    }

    void Driver::set_layout(NandLayout layout) {
        m_layout = std::move(layout);
    }

    const NandLayout& Driver::layout() const {
        return m_layout;
    }

    void Driver::write_block_metadata(size_t block_idx, const BlockMetadata& meta) {
        if (m_driver_mode == DriverMode::Emmc) {
            return;
        }

        size_t ppb = pages_per_block();
        size_t first_page = block_idx * ppb;

        for (size_t p = 0; p < ppb; ++p) {
            auto current_spare = read_page_spare(first_page + p);
            std::vector<uint8_t> spare_data(16, 0xFF);
            if (current_spare.size() >= 16) {
                std::copy_n(current_spare.begin(), 16, spare_data.begin());
            }

            if (m_driver_mode == DriverMode::Big) {
                if (meta.is_bad && p < 2) {
                    spare_data[0] = 0x00;
                } else if (!meta.is_bad && p < 2) {
                    spare_data[0] = 0xFF;
                }

                spare_data[1] = static_cast<uint8_t>(meta.logical_block_id & 0xFF);
                spare_data[2] = static_cast<uint8_t>((spare_data[2] & 0xF0) |
                                                     ((meta.logical_block_id >> 8) & 0x0F));
                spare_data[5] = static_cast<uint8_t>(meta.sequence & 0xFF);
                spare_data[3] = static_cast<uint8_t>((meta.sequence >> 8) & 0xFF);
                spare_data[4] = static_cast<uint8_t>((meta.sequence >> 16) & 0xFF);
                spare_data[6] = static_cast<uint8_t>((meta.sequence >> 24) & 0xFF);
                spare_data[9] = meta.page_count;
                spare_data[0xC] = meta.block_type;
            } else if (m_driver_mode == DriverMode::NewSmall) {
                // PSB/NewSmall layout (spare type 1):
                //   block_id: low byte at spare[1], high nibble at spare[2]
                //   sequence byte 0 at spare[0]
                //   bad block marker at spare[5]
                if (meta.is_bad && p < 2) {
                    spare_data[5] = 0x00;
                } else if (!meta.is_bad && p < 2) {
                    spare_data[5] = 0xFF;
                }

                spare_data[1] = static_cast<uint8_t>(meta.logical_block_id & 0xFF);
                spare_data[2] = static_cast<uint8_t>((spare_data[2] & 0xF0) |
                                                     ((meta.logical_block_id >> 8) & 0x0F));
                spare_data[0] = static_cast<uint8_t>(meta.sequence & 0xFF);
                spare_data[3] = static_cast<uint8_t>((meta.sequence >> 8) & 0xFF);
                spare_data[4] = static_cast<uint8_t>((meta.sequence >> 16) & 0xFF);
                spare_data[6] = static_cast<uint8_t>((meta.sequence >> 24) & 0xFF);
                spare_data[9] = meta.page_count;
                spare_data[0xC] = meta.block_type;
            } else {
                // XSB/Small layout (spare type 0):
                //   block_id: low byte at spare[0], high nibble at spare[1]
                //   sequence byte 0 at spare[2]
                //   bad block marker at spare[5]
                if (meta.is_bad && p < 2) {
                    spare_data[5] = 0x00;
                } else if (!meta.is_bad && p < 2) {
                    spare_data[5] = 0xFF;
                }

                spare_data[0] = static_cast<uint8_t>(meta.logical_block_id & 0xFF);
                spare_data[1] = static_cast<uint8_t>((spare_data[1] & 0xF0) |
                                                     ((meta.logical_block_id >> 8) & 0x0F));
                spare_data[2] = static_cast<uint8_t>(meta.sequence & 0xFF);
                spare_data[3] = static_cast<uint8_t>((meta.sequence >> 8) & 0xFF);
                spare_data[4] = static_cast<uint8_t>((meta.sequence >> 16) & 0xFF);
                spare_data[6] = static_cast<uint8_t>((meta.sequence >> 24) & 0xFF);
                spare_data[9] = meta.page_count;
                spare_data[0xC] = meta.block_type;
            }

            if (meta.fs_size != 0) {
                spare_data[0x7] = static_cast<uint8_t>(meta.fs_size & 0xFF);
                spare_data[0x8] = static_cast<uint8_t>((meta.fs_size >> 8) & 0xFF);
            }

            write_page_spare(first_page + p, spare_data);
        }
    }

    bool Driver::is_block_free(size_t block_idx) const {
        if (block_idx >= block_count() || is_bad_block(block_idx)) {
            return false;
        }

        if (m_driver_mode == DriverMode::Emmc) {
            size_t offset = block_idx * 0x4000;
            if (offset + 0x4000 > m_nand_image.size()) {
                return false;
            }
            return std::all_of(m_nand_image.begin() + offset, m_nand_image.begin() + offset + 0x4000,
                               [](uint8_t b) { return b == 0x00 || b == 0xFF; });
        }

        auto meta = interpret_block(block_idx);
        return meta.logical_block_id == 0 && (meta.block_type == 0 || meta.block_type == 0x3F);
    }

    std::optional<size_t> Driver::find_next_free_block(size_t start_block) const {
        const size_t total_blocks = block_count();
        for (size_t i = start_block; i < total_blocks; ++i) {
            if (is_block_free(i)) {
                return i;
            }
        }
        return std::nullopt;
    }

    std::optional<size_t> Driver::allocate_block(size_t start_block, uint8_t block_type,
                                                 uint32_t sequence) {
        auto free_block = find_next_free_block(start_block);
        if (!free_block) {
            return std::nullopt;
        }

        if (m_driver_mode != DriverMode::Emmc) {
            BlockMetadata meta{};
            meta.logical_block_id = static_cast<uint16_t>(*free_block);
            meta.sequence = sequence;
            meta.block_type = block_type;
            meta.page_count = 0;
            meta.is_bad = false;
            write_block_metadata(*free_block, meta);
        }

        return free_block;
    }

    std::vector<uint8_t> Driver::read_clean(size_t offset, size_t length) const {
        std::vector<uint8_t> result;
        if (length == 0) {
            return result;
        }
        result.resize(length);

        if (m_driver_mode == DriverMode::Emmc || m_page_size == 512) {
            if (offset + length > m_nand_image.size()) {
                return {};
            }
            std::memcpy(result.data(), m_nand_image.data() + offset, length);
            return result;
        }

        size_t offintopage = offset % 512;
        size_t currpage = 0;
        size_t pageinimage = offset / 512;
        size_t toread = length;

        while (toread > 0) {
            size_t read_len = std::min<size_t>(toread, 512 - offintopage);
            size_t copyto_idx = (currpage * 512) - (currpage > 0 ? (offset % 512) : 0);
            size_t copyfrom_idx = (pageinimage + currpage) * m_page_size + offintopage;

            if (copyfrom_idx + read_len > m_nand_image.size()) {
                return {};
            }

            std::memcpy(result.data() + copyto_idx, m_nand_image.data() + copyfrom_idx, read_len);
            offintopage = 0;
            toread -= read_len;
            currpage++;
        }
        return result;
    }

    std::span<const uint8_t> Driver::read_offset(size_t offset, size_t length) const {
        if (m_driver_mode == DriverMode::Emmc || m_page_size == 512) {
            if (offset + length > m_nand_image.size()) {
                return {};
            }
            return {m_nand_image.data() + offset, length};
        }

        size_t offintopage = offset % 512;
        size_t pageinimage = offset / 512;
        size_t raw_pos = pageinimage * m_page_size + offintopage;
        if (raw_pos + length > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + raw_pos, length};
    }

    std::span<uint8_t> Driver::read_offset(size_t offset, size_t length) {
        if (m_driver_mode == DriverMode::Emmc || m_page_size == 512) {
            if (offset + length > m_nand_image.size()) {
                return {};
            }
            return {m_nand_image.data() + offset, length};
        }

        size_t offintopage = offset % 512;
        size_t pageinimage = offset / 512;
        size_t raw_pos = pageinimage * m_page_size + offintopage;
        if (raw_pos + length > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + raw_pos, length};
    }

    void Driver::write_offset(size_t offset, std::span<const uint8_t> data) {
        if (data.empty()) {
            return;
        }
        if (m_driver_mode == DriverMode::Emmc || m_page_size == 512) {
            if (offset + data.size() > m_nand_image.size()) {
                return;
            }
            std::copy(data.begin(), data.end(), m_nand_image.begin() + offset);
            return;
        }

        size_t offintopage = offset % 512;
        size_t currpage = 0;
        size_t pageinimage = offset / 512;
        size_t towrite = data.size();

        while (towrite > 0) {
            size_t write_len = std::min<size_t>(towrite, 512 - offintopage);
            size_t copyfrom_idx = (currpage * 512) - (currpage > 0 ? (offset % 512) : 0);
            size_t copyto_idx = (pageinimage + currpage) * m_page_size + offintopage;

            if (copyto_idx + write_len > m_nand_image.size()) {
                break;
            }

            std::memcpy(m_nand_image.data() + copyto_idx, data.data() + copyfrom_idx, write_len);
            offintopage = 0;
            towrite -= write_len;
            currpage++;
        }
    }

    namespace {
        void calculate_edc(uint8_t* page_raw) {
            uint8_t* spare = page_raw + 0x200;

            spare[0xC] &= 0x3F;
            spare[0xD] = 0;
            spare[0xE] = 0;
            spare[0xF] = 0;

            uint32_t val = 0;
            uint32_t v = 0;
            uint32_t* data = reinterpret_cast<uint32_t*>(page_raw);

            for (uint32_t i = 0; i < 0x1066; i++) {
                if (i == 0x1000) {
                    data = reinterpret_cast<uint32_t*>(spare);
                }
                if (!(i & 31)) {
                    v = ~(*data++);
                }
                val ^= v & 1;
                v >>= 1;
                if (val & 1) {
                    val ^= 0x6954559;
                }
                val >>= 1;
            }

            val = ~val;

            spare[0xC] = static_cast<uint8_t>((spare[0xC] & 0x3F) | ((val << 6) & 0xC0));
            spare[0xD] = static_cast<uint8_t>((val >> 2) & 0xFF);
            spare[0xE] = static_cast<uint8_t>((val >> 10) & 0xFF);
            spare[0xF] = static_cast<uint8_t>((val >> 18) & 0xFF);
        }
    } // namespace

    std::vector<uint8_t>& Driver::serialize() {
        if (m_driver_mode != DriverMode::Emmc && m_page_size == 528) {
            const size_t total_blks = block_count();
            for (size_t blk = 0; blk < total_blks; ++blk) {
                if (is_bad_block(blk)) {
                    continue;
                }

                BlockMetadata meta{};
                meta.logical_block_id = static_cast<uint16_t>(blk);
                meta.is_bad = false;

                if (m_layout.fs_root_block != 0 && blk == m_layout.fs_root_block) {
                    meta.block_type = 0x30;
                    meta.sequence = m_layout.fs_version;
                    meta.fs_size = m_layout.fs_size;
                    write_block_metadata(blk, meta);
                } else {
                    bool is_mobile = false;
                    for (const auto& mob : m_layout.mobile_blocks) {
                        if (blk >= mob.start_block && blk < mob.start_block + mob.block_count) {
                            meta.block_type = mob.block_type;
                            meta.sequence = 1;
                            write_block_metadata(blk, meta);
                            is_mobile = true;
                            break;
                        }
                    }

                    if (!is_mobile) {
                        if (blk < 0x50) {
                            meta.block_type = 0x00;
                            meta.sequence = 0;
                            write_block_metadata(blk, meta);
                        }
                    }
                }
            }

            size_t total_pages = m_nand_image.size() / 528;
            for (size_t p = 0; p < total_pages; ++p) {
                size_t page_offset = p * 528;
                calculate_edc(m_nand_image.data() + page_offset);
            }
        }
        return m_nand_image;
    }

    const std::vector<uint8_t>& Driver::serialize() const {
        return m_nand_image;
    }

    void Driver::clean() {
        m_nand_image.clear();
    }

} // namespace gxbuild3::NAND