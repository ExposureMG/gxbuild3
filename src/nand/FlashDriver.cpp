#include "nand/FlashDriver.hpp"

#include <algorithm>
#include <span>
#include <vector>

namespace gxbuild3::NAND {

    Driver::Driver(ImageSize size, DriverMode mode) : m_image_size(size), m_driver_mode(mode) {
        switch (m_driver_mode) {
            case DriverMode::Small:
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
        : m_nand_image(std::move(image)),
          m_image_size(detect_image_size(m_nand_image)),
          m_driver_mode(detect_driver_mode(m_nand_image)),
          m_page_size((m_driver_mode == DriverMode::Emmc) ? 512 : 528) {}

    ImageSize Driver::detect_image_size(size_t size) {
        if (size <= 17301504) {
            return ImageSize::Smallblock;
        }
        if (size <= 50331648) {
            return ImageSize::Emmcblock;
        }
        return ImageSize::Bigordevkit;
    }

    ImageSize Driver::detect_image_size(std::span<const uint8_t> image) {
        return detect_image_size(image.size());
    }

    DriverMode Driver::detect_driver_mode(std::span<const uint8_t> image) {
        if (image.size() < 0x4410 || image.size() % 528 != 0) {
            return DriverMode::Emmc;
        }

        const uint8_t* p20_spare = image.data() + 0x4400;
        uint16_t old_sb_block = static_cast<uint16_t>(p20_spare[0] | ((p20_spare[1] & 0x0F) << 8));
        uint16_t new_sb_block = static_cast<uint16_t>(p20_spare[1] | ((p20_spare[2] & 0x0F) << 8));

        if ((old_sb_block == 1 || new_sb_block == 1) && p20_spare[5] == 0xFF) {
            return DriverMode::Small;
        }

        if (image.size() >= 0x21210) {
            const uint8_t* p100_spare = image.data() + 0x21200;
            uint16_t bb_block = static_cast<uint16_t>(p100_spare[1] | ((p100_spare[2] & 0x0F) << 8));
            if (bb_block == 1 && p100_spare[0] == 0xFF) {
                return DriverMode::Big;
            }
        }

        if (image.size() > 17301504) {
            return DriverMode::Big;
        }

        return DriverMode::Small;
    }

    DriverMode Driver::driver_mode() const {
        return m_driver_mode;
    }

    ImageSize Driver::image_size() const {
        return m_image_size;
    }

    size_t Driver::page_size() const {
        return m_page_size;
    }

    void Driver::input(std::vector<uint8_t> image) {
        m_nand_image = std::move(image);
        m_image_size = detect_image_size(m_nand_image);
        m_driver_mode = detect_driver_mode(m_nand_image);
        m_page_size = (m_driver_mode == DriverMode::Emmc) ? 512 : 528;
    }

    std::span<const uint8_t> Driver::read_page(size_t page) const {
        size_t offset = page * m_page_size;
        if (offset + 512 > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, 512};
    }

    void Driver::write_page(size_t page, std::span<const uint8_t> data) {
        size_t offset = page * m_page_size;
        size_t write_len = std::min<size_t>(data.size(), 512);
        if (offset + write_len > m_nand_image.size()) {
            return;
        }
        std::copy_n(data.data(), write_len, m_nand_image.data() + offset);
    }

    std::span<const uint8_t> Driver::read_page_raw(size_t page, size_t length) const {
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

    std::span<const uint8_t> Driver::read_offset(size_t offset, size_t length) const {
        if (offset + length > m_nand_image.size()) {
            return {};
        }
        return {m_nand_image.data() + offset, length};
    }

    void Driver::write_offset(size_t offset, std::span<const uint8_t> data) {
        if (offset + data.size() > m_nand_image.size()) {
            return;
        }
        std::copy(data.begin(), data.end(), m_nand_image.begin() + offset);
    }

    std::vector<uint8_t>& Driver::serialize() {
        return m_nand_image;
    }

    const std::vector<uint8_t>& Driver::serialize() const {
        return m_nand_image;
    }

    void Driver::clean() {
        m_nand_image.clear();
    }

} // namespace gxbuild3::NAND