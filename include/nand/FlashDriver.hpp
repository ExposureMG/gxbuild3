#pragma once

#include "NandTypes.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild3::NAND {
    class Driver {
      public:
        enum DriverMode {
            Small, // Sb
            Big,   // Bb
            Emmc   // Emmc
        };

        enum ImageSize {
            Smallblock,  // 16mb
            Emmcblock,   // 48mb
            Bigordevkit, // 64mb
        };

        Driver(ImageSize size, DriverMode mode);
        explicit Driver(std::vector<uint8_t> image);

        static ImageSize detect_image_size(size_t size);
        static ImageSize detect_image_size(std::span<const uint8_t> image);
        static DriverMode detect_driver_mode(std::span<const uint8_t> image);

        DriverMode driver_mode() const;
        ImageSize image_size() const;
        size_t page_size() const;

        void input(std::vector<uint8_t> image);

        std::span<const uint8_t> read_page(size_t page) const;
        std::span<uint8_t> read_page(size_t page);
        void write_page(size_t page, std::span<const uint8_t> data);

        std::span<const uint8_t> read_page_raw(size_t page, size_t length = 1) const;
        std::span<uint8_t> read_page_raw(size_t page, size_t length = 1);
        void write_page_raw(size_t page, std::span<const uint8_t> data);

        std::span<const uint8_t> read_page_spare(size_t page) const;
        std::span<uint8_t> read_page_spare(size_t page);
        void write_page_spare(size_t page, std::span<const uint8_t> spare);

        std::span<const uint8_t> read_offset(size_t offset, size_t length = 1) const;
        std::span<uint8_t> read_offset(size_t offset, size_t length = 1);
        void write_offset(size_t offset, std::span<const uint8_t> data);

        std::vector<uint8_t>& serialize();
        const std::vector<uint8_t>& serialize() const;
        void clean();

      private:
        std::vector<uint8_t> m_nand_image;
        DriverMode m_driver_mode;
        ImageSize m_image_size;
        size_t m_page_size;
    };

} // namespace gxbuild3::NAND