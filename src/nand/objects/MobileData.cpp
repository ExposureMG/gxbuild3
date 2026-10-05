#include "nand/objects/MobileData.hpp"

namespace gxbuild3::NAND {

    bool MobileData::empty() const noexcept {
        return !x31 && !x32 && !x33 && !x34 && !x35 && !x36 && !x37 && !x38 && !x39;
    }

    std::optional<std::vector<uint8_t>>* MobileData::get_slot(uint8_t block_type) noexcept {
        switch (block_type) {
            case 0x31:
                return &x31;
            case 0x32:
                return &x32;
            case 0x33:
                return &x33;
            case 0x34:
                return &x34;
            case 0x35:
                return &x35;
            case 0x36:
                return &x36;
            case 0x37:
                return &x37;
            case 0x38:
                return &x38;
            case 0x39:
                return &x39;
            default:
                return nullptr;
        }
    }

    const std::optional<std::vector<uint8_t>>*
    MobileData::get_slot(uint8_t block_type) const noexcept {
        switch (block_type) {
            case 0x31:
                return &x31;
            case 0x32:
                return &x32;
            case 0x33:
                return &x33;
            case 0x34:
                return &x34;
            case 0x35:
                return &x35;
            case 0x36:
                return &x36;
            case 0x37:
                return &x37;
            case 0x38:
                return &x38;
            case 0x39:
                return &x39;
            default:
                return nullptr;
        }
    }

} // namespace gxbuild3::NAND
