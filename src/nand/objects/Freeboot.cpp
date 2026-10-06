#include "nand/objects/Freeboot.hpp"

#include "Wire.hpp"
#include "freeboot.h"
#include "payload.h"

#include <algorithm>
#include <array>

namespace gxbuild3::nand {

    namespace {

        constexpr size_t kVersionLength = 0x20;
        constexpr size_t kLoadWordsOffset = 0x52;

    } // namespace

    std::span<const uint8_t> freeboot_rebooter() {
        return {freeboot, freeboot_size};
    }
    std::span<const uint8_t> freeboot_payload() {
        return {payload, payload_size};
    }

    std::vector<uint8_t> freeboot_rebooter_for(std::string_view version) {
        const auto core = freeboot_rebooter();
        std::vector<uint8_t> out(core.begin(), core.end());

        const std::array<uint8_t, kVersionLength> blank = [] {
            std::array<uint8_t, kVersionLength> x{};
            x.fill('X');
            return x;
        }();
        const auto at = std::search(out.begin(), out.end(), blank.begin(), blank.end());
        if (at != out.end()) {
            std::fill_n(at, kVersionLength, uint8_t{0});
            std::copy_n(version.begin(), std::min(version.size(), kVersionLength), at);
        }

        if (version == "9199") {
            static constexpr std::array<uint8_t, 8> kHold{0x80, 0x00, 0x00, 0x00,
                                                          0x01, 0x00, 0x30, 0x78};
            static constexpr std::array<uint8_t, 8> kOldHold{0x80, 0x00, 0x00, 0x00,
                                                             0x00, 0x1F, 0xFF, 0xF8};
            const auto hold = std::search(out.begin(), out.end(), kHold.begin(), kHold.end());
            if (hold != out.end()) {
                std::copy(kOldHold.begin(), kOldHold.end(), hold);
            }
        }
        return out;
    }

    std::vector<uint8_t> freeboot_payload_for(size_t core_length) {
        const auto bytes = freeboot_payload();
        std::vector<uint8_t> out(bytes.begin(), bytes.end());
        const size_t words = (core_length + 3) / 4;
        std::ranges::copy(wire::encode(wire::be16{static_cast<uint16_t>(words)}),
                          out.begin() + kLoadWordsOffset);
        return out;
    }

} // namespace gxbuild3::nand
