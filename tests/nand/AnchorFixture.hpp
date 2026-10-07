#pragma once

// The synthetic runtime-anchor images shared by the anchor, spill-chain and JTAG-window tests in
// tests/nand: a raw executable XeLL, a FlashImage of one shape whose patchset holds one KHV
// record, and the small CB and CD stages a JTAG window carries. raw_xell, anchor_image (the old
// fixture()), synthetic_cb and synthetic_cd are the old tests/AnchorLayoutTests.cpp builders,
// same bytes.

#include "Args.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/objects/XeLL.hpp"
#include "support/Bytes.hpp"

#include <cstdint>
#include <optional>

namespace gxbuild3::nand {

    // 0x40000 bytes: four PowerPC branch words (0x48000020, 0x480000EC, 0x48000000,
    // 0x48000000), then zeros. XeLL::parse takes it as a raw executable.
    [[nodiscard]] test::Bytes raw_xell();

    // An image of `mode` (Smallblock, Bigordevkit or Emmcblock driver) whose patchset is empty CB
    // and CD sections followed by one valid runtime KHV record (address 0x1000, one word
    // 0x60000000), with a fourth empty section for Jtag. A patchset that fails to parse leaves
    // the image without one, silently, as the old fixture() did.
    [[nodiscard]] FlashImage anchor_image(Driver::DriverMode mode, BuildType type);

    // A 0x100-byte CB or CD stage of `fill` bytes, header magic and size set, nothing sealed.
    [[nodiscard]] BootloaderCb synthetic_cb(uint8_t fill);
    [[nodiscard]] BootloaderCd synthetic_cd(uint8_t fill);

    // The XeLL's bytes, or none when there is no XeLL.
    [[nodiscard]] test::Bytes xell_bytes(const std::optional<XeLL>& xell);

} // namespace gxbuild3::nand
