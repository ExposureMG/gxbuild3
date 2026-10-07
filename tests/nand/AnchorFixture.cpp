#include "nand/AnchorFixture.hpp"

#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Patchset.hpp"

#include <algorithm>
#include <utility>

namespace gxbuild3::nand {

    using test::Bytes;

    Bytes raw_xell() {
        Bytes b(0x40000, 0);
        const Bytes entry{0x48, 0, 0, 0x20, 0x48, 0, 0, 0xEC, 0x48, 0, 0, 0, 0x48, 0, 0, 0};
        std::copy(entry.begin(), entry.end(), b.begin());
        return b;
    }

    FlashImage anchor_image(Driver::DriverMode mode, BuildType type) {
        FlashImage f{};
        f.flash_driver = Driver(mode == Driver::DriverMode::Big ? Driver::Bigordevkit
                                : mode == Driver::Emmc          ? Driver::Emmcblock
                                                                : Driver::Smallblock,
                                mode);
        // Empty CB/CD patch sections followed by one valid runtime KHV record.
        Bytes p{255, 255, 255, 255, 255,  255, 255, 255, 0,   0,   0x10, 0,
                0,   0,   0,   1,   0x60, 0,   0,   0,   255, 255, 255,  255};
        if (type == BuildType::Jtag) {
            p.insert(p.begin() + 8, {255, 255, 255, 255});
        }
        if (auto ps = parse_patch_set(p, type)) {
            f.payloads.patchset = std::move(*ps);
        }
        return f;
    }

    BootloaderCb synthetic_cb(uint8_t fill) {
        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.data.resize(0x100, fill);
        cb.header.header.size = sizeof(generic_header) + cb.data.size();
        return cb;
    }

    BootloaderCd synthetic_cd(uint8_t fill) {
        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.data.resize(0x100, fill);
        cd.header.header.size = sizeof(cd_header) + cd.data.size();
        return cd;
    }

    Bytes xell_bytes(const std::optional<XeLL>& xell) {
        return xell ? xell->data : Bytes{};
    }

} // namespace gxbuild3::nand
