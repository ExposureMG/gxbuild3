#include "nand/FlashImage.hpp"
#include "nand/bootloaders/Common.hpp"

#include <algorithm>
#include <iostream>
#include <utility>
using namespace gxbuild3::NAND;
using Bytes = std::vector<uint8_t>;
static bool check(bool ok, const char* message) {
    if (!ok)
        std::cerr << "FAIL: " << message << '\n';
    return ok;
}
static Bytes raw_xell() {
    Bytes b(0x40000, 0);
    const Bytes entry{0x48, 0, 0, 0x20, 0x48, 0, 0, 0xEC, 0x48, 0, 0, 0, 0x48, 0, 0, 0};
    std::copy(entry.begin(), entry.end(), b.begin());
    return b;
}
static FlashImage fixture(Driver::DriverMode mode, BuildType type) {
    FlashImage f{};
    f.flash_driver = Driver(mode == Driver::DriverMode::Big ? Driver::Bigordevkit
                            : mode == Driver::Emmc          ? Driver::Emmcblock
                                                            : Driver::Smallblock,
                            mode);
    // Empty CB/CD patch sections followed by one valid runtime KHV record.
    Bytes p{255, 255, 255, 255, 255,  255, 255, 255, 0,   0,   0x10, 0,
            0,   0,   0,   1,   0x60, 0,   0,   0,   255, 255, 255,  255};
    ParsedPatchSet ps;
    BinaryParser::ParsePatchSet(p, type, ps);
    f.payloads.patchset = ps;
    return f;
}
static uint32_t be32(std::span<const uint8_t> b, size_t o) {
    return uint32_t(b[o]) << 24 | uint32_t(b[o + 1]) << 16 | uint32_t(b[o + 2]) << 8 | b[o + 3];
}
static bool anchors() {
    bool ok = true;
    for (auto mode :
         {Driver::DriverMode::Small, Driver::DriverMode::Big, Driver::DriverMode::Emmc}) {
        for (auto type : {BuildType::Glitch2, BuildType::Glitch2m}) {
            auto f = fixture(mode, type);
            XeLL x{};
            x.data = raw_xell();
            f.payloads.xell = x;
            if (type == BuildType::Glitch2m)
                f.payloads.fuses = Bytes(0x60, 0xA5);
            if (!check(f.write_to_driver(), "runtime-anchor image writes")) {
                ok = false;
                continue;
            }
            const auto& d = std::as_const(f.flash_driver);
            auto h = d.read_offset(0, 0x80);
            auto s = be32(h, 0x64) + be32(h, 0x70);
            auto k = d.read_offset(s + (type == BuildType::Glitch2m ? 0x60 : 0x10), 16);
            ok = check(k.size() == 16 && be32(k, 0) == 0x1000 && be32(k, 4) == 1,
                       "CD finds KHV through header") &&
                 ok;
            auto xb = d.read_offset(0x70000, 0x40000);
            ok = check(Bytes(xb.begin(), xb.end()) == x.data,
                       "CD finds raw XeLL at 0x70000 on every geometry") &&
                 ok;
            if (type == BuildType::Glitch2m) {
                auto v = d.read_offset(s, 0x60);
                ok = check(std::all_of(v.begin(), v.end(), [](auto b) { return b == 0xA5; }),
                           "MFG fuse reader finds fuses at second-slot base") &&
                     ok;
            }
            auto parsed = FlashImage::read(f.write());
            ok = check(parsed && parsed->parse() && parsed->payloads.xell &&
                           parsed->payloads.xell->data == x.data,
                       "extract raw XeLL from runtime anchor") &&
                 ok;
            if (type == BuildType::Glitch2m)
                ok = check(parsed && parsed->payloads.fuses == f.payloads.fuses,
                           "extract manufacturing fuses") &&
                     ok;
        }
    }
    return ok;
}
static bool spill(BuildType type) {
    auto f = fixture(Driver::DriverMode::Big, BuildType::Glitch2);
    if (type != BuildType::Glitch2) f.payloads.patchset.reset();
    if (type == BuildType::Jtag) {
        XeLL x{};
        x.data = raw_xell();
        f.payloads.xell = x;
    }
    f.build_type = type;
    BootloaderCf cf{};
    cf.header.header.magic = NANDBootloaderMagic::CF;
    cf.data.resize(0x400, 0);
    cf.header.header.size = 0x430;
    cf.decrypted = true;
    BootloaderCg cg{};
    cg.header.header.magic = NANDBootloaderMagic::CG;
    cg.data.resize(0x30000, 0xAB);
    cg.header.header.size = sizeof(cg_header) + cg.data.size();
    cg.decrypted = false;
    f.system_update_0 = {cf, cg};
    if (type == BuildType::Retail) f.system_update_1 = {cf, cg};
    f.filesystem = FlashFileSystem{};
    f.filesystem->set_driver(&f.flash_driver);
    f.filesystem->format(f.flash_driver.block_count(), 0x1D0);
    const auto expected = cg.serialize();
    if (!check(f.encrypt_all({}, type) && f.write_to_driver(),
               "oversized CG prepares and writes within its slot"))
        return false;
    if (type == BuildType::Retail) {
        if (!check(!f.system_update_0.cg_spill_blocks.empty() &&
                       !f.system_update_1.cg_spill_blocks.empty(),
                   "retail allocates both CG continuation chains")) return false;
        for (auto block : f.system_update_0.cg_spill_blocks)
            if (!check(std::find(f.system_update_1.cg_spill_blocks.begin(),
                                f.system_update_1.cg_spill_blocks.end(), block) ==
                           f.system_update_1.cg_spill_blocks.end(),
                       "retail continuation chains do not overlap")) return false;
    }
    auto c = *f.system_update_0.cf;
    c.decrypt(key_1bl);
    if (!check(c.data[0] != 0 || c.data[1] != 0, "CF has a CG continuation block list"))
        return false;
    auto parsed = FlashImage::read(f.write());
    if (!check(parsed && parsed->parse() && parsed->system_update_0.cg &&
                   parsed->system_update_0.cg->serialize() == expected,
               "CF block list reconstructs the complete CG ciphertext"))
        return false;
    if (type == BuildType::Retail &&
        !check(parsed->header.patch_slots == 2 && parsed->system_update_1.cg &&
                   parsed->system_update_1.cg->serialize() == expected,
               "retail preserves slot one and reconstructs its complete CG")) return false;
    if (!check(parsed->parse(), "split image can be parsed twice")) return false;
    auto roundtrip = FlashImage::read(parsed->write());
    if (!check(roundtrip && roundtrip->parse() && roundtrip->system_update_0.cg &&
                   roundtrip->system_update_0.cg->serialize() == expected,
               "parsed split CG survives direct write/reparse"))
        return false;
    // A duplicate continuation cluster must not silently replace part of the CG.
    auto corrupt = *f.system_update_0.cf;
    corrupt.decrypt(key_1bl);
    corrupt.data[4] = corrupt.data[2];
    corrupt.data[5] = corrupt.data[3];
    corrupt.encrypt(key_1bl);
    parsed->flash_driver.write_offset(parsed->header.cf_offset, corrupt.serialize());
    auto damaged = FlashImage::read(parsed->flash_driver.serialize());
    if (!check(damaged && !damaged->parse(), "duplicate CG continuation clusters are rejected"))
        return false;
    f.system_update_0.cg->data.resize(0x20);
    f.system_update_0.cg->header.header.size = sizeof(cg_header) + 0x20;
    if (!check(f.encrypt_all({}, type), "shrunk CG prepares"))
        return false;
    auto shrunk = *f.system_update_0.cf;
    shrunk.decrypt(key_1bl);
    return check(shrunk.data[0] == 0 && shrunk.data[1] == 0 &&
                     !f.filesystem->exists("sysupdate.xexp1"),
                 "shrinking CG clears its block table and obsolete continuation file");
}
static bool custom_header_roundtrip() {
    auto f = fixture(Driver::Big, BuildType::Glitch2);
    f.preserve_layout = true;
    f.header.cf_offset = 0x100000;
    f.header.fs_addr = 0x30000;
    auto parsed = FlashImage::read(f.write());
    if (!check(parsed && parsed->parse(), "custom header layout parses"))
        return false;
    auto again = FlashImage::read(parsed->write());
    if (!check(again && again->parse(), "custom header layout rewrites"))
        return false;
    auto bytes = std::as_const(again->flash_driver).read_offset(0x130010, 16);
    return check(again->header.cf_offset == 0x100000 && again->header.fs_addr == 0x30000 &&
                     bytes.size() == 16 && be32(bytes, 0) == 0x1000,
                 "read/write preserves header-derived runtime KHV anchor");
}
int main() {
    bool ok = check(XeLL::parse(raw_xell()).has_value(), "raw executable XeLL is accepted");
    ok = anchors() && ok;
    ok = spill(BuildType::Retail) && ok;
    ok = spill(BuildType::Glitch2) && ok;
    ok = spill(BuildType::Jtag) && ok;
    ok = custom_header_roundtrip() && ok;
    return ok ? 0 : 1;
}
