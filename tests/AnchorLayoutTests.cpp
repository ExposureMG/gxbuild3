#include "nand/FlashImage.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Freeboot.hpp"

#include <algorithm>
#include <iostream>
#include <utility>

using namespace gxbuild3;
using namespace gxbuild3::nand;
using Bytes = std::vector<uint8_t>;
static bool check(bool ok, const char* message) {
    if (!ok)
        std::cerr << "FAIL: " << message << '\n';
    return ok;
}
static bool check(const Result<>& result, const char* message) {
    if (!result)
        std::cerr << "FAIL: " << message << ": " << result.error().describe() << '\n';
    return result.has_value();
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
    if (type == BuildType::Jtag) {
        p.insert(p.begin() + 8, {255, 255, 255, 255});
    }
    if (auto ps = parse_patch_set(p, type)) {
        f.payloads.patchset = std::move(*ps);
    }
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
            const size_t xell_at = 0x70000;
            auto xb = d.read_offset(xell_at, 0x40000);
            ok = check(Bytes(xb.begin(), xb.end()) == x.data,
                       "CD finds raw XeLL at 0x70000 on every shape") &&
                 ok;
            if (type == BuildType::Glitch2m) {
                auto v = d.read_offset(s, 0x60);
                ok = check(std::all_of(v.begin(), v.end(), [](auto b) { return b == 0xA5; }),
                           "MFG fuse reader finds fuses at second-slot base") &&
                     ok;
            }
            auto parsed = FlashImage::read(f.write().value_or(Bytes{}));
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
    if (type != BuildType::Glitch2)
        f.payloads.patchset.reset();
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
    if (type == BuildType::Retail)
        f.system_update_1 = {cf, cg};
    f.filesystem = FlashFileSystem{};
    f.filesystem->set_driver(&f.flash_driver);
    if (!check(f.filesystem->format(f.flash_driver.block_count(), 0x1D0).has_value(),
               "the filesystem formats"))
        return false;
    const auto expected = cg.serialize();
    if (!check(f.encrypt_all({}, type) && f.write_to_driver(),
               "oversized CG prepares and writes within its slot"))
        return false;
    if (type == BuildType::Retail) {
        if (!check(!f.system_update_0.cg_spill_blocks.empty() &&
                       !f.system_update_1.cg_spill_blocks.empty(),
                   "retail allocates both CG continuation chains"))
            return false;
        for (auto block : f.system_update_0.cg_spill_blocks)
            if (!check(std::find(f.system_update_1.cg_spill_blocks.begin(),
                                 f.system_update_1.cg_spill_blocks.end(),
                                 block) == f.system_update_1.cg_spill_blocks.end(),
                       "retail continuation chains do not overlap"))
                return false;
    }
    auto c = *f.system_update_0.cf;
    c.decrypt_or_throw(key_1bl);
    if (!check(c.data[0] != 0 || c.data[1] != 0, "CF has a CG continuation block list"))
        return false;
    auto parsed = FlashImage::read(f.write().value_or(Bytes{}));
    if (!check(parsed && parsed->parse() && parsed->system_update_0.cg &&
                   parsed->system_update_0.cg->serialize() == expected,
               "CF block list reconstructs the complete CG ciphertext"))
        return false;
    if (type == BuildType::Retail &&
        !check(parsed->header.patch_slots == 2 && parsed->system_update_1.cg &&
                   parsed->system_update_1.cg->serialize() == expected,
               "retail preserves slot one and reconstructs its complete CG"))
        return false;
    if (!check(parsed->parse(), "split image can be parsed twice"))
        return false;
    auto roundtrip = FlashImage::read(parsed->write().value_or(Bytes{}));
    if (!check(roundtrip && roundtrip->parse() && roundtrip->system_update_0.cg &&
                   roundtrip->system_update_0.cg->serialize() == expected,
               "parsed split CG survives direct write/reparse"))
        return false;
    // A duplicate continuation cluster must not silently replace part of the CG.
    auto corrupt = *f.system_update_0.cf;
    corrupt.decrypt_or_throw(key_1bl);
    corrupt.data[4] = corrupt.data[2];
    corrupt.data[5] = corrupt.data[3];
    corrupt.encrypt_or_throw(key_1bl);
    if (!check(parsed->flash_driver.write_offset(parsed->header.cf_offset, corrupt.serialize()),
               "the corrupt CF is laid"))
        return false;
    auto damaged = FlashImage::read(parsed->flash_driver.serialize());
    if (!check(damaged && !damaged->parse(), "duplicate CG continuation clusters are rejected"))
        return false;
    f.system_update_0.cg->data.resize(0x20);
    f.system_update_0.cg->header.header.size = sizeof(cg_header) + 0x20;
    if (!check(f.encrypt_all({}, type), "shrunk CG prepares"))
        return false;
    auto shrunk = *f.system_update_0.cf;
    shrunk.decrypt_or_throw(key_1bl);
    return check(shrunk.data[0] == 0 && shrunk.data[1] == 0 &&
                     !f.filesystem->exists("sysupdate.xexp1"),
                 "shrinking CG clears its block table and obsolete continuation file");
}
static bool custom_header_roundtrip() {
    auto f = fixture(Driver::Big, BuildType::Glitch2);
    f.preserve_layout = true;
    f.header.cf_offset = 0x100000;
    f.header.fs_addr = 0x30000;
    auto parsed = FlashImage::read(f.write().value_or(Bytes{}));
    if (!check(parsed && parsed->parse(), "custom header layout parses"))
        return false;
    auto again = FlashImage::read(parsed->write().value_or(Bytes{}));
    if (!check(again && again->parse(), "custom header layout rewrites"))
        return false;
    auto bytes = std::as_const(again->flash_driver).read_offset(0x130010, 16);
    return check(again->header.cf_offset == 0x100000 && again->header.fs_addr == 0x30000 &&
                     bytes.size() == 16 && be32(bytes, 0) == 0x1000,
                 "read/write preserves header-derived runtime KHV anchor");
}
static bool freeboot_provider() {
    bool ok = check(freeboot_rebooter().size() == 0xd40, "embedded rebooter is 0xd40 bytes");
    ok = check(freeboot_payload().size() == 0x200, "embedded payload is 0x200 bytes") && ok;
    ok = check(freeboot_rebooter()[0] == 0x3c, "embedded rebooter starts with 0x3c") && ok;
    ok = check(freeboot_payload()[0] == 0x80, "embedded payload starts with 0x80") && ok;

    // The core carries thirty-two X's at 0xD0B for the kernel version, and the payload's
    // `li r4, 0xFFFF` at 0x50 for the words it loads; a built image states both.
    const Bytes blank(0x20, 'X');
    const auto core = freeboot_rebooter();
    ok = check(std::equal(blank.begin(), blank.end(), core.begin() + 0xD0B),
               "embedded rebooter carries the version placeholder at 0xD0B") &&
         ok;
    Bytes version(0x20, 0);
    std::copy_n("17559", 5, version.begin());
    const auto stated = freeboot_rebooter_for("17559");
    ok = check(stated.size() == core.size() &&
                   std::equal(version.begin(), version.end(), stated.begin() + 0xD0B),
               "the rebooter states the kernel version, zero-padded, at 0xD0B") &&
         ok;
    const auto version_end = 0xD0B + blank.size();
    ok = check(
             stated.size() == core.size() &&
                 std::equal(stated.begin(), stated.begin() + 0xD0B, core.begin()) &&
                 std::equal(stated.begin() + version_end, stated.end(), core.begin() + version_end),
             "the version string is the only change to the rebooter") &&
         ok;
    const Bytes hold{0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x78};
    const Bytes old_hold{0x80, 0x00, 0x00, 0x00, 0x00, 0x1F, 0xFF, 0xF8};
    const auto old = freeboot_rebooter_for("9199");
    ok = check(std::search(core.begin(), core.end(), hold.begin(), hold.end()) != core.end() &&
                   std::search(old.begin(), old.end(), hold.begin(), hold.end()) == old.end() &&
                   std::search(old.begin(), old.end(), old_hold.begin(), old_hold.end()) !=
                       old.end(),
               "a 9199 rebooter takes the old hold address") &&
         ok;
    ok = check(freeboot_payload()[0x52] == 0xFF && freeboot_payload()[0x53] == 0xFF,
               "embedded payload loads 0xFFFF words") &&
         ok;
    const auto payload = freeboot_payload_for(stated.size());
    ok = check(payload.size() == 0x200 && payload[0x52] == 0x03 && payload[0x53] == 0x50,
               "the payload loads the 0xD40-byte core as 0x350 words") &&
         ok;
    ok = check(freeboot_payload_for(0xD2B)[0x53] == 0x4B, "a partial word rounds up") && ok;
    return ok;
}
static BootloaderCb synthetic_cb(uint8_t fill) {
    BootloaderCb cb{};
    cb.header.header.magic = NANDBootloaderMagic::CB;
    cb.data.resize(0x100, fill);
    cb.header.header.size = sizeof(generic_header) + cb.data.size();
    return cb;
}
static BootloaderCd synthetic_cd(uint8_t fill) {
    BootloaderCd cd{};
    cd.header.header.magic = NANDBootloaderMagic::CD;
    cd.data.resize(0x100, fill);
    cd.header.header.size = sizeof(cd_header) + cd.data.size();
    return cd;
}
// The JTAG loader reads its neighbours from addresses compiled into it, so its window sits at
// 0x90000 on every shape.
static bool jtag_window(Driver::DriverMode mode) {
    const size_t window = 0x90000;
    auto f = fixture(mode, BuildType::Jtag);
    f.build_type = BuildType::Jtag;
    XeLL x{};
    x.data = raw_xell();
    f.payloads.xell = x;
    f.payloads.rebooter = Bytes(0xd40, 0xAA);
    f.payloads.fuses = Bytes(0x60, 0xBB);
    f.payloads.payload = Bytes(0x200, 0xCC);
    f.payloads.extra_cb = synthetic_cb(0x11);
    f.payloads.extra_cd = synthetic_cd(0x22);
    if (!check(f.payloads.patchset && f.payloads.patchset->kind == PatchSetKind::Jtag,
               "fixture yields a JTAG patchset"))
        return false;
    const auto& sections = f.payloads.patchset->sections;
    if (!check(sections.size() == 4 && sections.back().target == PatchSectionTarget::JtagSection4 &&
                   sections.back().raw_data.size() == 12 &&
                   be32(sections.back().raw_data, 0) == 0x1000,
               "the KHV record occupies JtagSection4 as in [1bl][CB][CD][KHV]"))
        return false;
    if (!check(f.write_to_driver(), "anchored jtag image writes"))
        return false;
    const auto& d = std::as_const(f.flash_driver);
    const auto filled = [&](size_t offset, size_t length, uint8_t expected, const char* what) {
        const auto bytes = d.read_clean(offset, length);
        return check(
            bytes.size() == length &&
                std::all_of(bytes.begin(), bytes.end(), [&](uint8_t b) { return b == expected; }),
            what);
    };
    bool ok = filled(0x200, 0x200, 0xCC, "SMC payload lands at absolute 0x200");
    ok = filled(window, 0xd40, 0xAA, "rebooter lands at the anchored window base") && ok;
    ok = filled(window + 0x5000, 0x60, 0xBB, "virtual fuses land at window + 0x5000") && ok;
    const auto patches = serialize_patch_set(*f.payloads.patchset);
    ok = check(d.read_clean(window + 0x1000, patches.size()) == patches,
               "KHV patchset is pinned at window + 0x1000") &&
         ok;
    ok = check(d.read_clean(window + 0x5060, 0x40000) == x.data, "XeLL lands at window + 0x5060") &&
         ok;
    const auto extra_cb = f.payloads.extra_cb->serialize();
    const auto extra_cd = f.payloads.extra_cd->serialize();
    ok = check(d.read_clean(window + 0x45060, extra_cb.size()) == extra_cb,
               "extra CB lands immediately after XeLL at window + 0x45060") &&
         ok;
    const size_t cd_at = window + 0x45060 + ((extra_cb.size() + 0xF) & ~size_t{0xF});
    ok = check(d.read_clean(cd_at, extra_cd.size()) == extra_cd,
               "extra CD follows the 16-byte-aligned extra CB") &&
         ok;
    auto parsed = FlashImage::read(f.write().value_or(Bytes{}));
    ok = check(parsed && parsed->parse() && parsed->build_type == BuildType::Jtag,
               "anchored window is recognized as JTAG on read-back") &&
         ok;
    ok = check(parsed && parsed->payloads.xell && parsed->payloads.xell->data == x.data,
               "XeLL is recovered from the anchored window") &&
         ok;
    ok = check(parsed && parsed->payloads.fuses == f.payloads.fuses,
               "virtual fuses are recovered from the anchored window") &&
         ok;
    return ok;
}
int main() {
    bool ok = check(XeLL::parse(raw_xell()).has_value(), "raw executable XeLL is accepted");
    ok = freeboot_provider() && ok;
    ok = anchors() && ok;
    ok = spill(BuildType::Retail) && ok;
    ok = spill(BuildType::Glitch2) && ok;
    ok = spill(BuildType::Jtag) && ok;
    ok = jtag_window(Driver::DriverMode::Small) && ok;
    ok = jtag_window(Driver::DriverMode::Big) && ok;
    ok = custom_header_roundtrip() && ok;
    return ok ? 0 : 1;
}
