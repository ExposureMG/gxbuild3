// In-process FlashImage golden over the tracked donor dump tests/gxBuild-support-files/mydata/
// image.bin (16 MiB Jasper retail). Runs on a clean clone: it needs no untracked fixture.
//
// It renders one text snapshot and compares it with tests/golden/flashimage_golden.txt:
//   parse.*      every nand_header field, every boot stage, the console blocks, the payloads,
//                the filesystem, mobile data, SMC and keyvault right after parse();
//   layout.*     update_slots_end(), patch_slot_offset(), active_payload_block_ranges() and
//                payload_layout() on the parsed image;
//   write.*      SHA-256 of write() straight after parse();
//   decrypt.*    the same snapshot after decrypt_all() under the CPU key of image.bin;
//   roundtrip.*  SHA-256 of write() after parse, decrypt_all and encrypt_all;
//   info.*       extract_all_info()'s KeyvaultSummaryInfo (and its SMC and FlashFS summaries),
//                with Serial and ConsoleId cross-checked against xeBuild's own image.info.
// Console identity (serial, console id, OSIG, DVD key, manufacturing date, pairing data) only
// ever appears as a SHA-1.
//
// Two more goldens need no dump at all:
//   tests/golden/flashimage_matrix.txt    synthetic fresh layouts, Small/Big/Emmc x the eight
//                                         build types, hashed after write() and after the
//                                         seal, plus the header encoded for a zeroed header;
//   tests/golden/flashimage_failures.txt  ErrorCode and message of each reachable FlashImage
//                                         failure, in today's check order.
//
// The CPU key is the one already public in tests/gxBuild-support-files/build_all.sh. --update
// rewrites the goldens (CTest never passes it). GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE overrides the
// image path and GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT the support directory the matrix reads its
// stages from, for mutation checks against scratch copies only.

#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "Sha256.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/objects/Freeboot.hpp"
#include "nand/objects/SecuredFiles.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    // The CPU key of the tracked mydata/image.bin, public in build_all.sh (-p ...).
    constexpr std::array<uint8_t, 16> kCpuKey = {0x93, 0xFB, 0x9D, 0x01, 0x19, 0x30, 0xAF, 0xC4,
                                                 0x53, 0xAA, 0x75, 0xB1, 0x83, 0xEF, 0xAC, 0x09};
    constexpr const char* kSourceDateEpoch = "1791105724";

    int g_checks = 0;
    int g_failures = 0;

    bool check(bool ok, std::string_view message) {
        ++g_checks;
        if (!ok) {
            ++g_failures;
            std::cerr << "FAIL: " << message << '\n';
        }
        return ok;
    }

    bool check(const Result<void>& result, std::string_view message) {
        ++g_checks;
        if (!result) {
            ++g_failures;
            std::cerr << "FAIL: " << message << ": " << result.error().describe() << '\n';
        }
        return result.has_value();
    }

    std::string hex(std::span<const uint8_t> bytes) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(bytes.size() * 2);
        for (const uint8_t b : bytes) {
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 0xF]);
        }
        return out;
    }

    std::string sha1(std::span<const uint8_t> bytes) {
        std::array<uint8_t, 20> digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        return hex(digest);
    }

    std::string sha1(std::string_view text) {
        return sha1(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
    }

    // tests/Sha256.hpp: GxCrypt's ExCryptSha256 does not link.
    std::string sha256(std::span<const uint8_t> bytes) {
        return test::sha256_hex(bytes);
    }

    // FIPS 180-4 examples, including the two-block padding case.
    bool sha256_self_test() {
        const auto digest = [](std::string_view text) {
            return test::sha256_hex(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(text.data()), text.size()));
        };
        bool ok = check(digest("abc") ==
                            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                        "sha256(\"abc\")");
        ok = check(digest("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                   "sha256(\"\")") &&
             ok;
        ok = check(digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
                       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                   "sha256(448-bit message)") &&
             ok;
        return ok;
    }

    template <class T> std::span<const uint8_t> raw_bytes(const T& value) {
        return {reinterpret_cast<const uint8_t*>(&value), sizeof(value)};
    }

    std::string hex32(uint64_t value) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
        return buf;
    }

    // Printable ASCII as is, everything else (and the backslash) as \xNN.
    std::string escaped(std::string_view text) {
        std::string out;
        for (const char c : text) {
            const auto u = static_cast<unsigned char>(c);
            if (u >= 0x20 && u < 0x7F && c != '\\') {
                out.push_back(c);
            } else {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\x%02X", u);
                out += buf;
            }
        }
        return out;
    }

    class Snapshot {
      public:
        explicit Snapshot(std::ostringstream& out) : m_out(out) {}

        void line(std::string_view prefix, std::string_view key, std::string_view value) {
            m_out << prefix << key << '=' << value << '\n';
        }
        void num(std::string_view prefix, std::string_view key, uint64_t value) {
            line(prefix, key, hex32(value));
        }
        void flag(std::string_view prefix, std::string_view key, bool value) {
            line(prefix, key, value ? "1" : "0");
        }

      private:
        std::ostringstream& m_out;
    };

    std::string_view build_type_name(BuildType type) {
        switch (type) {
            case BuildType::Retail:
                return "Retail";
            case BuildType::Jtag:
                return "Jtag";
            case BuildType::Glitch:
                return "Glitch";
            case BuildType::Glitch2:
                return "Glitch2";
            case BuildType::Glitch2m:
                return "Glitch2m";
            case BuildType::Glitch3:
                return "Glitch3";
            case BuildType::Devkit:
                return "Devkit";
            case BuildType::Devgl:
                return "Devgl";
        }
        return "?";
    }

    std::string_view driver_mode_name(Driver::DriverMode mode) {
        switch (mode) {
            case Driver::Small:
                return "Small";
            case Driver::NewSmall:
                return "NewSmall";
            case Driver::Big:
                return "Big";
            case Driver::Emmc:
                return "Emmc";
        }
        return "?";
    }

    std::string_view section_target_name(PatchSectionTarget target) {
        switch (target) {
            case PatchSectionTarget::Unknown:
                return "Unknown";
            case PatchSectionTarget::JtagSection1:
                return "JtagSection1";
            case PatchSectionTarget::JtagSection2:
                return "JtagSection2";
            case PatchSectionTarget::JtagSection3:
                return "JtagSection3";
            case PatchSectionTarget::JtagSection4:
                return "JtagSection4";
            case PatchSectionTarget::Cb:
                return "Cb";
            case PatchSectionTarget::Cbb:
                return "Cbb";
            case PatchSectionTarget::Cd:
                return "Cd";
            case PatchSectionTarget::Khv:
                return "Khv";
        }
        return "?";
    }

    std::string_view fcrt_name(FcrtRequirement requirement) {
        switch (requirement) {
            case FcrtRequirement::NotRequired:
                return "NotRequired";
            case FcrtRequirement::Required:
                return "Required";
            case FcrtRequirement::RequiredByDrive:
                return "RequiredByDrive";
        }
        return "?";
    }

    void render_header(Snapshot& s, std::string_view p, const nand_header& h) {
        s.num(p, "header.magic", h.magic);
        s.num(p, "header.version", h.version);
        s.num(p, "header.pairing", h.pairing);
        s.num(p, "header.flags", h.flags);
        s.num(p, "header.entrypoint", h.entrypoint);
        s.num(p, "header.size", h.size);
        s.line(p, "header.copyright", hex(raw_bytes(h.copyright)));
        s.num(p, "header.hack_flags", h.hack_flags);
        s.num(p, "header.boot_flags", h.boot_flags);
        s.line(p, "header.reserved", hex(raw_bytes(h.reserved)));
        s.num(p, "header.kv_size", h.kv_size);
        s.num(p, "header.cf_offset", h.cf_offset);
        s.num(p, "header.patch_slots", h.patch_slots);
        s.num(p, "header.kv_version", h.kv_version);
        s.num(p, "header.kv_addr", h.kv_addr);
        s.num(p, "header.fs_addr", h.fs_addr);
        s.num(p, "header.smc_config_offset", h.smc_config_offset);
        s.num(p, "header.smc_boot_size", h.smc_boot_size);
        s.num(p, "header.smc_boot_offset", h.smc_boot_offset);
    }

    // One boot stage. Absent stages print a single present=0 line.
    template <class Stage>
    void render_stage(Snapshot& s, std::string_view p, std::string_view name, const Stage* stage) {
        const std::string k = "stage." + std::string{name} + '.';
        if (stage == nullptr || stage->data.empty()) {
            s.flag(p, k + "present", false);
            return;
        }
        const auto& g = stage->header.header;
        s.flag(p, k + "present", true);
        s.num(p, k + "magic", g.magic);
        s.num(p, k + "version", g.version);
        s.num(p, k + "pairing", g.pairing);
        s.num(p, k + "flags", g.flags);
        s.num(p, k + "entrypoint", g.entrypoint);
        s.num(p, k + "size", g.size);
        s.num(p, k + "data_size", stage->data.size());
        s.flag(p, k + "decrypted", stage->decrypted);
        s.flag(p, k + "is_decrypted", stage->is_decrypted());
        s.line(p, k + "data_sha1", sha1(stage->data));
        s.line(p, k + "serialize_sha1", sha1(stage->serialize()));
        if constexpr (requires { stage->derived_key; }) {
            s.flag(p, k + "derived_key", stage->derived_key.has_value());
        }
        if constexpr (requires { stage->perbox; }) {
            s.flag(p, k + "perbox", stage->perbox.has_value());
            if (stage->perbox) {
                s.num(p, k + "perbox.lockdown_value", stage->perbox->lockdown_value);
                s.line(p, k + "perbox.pairing_sha1", sha1(raw_bytes(stage->perbox->pairing_data)));
                s.line(p, k + "perbox.sha1", sha1(raw_bytes(*stage->perbox)));
            }
        }
    }

    template <class T> const T* opt_ptr(const std::optional<T>& value) {
        return value ? &*value : nullptr;
    }

    void render_blob(Snapshot& s, std::string_view p, std::string_view key,
                     const std::optional<std::vector<uint8_t>>& blob) {
        if (!blob) {
            s.line(p, key, "absent");
            return;
        }
        s.line(p, key, hex32(blob->size()) + " sha1:" + sha1(*blob));
    }

    void render_smc(Snapshot& s, std::string_view p, const std::optional<Smc>& smc) {
        s.flag(p, "smc.present", smc.has_value());
        if (!smc) {
            return;
        }
        s.flag(p, "smc.encrypted", smc->encrypted);
        s.line(p, "smc.motherboard", smc_motherboard_name(smc->motherboard));
        s.line(p, "smc.version", escaped(smc->version));
        s.line(p, "smc.variant", smc_type_name(smc->variant));
        s.num(p, "smc.size", smc->data.size());
        s.line(p, "smc.data_sha1", sha1(smc->data));
        s.flag(p, "smc.has_jtag_mark", smc_has_jtag_mark(smc->data));
        s.flag(p, "smc.is_encrypted_bytes", smc_is_encrypted(smc->data));
        s.line(p, "smc.get_type", smc_type_name(smc_get_type(smc->data)));
    }

    void render_keyvault(Snapshot& s, std::string_view p, const std::optional<Keyvault>& kv) {
        s.flag(p, "keyvault.present", kv.has_value());
        if (!kv) {
            return;
        }
        const auto& d = kv->data;
        s.flag(p, "keyvault.encrypted", kv->encrypted);
        s.num(p, "keyvault.raw_size", kv->raw_data.size());
        s.line(p, "keyvault.raw_sha1", sha1(kv->raw_data));
        s.line(p, "keyvault.serialize_sha1", sha1(kv->serialize()));
        s.line(p, "keyvault.serial_sha1",
               sha1(std::string_view(
                   d.sz14ConsoleSerialNumber,
                   strnlen(d.sz14ConsoleSerialNumber, sizeof(d.sz14ConsoleSerialNumber)))));
        s.num(p, "keyvault.region", bswap16(d.w16GameRegion));
        s.line(p, "keyvault.console_id_sha1", sha1(raw_bytes(d.b36ConsoleCertificate.ConsoleId)));
        s.line(p, "keyvault.mfr_date_sha1",
               sha1(raw_bytes(d.b36ConsoleCertificate.ManufacturingDate)));
        if (kv->raw_data.size() >= 0xC92 + 28) {
            s.line(p, "keyvault.osig_sha1",
                   sha1(std::span<const uint8_t>(kv->raw_data).subspan(0xC92, 28)));
        }
        s.num(p, "keyvault.odd_features", bswap16(d.w4OddFeatures));
        if (!kv->encrypted) {
            s.line(p, "keyvault.fcrt_requirement", fcrt_name(fcrt_requirement(kv->serialize())));
        }
    }

    void render_filesystem(Snapshot& s, std::string_view p,
                           const std::optional<FlashFileSystem>& fs) {
        s.flag(p, "fs.present", fs.has_value());
        if (!fs) {
            return;
        }
        s.num(p, "fs.version", fs->version());
        s.num(p, "fs.root_block", fs->root_block());
        s.flag(p, "fs.has_root", fs->has_root());
        s.num(p, "fs.timestamp", fs->timestamp());
        const auto& map = fs->blockmap();
        s.num(p, "fs.blockmap_entries", map.size());
        s.line(p, "fs.blockmap_sha1",
               sha1(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(map.data()),
                                             map.size() * sizeof(uint16_t))));
        const auto& entries = fs->entries();
        s.num(p, "fs.entries", entries.size());
        size_t index = 0;
        for (const auto& entry : entries) {
            const std::string k = "fs.entry." + std::to_string(index++) + '.';
            if (!entry.is_valid()) {
                s.line(p, k + "valid", "0 sha1:" + sha1(raw_bytes(entry)));
                continue;
            }
            const std::string name(entry.filename, strnlen(entry.filename, sizeof(entry.filename)));
            const auto file = fs->get_file(name);
            s.line(p, k + "name", escaped(name));
            s.line(p, k + "info",
                   "block=" + hex32(entry.block_number) + " length=" + hex32(entry.length) +
                       " timestamp=" + hex32(entry.timestamp) +
                       " file=" + (file ? hex32(file->size()) + " sha1:" + sha1(*file) : "absent"));
        }
        const auto root = fs->serialize_root_block();
        s.line(p, "fs.serialize_root_block",
               root ? hex32(root->size()) + " sha1:" + sha1(*root)
                    : "error " + std::string{to_string(root.error().code)});
    }

    void render_mobile(Snapshot& s, std::string_view p, const std::optional<MobileData>& mobile) {
        s.flag(p, "mobile.present", mobile.has_value());
        if (!mobile) {
            return;
        }
        for (uint8_t type = 0x31; type <= 0x39; ++type) {
            char key[24];
            std::snprintf(key, sizeof(key), "mobile.x%02X", type);
            render_blob(s, p, key, *mobile->get_slot(type));
        }
    }

    void render_payloads(Snapshot& s, std::string_view p, const Payloads& payloads) {
        if (payloads.xell) {
            s.line(p, "payloads.xell",
                   hex32(payloads.xell->data.size()) + " sha1:" + sha1(payloads.xell->data));
            s.line(p, "payloads.xell.version", escaped(payloads.xell->metadata.version));
            s.line(p, "payloads.xell.author", escaped(payloads.xell->metadata.author));
            s.line(p, "payloads.xell.date", escaped(payloads.xell->metadata.date));
        } else {
            s.line(p, "payloads.xell", "absent");
        }
        render_blob(s, p, "payloads.fuses", payloads.fuses);
        render_blob(s, p, "payloads.payload", payloads.payload);
        render_blob(s, p, "payloads.rebooter", payloads.rebooter);
        if (payloads.patchset) {
            const auto& ps = *payloads.patchset;
            s.line(p, "payloads.patchset.kind", ps.kind == PatchSetKind::Jtag ? "Jtag" : "Glitch");
            s.flag(p, "payloads.patchset.manufacturing", ps.manufacturing);
            s.num(p, "payloads.patchset.sections", ps.sections.size());
            for (size_t i = 0; i < ps.sections.size(); ++i) {
                const auto& sec = ps.sections[i];
                s.line(p, "payloads.patchset.section." + std::to_string(i),
                       std::string{section_target_name(sec.target)} + " id=" +
                           escaped(sec.identifier) + " entries=" + hex32(sec.entries.size()) +
                           " raw=" + hex32(sec.raw_data.size()) + " sha1:" + sha1(sec.raw_data));
            }
        } else {
            s.line(p, "payloads.patchset", "absent");
        }
        render_stage(s, p, "extra_cb", opt_ptr(payloads.extra_cb));
        render_stage(s, p, "extra_cd", opt_ptr(payloads.extra_cd));
    }

    std::string render_image(const FlashImage& img, std::string_view p) {
        std::ostringstream out;
        Snapshot s{out};
        s.line(p, "driver_mode", driver_mode_name(img.flash_driver.driver_mode()));
        s.num(p, "block_count", img.flash_driver.block_count());
        s.flag(p, "preserve_layout", img.preserve_layout);
        s.line(p, "build_type", img.build_type ? build_type_name(*img.build_type) : "none");
        s.flag(p, "devkit_chain", img.devkit_chain());
        render_header(s, p, img.header);

        render_stage(s, p, "CB_A", &img.cb_section.cb_or_A);
        render_stage(s, p, "CB_X", opt_ptr(img.cb_section.cb_x));
        render_stage(s, p, "CB_B", opt_ptr(img.cb_section.cb_B));
        render_stage(s, p, "SC", opt_ptr(img.cb_section.sc));
        render_stage(s, p, "CD", &img.kernel_section.cd);
        render_stage(s, p, "CE", opt_ptr(img.kernel_section.ce));
        render_stage(s, p, "CF0", opt_ptr(img.system_update_0.cf));
        render_stage(s, p, "CG0", opt_ptr(img.system_update_0.cg));
        render_stage(s, p, "CF1", opt_ptr(img.system_update_1.cf));
        render_stage(s, p, "CG1", opt_ptr(img.system_update_1.cg));
        for (const auto* su : {&img.system_update_0, &img.system_update_1}) {
            std::string blocks;
            for (const auto b : su->cg_spill_blocks) {
                blocks += (blocks.empty() ? "" : ",") + hex32(b);
            }
            s.line(p, su == &img.system_update_0 ? "cg_spill_blocks.0" : "cg_spill_blocks.1",
                   blocks.empty() ? "none" : blocks);
        }

        render_smc(s, p, img.smc);
        render_keyvault(s, p, img.keyvault);
        render_blob(s, p, "smc_config", img.smc_config);
        render_blob(s, p, "statistics", img.statistics);
        render_blob(s, p, "manufacturing", img.manufacturing);
        s.flag(p, "corona_config.present", img.corona_config.has_value());
        render_mobile(s, p, img.mobile_data);
        render_filesystem(s, p, img.filesystem);
        render_payloads(s, p, img.payloads);
        s.num(p, "raw_patches", img.raw_patches.size());
        return out.str();
    }

    std::string render_layout(const FlashImage& img) {
        std::ostringstream out;
        Snapshot s{out};
        constexpr std::string_view p = "layout.";
        s.num(p, "update_slots_end", img.update_slots_end());
        s.num(p, "patch_slot_offset", img.patch_slot_offset());
        std::string ranges;
        for (const auto& range : img.active_payload_block_ranges()) {
            ranges += (ranges.empty() ? "" : ",") + hex32(range.start_block) + "+" +
                      hex32(range.block_count);
        }
        s.line(p, "active_payload_block_ranges", ranges.empty() ? "none" : ranges);
        const auto layout = img.payload_layout();
        s.line(p, "payload_layout",
               layout ? "ok" : "error " + std::string{to_string(layout.error().code)});
        check(layout, "payload_layout() on the parsed donor");
        return out.str();
    }

    std::optional<std::vector<uint8_t>> read_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }
        return std::vector<uint8_t>{std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>()};
    }

    std::optional<FlashImage> parsed_image(const std::vector<uint8_t>& bytes) {
        auto img = FlashImage::read(bytes);
        if (!check(img.has_value(), "FlashImage::read on the donor")) {
            return std::nullopt;
        }
        if (!check(img->parse(), "FlashImage::parse on the donor")) {
            return std::nullopt;
        }
        return img;
    }

    // The value of `Key : value` in xeBuild's image.info, trimmed.
    std::optional<std::string> info_value(std::string_view text, std::string_view key) {
        std::istringstream in{std::string{text}};
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const auto colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            auto name = line.substr(0, colon);
            while (!name.empty() && name.back() == ' ') {
                name.pop_back();
            }
            if (name != key) {
                continue;
            }
            auto value = line.substr(colon + 1);
            const auto first = value.find_first_not_of(' ');
            const auto last = value.find_last_not_of(' ');
            return first == std::string::npos ? std::string{}
                                              : value.substr(first, last - first + 1);
        }
        return std::nullopt;
    }

    std::string render_info(const std::vector<uint8_t>& bytes, std::string_view image_info) {
        std::ostringstream out;
        Snapshot s{out};
        constexpr std::string_view p = "info.";
        const auto info =
            extract_all_info(std::span<const uint8_t>(bytes), std::span<const uint8_t>(kCpuKey));
        if (!check(info.has_value(), "extract_all_info on the donor")) {
            s.line(p, "result", "error " + std::string{to_string(info.error().code)});
            return out.str();
        }
        const auto& kv = info->keyvault;
        s.flag(p, "keyvault.present", kv.present);
        s.flag(p, "keyvault.decrypted", kv.decrypted);
        s.line(p, "keyvault.serial_number_sha1", sha1(kv.serial_number));
        s.line(p, "keyvault.dvd_key_sha1", sha1(kv.dvd_key));
        s.line(p, "keyvault.console_id_raw_sha1", sha1(kv.console_id_raw));
        s.line(p, "keyvault.console_id_friendly_sha1", sha1(kv.console_id_friendly));
        s.line(p, "keyvault.osig_sha1", sha1(kv.osig));
        s.line(p, "keyvault.mfr_date_sha1", sha1(kv.mfr_date));
        s.line(p, "keyvault.region_name", kv.region_name);
        s.num(p, "keyvault.region_raw", kv.region_raw);
        s.num(p, "keyvault.kv_type", kv.kv_type);
        s.flag(p, "keyvault.fcrt_required", kv.fcrt_required);
        s.line(p, "raw_keyvault",
               info->raw_keyvault
                   ? hex32(info->raw_keyvault->size()) + " sha1:" + sha1(*info->raw_keyvault)
                   : "absent");
        s.flag(p, "smc.present", info->smc.present);
        s.flag(p, "smc.decrypted", info->smc.decrypted);
        s.line(p, "smc.version", escaped(info->smc.version));
        s.line(p, "smc.motherboard_name", info->smc.motherboard_name);
        s.line(p, "smc.type_name", info->smc.type_name);
        s.num(p, "smc.size", info->smc.size);
        s.flag(p, "flashfs.present", info->flashfs.present);
        s.num(p, "flashfs.files", info->flashfs.files.size());

        // xeBuild's own report of this dump must agree with what gxbuild3 reads.
        const auto serial = info_value(image_info, "Serial");
        const auto console_id = info_value(image_info, "ConsoleId");
        const auto cpu_key = info_value(image_info, "CPU Key");
        check(serial.has_value() && console_id.has_value() && cpu_key.has_value(),
              "image.info carries Serial, ConsoleId and CPU Key lines");
        const bool serial_match = serial && *serial == kv.serial_number;
        const bool console_id_match = console_id && *console_id == kv.console_id_friendly;
        std::string want_key;
        for (const char c : cpu_key.value_or("")) {
            want_key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        check(serial_match, "KeyvaultSummaryInfo serial matches image.info Serial");
        check(console_id_match, "KeyvaultSummaryInfo console id matches image.info ConsoleId");
        check(want_key == hex(kCpuKey), "image.info CPU Key is the key this test uses");
        s.flag(p, "image_info.serial_match", serial_match);
        s.flag(p, "image_info.console_id_match", console_id_match);
        return out.str();
    }

    // ---- Synthetic fresh layouts (tests/golden/flashimage_matrix.txt) ----------------------
    //
    // Each cell is one driver shape (Small, Big, Emmc) times one build type, built the way
    // run_build builds a fresh image but without a donor: the tracked plaintext stages the
    // 17559 INIs name for Jasper, a synthetic SMC and sealed keyvault (pattern bytes, no console
    // identity), the payloads the resolver adds for the type, a FlashFS with two files and
    // mobile blobs x31/x32.
    //   plain.*   the cell without an update pair, written straight away (stages plaintext);
    //   sealed.*  the cell with CF/CG 4532, whose CG is longer than any slot, after
    //             encrypt_all under the public CPU key, then written and parsed back.
    // encrypt_all draws a random nonce for an SC/CD/CE/CG whose nonce is zero, so every stage
    // nonce is pinned here first and the seal is skipped (and says so) if one is still zero.

    using Bytes = std::vector<uint8_t>;
    using Nonce = std::array<uint8_t, 16>;

    // Distinct, never-zero fixed nonces, one per stage tag.
    Nonce pinned_nonce(uint8_t tag) {
        Nonce nonce{};
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<uint8_t>(tag + i * 0x11);
        }
        return nonce;
    }

    bool zero_nonce(std::span<const uint8_t> nonce) {
        return std::all_of(nonce.begin(), nonce.end(), [](uint8_t b) { return b == 0; });
    }

    Bytes pattern(size_t size, uint8_t seed) {
        Bytes bytes(size);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = static_cast<uint8_t>(seed + i * 7 + (i >> 9));
        }
        return bytes;
    }

    std::filesystem::path g_support;

    // Tracked support files, read once.
    const Bytes& support_file(const std::string& relative) {
        static std::map<std::string, Bytes> cache;
        if (const auto found = cache.find(relative); found != cache.end()) {
            return found->second;
        }
        auto bytes = read_file(g_support / relative);
        check(bytes.has_value() && !bytes->empty(), "read tracked fixture " + relative);
        return cache.emplace(relative, bytes.value_or(Bytes{})).first->second;
    }

    std::string describe_error(const Error& error) {
        return std::string{to_string(error.code)} + " | " + error.describe();
    }

    template <class T> std::string outcome(const Result<T>& result) {
        return result ? "ok" : "error " + describe_error(result.error());
    }

    // The 17559 Jasper chain of each build type (17559/_*.ini [jasperbl]; the devkit chain from
    // common/), with CF/CG 4532 as the update pair and the patch file the resolver picks.
    struct ChainSpec {
        const char* cb_a;
        const char* cb_x;
        const char* cb_b;
        const char* sc;
        const char* cd;
        const char* ce;
        const char* patches;
    };

    ChainSpec chain_for(BuildType type) {
        constexpr const char* ce = "common/ce_1888.bin";
        switch (type) {
            case BuildType::Retail:
                return {"common/cba_6754.bin",
                        nullptr,
                        "common/cbb_6754.bin",
                        nullptr,
                        "common/cd_6754.bin",
                        ce,
                        nullptr};
            case BuildType::Jtag:
                return {"common/cb_6723.bin",
                        nullptr,
                        nullptr,
                        nullptr,
                        "common/cd_6723.bin",
                        ce,
                        "17559/bin/patches_jasper.bin"};
            case BuildType::Glitch:
                return {
                    "common/cb_6750.bin",       nullptr, nullptr, nullptr, "common/cd_8453.bin", ce,
                    "17559/bin/patches_fat.bin"};
            case BuildType::Glitch2:
                return {"common/cba_6752.bin", nullptr, "common/cbb_6752.bin",           nullptr,
                        "common/cd_9452.bin",  ce,      "17559/bin/patches_g2jasper.bin"};
            case BuildType::Glitch2m:
                return {"common/cba_9188_mfg.bin",
                        nullptr,
                        "common/cbb_6752.bin",
                        nullptr,
                        "common/cd_9452.bin",
                        ce,
                        "17559/bin/patches_g2mjasper.bin"};
            case BuildType::Glitch3:
                return {"rgh3/cba_rgh3.bin",
                        "rgh3/cbx_rgh3.bin",
                        "rgh3/cbb_rgh3_jasper.bin",
                        nullptr,
                        "common/cd_9452.bin",
                        ce,
                        "17559/bin/patches_g2jasper.bin"};
            case BuildType::Devkit:
                return {"common/SB_10375.bin", nullptr, nullptr, "common/SC_17489.bin",
                        "common/SD_17489.bin", ce,      nullptr};
            case BuildType::Devgl:
                return {"common/SB_10375.bin",
                        nullptr,
                        nullptr,
                        "common/SC_17489.bin",
                        "common/cd_9452.bin",
                        ce,
                        "17559/bin/patches_g2mjasper.bin"};
        }
        return {};
    }

    template <class Stage, class Target>
    Result<void> load_stage(Target& target, const char* relative) {
        auto parsed = Stage::parse(support_file(relative));
        if (!parsed) {
            return std::unexpected(std::move(parsed.error()).add_context(relative));
        }
        target = std::move(*parsed);
        return {};
    }

    Smc synthetic_smc() {
        Smc smc{};
        smc.encrypted = false;
        smc.data = pattern(0x3000, 0x5A);
        return smc;
    }

    // The stage nonces run_build's apply_nonces sets on a plaintext chain, pinned.
    void pin_nonces(FlashImage& f) {
        const auto set_cb = [](BootloaderCb& cb, const Nonce& nonce) {
            std::copy(nonce.begin(), nonce.end(), cb.data.begin());
            std::copy(nonce.begin(), nonce.end(), std::begin(cb.header.key));
        };
        auto& cb_a = f.cb_section.cb_or_A;
        if (cb_a.data.size() >= 0x10) {
            set_cb(cb_a, pinned_nonce(0x10));
        }
        if (!f.cb_section.cb_x && f.cb_section.cb_B && f.cb_section.cb_B->data.size() >= 0x10) {
            set_cb(*f.cb_section.cb_B, pinned_nonce(0x20));
        } else if (f.devkit_chain() && f.cb_section.sc) {
            const auto nonce = pinned_nonce(0x30);
            std::copy(nonce.begin(), nonce.end(), std::begin(f.cb_section.sc->header.key));
        }
        const auto cd_nonce = pinned_nonce(0x40);
        std::copy(cd_nonce.begin(), cd_nonce.end(), std::begin(f.kernel_section.cd.header.key));
        if (f.kernel_section.ce) {
            const auto nonce = pinned_nonce(0x50);
            std::copy(nonce.begin(), nonce.end(), std::begin(f.kernel_section.ce->header.key));
        }
        if (f.payloads.extra_cb && f.payloads.extra_cb->data.size() >= 0x10) {
            set_cb(*f.payloads.extra_cb, pinned_nonce(0x10));
        }
        if (f.payloads.extra_cd) {
            std::copy(cd_nonce.begin(), cd_nonce.end(),
                      std::begin(f.payloads.extra_cd->header.key));
        }
        for (auto* slot : {&f.system_update_0, &f.system_update_1}) {
            if (slot->cf) {
                const auto nonce = pinned_nonce(0x60);
                std::copy(nonce.begin(), nonce.end(), std::begin(slot->cf->header.fixpoint_nonce));
            }
            if (slot->cg) {
                const auto nonce = pinned_nonce(0x70);
                std::copy(nonce.begin(), nonce.end(), std::begin(slot->cg->header.key));
            }
        }
    }

    // Every nonce encrypt_all would otherwise draw from ExCryptRandom (SC, CD, CE, CG and the
    // JTAG second CD), named when it is zero.
    std::optional<std::string> zero_random_nonce(const FlashImage& f) {
        if (f.cb_section.sc && zero_nonce(f.cb_section.sc->header.key)) {
            return "SC";
        }
        if (!f.kernel_section.cd.data.empty() && zero_nonce(f.kernel_section.cd.header.key)) {
            return "CD";
        }
        if (f.kernel_section.ce && zero_nonce(f.kernel_section.ce->header.key)) {
            return "CE";
        }
        if (f.payloads.extra_cd && zero_nonce(f.payloads.extra_cd->header.key)) {
            return "JTAG second CD";
        }
        for (const auto* slot : {&f.system_update_0, &f.system_update_1}) {
            if (slot->cg && zero_nonce(slot->cg->header.key)) {
                return "CG";
            }
        }
        return std::nullopt;
    }

    constexpr uint32_t kFsTimestamp = 0x5B2C3D4E;

    // run_build's fresh FlashFS: deferred root, files from the first block past the update slots
    // and the payloads, the geometry tail and the payload blocks reserved; then two files.
    Result<void> add_filesystem(FlashImage& f, BuildType type) {
        FlashFileSystem fs{};
        fs.set_driver(&f.flash_driver);
        fs.set_larger_filesystem(type == BuildType::Devkit);
        fs.set_timestamp(kFsTimestamp);
        fs.set_big_system_blocks(type == BuildType::Retail
                                     ? static_cast<uint8_t>(f.update_slots_end() / 0x20000)
                                     : uint8_t{0x10});
        const size_t total_blocks = f.flash_driver.block_count();
        const size_t data_limit = f.flash_driver.data_block_limit();
        const size_t block_size = f.flash_driver.block_size_clean();
        size_t first_block = (f.update_slots_end() + block_size - 1) / block_size;
        for (const auto& range : f.active_payload_block_ranges()) {
            first_block = std::max(first_block, range.start_block + range.block_count);
        }
        if (auto formatted = fs.format(total_blocks, FlashFileSystem::kDeferRoot, 1,
                                       static_cast<uint32_t>(first_block));
            !formatted) {
            return with_context(std::move(formatted), "format");
        }
        if (data_limit < total_blocks) {
            const auto mode = f.flash_driver.driver_mode();
            const bool pool =
                mode == Driver::Big ||
                ((mode == Driver::Small || mode == Driver::NewSmall) && total_blocks <= 0x400);
            const size_t held =
                pool ? (mode == Driver::Big ? 0 : std::min<size_t>(4, total_blocks - data_limit))
                     : total_blocks - data_limit;
            if (held > 0) {
                if (auto reserved = fs.reserve_blocks(data_limit, held); !reserved) {
                    return with_context(std::move(reserved), "reserve tail");
                }
            }
            if (data_limit + held < total_blocks) {
                if (auto withheld =
                        fs.withhold_blocks(data_limit + held, total_blocks - data_limit - held,
                                           BlockMapStatus::Unnamed);
                    !withheld) {
                    return with_context(std::move(withheld), "withhold tail");
                }
            }
        }
        for (const auto& range : f.active_payload_block_ranges()) {
            if (auto reserved = fs.reserve_blocks(range.start_block, range.block_count);
                !reserved) {
                return with_context(std::move(reserved), "reserve payload blocks");
            }
        }
        f.filesystem = std::move(fs);
        f.filesystem->set_driver(&f.flash_driver);
        if (auto added = f.filesystem->add_file("gxb_alpha.bin", pattern(0x5123, 0x11)); !added) {
            return with_context(std::move(added), "add gxb_alpha.bin");
        }
        if (auto added = f.filesystem->add_file("gxb_beta.bin", pattern(0x1F0, 0x22)); !added) {
            return with_context(std::move(added), "add gxb_beta.bin");
        }
        return {};
    }

    Driver::ImageSize image_size_for(Driver::DriverMode mode, BuildType type) {
        switch (mode) {
            case Driver::Big:
                return Driver::Bigordevkit;
            case Driver::Emmc:
                return Driver::Emmcblock;
            case Driver::Small:
            case Driver::NewSmall:
                break;
        }
        // run_build: a small-block devkit image is 64 MB.
        return type == BuildType::Devkit ? Driver::Bigordevkit : Driver::Smallblock;
    }

    // Builds one cell into `f` in place: its filesystem points at f.flash_driver, so `f` is
    // never moved afterwards.
    Result<void> build_cell(FlashImage& f, Driver::DriverMode mode, BuildType type,
                            bool with_update) {
        f.flash_driver = Driver(image_size_for(mode, type), mode);
        f.build_type = type;
        f.smc = synthetic_smc();
        // A stand-in for the console's sealed keyvault: opaque bytes, written as they are.
        Keyvault keyvault{};
        keyvault.encrypted = true;
        keyvault.raw_data = pattern(Keyvault::kSize, 0x4B);
        f.keyvault = std::move(keyvault);
        const auto spec = chain_for(type);
        if (auto loaded = load_stage<BootloaderCb>(f.cb_section.cb_or_A, spec.cb_a); !loaded) {
            return loaded;
        }
        if (spec.cb_x) {
            if (auto loaded = load_stage<BootloaderCb>(f.cb_section.cb_x, spec.cb_x); !loaded) {
                return loaded;
            }
            // run_build: a Glitch3 CB_X is supplied plaintext and takes the RGH2to3 v1 fix.
            f.cb_section.cb_x->decrypted = true;
            f.cb_section.cb_x->populate_metadata();
            (void) f.cb_section.cb_x->patch_rgh3_v1_cb_x();
        }
        if (spec.cb_b) {
            if (auto loaded = load_stage<BootloaderCb>(f.cb_section.cb_B, spec.cb_b); !loaded) {
                return loaded;
            }
        }
        if (spec.sc) {
            if (auto loaded = load_stage<BootloaderSc>(f.cb_section.sc, spec.sc); !loaded) {
                return loaded;
            }
        }
        if (auto loaded = load_stage<BootloaderCd>(f.kernel_section.cd, spec.cd); !loaded) {
            return loaded;
        }
        if (auto loaded = load_stage<BootloaderCe>(f.kernel_section.ce, spec.ce); !loaded) {
            return loaded;
        }
        if (with_update) {
            if (auto loaded = load_stage<BootloaderCf>(f.system_update_0.cf, "common/cf_4532.bin");
                !loaded) {
                return loaded;
            }
            if (auto loaded = load_stage<BootloaderCg>(f.system_update_0.cg, "common/cg_4532.bin");
                !loaded) {
                return loaded;
            }
        }
        // run_build: a devkit chain is supplied plaintext.
        if (f.devkit_chain()) {
            f.cb_section.cb_or_A.decrypted = true;
            f.cb_section.cb_or_A.populate_metadata();
            if (f.cb_section.sc) {
                f.cb_section.sc->decrypted = true;
            }
            f.kernel_section.cd.decrypted = true;
            if (f.kernel_section.ce) {
                f.kernel_section.ce->decrypted = true;
            }
        }

        if (spec.patches) {
            auto patches = parse_patch_set(support_file(spec.patches), type);
            if (!patches) {
                return std::unexpected(std::move(patches.error()).add_context(spec.patches));
            }
            f.payloads.patchset = std::move(*patches);
        }
        // The payloads the resolver adds: XeLL for JTAG and the glitch family, the freeBOOT
        // core, its loader and the JTAG second chain for JTAG, fuses for JTAG, Glitch2m and
        // devgl.
        const bool jtag = type == BuildType::Jtag;
        const bool glitch_family = type == BuildType::Glitch || type == BuildType::Glitch2 ||
                                   type == BuildType::Glitch2m || type == BuildType::Glitch3;
        if (jtag || glitch_family) {
            auto xell =
                XeLL::parse(support_file(jtag ? "mydata/xell-2f.bin" : "mydata/xell-gggggg.bin"));
            if (!xell) {
                return std::unexpected(std::move(xell.error()).add_context("XeLL"));
            }
            f.payloads.xell = std::move(*xell);
        }
        if (jtag) {
            f.payloads.rebooter = freeboot_rebooter_for("17559");
            f.payloads.payload = freeboot_payload_for(f.payloads.rebooter->size());
            if (auto loaded = load_stage<BootloaderCb>(f.payloads.extra_cb, "common/cb_6750.bin");
                !loaded) {
                return loaded;
            }
            if (auto loaded = load_stage<BootloaderCd>(f.payloads.extra_cd, "common/cd_8453.bin");
                !loaded) {
                return loaded;
            }
        }
        if (jtag || type == BuildType::Glitch2m || type == BuildType::Devgl) {
            f.payloads.fuses = pattern(0x60, 0xF0);
        }

        pin_nonces(f);

        if (auto fs = add_filesystem(f, type); !fs) {
            return with_context(std::move(fs), "FlashFS");
        }
        f.mobile_data = MobileData{};
        f.mobile_data->x31 = pattern(0x1F0, 0x31);
        f.mobile_data->x32 = pattern(0x8C0, 0x32);
        return {};
    }

    std::string stage_flags(const FlashImage& f) {
        std::string out;
        const auto add = [&out](std::string_view name, bool present, bool plaintext) {
            if (!present) {
                return;
            }
            out +=
                (out.empty() ? "" : " ") + std::string{name} + (plaintext ? ":plain" : ":sealed");
        };
        add("CB_A", !f.cb_section.cb_or_A.data.empty(), f.cb_section.cb_or_A.decrypted);
        add("CB_X", f.cb_section.cb_x.has_value(),
            f.cb_section.cb_x && f.cb_section.cb_x->decrypted);
        add("CB_B", f.cb_section.cb_B.has_value(),
            f.cb_section.cb_B && f.cb_section.cb_B->decrypted);
        add("SC", f.cb_section.sc.has_value(), f.cb_section.sc && f.cb_section.sc->decrypted);
        add("CD", !f.kernel_section.cd.data.empty(), f.kernel_section.cd.is_decrypted());
        add("CE", f.kernel_section.ce.has_value(),
            f.kernel_section.ce && f.kernel_section.ce->is_decrypted());
        add("CF0", f.system_update_0.cf.has_value(),
            f.system_update_0.cf && f.system_update_0.cf->is_decrypted());
        add("CG0", f.system_update_0.cg.has_value(),
            f.system_update_0.cg && f.system_update_0.cg->is_decrypted());
        add("XCB", f.payloads.extra_cb.has_value(),
            f.payloads.extra_cb && f.payloads.extra_cb->decrypted);
        add("XCD", f.payloads.extra_cd.has_value(),
            f.payloads.extra_cd && f.payloads.extra_cd->is_decrypted());
        return out.empty() ? "none" : out;
    }

    template <class Stage>
    void render_serialized(Snapshot& s, std::string_view p, std::string_view name,
                           const Stage* stage) {
        if (stage == nullptr) {
            return;
        }
        const auto bytes = stage->serialize();
        s.line(p, "stage." + std::string{name}, hex32(bytes.size()) + " sha1:" + sha1(bytes));
    }

    void render_layout_queries(Snapshot& s, std::string_view p, const FlashImage& f) {
        s.num(p, "update_slots_end", f.update_slots_end());
        s.num(p, "patch_slot_offset", f.patch_slot_offset());
        std::string ranges;
        for (const auto& range : f.active_payload_block_ranges()) {
            ranges += (ranges.empty() ? "" : ",") + hex32(range.start_block) + "+" +
                      hex32(range.block_count);
        }
        s.line(p, "active_payload_block_ranges", ranges.empty() ? "none" : ranges);
        s.line(p, "payload_layout", outcome(f.payload_layout()));
    }

    void render_fs_entries(Snapshot& s, std::string_view p, const FlashImage& f) {
        if (!f.filesystem) {
            s.line(p, "fs", "absent");
            return;
        }
        std::string entries;
        for (const auto& entry : f.filesystem->entries()) {
            if (!entry.is_valid()) {
                continue;
            }
            const std::string name(entry.filename, strnlen(entry.filename, sizeof(entry.filename)));
            entries += (entries.empty() ? "" : ",") + escaped(name) + "@" +
                       hex32(entry.block_number) + "+" + hex32(entry.length);
        }
        s.line(p, "fs.entries", entries.empty() ? "none" : entries);
        s.num(p, "fs.root_block", f.filesystem->root_block());
        const auto& map = f.filesystem->blockmap();
        s.line(p, "fs.blockmap_sha1",
               sha1(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(map.data()),
                                             map.size() * sizeof(uint16_t))));
    }

    // Records write(): size, SHA-256 and the 0x80 header bytes as laid, or the failure.
    std::optional<Bytes> render_write(Snapshot& s, std::string_view p, const FlashImage& f) {
        auto written = f.write();
        if (!written) {
            s.line(p, "write", "error " + describe_error(written.error()));
            return std::nullopt;
        }
        s.line(p, "write", hex32(written->size()) + " sha256:" + sha256(*written));
        s.line(p, "header", hex(std::as_const(f.flash_driver).read_offset(0, sizeof(nand_header))));
        return std::move(*written);
    }

    std::string render_cell(Driver::DriverMode mode, BuildType type) {
        std::ostringstream out;
        Snapshot s{out};
        const std::string base = "matrix." + std::string{driver_mode_name(mode)} + '.' +
                                 std::string{build_type_name(type)} + '.';

        // plain: no update pair, written unsealed.
        {
            const std::string p = base + "plain.";
            auto f = std::make_unique<FlashImage>();
            if (auto built = build_cell(*f, mode, type, false); !built) {
                check(false, p + "build");
                s.line(p, "build", outcome(built));
            } else {
                s.line(p, "stages", stage_flags(*f));
                render_layout_queries(s, p, *f);
                (void) render_write(s, p, *f);
                render_fs_entries(s, p, *f);
            }
        }

        // sealed: CF/CG 4532 in slot 0, encrypt_all, write, parse back.
        const std::string p = base + "sealed.";
        auto f = std::make_unique<FlashImage>();
        if (auto built = build_cell(*f, mode, type, true); !built) {
            check(false, p + "build");
            s.line(p, "build", outcome(built));
            return out.str();
        }
        s.line(p, "stages", stage_flags(*f));
        if (const auto zero = zero_random_nonce(*f)) {
            check(false, p + "nonce pinned");
            s.line(p, "seal", "skipped: zero " + *zero + " nonce");
            return out.str();
        }
        const auto sealed = f->encrypt_all(kCpuKey, type);
        s.line(p, "seal", outcome(sealed));
        if (!sealed) {
            return out.str();
        }
        s.line(p, "stages_after_seal", stage_flags(*f));
        render_serialized(s, p, "CB_A", &f->cb_section.cb_or_A);
        render_serialized(s, p, "CB_X", opt_ptr(f->cb_section.cb_x));
        render_serialized(s, p, "CB_B", opt_ptr(f->cb_section.cb_B));
        render_serialized(s, p, "SC", opt_ptr(f->cb_section.sc));
        render_serialized(s, p, "CD", &f->kernel_section.cd);
        render_serialized(s, p, "CE", opt_ptr(f->kernel_section.ce));
        render_serialized(s, p, "CF0", opt_ptr(f->system_update_0.cf));
        render_serialized(s, p, "CG0", opt_ptr(f->system_update_0.cg));
        render_serialized(s, p, "XCB", opt_ptr(f->payloads.extra_cb));
        render_serialized(s, p, "XCD", opt_ptr(f->payloads.extra_cd));
        s.line(p, "smc_sha1", f->smc ? sha1(f->smc->data) : "absent");
        std::string spill;
        for (const auto block : f->system_update_0.cg_spill_blocks) {
            spill += (spill.empty() ? "" : ",") + hex32(block);
        }
        s.line(p, "cg_spill_blocks.0", spill.empty() ? "none" : spill);
        render_layout_queries(s, p, *f);
        const auto written = render_write(s, p, *f);
        render_fs_entries(s, p, *f);
        if (!written) {
            return out.str();
        }
        auto back = FlashImage::read(*written);
        if (!back) {
            s.line(p, "reparse", "absent");
            return out.str();
        }
        const auto parsed = back->parse();
        s.line(p, "reparse", outcome(parsed));
        if (parsed) {
            s.line(p, "reparse.build_type",
                   back->build_type ? build_type_name(*back->build_type) : "none");
            s.line(p, "reparse.driver_mode", driver_mode_name(back->flash_driver.driver_mode()));
            // The parsed CG stops at its declared size; the sealed one carries the 16-byte
            // rounding, so the parsed bytes are compared as a prefix.
            if (back->system_update_0.cg && f->system_update_0.cg) {
                const auto read_back = back->system_update_0.cg->serialize();
                const auto sealed_cg = f->system_update_0.cg->serialize();
                s.line(
                    p, "reparse.cg0",
                    hex32(read_back.size()) + " of " + hex32(sealed_cg.size()) + " prefix_match=" +
                        (read_back.size() <= sealed_cg.size() &&
                                 std::equal(read_back.begin(), read_back.end(), sealed_cg.begin())
                             ? "1"
                             : "0"));
            } else {
                s.line(p, "reparse.cg0", "absent");
            }
        }
        return out.str();
    }

    std::string render_matrix() {
        std::ostringstream out;
        out << "# F0c synthetic fresh-layout matrix: see FlashImageGoldenTests.cpp.\n";
        // The 0x80-byte header write_to_driver encodes for an all-zero nand_header on an
        // otherwise empty image.
        for (const auto mode : {Driver::Small, Driver::Big, Driver::Emmc}) {
            FlashImage zeroed{};
            zeroed.flash_driver = Driver(image_size_for(mode, BuildType::Retail), mode);
            Snapshot s{out};
            const std::string p = "header_encode." + std::string{driver_mode_name(mode)} + '.';
            (void) render_write(s, p, zeroed);
        }
        size_t cells = 0;
        for (const auto mode : {Driver::Small, Driver::Big, Driver::Emmc}) {
            for (const auto type :
                 {BuildType::Retail, BuildType::Jtag, BuildType::Glitch, BuildType::Glitch2,
                  BuildType::Glitch2m, BuildType::Glitch3, BuildType::Devgl, BuildType::Devkit}) {
                out << render_cell(mode, type);
                ++cells;
            }
        }
        out << "matrix.cells=" << cells << '\n';
        return out.str();
    }

    // ---- Failure table (tests/golden/flashimage_failures.txt) -----------------------------
    //
    // ErrorCode and describe() of each reachable FlashImage exit, in the order the checks run
    // today: the stage splits must keep both.

    class FailureTable {
      public:
        template <class T> void add(std::string_view name, const Result<T>& result) {
            m_out << "fail." << name << '='
                  << (result ? std::string{"ok"} : describe_error(result.error())) << '\n';
            ++m_rows;
        }
        void note(std::string_view name, std::string_view text) {
            m_out << "fail." << name << '=' << text << '\n';
            ++m_rows;
        }
        [[nodiscard]] std::string text() const {
            return m_out.str() + "fail.rows=" + std::to_string(m_rows) + '\n';
        }

      private:
        std::ostringstream m_out;
        size_t m_rows = 0;
    };

    // A sealed Small Retail cell, written; the spill-table cases corrupt its bytes.
    std::optional<Bytes> sealed_retail_bytes() {
        auto f = std::make_unique<FlashImage>();
        if (!check(build_cell(*f, Driver::Small, BuildType::Retail, true),
                   "failure fixture: Small Retail cell builds") ||
            !check(f->encrypt_all(kCpuKey, BuildType::Retail),
                   "failure fixture: Small Retail cell seals")) {
            return std::nullopt;
        }
        auto written = f->write();
        if (!check(written.has_value(), "failure fixture: Small Retail cell writes")) {
            return std::nullopt;
        }
        return std::move(*written);
    }

    // Parses `bytes` after rewriting slot 0's CF continuation table through `edit`.
    Result<void> parse_with_cf_table(const Bytes& bytes,
                                     const std::function<void(std::vector<uint8_t>&)>& edit) {
        auto img = FlashImage::read(bytes);
        if (!img || !img->parse() || !img->system_update_0.cf) {
            return fail(ErrorCode::Internal, "test fixture: the sealed cell does not parse");
        }
        auto cf = *img->system_update_0.cf;
        if (auto opened = cf.decrypt(key_1bl); !opened) {
            return opened;
        }
        edit(cf.data);
        if (auto sealed = cf.encrypt(key_1bl); !sealed) {
            return sealed;
        }
        if (!img->flash_driver.write_offset(img->header.cf_offset, cf.serialize())) {
            return fail(ErrorCode::Internal, "test fixture: the CF cannot be laid back");
        }
        auto damaged = FlashImage::read(img->flash_driver.serialize());
        if (!damaged) {
            return fail(ErrorCode::Internal, "test fixture: the damaged image is empty");
        }
        return damaged->parse();
    }

    BootloaderCf oversized_cf(size_t payload) {
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.data.assign(payload, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + payload);
        cf.decrypted = true;
        return cf;
    }

    BootloaderCg small_cg() {
        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.data.assign(0x20, 0);
        cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + 0x20);
        return cg;
    }

    std::unique_ptr<FlashImage> bare(Driver::DriverMode mode, BuildType type) {
        auto f = std::make_unique<FlashImage>();
        f->flash_driver = Driver(image_size_for(mode, type), mode);
        f->build_type = type;
        return f;
    }

    std::string render_failures() {
        FailureTable t;

        // parse(), write_to_driver() and clear_bootloader_chain() on an image with no blocks.
        {
            FlashImage f{};
            f.flash_driver = Driver(Bytes{});
            t.add("empty.parse", f.parse());
            t.add("empty.write_to_driver", f.write_to_driver());
            t.add("empty.clear_bootloader_chain", f.clear_bootloader_chain());
            t.note("empty.read", FlashImage::read(Bytes{}) ? "present" : "absent");
        }
        // Smaller than the header: no shape has a block that small, so the no-blocks check
        // answers first.
        {
            FlashImage f{};
            f.flash_driver = Driver(Bytes(0x40, 0));
            t.add("smaller_than_header.parse", f.parse());
        }

        // The CF continuation table of a sealed image, damaged.
        if (const auto bytes = sealed_retail_bytes()) {
            t.add("cf_table.untouched.parse", parse_with_cf_table(*bytes, [](Bytes&) {}));
            t.add("cf_table.duplicate_cluster.parse", parse_with_cf_table(*bytes, [](Bytes& d) {
                      d[4] = d[2];
                      d[5] = d[3];
                  }));
            t.add("cf_table.count_mismatch.parse", parse_with_cf_table(*bytes, [](Bytes& d) {
                      d[1] = static_cast<uint8_t>(d[1] + 1);
                  }));
            t.add("cf_table.cluster_outside_data_area.parse",
                  parse_with_cf_table(*bytes, [](Bytes& d) {
                      d[2] = 0xFF;
                      d[3] = 0xFF;
                  }));
        } else {
            t.note("cf_table", "fixture unavailable");
        }

        // Update-slot shape, checked by payload_layout() before anything is laid.
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->system_update_0.cg = small_cg();
            t.add("cg0_without_cf0.payload_layout", f->payload_layout());
            t.add("cg0_without_cf0.write", f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->system_update_1.cg = small_cg();
            t.add("cg1_without_cf1.payload_layout", f->payload_layout());
        }
        {
            auto f = bare(Driver::Small, BuildType::Glitch2);
            f->system_update_1.cf = oversized_cf(0x400);
            t.add("glitch_with_cf1.payload_layout", f->payload_layout());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->system_update_0.cf = oversized_cf(0x10000);
            t.add("cf_overruns_slot.payload_layout", f->payload_layout());
            f->system_update_0.cg = small_cg();
            f->system_update_0.cf = oversized_cf(0x10000 - 0x30 - 0x10);
            t.add("cf_leaves_no_room_for_cg.payload_layout", f->payload_layout());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->cb_section.cb_or_A.header.header.magic = NANDBootloaderMagic::CB;
            f->cb_section.cb_or_A.header.header.size = 0x400;
            t.add("cb_header_without_payload.payload_layout", f->payload_layout());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->kernel_section.cd.header.header.magic = NANDBootloaderMagic::CD;
            f->kernel_section.cd.header.header.size = 0x400;
            t.add("cd_header_without_payload.payload_layout", f->payload_layout());
        }
        // XeLL against the glitch KHV slot: a header that puts the slots inside XeLL.
        {
            auto f = bare(Driver::Small, BuildType::Glitch2);
            f->preserve_layout = true;
            f->header.cf_offset = 0x80000;
            f->header.fs_addr = 0x10000;
            XeLL xell{};
            xell.data = support_file("mydata/xell-gggggg.bin");
            f->payloads.xell = xell;
            ParsedPatchSet patches{};
            patches.kind = PatchSetKind::Glitch;
            patches.sections.push_back({PatchSectionTarget::Khv, "khv", Bytes(0x20, 0), {}});
            f->payloads.patchset = patches;
            t.add("xell_overlaps_khv.payload_layout", f->payload_layout());
            t.add("xell_overlaps_khv.write", f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Glitch2);
            ParsedPatchSet patches{};
            patches.kind = PatchSetKind::Glitch;
            patches.sections.push_back({PatchSectionTarget::Khv, "khv", Bytes(0x10000, 0), {}});
            f->payloads.patchset = patches;
            t.add("khv_exceeds_slot.payload_layout", f->payload_layout());
        }
        {
            auto f = bare(Driver::Small, BuildType::Glitch2);
            ParsedPatchSet patches{};
            patches.kind = PatchSetKind::Glitch;
            patches.sections.push_back({PatchSectionTarget::Cd, "cd", Bytes(0x20, 0), {}});
            f->payloads.patchset = patches;
            t.add("glitch_patchset_without_khv.write", f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Jtag);
            ParsedPatchSet patches{};
            patches.kind = PatchSetKind::Jtag;
            patches.sections.push_back(
                {PatchSectionTarget::JtagSection1, "s1", Bytes(0x4400, 0), {}});
            f->payloads.patchset = patches;
            t.add("jtag_patch_exceeds_region.write", f->write());
        }

        // write_to_driver's own checks.
        for (const auto mode : {Driver::Small, Driver::Big, Driver::Emmc}) {
            auto f = bare(mode, BuildType::Retail);
            f->mobile_data = MobileData{};
            const size_t over = mode == Driver::Small ? 0x4001 : 0x10000;
            f->mobile_data->x31 = Bytes(over, 0x31);
            t.add("mobile_over_limit." + std::string{driver_mode_name(mode)} + ".write",
                  f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->smc = synthetic_smc();
            f->smc->data.resize(0x4000);
            t.add("smc_too_large.write", f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->smc_config = Bytes(0x200, 0);
            t.add("smc_config_wrong_size.write", f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->statistics = Bytes(0x200, 0);
            t.add("statistics_wrong_size.write", f->write());
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->raw_patches.push_back({"tail", 0x1000000 - 8, Bytes(0x10, 0xAA)});
            t.add("rawpatch_past_image.write", f->write());
        }
        {
            FlashImage f{};
            f.flash_driver = Driver(Bytes(0x4200 * 2, 0xFF));
            t.add("two_block_image.write", f.write());
        }

        // encrypt_all's checks, in the order it makes them.
        {
            auto f = bare(Driver::Small, BuildType::Glitch3);
            t.add("glitch3_without_cb_x.encrypt_all", f->encrypt_all(kCpuKey, BuildType::Glitch3));
        }
        {
            auto f = bare(Driver::Small, BuildType::Devkit);
            check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, "common/SB_10375.bin"),
                  "failure fixture loads");
            t.add("devkit_without_sc.encrypt_all", f->encrypt_all(kCpuKey, BuildType::Devkit));
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, "common/cba_6754.bin"),
                  "failure fixture loads");
            check(load_stage<BootloaderCb>(f->cb_section.cb_B, "common/cbb_6754.bin"),
                  "failure fixture loads");
            t.add("split_chain_without_smc.encrypt_all", f->encrypt_all(kCpuKey));
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->smc = synthetic_smc();
            check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, "common/cba_6754.bin"),
                  "failure fixture loads");
            check(load_stage<BootloaderCb>(f->cb_section.cb_B, "common/cbb_6754.bin"),
                  "failure fixture loads");
            f->cb_section.cb_or_A.decrypted = false;
            f->cb_section.cb_or_A.derived_key.reset();
            t.add("cb_b_without_cb_a_key.encrypt_all", f->encrypt_all(kCpuKey));
        }
        {
            auto f = bare(Driver::Small, BuildType::Glitch);
            check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, "common/cb_6750.bin"),
                  "failure fixture loads");
            check(load_stage<BootloaderCd>(f->kernel_section.cd, "common/cd_8453.bin"),
                  "failure fixture loads");
            f->kernel_section.cd.decrypted = true;
            f->cb_section.cb_or_A.decrypted = false;
            f->cb_section.cb_or_A.derived_key.reset();
            t.add("cd_without_parent_key.encrypt_all", f->encrypt_all(kCpuKey, BuildType::Glitch));
        }
        {
            auto f = bare(Driver::Small, BuildType::Glitch);
            check(load_stage<BootloaderCe>(f->kernel_section.ce, "common/ce_1888.bin"),
                  "failure fixture loads");
            f->kernel_section.ce->decrypted = true;
            t.add("ce_without_cd_key.encrypt_all", f->encrypt_all(kCpuKey, BuildType::Glitch));
        }
        {
            auto f = bare(Driver::Small, BuildType::Jtag);
            check(load_stage<BootloaderCd>(f->payloads.extra_cd, "common/cd_8453.bin"),
                  "failure fixture loads");
            f->payloads.extra_cd->decrypted = true;
            t.add("jtag_second_cd_without_cb.encrypt_all",
                  f->encrypt_all(kCpuKey, BuildType::Jtag));
        }
        {
            auto f = bare(Driver::Small, BuildType::Retail);
            f->system_update_0.cf = oversized_cf(0x10000 - 0x30 - 0x10);
            f->system_update_0.cg = small_cg();
            f->system_update_0.cg->header.key[0] = 1;
            f->system_update_0.cg->decrypted = false;
            t.add("cf_leaves_no_room_for_cg.encrypt_all", f->encrypt_all(kCpuKey));
        }
        // An oversized CG with no filesystem to hold its tail.
        {
            auto f = std::make_unique<FlashImage>();
            if (check(build_cell(*f, Driver::Small, BuildType::Retail, true),
                      "failure fixture: Small Retail cell builds")) {
                f->filesystem.reset();
                t.add("cg_tail_without_flashfs.encrypt_all",
                      f->encrypt_all(kCpuKey, BuildType::Retail));
            }
        }
        // An oversized CG that was never given its continuation clusters.
        {
            auto f = std::make_unique<FlashImage>();
            if (check(build_cell(*f, Driver::Small, BuildType::Retail, true),
                      "failure fixture: Small Retail cell builds")) {
                t.add("cg_tail_unallocated.write", f->write());
            }
        }
        return "# F0c FlashImage failure table: code | describe().\n" + t.text();
    }

    void pin_build_time() {
#ifdef _WIN32
        _putenv_s("SOURCE_DATE_EPOCH", kSourceDateEpoch);
        _putenv_s("TZ", "UTC");
#else
        setenv("SOURCE_DATE_EPOCH", kSourceDateEpoch, 1);
        setenv("TZ", "UTC", 1);
#endif
    }

} // namespace

int main(int argc, char** argv) {
    pin_build_time();
    const auto options = test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }
    if (!sha256_self_test()) {
        return 1;
    }

    const std::filesystem::path support{GXBUILD3_SUPPORT_DIR};
    std::filesystem::path image_path = support / "mydata" / "image.bin";
    if (const char* override_path = std::getenv("GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE");
        override_path != nullptr && *override_path != '\0') {
        image_path = override_path;
        std::cerr << "note: image overridden by GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE\n";
    }
    const auto bytes = read_file(image_path);
    if (!bytes || bytes->empty()) {
        std::cerr << "FAIL: cannot read the tracked donor " << image_path.string() << '\n';
        return 1;
    }
    const auto info_bytes = read_file(support / "mydata" / "image.info");
    if (!info_bytes) {
        std::cerr << "FAIL: cannot read the tracked mydata/image.info\n";
        return 1;
    }
    const std::string image_info(info_bytes->begin(), info_bytes->end());

    std::ostringstream text;
    text << "# FlashImage golden over tracked mydata/image.bin; identities only as SHA-1.\n";
    text << "input.size=" << hex32(bytes->size()) << '\n';
    text << "input.sha256=" << sha256(*bytes) << '\n';

    // (1)-(3): parse, layout queries, write() straight after parse.
    if (auto img = parsed_image(*bytes)) {
        text << render_image(*img, "parse.");
        text << render_layout(*img);
        const auto written = img->write();
        if (check(written.has_value(), "write() after parse")) {
            text << "write.size=" << hex32(written->size()) << '\n';
            text << "write.sha256=" << sha256(*written) << '\n';
            text << "write.identity=" << (*written == *bytes ? 1 : 0) << '\n';
        }
    }

    // (4)-(5): parse, decrypt_all (snapshot), encrypt_all, write().
    if (auto img = parsed_image(*bytes)) {
        if (check(img->decrypt_all(kCpuKey), "decrypt_all under the donor's CPU key")) {
            text << render_image(*img, "decrypt.");
            const auto type = img->build_type.value_or(BuildType::Retail);
            text << "roundtrip.encrypt_build_type=" << build_type_name(type) << '\n';
            if (check(img->encrypt_all(kCpuKey, type), "encrypt_all after decrypt_all")) {
                const auto written = img->write();
                if (check(written.has_value(), "write() after decrypt_all and encrypt_all")) {
                    text << "roundtrip.size=" << hex32(written->size()) << '\n';
                    text << "roundtrip.sha256=" << sha256(*written) << '\n';
                    text << "roundtrip.identity=" << (*written == *bytes ? 1 : 0) << '\n';
                }
            }
        }
    }

    // O0b part (2): the public summary of the same dump.
    text << render_info(*bytes, image_info);

    // F0c: the synthetic fresh-layout matrix and the failure table. Neither needs the donor.
    g_support = support;
    if (const char* override_dir = std::getenv("GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT");
        override_dir != nullptr && *override_dir != '\0') {
        g_support = override_dir;
        std::cerr << "note: matrix fixtures overridden by GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT\n";
    }
    const std::array<std::pair<std::string_view, std::string>, 3> goldens{{
        {"flashimage_golden", text.str()},
        {"flashimage_matrix", render_matrix()},
        {"flashimage_failures", render_failures()},
    }};

    for (const auto& [name, rendered] : goldens) {
        const bool golden_ok = test::check_golden(*options, name, rendered);
        ++g_checks;
        if (!golden_ok) {
            ++g_failures;
        }
        size_t lines = 0;
        for (const char c : rendered) {
            lines += c == '\n' ? 1 : 0;
        }
        std::cout << name << ": snapshot lines " << lines << (golden_ok ? " match" : " DIFFER")
                  << '\n';
    }
    std::cout << "flashimage_golden: goldens 3, checks " << (g_checks - g_failures) << '/'
              << g_checks << " passed\n";
    return g_failures == 0 ? 0 : 1;
}
