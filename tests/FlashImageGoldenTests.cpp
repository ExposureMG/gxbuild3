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
// The CPU key is the one already public in tests/gxBuild-support-files/build_all.sh. --update
// rewrites the golden (CTest never passes it). GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE overrides the
// image path, for mutation checks against a scratch copy only.

#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "Sha256.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/objects/SecuredFiles.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
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

    const std::string rendered = text.str();
    const bool golden_ok = test::check_golden(*options, "flashimage_golden", rendered);
    ++g_checks;
    if (!golden_ok) {
        ++g_failures;
    }

    size_t lines = 0;
    for (const char c : rendered) {
        lines += c == '\n' ? 1 : 0;
    }
    std::cout << "flashimage_golden: snapshot lines " << lines << ", checks "
              << (g_checks - g_failures) << '/' << g_checks << " passed\n";
    return g_failures == 0 ? 0 : 1;
}
