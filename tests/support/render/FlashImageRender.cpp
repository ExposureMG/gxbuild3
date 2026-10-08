// gxbuild3_flashimage_render, parse side: the snapshot of a parsed FlashImage, its layout
// queries and extract_all_info()'s summary. Moved verbatim from FlashImageGoldenTests.cpp; see
// FlashImageRender.hpp.

#include "support/render/FlashImageRender.hpp"

#include "BuildRunner.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "support/Sha256.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::test::render {

    using namespace gxbuild3::nand;

    bool RenderChecks::check(bool ok, std::string_view message) {
        ++count;
        if (!ok) {
            problems.emplace_back(message);
        }
        return ok;
    }

    bool RenderChecks::check(const Result<void>& result, std::string_view message) {
        ++count;
        if (!result) {
            problems.push_back(std::string{message} + ": " + result.error().describe());
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

    // tests/support/Sha256.hpp: GxCrypt's ExCryptSha256 does not link.
    std::string sha256(std::span<const uint8_t> bytes) {
        return test::sha256_hex(bytes);
    }

    namespace {

        template <class T> std::span<const uint8_t> raw_bytes(const T& value) {
            return {reinterpret_cast<const uint8_t*>(&value), sizeof(value)};
        }

    } // namespace

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

    namespace {

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
        void render_stage(Snapshot& s, std::string_view p, std::string_view name,
                          const Stage* stage) {
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
                    s.line(p, k + "perbox.pairing_sha1",
                           sha1(raw_bytes(stage->perbox->pairing_data)));
                    s.line(p, k + "perbox.sha1", sha1(raw_bytes(*stage->perbox)));
                }
            }
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
            s.num(p, "keyvault.region", d.w16GameRegion.get());
            s.line(p, "keyvault.console_id_sha1",
                   sha1(raw_bytes(d.b36ConsoleCertificate.ConsoleId)));
            s.line(p, "keyvault.mfr_date_sha1",
                   sha1(raw_bytes(d.b36ConsoleCertificate.ManufacturingDate)));
            if (kv->raw_data.size() >= 0xC92 + 28) {
                s.line(p, "keyvault.osig_sha1",
                       sha1(std::span<const uint8_t>(kv->raw_data).subspan(0xC92, 28)));
            }
            s.num(p, "keyvault.odd_features", d.w4OddFeatures.get());
            if (!kv->encrypted) {
                s.line(p, "keyvault.fcrt_requirement",
                       fcrt_name(fcrt_requirement(kv->serialize())));
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
                const std::string name(entry.filename,
                                       strnlen(entry.filename, sizeof(entry.filename)));
                const auto file = fs->get_file(name);
                s.line(p, k + "name", escaped(name));
                s.line(p, k + "info",
                       "block=" + hex32(entry.block_number) + " length=" + hex32(entry.length) +
                           " timestamp=" + hex32(entry.timestamp) + " file=" +
                           (file ? hex32(file->size()) + " sha1:" + sha1(*file) : "absent"));
            }
            const auto root = fs->serialize_root_block();
            s.line(p, "fs.serialize_root_block",
                   root ? hex32(root->size()) + " sha1:" + sha1(*root)
                        : "error " + std::string{to_string(root.error().code)});
        }

        void render_mobile(Snapshot& s, std::string_view p,
                           const std::optional<MobileData>& mobile) {
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
                s.line(p, "payloads.patchset.kind",
                       ps.kind == PatchSetKind::Jtag ? "Jtag" : "Glitch");
                s.flag(p, "payloads.patchset.manufacturing", ps.manufacturing);
                s.num(p, "payloads.patchset.sections", ps.sections.size());
                for (size_t i = 0; i < ps.sections.size(); ++i) {
                    const auto& sec = ps.sections[i];
                    s.line(p, "payloads.patchset.section." + std::to_string(i),
                           std::string{section_target_name(sec.target)} + " id=" +
                               escaped(sec.identifier) + " entries=" + hex32(sec.entries.size()) +
                               " raw=" + hex32(sec.raw_data.size()) +
                               " sha1:" + sha1(sec.raw_data));
                }
            } else {
                s.line(p, "payloads.patchset", "absent");
            }
            render_stage(s, p, "extra_cb", opt_ptr(payloads.extra_cb));
            render_stage(s, p, "extra_cd", opt_ptr(payloads.extra_cd));
        }

    } // namespace

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

    // checks: count a payload_layout() failure as a problem (the donor golden); the snapshot
    // tool passes nullptr and only records it.
    std::string render_layout(const FlashImage& img, RenderChecks* checks) {
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
        if (checks != nullptr) {
            checks->check(layout, "payload_layout() on the parsed donor");
        }
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

    std::optional<FlashImage> parsed_image(const std::vector<uint8_t>& bytes,
                                           RenderChecks& checks) {
        auto img = FlashImage::read(bytes);
        if (!checks.check(img.has_value(), "FlashImage::read on the donor")) {
            return std::nullopt;
        }
        if (!checks.check(img->parse(), "FlashImage::parse on the donor")) {
            return std::nullopt;
        }
        return img;
    }

    namespace {

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

    } // namespace

    // extract_all_info()'s summary of `bytes` under the public CPU key. With checks a failure
    // is a problem (the donor golden); the snapshot tool passes nullptr and only records it.
    std::optional<AllNandInfo> render_info_summary(Snapshot& s, const std::vector<uint8_t>& bytes,
                                                   RenderChecks* checks) {
        constexpr std::string_view p = "info.";
        auto info =
            extract_all_info(std::span<const uint8_t>(bytes), std::span<const uint8_t>(kCpuKey));
        if (!info.has_value()) {
            if (checks != nullptr) {
                checks->check(false, "extract_all_info on the donor");
            }
            s.line(p, "result", "error " + std::string{to_string(info.error().code)});
            return std::nullopt;
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
        return std::move(*info);
    }

    std::string render_info(const std::vector<uint8_t>& bytes, std::string_view image_info,
                            RenderChecks& checks) {
        std::ostringstream out;
        Snapshot s{out};
        constexpr std::string_view p = "info.";
        const auto info = render_info_summary(s, bytes, &checks);
        if (!info) {
            return out.str();
        }
        const auto& kv = info->keyvault;

        // xeBuild's own report of this dump must agree with what gxbuild3 reads.
        const auto serial = info_value(image_info, "Serial");
        const auto console_id = info_value(image_info, "ConsoleId");
        const auto cpu_key = info_value(image_info, "CPU Key");
        checks.check(serial.has_value() && console_id.has_value() && cpu_key.has_value(),
                     "image.info carries Serial, ConsoleId and CPU Key lines");
        const bool serial_match = serial && *serial == kv.serial_number;
        const bool console_id_match = console_id && *console_id == kv.console_id_friendly;
        std::string want_key;
        for (const char c : cpu_key.value_or("")) {
            want_key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        checks.check(serial_match, "KeyvaultSummaryInfo serial matches image.info Serial");
        checks.check(console_id_match,
                     "KeyvaultSummaryInfo console id matches image.info ConsoleId");
        checks.check(want_key == hex(kCpuKey), "image.info CPU Key is the key this test uses");
        s.flag(p, "image_info.serial_match", serial_match);
        s.flag(p, "image_info.console_id_match", console_id_match);
        return out.str();
    }

    std::string describe_error(const Error& error) {
        return std::string{to_string(error.code)} + " | " + error.describe();
    }

} // namespace gxbuild3::test::render
