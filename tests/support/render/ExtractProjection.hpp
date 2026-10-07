#pragma once

// Text projections of the four public extraction entry points, for goldens.
//
// render_extract_projections(label, image, cpu_key) runs extract_some_info, extract_metadata,
// extract_all_info and extract_all over one image and renders every field of what each returns
// (or its describe() on failure) as "<label>.<projection> ..." lines:
//   - AllNandInfo: the header fields, copyright and block type, every BootloaderEntryInfo field
//     (ldv and pairing included) and the BootloaderChainInfo LDV/pairing summary, the SMC and
//     FlashFS summaries, the KeyvaultSummaryInfo, the CPU key and raw keyvault;
//   - InputMetadata: every scalar, the donor nonces, the settings blocks and the console's
//     secured files;
//   - Input: every scalar and option, and the size and SHA-1 of every byte vector.
// Console identity strings (serial, console ID raw and friendly, OSIG, manufacturing date, DVD
// key) are rendered as SHA-1 only, so a golden does not repeat a console's identity in clear.
//
// The same projection is also taken through the other overload of each core (vector or span)
// and through the GxBuild:: library shims; each must render identically to the core's span
// overload, and agreements()/comparisons() count how many did.

#include "BuildRunner.hpp"
#include "Library.hpp"
#include "excrypt.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::test::projection {

    [[nodiscard]] inline std::string sha1(std::span<const uint8_t> bytes) {
        std::array<uint8_t, 20> digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const uint8_t byte : digest) {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0F]);
        }
        return out;
    }

    [[nodiscard]] inline std::string hex(std::span<const uint8_t> bytes) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const uint8_t byte : bytes) {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0F]);
        }
        return out;
    }

    [[nodiscard]] inline std::string num(uint64_t value) {
        char text[32];
        std::snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
        return text;
    }

    // "size=0x.. sha1=.." of a byte vector.
    [[nodiscard]] inline std::string blob(std::span<const uint8_t> bytes) {
        return "size=" + num(bytes.size()) + " sha1=" + sha1(bytes);
    }

    [[nodiscard]] inline std::string blob(const std::vector<uint8_t>& bytes) {
        return blob(std::span<const uint8_t>(bytes));
    }

    [[nodiscard]] inline std::string blob(const std::optional<std::vector<uint8_t>>& bytes) {
        return bytes ? blob(*bytes) : std::string{"none"};
    }

    // An identity string: "empty", or the SHA-1 of its bytes and its length.
    [[nodiscard]] inline std::string identity(std::string_view text) {
        if (text.empty()) {
            return "empty";
        }
        return "len=" + std::to_string(text.size()) +
               ",sha1=" + sha1({reinterpret_cast<const uint8_t*>(text.data()), text.size()});
    }

    [[nodiscard]] inline std::string quote_text(std::string_view text) {
        std::string out{"\""};
        for (const char c : text) {
            const auto byte = static_cast<unsigned char>(c);
            if (byte < 0x20 || byte >= 0x7F || c == '"' || c == '\\') {
                char escaped[8];
                std::snprintf(escaped, sizeof(escaped), "\\x%02x", byte);
                out += escaped;
            } else {
                out.push_back(c);
            }
        }
        return out + '"';
    }

    [[nodiscard]] inline std::string_view name(BuildType type) {
        switch (type) {
            case BuildType::Retail:
                return "retail";
            case BuildType::Jtag:
                return "jtag";
            case BuildType::Glitch:
                return "glitch";
            case BuildType::Glitch2:
                return "glitch2";
            case BuildType::Glitch2m:
                return "glitch2m";
            case BuildType::Glitch3:
                return "glitch3";
            case BuildType::Devkit:
                return "devkit";
            case BuildType::Devgl:
                return "devgl";
        }
        return "unknown";
    }

    [[nodiscard]] inline std::string_view name(ImageType type) {
        switch (type) {
            case ImageType::SmallBlock:
                return "SmallBlock";
            case ImageType::NewSmallBlock:
                return "NewSmallBlock";
            case ImageType::BigBlock:
                return "BigBlock";
            case ImageType::Emmc:
                return "Emmc";
        }
        return "unknown";
    }

    [[nodiscard]] inline std::string_view name(ConsoleType type) {
        switch (type) {
            case ConsoleType::Xenon:
                return "Xenon";
            case ConsoleType::Zephyr:
                return "Zephyr";
            case ConsoleType::Falcon:
                return "Falcon";
            case ConsoleType::Jasper:
                return "Jasper";
            case ConsoleType::Trinity:
                return "Trinity";
            case ConsoleType::Corona:
                return "Corona";
            case ConsoleType::Winchester:
                return "Winchester";
        }
        return "unknown";
    }

    [[nodiscard]] inline std::string optional_ldv(const std::optional<uint8_t>& ldv) {
        return ldv ? std::to_string(*ldv) : std::string{"none"};
    }

    [[nodiscard]] inline std::string
    optional_pairing(const std::optional<std::array<uint8_t, 3>>& pairing) {
        return pairing ? hex(*pairing) : std::string{"none"};
    }

    [[nodiscard]] inline std::string optional_bool(const std::optional<bool>& value) {
        return value ? (*value ? "true" : "false") : "unset";
    }

    [[nodiscard]] inline std::string optional_text(const std::optional<std::string>& value) {
        return value ? quote_text(*value) : std::string{"unset"};
    }

    inline void render_entry(std::string& out, const std::string& prefix, std::string_view slot,
                             const std::optional<BootloaderEntryInfo>& entry) {
        out += prefix + " bl." + std::string{slot};
        if (!entry) {
            out += " none\n";
            return;
        }
        out += " name=" + quote_text(entry->name) + " present=" + (entry->present ? "1" : "0") +
               " decrypted=" + (entry->decrypted ? "1" : "0") + " version=" + num(entry->version) +
               " size=" + num(entry->size) + " flags=" + num(entry->flags) +
               " entrypoint=" + num(entry->entrypoint) + " ldv=" + optional_ldv(entry->ldv) +
               " pairing=" + optional_pairing(entry->pairing_data) + '\n';
    }

    [[nodiscard]] inline std::string render(const std::string& prefix, const AllNandInfo& info) {
        std::string out;
        out += prefix + " header magic=" + num(info.header_magic) +
               " version=" + num(info.header_version) + " flags=" + num(info.header_flags) +
               " size=" + num(info.header_size) + '\n';
        out += prefix + " copyright=" + quote_text(info.copyright) + '\n';
        out += prefix + " block_type=" +
               (info.block_type ? std::string{name(*info.block_type)} : std::string{"none"}) + '\n';
        const auto& chain = info.bootloaders;
        render_entry(out, prefix, "cb_a", chain.cb_a);
        render_entry(out, prefix, "cb_b", chain.cb_b);
        render_entry(out, prefix, "cb_x", chain.cb_x);
        render_entry(out, prefix, "sc", chain.sc);
        render_entry(out, prefix, "cd", chain.cd);
        render_entry(out, prefix, "ce", chain.ce);
        render_entry(out, prefix, "cf_0", chain.cf_0);
        render_entry(out, prefix, "cg_0", chain.cg_0);
        render_entry(out, prefix, "cf_1", chain.cf_1);
        render_entry(out, prefix, "cg_1", chain.cg_1);
        out += prefix + " chain cb_ldv=" + std::to_string(chain.cb_ldv) +
               " cb_pairing=" + hex(chain.cb_pairing_data) +
               " cf0_ldv=" + optional_ldv(chain.cf0_ldv) +
               " cf0_pairing=" + optional_pairing(chain.cf0_pairing_data) +
               " cf1_ldv=" + optional_ldv(chain.cf1_ldv) +
               " cf1_pairing=" + optional_pairing(chain.cf1_pairing_data) + '\n';
        out += prefix + " smc present=" + (info.smc.present ? "1" : "0") +
               " decrypted=" + (info.smc.decrypted ? "1" : "0") + " size=" + num(info.smc.size) +
               " version=" + quote_text(info.smc.version) +
               " motherboard=" + quote_text(info.smc.motherboard_name) +
               " type=" + quote_text(info.smc.type_name) + '\n';
        out += prefix + " flashfs present=" + (info.flashfs.present ? "1" : "0") +
               " files=" + std::to_string(info.flashfs.files.size()) + '\n';
        for (const auto& file : info.flashfs.files) {
            out += prefix + " flashfs.file " + quote_text(file.filename) +
                   " block=" + num(file.block_number) + " length=" + num(file.length) +
                   " timestamp=" + num(file.timestamp) + '\n';
        }
        const auto& kv = info.keyvault;
        out += prefix + " keyvault present=" + (kv.present ? "1" : "0") +
               " decrypted=" + (kv.decrypted ? "1" : "0") +
               " kv_type=" + std::to_string(kv.kv_type) +
               " fcrt_required=" + (kv.fcrt_required ? "1" : "0") +
               " region_raw=" + num(kv.region_raw) + " region_name=" + quote_text(kv.region_name) +
               '\n';
        out += prefix + " keyvault.identity serial=" + identity(kv.serial_number) +
               " console_id_raw=" + identity(kv.console_id_raw) +
               " console_id_friendly=" + identity(kv.console_id_friendly) +
               " osig=" + identity(kv.osig) + " mfr_date=" + identity(kv.mfr_date) +
               " dvd_key=" + identity(kv.dvd_key) + '\n';
        out += prefix + " cpu_key " +
               (info.cpu_key.empty() ? std::string{"none"} : blob(info.cpu_key)) + '\n';
        out += prefix + " raw_keyvault " + blob(info.raw_keyvault) + '\n';
        return out;
    }

    [[nodiscard]] inline std::string render(const std::string& prefix, const InputMetadata& meta) {
        std::string out;
        out += prefix + " cpu_key " + blob(meta.cpu_key) + '\n';
        out += prefix + " nand_image " + blob(meta.nand_image) + '\n';
        out += prefix + " keyvault " + blob(meta.keyvault) + '\n';
        out += prefix + " smc " + blob(meta.smc) + '\n';
        out += prefix + " cb_ldv=" + std::to_string(meta.cb_ldv) +
               " pairing=" + hex(meta.pairing_data) + " cf_ldv=" + optional_ldv(meta.cf_ldv) +
               " cf_pairing=" + optional_pairing(meta.cf_pairing_data) + '\n';
        out += prefix + " console_type=" + num(meta.console_type) +
               " console_sequence=" + num(meta.console_sequence) +
               " console_sequence_allow=" + num(meta.console_sequence_allow) + '\n';
        if (!meta.donor_nonces) {
            out += prefix + " donor_nonces none\n";
        } else {
            const auto nonce = [](const std::optional<BootloaderNonce>& value) {
                return value ? hex(*value) : std::string{"none"};
            };
            const auto& nonces = *meta.donor_nonces;
            for (size_t i = 0; i < nonces.stages.size(); ++i) {
                out += prefix + " donor_nonces.stage" + std::to_string(i) + '=' +
                       nonce(nonces.stages[i]) + '\n';
            }
            out += prefix + " donor_nonces.cf=" + nonce(nonces.cf) + '\n';
            out += prefix + " donor_nonces.cg=" + nonce(nonces.cg) + '\n';
        }
        out += prefix + " smc_config " + blob(meta.smc_config) + '\n';
        out += prefix + " statistics " + blob(meta.statistics) + '\n';
        out += prefix + " manufacturing " + blob(meta.manufacturing) + '\n';
        out += prefix +
               " console_secured_files=" + std::to_string(meta.console_secured_files.size()) + '\n';
        for (const auto& [file, bytes] : meta.console_secured_files) {
            out += prefix + " console_secured_file " + quote_text(file) + ' ' + blob(bytes) + '\n';
        }
        return out;
    }

    [[nodiscard]] inline std::string render(const std::string& prefix, const Input& input) {
        std::string out;
        out += prefix + " build_type=" + std::string{name(input.build_type)} +
               " image_type=" + std::string{name(input.image_type)} + " console=" +
               (input.console ? std::string{name(*input.console)} : std::string{"none"}) + '\n';

        const auto& o = input.options;
        out += prefix + " options cbldv=" + optional_text(o.cbldv) +
               " pairing_data=" + optional_text(o.pairing_data) +
               " cfldv=" + optional_text(o.cfldv) + " xellbutton=" + optional_text(o.xellbutton) +
               " xellbutton2=" + optional_text(o.xellbutton2) +
               " cygnos=" + optional_bool(o.cygnos) + " demon=" + optional_bool(o.demon) +
               " olddvd=" + optional_bool(o.olddvd) + " nodvd=" + optional_bool(o.nodvd) +
               " dualboot=" + optional_text(o.dualboot) + '\n';
        out += prefix + " options nomobile=" + optional_bool(o.nomobile) +
               " nofcrt=" + optional_bool(o.nofcrt) + " noremap=" + optional_bool(o.noremap) +
               " noecdremap=" + optional_bool(o.noecdremap) + " nandmu=" + optional_bool(o.nandmu) +
               " nosecurity=" + optional_bool(o.nosecurity) +
               " nosusecurity=" + optional_bool(o.nosusecurity) +
               " smcnocheck=" + optional_bool(o.smcnocheck) +
               " noblpatch=" + optional_bool(o.noblpatch) + " nopatch=" + optional_text(o.nopatch) +
               '\n';
        out += prefix + " options cputemp=" + optional_text(o.cputemp) +
               " gputemp=" + optional_text(o.gputemp) + " edramtemp=" + optional_text(o.edramtemp) +
               " overcputemp=" + optional_text(o.overcputemp) +
               " overgputemp=" + optional_text(o.overgputemp) +
               " overedramtemp=" + optional_text(o.overedramtemp) +
               " cpufan=" + optional_text(o.cpufan) + " gpufan=" + optional_text(o.gpufan) +
               " dvdkey=" + optional_text(o.dvdkey) + " avregion=" + optional_text(o.avregion) +
               " gameregion=" + optional_text(o.gameregion) +
               " dvdregion=" + optional_text(o.dvdregion) + " macid=" + optional_text(o.macid) +
               '\n';

        out += render(prefix + ".metadata", input.metadata);

        const auto& b = input.bootloaders;
        const std::string bl = prefix + ".bootloaders ";
        out += bl + "cb_or_a " + blob(b.cb_or_a) + '\n';
        out += bl + "cb_x " + blob(b.cb_x) + '\n';
        out += bl + "cb_b " + blob(b.cb_b) + '\n';
        out += bl + "sc " + blob(b.sc) + '\n';
        out += bl + "cd " + blob(b.cd) + '\n';
        out += bl + "ce " + blob(b.ce) + '\n';
        out += bl + "cf0 " + blob(b.cf0) + '\n';
        out += bl + "cg0 " + blob(b.cg0) + '\n';
        out += bl + "cf1 " + blob(b.cf1) + '\n';
        out += bl + "cg1 " + blob(b.cg1) + '\n';
        out += bl + "extra_cb " + blob(b.extra_cb) + '\n';
        out += bl + "extra_cd " + blob(b.extra_cd) + '\n';

        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            out += prefix + ".mobiles " + num(block_type) + ' ' +
                   blob(*input.mobiles.slot(block_type)) + '\n';
        }

        if (!input.patches) {
            out += prefix + ".patches none\n";
        } else {
            const auto& automatic = input.patches->automatic;
            out += prefix + ".patches automatic " +
                   (automatic ? quote_text(automatic->name) + ' ' + blob(automatic->data)
                              : std::string{"none"}) +
                   " addons=" + std::to_string(input.patches->addons.size()) + '\n';
            for (const auto& addon : input.patches->addons) {
                out += prefix + ".patches addon " + quote_text(addon.name) + ' ' +
                       blob(addon.data) + '\n';
            }
        }

        if (!input.payloads) {
            out += prefix + ".payloads none\n";
        } else {
            const auto& p = *input.payloads;
            out += prefix + ".payloads xell " + blob(p.xell) + '\n';
            out += prefix + ".payloads rebooter " + blob(p.rebooter) + '\n';
            out += prefix + ".payloads fuses " + blob(p.fuses) + '\n';
            out += prefix + ".payloads patches " + blob(p.patches) + '\n';
            out += prefix + ".payloads payload " + blob(p.payload) + '\n';
        }

        if (!input.flashfs_sec) {
            out += prefix + ".flashfs_sec none\n";
        } else {
            out +=
                prefix + ".flashfs_sec files=" + std::to_string(input.flashfs_sec->size()) + '\n';
            for (const auto& [file, bytes] : *input.flashfs_sec) {
                out += prefix + ".flashfs_sec " + quote_text(file) + ' ' + blob(bytes) + '\n';
            }
        }

        out += prefix + ".raw_patches=" + std::to_string(input.raw_patches.size()) + '\n';
        for (const auto& patch : input.raw_patches) {
            out += prefix + ".raw_patch " + quote_text(patch.name) +
                   " offset=" + num(patch.offset) + ' ' + blob(patch.data) + '\n';
        }
        // Never the key's digest: only whether one is carried.
        out += prefix + ".sb_private_key " +
               (input.sb_private_key ? "size=" + num(input.sb_private_key->size())
                                     : std::string{"none"}) +
               '\n';
        return out;
    }

    template <class T>
    [[nodiscard]] std::string render_result(const std::string& prefix, const Result<T>& result) {
        if (!result) {
            return prefix + " error " + result.error().describe() + '\n';
        }
        return render(prefix, *result);
    }

    template <class T>
    [[nodiscard]] std::string render_optional(const std::string& prefix,
                                              const std::optional<T>& value) {
        if (!value) {
            return prefix + " error\n";
        }
        return render(prefix, *value);
    }

    // The rendered projections of one image, and how many of the other overloads and shims
    // rendered the same as the core's span overload.
    struct Projections {
        std::string text;
        size_t comparisons = 0;
        size_t agreements = 0;
        std::vector<std::string> disagreements;
    };

    [[nodiscard]] inline Projections render_extract_projections(const std::string& label,
                                                                std::span<const uint8_t> image,
                                                                std::span<const uint8_t> cpu_key) {
        Projections out;
        const std::vector<uint8_t> image_vector(image.begin(), image.end());
        const std::vector<uint8_t> key_vector(cpu_key.begin(), cpu_key.end());

        // The core's span overload is the snapshot. Its vector overload must render the same,
        // and so must the GxBuild shim (which returns nullopt where the core returns an error;
        // that is compared as presence only).
        const auto agree = [&out](const std::string& what, const std::string& core,
                                  const std::string& other) {
            ++out.comparisons;
            if (core == other) {
                ++out.agreements;
            } else {
                out.disagreements.push_back(what);
            }
        };
        const auto shim_agree = [&agree](const std::string& what, const std::string& prefix,
                                         const auto& core, const auto& shim) {
            if (core) {
                agree(what, render(prefix, *core), render_optional(prefix, shim));
            } else {
                agree(what, prefix + " error\n", render_optional(prefix, shim));
            }
        };

        {
            const std::string prefix = label + ".extract_some_info";
            const auto core = extract_some_info(image);
            out.text += render_result(prefix, core);
            agree(prefix + " (vector overload)", render_result(prefix, core),
                  render_result(prefix, extract_some_info(image_vector)));
            shim_agree(prefix + " (GxBuild::ExtractSomeInfo span)", prefix, core,
                       GxBuild::ExtractSomeInfo(image));
            shim_agree(prefix + " (GxBuild::ExtractSomeInfo vector)", prefix, core,
                       GxBuild::ExtractSomeInfo(image_vector));
        }
        {
            const std::string prefix = label + ".extract_metadata";
            const auto core = extract_metadata(image, cpu_key);
            out.text += render_result(prefix, core);
            agree(prefix + " (vector overload)", render_result(prefix, core),
                  render_result(prefix, extract_metadata(image_vector, key_vector)));
            shim_agree(prefix + " (GxBuild::ExtractMetadata span)", prefix, core,
                       GxBuild::ExtractMetadata(image, cpu_key));
            shim_agree(prefix + " (GxBuild::ExtractMetadata vector)", prefix, core,
                       GxBuild::ExtractMetadata(image_vector, key_vector));
        }
        {
            const std::string prefix = label + ".extract_all_info";
            const auto core = extract_all_info(image, cpu_key);
            out.text += render_result(prefix, core);
            agree(prefix + " (vector overload)", render_result(prefix, core),
                  render_result(prefix, extract_all_info(image_vector, key_vector)));
            shim_agree(prefix + " (GxBuild::ExtractAllInfo span)", prefix, core,
                       GxBuild::ExtractAllInfo(image, cpu_key));
            shim_agree(prefix + " (GxBuild::ExtractAllInfo vector)", prefix, core,
                       GxBuild::ExtractAllInfo(image_vector, key_vector));
        }
        {
            const std::string prefix = label + ".extract_all";
            const auto core = extract_all(image, cpu_key);
            out.text += render_result(prefix, core);
            agree(prefix + " (vector overload)", render_result(prefix, core),
                  render_result(prefix, extract_all(image_vector, key_vector)));
            shim_agree(prefix + " (GxBuild::ExtractAll span)", prefix, core,
                       GxBuild::ExtractAll(image, cpu_key));
            shim_agree(prefix + " (GxBuild::ExtractAll vector)", prefix, core,
                       GxBuild::ExtractAll(image_vector, key_vector));
        }
        return out;
    }

} // namespace gxbuild3::test::projection
