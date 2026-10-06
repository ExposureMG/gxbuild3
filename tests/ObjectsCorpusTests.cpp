// Objects corpus snapshot over the tracked NAND-object fixtures in tests/gxBuild-support-files.
// Runs on a clean clone: it needs no untracked fixture. One line per item and operation, compared
// with tests/golden/objects_corpus.txt:
//   patchset.*   every 17559/bin/patches_*.bin x {jtag, glitch, glitch2, glitch2m, glitch3,
//                devgl}: parse_patch_set (kind, manufacturing, per section target, identifier,
//                entry count, sum of entry lengths, raw size and SHA-1), serialize_patch_set and
//                serialize_khv_payload of the last section, then parse_and_merge_patch_set with
//                every other 17559/bin/*.bin as add-ons; each add-on alone over one JTAG and one
//                glitch2m file; synthetic failures.
//   xell.*       XeLL::parse of mydata/xell-*.bin and synthetic sizes and heads.
//   secured.*    mydata crl/dae/extended/secdata/fcrt under the image CPU key: sealing found,
//                opening outcome, deterministic reseals with fixed inputs (never the random
//                sealing paths), seal_fcrt; secured_file_stamp for fixed seconds;
//                fcrt_requirement over synthetic keyvault words.
//   xboxupd.*    split_xboxupd_raw on xboxupd.bin extracted from 17559/su20076000_00000000
//                through stfs::StfsContainer, and synthetic failures.
//   corona.*     CoronaConfig serialize -> parse -> serialize for three configs, parse failures
//                and choose() with corrupted or short copies.
//   freeboot.*   SHA-1 of freeboot_payload_for / freeboot_rebooter_for for fixed inputs.
//   xconfig.*    SmcConfig over a patterned 0x10000 buffer (byte i*7+3) at base 0 and 0xC000:
//                how serialize(parse(b)) compares with b inside and outside the region. XConfig
//                stays packed; this pins its current behaviour only.
//   smc.*        smc_get_type / smc_is_encrypted / smc_has_jtag_mark / Smc::parse over the SMC
//                of mydata/image.bin (sealed and plain) and synthetic signature buffers, each
//                both plain and sealed with smc_encrypt.
// A failure is recorded as its ErrorCode and context chain, never the leaf message text.
// Console identity never appears in the clear: secured-file sealings and heads are SHA-1s.
//
// The only CPU key is the one already public in tests/gxBuild-support-files/build_all.sh.
// The rendering runs twice in-process and must be identical (determinism). --update rewrites
// tests/golden/objects_corpus.txt (CTest never passes it). GXBUILD3_OBJECTS_CORPUS_SUPPORT
// overrides the support directory, for mutation checks against scratch copies only.

#include "GoldenSnapshot.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/Freeboot.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "nand/objects/XConfig.hpp"
#include "nand/objects/Xboxupd.hpp"
#include "nand/objects/XeLL.hpp"
#include "stfs/StfsContainer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;
    using GxBuild::BuildType;

    // The CPU key of the tracked mydata/image.bin, public in build_all.sh (-p ...).
    constexpr std::array<uint8_t, 16> kCpuKey = {0x93, 0xFB, 0x9D, 0x01, 0x19, 0x30, 0xAF, 0xC4,
                                                 0x53, 0xAA, 0x75, 0xB1, 0x83, 0xEF, 0xAC, 0x09};
    // A fixed key that is no console's, for the "wrong key" outcomes.
    constexpr std::array<uint8_t, 16> kOtherKey = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                                   0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    // Fixed inputs for the deterministic reseal paths (no console's).
    constexpr std::array<uint8_t, 8> kKeyvaultHead = {0x01, 0x02, 0x03, 0x04,
                                                      0x05, 0x06, 0x07, 0x08};
    constexpr std::array<uint8_t, 8> kSecdataHead = {0x51, 0x52, 0x53, 0x54,
                                                     0x55, 0x56, 0x57, 0x58};
    constexpr SecuredFileBuild kBuild{1791105724, 14};

    constexpr size_t kExpectedPatchFiles = 25;
    constexpr size_t kExpectedAddons = 14;

    bool check(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
        }
        return condition;
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

    std::string blob(std::span<const uint8_t> bytes) {
        return std::format("size=0x{:X} sha1={}", bytes.size(), sha1(bytes));
    }

    // ErrorCode plus the context chain (outermost first); never the leaf message text.
    std::string describe(const Error& error) {
        std::string text = std::format("err={}", to_string(error.code));
        if (!error.context.empty()) {
            text += " ctx=[";
            for (auto it = error.context.rbegin(); it != error.context.rend(); ++it) {
                if (it != error.context.rbegin()) {
                    text += " | ";
                }
                text += *it;
            }
            text += ']';
        }
        return text;
    }

    template <class T> std::string outcome(const Result<T>& result) {
        return result ? std::string{"ok"} : describe(result.error());
    }

    std::string yn(bool value) {
        return value ? "yes" : "no";
    }

    std::optional<Bytes> read_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }
        return Bytes(std::istreambuf_iterator<char>(in), {});
    }

    struct Fixture {
        std::string name;
        Bytes bytes;
    };

    class Writer {
      public:
        explicit Writer(std::ostringstream& out) : out_(out) {}
        void line(std::string_view key, std::string_view text) {
            out_ << key << ' ' << text << '\n';
        }

      private:
        std::ostringstream& out_;
    };

    struct Corpus {
        std::vector<Fixture> patches;
        std::vector<Fixture> addons;
        std::vector<Fixture> xells;
        std::vector<Fixture> secured; // crl, dae, extended, secdata, fcrt (by name)
        Bytes image;
        Bytes update_package;
    };

    struct Counters {
        size_t patch_parses = 0;
        size_t patch_parses_ok = 0;
        size_t xells_ok = 0;
        size_t secured_files = 0;
        size_t smc_cases = 0;
        bool xboxupd_split = false;
        bool image_smc = false;
    };

    // ---- patchset -------------------------------------------------------------------------

    std::string_view target_name(PatchSectionTarget target) {
        switch (target) {
            case PatchSectionTarget::Unknown:
                return "unknown";
            case PatchSectionTarget::JtagSection1:
                return "jtag1";
            case PatchSectionTarget::JtagSection2:
                return "jtag2";
            case PatchSectionTarget::JtagSection3:
                return "jtag3";
            case PatchSectionTarget::JtagSection4:
                return "jtag4";
            case PatchSectionTarget::Cb:
                return "cb";
            case PatchSectionTarget::Cbb:
                return "cbb";
            case PatchSectionTarget::Cd:
                return "cd";
            case PatchSectionTarget::Khv:
                return "khv";
        }
        return "?";
    }

    struct NamedType {
        std::string_view name;
        BuildType type;
    };

    constexpr std::array<NamedType, 6> kPatchTypes{{
        {"jtag", BuildType::Jtag},
        {"glitch", BuildType::Glitch},
        {"glitch2", BuildType::Glitch2},
        {"glitch2m", BuildType::Glitch2m},
        {"glitch3", BuildType::Glitch3},
        {"devgl", BuildType::Devgl},
    }};

    void render_patch_set(Writer& w, const std::string& key, std::span<const uint8_t> input,
                          const ParsedPatchSet& set) {
        w.line(key, std::format("kind={} manufacturing={} sections={}",
                                set.kind == PatchSetKind::Jtag ? "jtag" : "glitch",
                                set.manufacturing ? 1 : 0, set.sections.size()));
        for (size_t i = 0; i < set.sections.size(); ++i) {
            const auto& s = set.sections[i];
            uint64_t lengths = 0;
            for (const auto& e : s.entries) {
                lengths += e.length;
            }
            w.line(std::format("{}.section{}", key, i),
                   std::format("target={} id={} entries={} entry_words={} raw_size=0x{:X} "
                               "raw_sha1={}",
                               target_name(s.target), s.identifier, s.entries.size(), lengths,
                               s.raw_data.size(), sha1(s.raw_data)));
        }
        const Bytes serial = serialize_patch_set(set);
        w.line(key + ".serialize",
               std::format("identity={} {}", yn(std::ranges::equal(serial, input)), blob(serial)));
        if (!set.sections.empty()) {
            const auto& last = set.sections.back();
            w.line(key + ".khv_payload", std::format("of={} {}", target_name(last.target),
                                                     blob(serialize_khv_payload(last))));
        }
    }

    GxBuild::InputPatches make_patches(const Fixture& automatic, std::span<const Fixture> addons) {
        GxBuild::InputPatches patches;
        patches.automatic = GxBuild::InputPatchFile{automatic.name, automatic.bytes};
        for (const auto& addon : addons) {
            patches.addons.push_back({addon.name, addon.bytes});
        }
        return patches;
    }

    void render_patchsets(Writer& w, const Corpus& c, Counters& n) {
        w.line("patchset.files", std::to_string(c.patches.size()));
        w.line("patchset.addons", std::to_string(c.addons.size()));
        for (const auto& addon : c.addons) {
            w.line("patchset.addon." + addon.name, blob(addon.bytes));
        }
        for (const auto& file : c.patches) {
            const std::string base = "patchset." + file.name;
            w.line(base + ".input", blob(file.bytes));
            for (const auto& [type_name, type] : kPatchTypes) {
                const std::string key = std::format("{}.{}", base, type_name);
                ++n.patch_parses;
                const auto parsed = parse_patch_set(file.bytes, type);
                w.line(key + ".parse", outcome(parsed));
                if (parsed) {
                    ++n.patch_parses_ok;
                    render_patch_set(w, key, file.bytes, *parsed);
                }
                const auto merged = parse_and_merge_patch_set(make_patches(file, c.addons), type);
                std::string text = outcome(merged);
                if (merged) {
                    const Bytes serial = serialize_patch_set(*merged);
                    text += std::format(" sections={} {}", merged->sections.size(), blob(serial));
                    if (!merged->sections.empty()) {
                        const auto& last = merged->sections.back();
                        text += std::format(" last={} last_raw_size=0x{:X} khv_payload_sha1={}",
                                            target_name(last.target), last.raw_data.size(),
                                            sha1(serialize_khv_payload(last)));
                    }
                }
                w.line(key + ".merge_all", text);
            }
        }

        // Each add-on alone, over one JTAG and one manufacturing-glitch file.
        struct Pick {
            std::string_view file;
            BuildType type;
            std::string_view type_name;
        };
        static constexpr std::array<Pick, 2> kPicks{{
            {"patches_jasper.bin", BuildType::Jtag, "jtag"},
            {"patches_g2mjasper.bin", BuildType::Glitch2m, "glitch2m"},
        }};
        for (const auto& pick : kPicks) {
            const auto it = std::ranges::find(c.patches, pick.file, &Fixture::name);
            if (it == c.patches.end()) {
                w.line(std::format("patchset.merge_one.{}", pick.file), "missing");
                continue;
            }
            for (const auto& addon : c.addons) {
                const auto merged = parse_and_merge_patch_set(
                    make_patches(*it, std::span<const Fixture>(&addon, 1)), pick.type);
                std::string text = outcome(merged);
                if (merged && !merged->sections.empty()) {
                    const auto& last = merged->sections.back();
                    text +=
                        std::format(" last={} last_raw_size=0x{:X} {}", target_name(last.target),
                                    last.raw_data.size(), blob(serialize_patch_set(*merged)));
                }
                w.line(std::format("patchset.merge_one.{}.{}.{}", pick.file, pick.type_name,
                                   addon.name),
                       text);
            }
        }

        // Synthetic failures and edge cases.
        const auto be = [](std::initializer_list<uint32_t> words) {
            Bytes out;
            for (const uint32_t v : words) {
                out.push_back(static_cast<uint8_t>(v >> 24));
                out.push_back(static_cast<uint8_t>(v >> 16));
                out.push_back(static_cast<uint8_t>(v >> 8));
                out.push_back(static_cast<uint8_t>(v));
            }
            return out;
        };
        struct Synthetic {
            std::string_view name;
            Bytes data;
        };
        const std::array<Synthetic, 7> synthetic{{
            {"empty", {}},
            {"one_delimiter", be({0xFFFFFFFF})},
            {"three_empty_sections", be({0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF})},
            {"four_empty_sections", be({0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF})},
            {"entry_without_length",
             be({0x00001000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00002000})},
            {"entry_words_overrun",
             be({0x00001000, 0x00000010, 0x60000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF})},
            {"glitch_minimal",
             be({0x00001000, 0x00000001, 0x60000000, 0xFFFFFFFF, 0x00002000, 0x00000002, 0x11111111,
                 0x22222222, 0xFFFFFFFF, 0xAABBCCDD, 0xFFFFFFFF})},
        }};
        for (const auto& s : synthetic) {
            for (const auto& [type_name, type] : kPatchTypes) {
                const std::string key = std::format("patchset.synthetic.{}.{}", s.name, type_name);
                const auto parsed = parse_patch_set(s.data, type);
                w.line(key + ".parse", outcome(parsed));
                if (parsed) {
                    render_patch_set(w, key, s.data, *parsed);
                }
                const Fixture named{std::string{s.name}, s.data};
                const auto merged = parse_and_merge_patch_set(
                    make_patches(named, std::span<const Fixture>{}), type);
                w.line(key + ".merge_none", outcome(merged));
            }
        }
        for (const auto& [type_name, type] : std::array<NamedType, 2>{
                 {{"retail", BuildType::Retail}, {"devkit", BuildType::Devkit}}}) {
            const Bytes data = be({0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF});
            w.line(std::format("patchset.unsupported.{}.parse", type_name),
                   outcome(parse_patch_set(data, type)));
            const Fixture named{"four_empty_sections", data};
            w.line(std::format("patchset.unsupported.{}.merge_none", type_name),
                   outcome(parse_and_merge_patch_set(
                       make_patches(named, std::span<const Fixture>{}), type)));
        }
        GxBuild::InputPatches no_automatic;
        no_automatic.addons.push_back({"nolan.bin", be({0x12345678})});
        w.line("patchset.no_automatic.merge",
               outcome(parse_and_merge_patch_set(no_automatic, BuildType::Glitch2)));
    }

    // ---- XeLL -----------------------------------------------------------------------------

    void render_xell_one(Writer& w, const std::string& key, std::span<const uint8_t> input,
                         Counters* n) {
        w.line(key + ".input", blob(input));
        const auto parsed = XeLL::parse(input);
        std::string text = outcome(parsed);
        if (parsed) {
            if (n != nullptr) {
                ++n->xells_ok;
            }
            text += std::format(" version=\"{}\" author=\"{}\" date=\"{}\" data_identity={}",
                                parsed->metadata.version, parsed->metadata.author,
                                parsed->metadata.date, yn(std::ranges::equal(parsed->data, input)));
        }
        w.line(key + ".parse", text);
    }

    void render_xell(Writer& w, const Corpus& c, Counters& n) {
        for (const auto& file : c.xells) {
            render_xell_one(w, "xell." + file.name, file.bytes, &n);
        }
        const auto put = [](Bytes& b, size_t at, std::string_view text) {
            std::copy(text.begin(), text.end(), b.begin() + static_cast<std::ptrdiff_t>(at));
        };
        constexpr std::array<uint8_t, 16> vectors = {0x48, 0, 0, 0x20, 0x48, 0, 0, 0xEC,
                                                     0x48, 0, 0, 0,    0x48, 0, 0, 0};
        Bytes short_one(XeLL::kSize - 1, 0);
        render_xell_one(w, "xell.synthetic.short", short_one, nullptr);
        Bytes long_one(XeLL::kSize + 1, 0);
        render_xell_one(w, "xell.synthetic.long", long_one, nullptr);
        Bytes zero(XeLL::kSize, 0);
        render_xell_one(w, "xell.synthetic.zero_head", zero, nullptr);
        Bytes elf(XeLL::kSize, 0);
        put(elf, 0,
            "\x7F"
            "ELF");
        render_xell_one(w, "xell.synthetic.elf_bare", elf, nullptr);
        Bytes dated(XeLL::kSize, 0);
        std::ranges::copy(vectors, dated.begin());
        put(dated, 0x1000, "XeLL-Reloaded v9.9 2012-03-04 (synthetic author)");
        render_xell_one(w, "xell.synthetic.vectors_dated", dated, nullptr);
        Bytes prefixed(XeLL::kSize, 0);
        std::ranges::copy(vectors, prefixed.begin());
        put(prefixed, 0x2000, "Free60.org XeLL - Xenon Linux Loader 0.991\n");
        render_xell_one(w, "xell.synthetic.vectors_prefix", prefixed, nullptr);
        Bytes bad_date(XeLL::kSize, 0);
        put(bad_date, 0,
            "\x7F"
            "ELF");
        put(bad_date, 0x3000, "XeLL 1.0 2199-13-40 (nobody) LibXenon");
        render_xell_one(w, "xell.synthetic.elf_bad_date", bad_date, nullptr);
    }

    // ---- secured files --------------------------------------------------------------------

    std::string crl_text(const Result<CrlSealing>& s) {
        if (!s) {
            return describe(s.error());
        }
        return std::format("ok iv_sha1={} file_key_sha1={}", sha1(s->iv), sha1(s->file_key));
    }

    std::string dae_text(const Result<DaeSealing>& s) {
        if (!s) {
            return describe(s.error());
        }
        return std::format("ok head_sha1={} field_sha1={}", sha1(s->head), sha1(s->field));
    }

    std::string bytes_text(const Result<Bytes>& r) {
        return r ? "ok " + blob(*r) : describe(r.error());
    }

    std::string_view fcrt_name(FcrtSealing s) {
        switch (s) {
            case FcrtSealing::Sealed:
                return "sealed";
            case FcrtSealing::Carried:
                return "carried";
            case FcrtSealing::InvalidSize:
                return "invalid_size";
            case FcrtSealing::InvalidOffset:
                return "invalid_offset";
            case FcrtSealing::Damaged:
                return "damaged";
        }
        return "?";
    }

    std::string_view requirement_name(FcrtRequirement r) {
        switch (r) {
            case FcrtRequirement::NotRequired:
                return "not_required";
            case FcrtRequirement::Required:
                return "required";
            case FcrtRequirement::RequiredByDrive:
                return "required_by_drive";
        }
        return "?";
    }

    void render_secured(Writer& w, const Corpus& c, Counters& n) {
        struct KeyCase {
            std::string_view name;
            std::span<const uint8_t> key;
        };
        const std::array<KeyCase, 2> keys{{{"image_key", kCpuKey}, {"other_key", kOtherKey}}};
        // A fixed sealing (no console's) for the reseal paths when the own one does not open.
        CrlSealing fixed_crl{};
        DaeSealing fixed_dae{};
        for (size_t i = 0; i < 16; ++i) {
            fixed_crl.iv[i] = static_cast<uint8_t>(0x30 + i);
            fixed_crl.file_key[i] = static_cast<uint8_t>(0x40 + i);
            fixed_dae.field[i] = static_cast<uint8_t>(0x60 + i);
        }
        for (size_t i = 0; i < fixed_dae.head.size(); ++i) {
            fixed_dae.head[i] = static_cast<uint8_t>(0x50 + i);
        }

        for (const auto& f : c.secured) {
            ++n.secured_files;
            const std::string base = "secured." + f.name;
            w.line(base + ".input", blob(f.bytes));
            for (const auto& [key_name, key] : keys) {
                const std::string k = std::format("{}.{}", base, key_name);
                if (f.name == "crl.bin") {
                    const auto own = crl_sealing(f.bytes, key);
                    w.line(k + ".crl_sealing", crl_text(own));
                    w.line(k + ".reseal_own",
                           own ? bytes_text(reseal_crl(f.bytes, key, *own, kBuild)) : "skipped");
                    w.line(k + ".reseal_fixed",
                           bytes_text(reseal_crl(f.bytes, key, fixed_crl, kBuild)));
                } else if (f.name == "dae.bin") {
                    const auto own = dae_sealing(f.bytes, key);
                    w.line(k + ".dae_sealing", dae_text(own));
                    w.line(k + ".reseal_own",
                           own ? bytes_text(reseal_dae(f.bytes, key, *own, kBuild)) : "skipped");
                    w.line(k + ".reseal_fixed",
                           bytes_text(reseal_dae(f.bytes, key, fixed_dae, kBuild)));
                } else if (f.name == "extended.bin") {
                    const auto opened = open_loose_extended(f.bytes, key);
                    w.line(k + ".open_loose", bytes_text(opened));
                    if (opened) {
                        w.line(k + ".opened", yn(extended_opened(*opened, key)));
                        w.line(k + ".reseal",
                               bytes_text(reseal_extended(*opened, key, kKeyvaultHead)));
                    }
                } else if (f.name == "secdata.bin") {
                    const auto opened = open_loose_secdata(f.bytes, key);
                    w.line(k + ".open_loose", bytes_text(opened));
                    if (opened) {
                        w.line(k + ".opened", yn(secdata_opened(*opened, key)));
                        const auto head = secdata_head(*opened);
                        w.line(k + ".head",
                               head ? "ok sha1=" + sha1(*head) : describe(head.error()));
                        w.line(k + ".reseal_no_head",
                               bytes_text(reseal_secdata(*opened, key, std::nullopt, kBuild)));
                        w.line(k + ".reseal_fixed_head",
                               bytes_text(reseal_secdata(*opened, key, kSecdataHead, kBuild)));
                    }
                } else if (f.name == "fcrt.bin") {
                    const auto sealed = seal_fcrt(f.bytes, key);
                    w.line(k + ".seal_fcrt",
                           std::format("sealing={} identity={} {}", fcrt_name(sealed.sealing),
                                       yn(std::ranges::equal(sealed.data, f.bytes)),
                                       blob(sealed.data)));
                    const auto again = seal_fcrt(sealed.data, key);
                    w.line(k + ".seal_fcrt_again",
                           std::format("sealing={} identity={} {}", fcrt_name(again.sealing),
                                       yn(std::ranges::equal(again.data, sealed.data)),
                                       blob(again.data)));
                }
            }
        }

        // Deterministic clean files and synthetic fcrt edge cases.
        w.line("secured.clean_extended",
               bytes_text(clean_extended(kCpuKey, std::span<const uint8_t, 8>(kKeyvaultHead))));
        w.line("secured.clean_secdata", bytes_text(clean_secdata(kCpuKey, kSecdataHead, kBuild)));
        const std::array<uint8_t, 15> short_key{};
        w.line("secured.clean_extended.short_key",
               bytes_text(clean_extended(short_key, std::span<const uint8_t, 8>(kKeyvaultHead))));
        w.line("secured.open_loose_extended.short_blob",
               bytes_text(open_loose_extended(Bytes(15, 0), kCpuKey)));
        w.line("secured.open_loose_secdata.short_blob",
               bytes_text(open_loose_secdata(Bytes(15, 0), kCpuKey)));
        w.line("secured.crl_sealing.empty", crl_text(crl_sealing(Bytes{}, kCpuKey)));
        w.line("secured.dae_sealing.empty", dae_text(dae_sealing(Bytes{}, kCpuKey)));

        const auto fcrt_case = [&w](std::string_view name, const Bytes& data) {
            const auto sealed = seal_fcrt(data, kCpuKey);
            w.line(std::format("secured.fcrt.synthetic.{}", name),
                   std::format("sealing={} identity={} {}", fcrt_name(sealed.sealing),
                               yn(std::ranges::equal(sealed.data, data)), blob(sealed.data)));
        };
        fcrt_case("short", Bytes(0x3FFF, 0));
        Bytes bad_offset(0x4000, 0);
        bad_offset[0x11C] = 0x00;
        bad_offset[0x11D] = 0x00;
        bad_offset[0x11E] = 0x40;
        bad_offset[0x11F] = 0x00;
        fcrt_case("offset_0x4000", bad_offset);
        Bytes clear(0x4000, 0);
        clear[0x11E] = 0x01;
        clear[0x11F] = 0x40;
        for (size_t i = 0x140; i < clear.size(); ++i) {
            clear[i] = static_cast<uint8_t>(i * 13 + 1);
        }
        ExCryptSha(clear.data() + 0x140, static_cast<uint32_t>(clear.size() - 0x140), nullptr, 0,
                   nullptr, 0, clear.data() + 0x12C, 20);
        fcrt_case("clear_hash_holds", clear);
        Bytes damaged = clear;
        damaged[0x200] ^= 0x01;
        fcrt_case("hash_broken", damaged);

        for (const int64_t seconds :
             {int64_t{0}, int64_t{1}, int64_t{2}, int64_t{3}, int64_t{0x5A123457},
              int64_t{1791105724}, int64_t{1791105725}, int64_t{0x7FFFFFFF}}) {
            w.line(std::format("secured.stamp.{}", seconds), hex(secured_file_stamp(seconds)));
        }

        for (const uint16_t word :
             {uint16_t{0x0000}, uint16_t{0x0020}, uint16_t{0x0100}, uint16_t{0x0200},
              uint16_t{0x0300}, uint16_t{0x0320}, uint16_t{0xFFDF}, uint16_t{0xFFFF}}) {
            Bytes kv(0x20, 0);
            kv[0x1C] = static_cast<uint8_t>(word >> 8);
            kv[0x1D] = static_cast<uint8_t>(word);
            w.line(std::format("secured.fcrt_requirement.0x{:04X}", word),
                   requirement_name(fcrt_requirement(kv)));
        }
        w.line("secured.fcrt_requirement.short", requirement_name(fcrt_requirement(Bytes(0x1D))));
    }

    // ---- Xboxupd --------------------------------------------------------------------------

    std::string split_text(const Result<XboxupdParts>& parts) {
        if (!parts) {
            return describe(parts.error());
        }
        return std::format("ok cf_size=0x{:X} cf_sha1={} cg_size=0x{:X} cg_sha1={}",
                           parts->cf_raw.size(), sha1(parts->cf_raw), parts->cg_raw.size(),
                           sha1(parts->cg_raw));
    }

    void render_xboxupd(Writer& w, const Corpus& c, Counters& n) {
        std::vector<std::byte> package(c.update_package.size());
        std::memcpy(package.data(), c.update_package.data(), package.size());
        w.line("xboxupd.package", blob(c.update_package));
        auto container = stfs::StfsContainer::open(package);
        w.line("xboxupd.open", outcome(container));
        if (container) {
            const auto file = container->extract_file_by_name("xboxupd.bin");
            w.line("xboxupd.extract", outcome(file));
            if (file) {
                Bytes raw(file->size());
                std::memcpy(raw.data(), file->data(), raw.size());
                w.line("xboxupd.file", blob(raw));
                const auto parts = split_xboxupd_raw(std::span<const std::byte>(*file));
                n.xboxupd_split = parts.has_value();
                w.line("xboxupd.split", split_text(parts));
                const auto again = split_xboxupd_raw(std::span<const uint8_t>(raw));
                w.line("xboxupd.split_u8_same",
                       yn(parts && again && parts->cf_raw == again->cf_raw &&
                          parts->cg_raw == again->cg_raw));
            }
        }

        // Synthetic: CF at 0 (magic 0x?346), its size at 0x0C, the CG size at 0x1C, CG at the
        // CF size (magic 0x?347).
        const auto make = [](uint32_t cf_size, uint32_t cg_size, size_t total, uint16_t cf_magic,
                             uint16_t cg_magic) {
            Bytes b(total, 0);
            for (size_t i = 0; i < b.size(); ++i) {
                b[i] = static_cast<uint8_t>(i * 3 + 7);
            }
            const auto store16 = [&b](size_t at, uint16_t v) {
                if (at + 2 <= b.size()) {
                    b[at] = static_cast<uint8_t>(v >> 8);
                    b[at + 1] = static_cast<uint8_t>(v);
                }
            };
            const auto store32 = [&](size_t at, uint32_t v) {
                store16(at, static_cast<uint16_t>(v >> 16));
                store16(at + 2, static_cast<uint16_t>(v));
            };
            store16(0, cf_magic);
            store32(0x0C, cf_size);
            store32(0x1C, cg_size);
            store16(cf_size, cg_magic);
            return b;
        };
        struct Case {
            std::string_view name;
            Bytes data;
        };
        const std::array<Case, 9> cases{{
            {"valid", make(0x40, 0x40, 0x80, 0x4346, 0x4347)},
            {"valid_trailing", make(0x40, 0x40, 0x90, 0x4346, 0x4347)},
            {"valid_high_nibble", make(0x40, 0x40, 0x80, 0xF346, 0x1347)},
            {"short_0x1f", Bytes(0x1F, 0)},
            {"bad_cf_magic", make(0x40, 0x40, 0x80, 0x4345, 0x4347)},
            {"cf_size_below_0x20", make(0x1F, 0x40, 0x80, 0x4346, 0x4347)},
            {"cf_overflow", make(0x100, 0x40, 0x80, 0x4346, 0x4347)},
            {"cg_overflow", make(0x40, 0x41, 0x80, 0x4346, 0x4347)},
            {"bad_cg_magic", make(0x40, 0x40, 0x80, 0x4346, 0x4348)},
        }};
        for (const auto& cs : cases) {
            w.line(std::format("xboxupd.synthetic.{}", cs.name),
                   split_text(split_xboxupd_raw(std::span<const uint8_t>(cs.data))));
        }
        const Bytes small_cg = make(0x40, 0x1F, 0x80, 0x4346, 0x4347);
        w.line("xboxupd.synthetic.cg_size_below_0x20",
               split_text(split_xboxupd_raw(std::span<const uint8_t>(small_cg))));
    }

    // ---- CoronaConfig ---------------------------------------------------------------------

    std::string corona_fields(const CoronaConfig& cfg) {
        std::string text = std::format("number=0x{:08X} table=0x{:04X}", cfg.number, cfg.table);
        for (size_t i = 0; i < cfg.blobs.size(); ++i) {
            text += std::format(" blob{}=0x{:04X}/0x{:04X}", i, cfg.blobs[i].block,
                                cfg.blobs[i].length);
        }
        return text;
    }

    void render_corona(Writer& w) {
        std::array<CoronaConfig, 3> configs{};
        configs[0].number = 1;
        configs[0].table = 0x0BF6;
        configs[0].blobs = {{{0x0BF7, 0x1000}, {0x0BF8, 0x0200}, {0, 0}, {0x0BFA, 0x4000}}};
        configs[1].number = 0x00000102;
        configs[1].table = 0x0010;
        configs[1].blobs = {
            {{0x0011, 0x0001}, {0x0012, 0x0002}, {0x0013, 0x0003}, {0x0014, 0x0004}}};
        configs[2].number = 0xFFFFFFFF;
        configs[2].table = 0xFFFF;
        configs[2].blobs = {{{0xFFFF, 0xFFFF}, {0, 0}, {0, 0}, {0, 0}}};

        std::array<Bytes, 3> serialized;
        for (size_t i = 0; i < configs.size(); ++i) {
            const std::string key = std::format("corona.config{}", i);
            serialized[i] = configs[i].serialize();
            w.line(key + ".serialize", blob(serialized[i]));
            const auto parsed = CoronaConfig::parse(serialized[i]);
            std::string text = outcome(parsed);
            if (parsed) {
                const Bytes again = parsed->serialize();
                text += std::format(" {} reserialize_identity={}", corona_fields(*parsed),
                                    yn(again == serialized[i]));
            }
            w.line(key + ".parse", text);
        }

        const Bytes& a = serialized[0];
        const Bytes& b = serialized[1];
        Bytes corrupt_b = b;
        corrupt_b[0x40] ^= 0x01;
        Bytes corrupt_digest = a;
        corrupt_digest[0] ^= 0x80;
        const Bytes short_a(a.begin(), a.begin() + CoronaConfig::kSize - 1);
        Bytes long_a = a;
        long_a.resize(CoronaConfig::kSpan, 0xFF);

        w.line("corona.parse.short", outcome(CoronaConfig::parse(short_a)));
        w.line("corona.parse.body_flip", outcome(CoronaConfig::parse(corrupt_b)));
        w.line("corona.parse.digest_flip", outcome(CoronaConfig::parse(corrupt_digest)));
        const auto long_parsed = CoronaConfig::parse(long_a);
        w.line("corona.parse.span_0x1000",
               long_parsed ? "ok " + corona_fields(*long_parsed) : describe(long_parsed.error()));

        const auto choose = [&w](std::string_view name, std::span<const uint8_t> first,
                                 std::span<const uint8_t> second) {
            const auto chosen = CoronaConfig::choose({first, second});
            w.line(std::format("corona.choose.{}", name),
                   chosen ? corona_fields(*chosen) : std::string{"none"});
        };
        choose("a_b", a, b);
        choose("b_a", b, a);
        choose("a_corruptb", a, corrupt_b);
        choose("corruptb_a", corrupt_b, a);
        choose("corruptdigest_b", corrupt_digest, b);
        choose("short_b", short_a, b);
        choose("a_a", a, a);
        choose("corrupt_corrupt", corrupt_b, corrupt_digest);
        choose("empty_empty", {}, {});
        choose("max_a", serialized[2], a);
    }

    // ---- Freeboot -------------------------------------------------------------------------

    void render_freeboot(Writer& w) {
        w.line("freeboot.rebooter", blob(freeboot_rebooter()));
        w.line("freeboot.payload", blob(freeboot_payload()));
        for (const size_t length : {size_t{0}, size_t{1}, size_t{4}, size_t{5}, size_t{0xD40},
                                    size_t{0x3FFFF}, size_t{0x3FFFC}, size_t{0x40000}}) {
            const Bytes out = freeboot_payload_for(length);
            w.line(std::format("freeboot.payload_for.0x{:X}", length),
                   std::format("{} words_field={}", blob(out),
                               out.size() > 0x53 ? hex(std::span<const uint8_t>(&out[0x52], 2))
                                                 : std::string{"n/a"}));
        }
        for (const std::string_view version :
             {std::string_view{"9199"}, std::string_view{"17559"}, std::string_view{"17489"},
              std::string_view{""},
              std::string_view{"0123456789ABCDEF0123456789ABCDEF-overflow"}}) {
            w.line(std::format("freeboot.rebooter_for.\"{}\"", version),
                   blob(freeboot_rebooter_for(version)));
        }
    }

    // ---- XConfig --------------------------------------------------------------------------

    void render_xconfig(Writer& w, bool& ok) {
        constexpr size_t kRegion = 0x1A18;
        Bytes pattern(0x10000);
        for (size_t i = 0; i < pattern.size(); ++i) {
            pattern[i] = static_cast<uint8_t>(i * 7 + 3);
        }
        w.line("xconfig.input", blob(pattern));
        for (const size_t base : {size_t{0}, size_t{0xC000}}) {
            const std::string key = std::format("xconfig.base_0x{:X}", base);
            const auto parsed = SmcConfig::parse(pattern, base);
            w.line(key + ".parse", outcome(parsed));
            if (!parsed) {
                ok = false;
                continue;
            }
            const Bytes out = parsed->serialize(0x10000, base);
            size_t inside_equal = 0;
            size_t outside_zero = 0;
            for (size_t i = 0; i < out.size(); ++i) {
                if (i >= base && i < base + kRegion) {
                    inside_equal += i < pattern.size() && out[i] == pattern[i] ? 1 : 0;
                } else {
                    outside_zero += out[i] == 0 ? 1 : 0;
                }
            }
            const size_t outside = out.size() - kRegion;
            w.line(key + ".serialize",
                   std::format("{} inside_equal=0x{:X}/0x{:X} outside_zero=0x{:X}/0x{:X}",
                               blob(out), inside_equal, kRegion, outside_zero, outside));
            ok = check(inside_equal == kRegion && outside_zero == outside,
                       std::format("{}: serialize(parse(b)) equals b over the region and is zero "
                                   "elsewhere",
                                   key)) &&
                 ok;
            const auto ns = xconfig::parse(pattern, base);
            w.line(key + ".namespace_same",
                   yn(ns && xconfig::serialize(*ns, 0x10000, base) == out));
        }
        const auto default_base = xconfig::parse(pattern);
        w.line("xconfig.namespace_default_base",
               default_base ? "ok " + blob(xconfig::serialize(*default_base))
                            : describe(default_base.error()));
        w.line("xconfig.parse.short", outcome(SmcConfig::parse(Bytes(kRegion - 1, 0), size_t{0})));
        w.line("xconfig.parse.exact", outcome(SmcConfig::parse(Bytes(kRegion, 0), size_t{0})));
        w.line("xconfig.parse.base_past_end",
               outcome(SmcConfig::parse(Bytes(0x100, 0), size_t{0x200})));
        w.line("xconfig.parse.base_0xF000", outcome(SmcConfig::parse(pattern, size_t{0xF000})));
        const SmcConfig zero{};
        w.line("xconfig.serialize.default_small_total", blob(zero.serialize(0x10, 0x20)));
    }

    // ---- SMC classifier -------------------------------------------------------------------

    void smc_lines(Writer& w, const std::string& key, std::span<const uint8_t> data) {
        w.line(key + ".input", blob(data));
        w.line(key + ".classify",
               std::format("is_encrypted={} type={} jtag_mark={}", yn(smc_is_encrypted(data)),
                           smc_type_name(smc_get_type(data)), yn(smc_has_jtag_mark(data))));
        const auto parsed = Smc::parse(data);
        std::string text = outcome(parsed);
        if (parsed) {
            text += std::format(" encrypted={} motherboard={} version={} variant={}",
                                yn(parsed->encrypted), smc_motherboard_name(parsed->motherboard),
                                parsed->version, smc_type_name(parsed->variant));
        }
        w.line(key + ".parse", text);
    }

    void smc_both(Writer& w, const std::string& key, const Bytes& plain, Counters& n) {
        ++n.smc_cases;
        smc_lines(w, key + ".plain", plain);
        const Bytes sealed = smc_encrypt(plain);
        smc_lines(w, key + ".sealed", sealed);
        w.line(key + ".roundtrip", yn(smc_decrypt(sealed) == plain));
    }

    void render_smc(Writer& w, const Corpus& c, Counters& n) {
        auto img = FlashImage::read(c.image);
        if (img && img->parse() && img->smc) {
            n.image_smc = true;
            const Bytes& raw = img->smc->data;
            smc_lines(w, "smc.image.as_parsed", raw);
            const Bytes other = smc_is_encrypted(raw) ? smc_decrypt(raw) : smc_encrypt(raw);
            smc_lines(w, "smc.image.other_form", other);
        } else {
            w.line("smc.image", "no SMC parsed from mydata/image.bin");
        }

        // A neutral 0x3000-byte plaintext: 0xFF, a Jasper 4.1 board byte at 0x100 and the four
        // zero bytes every plaintext SMC ends with. Each case writes its marks into a copy.
        const auto neutral = [] {
            Bytes b(0x3000, 0xFF);
            b[0x100] = 0x41;
            b[0x101] = 0x02;
            std::fill(b.end() - 4, b.end(), uint8_t{0});
            return b;
        };
        const auto put = [](Bytes& b, size_t at, std::initializer_list<uint8_t> bytes) {
            std::ranges::copy(bytes, b.begin() + static_cast<std::ptrdiff_t>(at));
        };
        struct Mark {
            size_t at;
            std::vector<uint8_t> bytes;
        };
        const std::vector<uint8_t> retail = {0x05, 0x11, 0xE5, 0x22, 0xB4, 0x05};
        const std::vector<uint8_t> glitch = {0x00, 0x00, 0xE5, 0x22, 0xB4, 0x05};
        const std::vector<uint8_t> jtag = {0xD0, 0x00, 0x00, 0x1B};
        const std::vector<uint8_t> cygnos = {0x78, 0xBA, 0xB6};
        const std::vector<uint8_t> cr4 = {0x43, 0x08, 0x80, 0x03};
        const std::vector<uint8_t> rgh3v1 = {0xE5, 0x02, 0x65, 0x03, 0xF6, 0xE5, 0x06, 0x24, 0x49,
                                             0xC0, 0xE0, 0x54, 0x32, 0x24, 0xF5, 0xC0, 0xE0, 0x22};
        struct Case {
            std::string_view name;
            std::vector<Mark> marks;
        };
        const std::vector<Case> cases = {
            {"neutral", {}},
            {"retail", {{0x400, retail}}},
            {"glitch", {{0x400, glitch}}},
            {"glitch_d4_write_75", {{0x400, glitch}, {0x800, {0x75, 0x11, 0xD4}}}},
            {"glitch_d4_write_74", {{0x400, glitch}, {0x800, {0x74, 0xD4}}}},
            {"glitch_high_code", {{0x400, glitch}, {0x2E00, {0x12}}}},
            {"glitch_jtag", {{0x400, glitch}, {0x600, jtag}}},
            {"glitch_cygnos", {{0x400, glitch}, {0x600, cygnos}}},
            {"glitch_high_code_jtag", {{0x400, glitch}, {0x600, jtag}, {0x2E00, {0x12}}}},
            {"jtag_d0_00_00_1b", {{0x600, jtag}}},
            {"cygnos_78_ba_b6", {{0x600, cygnos}}},
            {"retail_jtag", {{0x400, retail}, {0x600, jtag}}},
            {"retail_then_glitch", {{0x400, retail}, {0x500, glitch}}},
            {"glitch_then_retail", {{0x400, glitch}, {0x500, retail}}},
            {"rgh3v1_signature", {{0x900, rgh3v1}}},
            {"rgh3v1_reset_head", {{0x000, {0x02, 0x2E, 0x21}}}},
            {"cr4", {{0x900, cr4}}},
            {"cr4_smcplus_0x1276_8a", {{0x900, cr4}, {0x1276, {0x8A}}}},
            {"cr4_smcplus_0x127b_50", {{0x900, cr4}, {0x127B, {0x50}}}},
            {"cr4_smcplus_0x1396_41", {{0x900, cr4}, {0x1396, {0x41}}}},
            {"cr4_smcplus_scan_75_3c_41", {{0x900, cr4}, {0x1800, {0x75, 0x3C, 0x41}}}},
            {"cr4_and_rgh3v1", {{0x900, cr4}, {0xA00, rgh3v1}}},
        };
        for (const auto& cs : cases) {
            Bytes b = neutral();
            for (const auto& m : cs.marks) {
                std::ranges::copy(m.bytes, b.begin() + static_cast<std::ptrdiff_t>(m.at));
            }
            smc_both(w, std::format("smc.synthetic.{}", cs.name), b, n);
        }

        // Sizes at the edges of the classifier and of Smc::parse.
        Bytes tiny = {0xD0, 0x00, 0x00, 0x1B, 0x00};
        smc_lines(w, "smc.size.5_bytes", tiny);
        Bytes six = {0xD0, 0x00, 0x00, 0x1B, 0x00, 0x00};
        smc_lines(w, "smc.size.6_bytes", six);
        Bytes at_0x100 = neutral();
        at_0x100.resize(0x100);
        smc_lines(w, "smc.size.0x100", at_0x100);
        Bytes at_0x107 = neutral();
        at_0x107.resize(0x107);
        smc_lines(w, "smc.size.0x107", at_0x107);
        Bytes at_0x108 = neutral();
        at_0x108.resize(0x108);
        smc_lines(w, "smc.size.0x108", at_0x108);
        Bytes at_0x4000 = neutral();
        at_0x4000.resize(0x4000, 0);
        smc_lines(w, "smc.size.0x4000", at_0x4000);
        Bytes at_0x4001 = neutral();
        at_0x4001.resize(0x4001, 0);
        smc_lines(w, "smc.size.0x4001", at_0x4001);
        // Neither form ends in zeros: the board-nibble fallback decides.
        Bytes no_tail = neutral();
        std::fill(no_tail.end() - 4, no_tail.end(), uint8_t{0x11});
        smc_lines(w, "smc.no_zero_tail.plain_board", no_tail);
        no_tail[0x100] = 0x91;
        smc_lines(w, "smc.no_zero_tail.no_board", no_tail);
        put(no_tail, 0x100, {0x00});
        smc_lines(w, "smc.no_zero_tail.zero_board", no_tail);
    }

    // ---- driver ---------------------------------------------------------------------------

    struct Rendered {
        std::string text;
        Counters counters;
        bool ok = true;
    };

    Rendered render(const Corpus& corpus) {
        std::ostringstream out;
        out << "# Objects corpus over tracked tests/gxBuild-support-files fixtures; one line per "
               "item and operation.\n";
        Writer w(out);
        Rendered r;
        render_patchsets(w, corpus, r.counters);
        render_xell(w, corpus, r.counters);
        render_secured(w, corpus, r.counters);
        render_xboxupd(w, corpus, r.counters);
        render_corona(w);
        render_freeboot(w);
        render_xconfig(w, r.ok);
        render_smc(w, corpus, r.counters);
        r.text = out.str();
        return r;
    }

    bool load_dir(const std::filesystem::path& dir, std::vector<Fixture>& patches,
                  std::vector<Fixture>& addons) {
        std::error_code error;
        for (const auto& entry : std::filesystem::directory_iterator(dir, error)) {
            if (!entry.is_regular_file() || entry.path().extension() != ".bin") {
                continue;
            }
            auto bytes = read_file(entry.path());
            if (!bytes) {
                std::cerr << "FAIL: cannot read " << entry.path().string() << '\n';
                return false;
            }
            const std::string name = entry.path().filename().string();
            (name.starts_with("patches_") ? patches : addons).push_back({name, std::move(*bytes)});
        }
        if (error) {
            std::cerr << "FAIL: cannot list " << dir.string() << ": " << error.message() << '\n';
            return false;
        }
        std::ranges::sort(patches, {}, &Fixture::name);
        std::ranges::sort(addons, {}, &Fixture::name);
        return true;
    }

    bool load_named(const std::filesystem::path& dir, std::initializer_list<std::string_view> names,
                    std::vector<Fixture>& into) {
        for (const auto name : names) {
            auto bytes = read_file(dir / name);
            if (!bytes) {
                std::cerr << "FAIL: cannot read tracked fixture " << (dir / name).string() << '\n';
                return false;
            }
            into.push_back({std::string{name}, std::move(*bytes)});
        }
        return true;
    }

} // namespace

int main(int argc, char** argv) {
    const auto options = test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }

    std::filesystem::path support{GXBUILD3_SUPPORT_DIR};
    if (const char* override_dir = std::getenv("GXBUILD3_OBJECTS_CORPUS_SUPPORT");
        override_dir != nullptr && *override_dir != '\0') {
        support = override_dir;
        std::cerr << "note: support directory overridden by GXBUILD3_OBJECTS_CORPUS_SUPPORT\n";
    }

    Corpus corpus;
    bool ok = load_dir(support / "17559" / "bin", corpus.patches, corpus.addons);
    const auto mydata = support / "mydata";
    ok = ok && load_named(mydata, {"xell-1f.bin", "xell-2f.bin", "xell-gggggg.bin"}, corpus.xells);
    ok = ok && load_named(mydata, {"crl.bin", "dae.bin", "extended.bin", "secdata.bin", "fcrt.bin"},
                          corpus.secured);
    if (ok) {
        auto image = read_file(mydata / "image.bin");
        auto package = read_file(support / "17559" / "su20076000_00000000");
        ok = check(image.has_value(), "tracked mydata/image.bin is readable") &&
             check(package.has_value(), "tracked 17559/su20076000_00000000 is readable");
        if (ok) {
            corpus.image = std::move(*image);
            corpus.update_package = std::move(*package);
        }
    }
    if (!ok) {
        std::cout << "FAIL: gxbuild3_objects_corpus_tests (tracked fixtures missing)\n";
        return 1;
    }
    ok = check(corpus.patches.size() == kExpectedPatchFiles,
               std::format("expected {} tracked patches_*.bin, found {}", kExpectedPatchFiles,
                           corpus.patches.size())) &&
         ok;
    ok = check(corpus.addons.size() == kExpectedAddons,
               std::format("expected {} tracked add-on .bin files, found {}", kExpectedAddons,
                           corpus.addons.size())) &&
         ok;

    const Rendered first = render(corpus);
    const Rendered second = render(corpus);
    if (first.text != second.text) {
        std::cerr << "FAIL: two in-process renderings differ (nondeterministic)\n"
                  << *test::golden_difference(first.text, second.text);
        ok = false;
    }
    ok = first.ok && ok;
    const auto& n = first.counters;
    ok = check(n.xboxupd_split, "xboxupd.bin from su20076000 splits into CF and CG") && ok;
    ok = check(n.image_smc, "mydata/image.bin yields an SMC") && ok;

    std::cout << "patchsets " << corpus.patches.size() << " files x " << kPatchTypes.size()
              << " build types: parsed " << n.patch_parses_ok << "/" << n.patch_parses
              << ", add-ons " << corpus.addons.size() << '\n';
    std::cout << "xell parsed " << n.xells_ok << "/" << corpus.xells.size() << ", secured files "
              << n.secured_files << "/5, xboxupd split " << (n.xboxupd_split ? 1 : 0)
              << "/1, image smc " << (n.image_smc ? 1 : 0) << "/1, synthetic smc cases "
              << n.smc_cases << '\n';
    const size_t lines = static_cast<size_t>(std::ranges::count(first.text, '\n'));
    const bool matched = test::check_golden(*options, "objects_corpus", first.text);
    std::cout << "compared " << (matched ? lines : 0) << "/" << lines
              << " snapshot lines against objects_corpus.txt\n";
    ok = matched && ok;

    std::cout << (ok ? "PASS" : "FAIL") << ": gxbuild3_objects_corpus_tests\n";
    return ok ? 0 : 1;
}
