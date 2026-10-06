// Wire-corpus snapshot over the tracked bootloader stage fixtures in
// tests/gxBuild-support-files/common (every *.bin there; 145 on a clean clone). Runs on a clean
// clone: it needs no untracked fixture.
//
// Each fixture is dispatched on its first two bytes (CB/SB -> Cb, SC -> Sc, CD/SD -> Cd,
// CE -> Ce, CF -> Cf, CG -> Cg) and recorded one line per operation, prefixed by its file name:
//   input      size and SHA-1 of the fixture bytes;
//   parse      ok, or the ErrorCode and message of the failure;
//   serialize  whether serialize() == input, and the SHA-1 of serialize();
//   state      is_decrypted() and the decrypted flag;
//   header     the generic header fields in host order;
//   fields     the stage numeric fields (CB console type/sequence/allow, CD padding,
//              CE address/size/padding, CF versions/qfe/reserved/cg_size, CG sizes);
//   perbox     the CB/CF per-box bytes in hex when parsed;
//   cb.*       requires_cpu_key_for_cd(), patch_rgh3_v1_cb_x() and the 1BL-key crypt;
//   cbb.*      encrypt_cb_b/decrypt_cb_b under the parsed cba_9188 header (flags as-is,
//              |0x1000, |0x1) and encrypt_retail over a fixed 0x3000-byte SMC pattern;
//   seal.*     SC/CD/CE/CG/CF forced to decrypted=true, encrypted and decrypted again under
//              fixed keys; CF also calc_mac and cg_key().
//
// The snapshot records whatever HEAD does; it asserts no identity on its own, so quirks
// (SC's flag-only is_decrypted, CB's 1BL crypt toggling instead of forcing) are pinned, not
// fixed. Sealing randomises an all-zero stage nonce through ExCryptRandom, so the test writes
// kPinnedNonce (0x11..0x20) into header.key, or CB data[0..16], whenever it is all zero before
// a crypt. That pin lives here only, never in src/.
//
// The only CPU key is the one already public in tests/gxBuild-support-files/build_all.sh.
// The rendering runs twice in-process and must be identical (determinism). --update rewrites
// tests/golden/wire_corpus_bootloaders.txt (CTest never passes it). GXBUILD3_WIRE_CORPUS_SUPPORT
// overrides the support directory, for mutation checks against scratch copies only.

#include "GoldenSnapshot.hpp"
#include "excrypt.h"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"

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

    // The CPU key of the tracked mydata/image.bin, public in build_all.sh (-p ...).
    constexpr std::array<uint8_t, 16> kCpuKey = {0x93, 0xFB, 0x9D, 0x01, 0x19, 0x30, 0xAF, 0xC4,
                                                 0x53, 0xAA, 0x75, 0xB1, 0x83, 0xEF, 0xAC, 0x09};
    // Written over an all-zero stage nonce before any crypt, so ExCryptRandom never runs.
    constexpr std::array<uint8_t, 16> kPinnedNonce = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                                      0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                                                      0x1D, 0x1E, 0x1F, 0x20};
    // Fixed parent key for CD/CE and the CB_A key of the CB_B chain (not a CPU key).
    constexpr std::array<uint8_t, 16> kParentKey = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                                    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    constexpr size_t kExpectedFixtures = 145;

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

    template <class T> std::span<const uint8_t> raw_bytes(const T& value) {
        return {reinterpret_cast<const uint8_t*>(&value), sizeof(T)};
    }

    std::string describe(const Error& error) {
        return std::format("err={} msg=\"{}\"", to_string(error.code), error.describe());
    }

    std::string result_text(const Result<void>& result) {
        return result ? std::string{"ok"} : describe(result.error());
    }

    std::string derived_text(const std::optional<std::array<uint8_t, 16>>& key) {
        return key ? sha1(*key) : std::string{"none"};
    }

    std::optional<Bytes> read_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }
        return Bytes(std::istreambuf_iterator<char>(in), {});
    }

    // Writes kPinnedNonce over an all-zero nonce; reports whether it did.
    bool pin_nonce(uint8_t* nonce) {
        if (std::all_of(nonce, nonce + 16, [](uint8_t b) { return b == 0; })) {
            std::memcpy(nonce, kPinnedNonce.data(), kPinnedNonce.size());
            return true;
        }
        return false;
    }

    std::string pin_text(bool pinned) {
        return pinned ? "pinned" : "kept";
    }

    bool pin_cb_nonce(BootloaderCb& cb) {
        return cb.data.size() >= 16 && pin_nonce(cb.data.data());
    }

    // A fixed SMC-sized pattern: only its words feed the CB per-box checksum.
    Bytes smc_pattern() {
        Bytes smc(0x3000);
        for (size_t i = 0; i < smc.size(); ++i) {
            smc[i] = static_cast<uint8_t>(i * 0x9D + 0x5B);
        }
        return smc;
    }

    class Writer {
      public:
        explicit Writer(std::ostringstream& out) : out_(out) {}
        void item(std::string name) { name_ = std::move(name); }
        void line(std::string_view op, std::string_view text) {
            out_ << name_ << ' ' << op << ' ' << text << '\n';
        }

      private:
        std::ostringstream& out_;
        std::string name_;
    };

    void common_lines(Writer& w, std::span<const uint8_t> input, std::span<const uint8_t> serial,
                      bool is_decrypted, bool decrypted, const generic_header& h) {
        const bool identical = std::ranges::equal(input, serial);
        w.line("serialize", std::format("identity={} size=0x{:X} sha1={}", identical ? "yes" : "no",
                                        serial.size(), sha1(serial)));
        w.line("state", std::format("is_decrypted={} decrypted={}", is_decrypted, decrypted));
        w.line("header", std::format("magic=0x{:04X} version={} pairing=0x{:04X} flags=0x{:04X} "
                                     "entrypoint=0x{:08X} size=0x{:X}",
                                     h.magic, h.version, h.pairing, h.flags, h.entrypoint, h.size));
    }

    // SC/CD/CE/CG: forced plaintext, nonce pinned, encrypt then decrypt under one key.
    template <class Stage, class Encrypt, class Decrypt>
    void seal_lines(Writer& w, std::string_view label, const Stage& parsed, Encrypt&& encrypt,
                    Decrypt&& decrypt) {
        Stage stage = parsed;
        const bool pinned = pin_nonce(stage.header.key);
        stage.decrypted = true;
        const auto encrypted = encrypt(stage);
        std::string text =
            std::format("nonce={} encrypt={}", pin_text(pinned), result_text(encrypted));
        if (encrypted) {
            std::string derived = "n/a";
            if constexpr (requires(const Stage& s) { s.derived_key; }) {
                derived = derived_text(stage.derived_key);
            }
            text += std::format(" decrypted={} sha1={} derived_sha1={}", stage.decrypted,
                                sha1(stage.serialize()), derived);
            const auto decrypted = decrypt(stage);
            text += std::format(" decrypt={}", result_text(decrypted));
            if (decrypted) {
                text +=
                    std::format(" decrypted={} sha1={}", stage.decrypted, sha1(stage.serialize()));
            }
        }
        w.line(label, text);
    }

    struct Context {
        std::optional<cb_header> cba_9188;
        std::optional<std::array<uint8_t, 16>> cg_key;
        Bytes smc = smc_pattern();
    };

    void render_cb(Writer& w, std::string_view name, std::span<const uint8_t> input,
                   const BootloaderCb& cb, const Context& ctx) {
        common_lines(w, input, cb.serialize(), cb.is_decrypted(), cb.decrypted, cb.header.header);
        const auto& seq = cb.header.console_seq_allow;
        w.line("fields",
               std::format("console_type={} console_sequence={} sequence_allow=0x{:04X}",
                           seq.console_type, seq.console_sequence, seq.console_sequence_allow));
        w.line("perbox", cb.perbox ? hex(raw_bytes(*cb.perbox)) : std::string{"none"});
        w.line("cb.requires_cpu_key_for_cd", cb.requires_cpu_key_for_cd() ? "true" : "false");

        {
            BootloaderCb copy = cb;
            const bool patched = copy.patch_rgh3_v1_cb_x();
            w.line("cb.rgh3_v1",
                   std::format("patched={} sha1={}", patched, sha1(copy.serialize())));
        }

        if (!name.starts_with("cbb_")) {
            // CB/CB_A/SB under the 1BL key: encrypt() toggles, so an encrypted fixture opens.
            BootloaderCb copy = cb;
            const bool pinned = pin_cb_nonce(copy);
            const auto first = copy.encrypt(key_1bl);
            std::string text =
                std::format("nonce={} encrypt={}", pin_text(pinned), result_text(first));
            if (first) {
                text += std::format(" decrypted={} sha1={} derived_sha1={}", copy.decrypted,
                                    sha1(copy.serialize()), derived_text(copy.derived_key));
                const auto second = copy.decrypt(key_1bl);
                text += std::format(" decrypt={}", result_text(second));
                if (second) {
                    text += std::format(" decrypted={} sha1={}", copy.decrypted,
                                        sha1(copy.serialize()));
                }
            }
            w.line("cb.crypt_1bl", text);

            BootloaderCb retail = cb;
            const bool retail_pinned = pin_cb_nonce(retail);
            const auto sealed = retail.encrypt_retail(key_1bl, kCpuKey, ctx.smc, nullptr);
            std::string retail_text =
                std::format("nonce={} result={}", pin_text(retail_pinned), result_text(sealed));
            if (sealed) {
                retail_text += std::format(
                    " decrypted={} sha1={} digest={}", retail.decrypted, sha1(retail.serialize()),
                    retail.perbox ? hex(raw_bytes(retail.perbox->per_box_digest)) : "none");
            }
            w.line("cb.encrypt_retail", retail_text);
            return;
        }

        if (!ctx.cba_9188) {
            w.line("cbb", "skipped: cba_9188.bin did not parse");
            return;
        }
        struct Variant {
            std::string_view label;
            uint16_t or_flags;
        };
        static constexpr std::array<Variant, 3> kVariants{{
            {"flags_as_is", 0x0000},
            {"flags_or_0x1000", 0x1000},
            {"flags_or_0x1", 0x0001},
        }};
        for (const auto& variant : kVariants) {
            cb_header cba = *ctx.cba_9188;
            cba.header.flags = static_cast<uint16_t>(cba.header.flags | variant.or_flags);

            BootloaderCb copy = cb;
            const bool pinned = pin_cb_nonce(copy);
            const auto first = copy.encrypt_cb_b(cba, kParentKey.data(), kCpuKey.data());
            std::string text = std::format("cba_flags=0x{:04X} nonce={} encrypt={}",
                                           cba.header.flags, pin_text(pinned), result_text(first));
            if (first) {
                text += std::format(" decrypted={} sha1={} derived_sha1={}", copy.decrypted,
                                    sha1(copy.serialize()), derived_text(copy.derived_key));
                const auto second = copy.decrypt_cb_b(cba, kParentKey.data(), kCpuKey.data());
                text += std::format(" decrypt={}", result_text(second));
                if (second) {
                    text += std::format(" decrypted={} sha1={}", copy.decrypted,
                                        sha1(copy.serialize()));
                }
            }
            w.line(std::format("cbb.crypt.{}", variant.label), text);
        }
        for (const auto& variant : kVariants) {
            cb_header cba = *ctx.cba_9188;
            cba.header.flags = static_cast<uint16_t>(cba.header.flags | variant.or_flags);

            BootloaderCb copy = cb;
            const bool pinned = pin_cb_nonce(copy);
            const auto sealed = copy.encrypt_retail(kParentKey.data(), kCpuKey, ctx.smc, &cba);
            std::string text = std::format("cba_flags=0x{:04X} nonce={} result={}",
                                           cba.header.flags, pin_text(pinned), result_text(sealed));
            if (sealed) {
                text +=
                    std::format(" decrypted={} sha1={} derived_sha1={} digest={}", copy.decrypted,
                                sha1(copy.serialize()), derived_text(copy.derived_key),
                                copy.perbox ? hex(raw_bytes(copy.perbox->per_box_digest)) : "none");
            }
            w.line(std::format("cbb.encrypt_retail.{}", variant.label), text);
        }
    }

    void render_sc(Writer& w, std::span<const uint8_t> input, const BootloaderSc& sc) {
        common_lines(w, input, sc.serialize(), sc.is_decrypted(), sc.decrypted, sc.header.header);
        w.line("fields", "none");
        seal_lines(
            w, "seal.zero_secret", sc,
            [](BootloaderSc& s) { return s.encrypt(BootloaderSc::kZeroSecret); },
            [](BootloaderSc& s) { return s.decrypt(BootloaderSc::kZeroSecret); });
    }

    void render_cd(Writer& w, std::span<const uint8_t> input, const BootloaderCd& cd) {
        common_lines(w, input, cd.serialize(), cd.is_decrypted(), cd.decrypted, cd.header.header);
        w.line("fields", std::format("padding=0x{:04X}", cd.header.padding));
        seal_lines(
            w, "seal.default", cd, [](BootloaderCd& s) { return s.encrypt(kParentKey.data()); },
            [](BootloaderCd& s) { return s.decrypt(kParentKey.data()); });
        seal_lines(
            w, "seal.hmac1920", cd,
            [](BootloaderCd& s) { return s.encrypt(kParentKey.data(), kCpuKey.data()); },
            [](BootloaderCd& s) { return s.decrypt(kParentKey.data(), kCpuKey.data()); });
    }

    void render_ce(Writer& w, std::span<const uint8_t> input, const BootloaderCe& ce) {
        common_lines(w, input, ce.serialize(), ce.is_decrypted(), ce.decrypted, ce.header.header);
        w.line("fields", std::format("address=0x{:016X} size=0x{:X} padding=0x{:08X}",
                                     ce.header.address, ce.header.size, ce.header.padding));
        seal_lines(
            w, "seal.parent_key", ce, [](BootloaderCe& s) { return s.encrypt(kParentKey.data()); },
            [](BootloaderCe& s) { return s.decrypt(kParentKey.data()); });
    }

    std::string cg_key_text(const std::optional<std::array<uint8_t, 16>>& key) {
        return key ? hex(*key) : std::string{"none"};
    }

    void render_cf(Writer& w, std::span<const uint8_t> input, const BootloaderCf& cf) {
        common_lines(w, input, cf.serialize(), cf.is_decrypted(), cf.decrypted, cf.header.header);
        const auto& h = cf.header;
        w.line("fields",
               std::format("source_version={} source_qfe={} target_version={} target_qfe={} "
                           "reserved=0x{:08X} cg_size=0x{:X} fixpoint_sha1={}",
                           h.source_version, h.source_qfe, h.target_version, h.target_qfe,
                           h.reserved, h.cg_size, sha1(h.fixpoint_nonce)));
        w.line("perbox", cf.perbox ? hex(raw_bytes(*cf.perbox)) : std::string{"none"});
        w.line("cf.cg_key", cg_key_text(cf.cg_key()));

        {
            BootloaderCf copy = cf;
            const auto mac = copy.calc_mac(key_1bl, kCpuKey.data());
            std::string text = std::format("result={}", result_text(mac));
            if (mac) {
                text += std::format(
                    " sha1={} digest={}", sha1(copy.serialize()),
                    hex(std::span<const uint8_t>(
                        copy.data.data() + 0x1C0 + offsetof(cf_perbox, per_box_digest), 16)));
            }
            w.line("cf.calc_mac", text);
        }

        // CF seals from 0x30 under its header fixpoint and never randomises it.
        BootloaderCf copy = cf;
        copy.decrypted = true;
        const auto encrypted = copy.encrypt(key_1bl);
        std::string text = std::format("encrypt={}", result_text(encrypted));
        if (encrypted) {
            text += std::format(" decrypted={} sha1={}", copy.decrypted, sha1(copy.serialize()));
            const auto decrypted = copy.decrypt(key_1bl);
            text += std::format(" decrypt={}", result_text(decrypted));
            if (decrypted) {
                text += std::format(" decrypted={} sha1={} cg_key={}", copy.decrypted,
                                    sha1(copy.serialize()), cg_key_text(copy.cg_key()));
            }
        }
        w.line("seal.1bl", text);
    }

    void render_cg(Writer& w, std::span<const uint8_t> input, const BootloaderCg& cg,
                   const Context& ctx) {
        common_lines(w, input, cg.serialize(), cg.is_decrypted(), cg.decrypted, cg.header.header);
        w.line("fields", std::format("source_size=0x{:X} target_size=0x{:X}", cg.header.source_size,
                                     cg.header.target_size));
        if (!ctx.cg_key) {
            w.line("seal.cf_4532_cg_key", "skipped: cf_4532.bin yields no cg_key");
            return;
        }
        const auto key = *ctx.cg_key;
        seal_lines(
            w, "seal.cf_4532_cg_key", cg, [&key](BootloaderCg& s) { return s.encrypt(key.data()); },
            [&key](BootloaderCg& s) { return s.decrypt(key.data()); });
    }

    template <class Stage>
    std::optional<Stage> parse_line(Writer& w, std::span<const uint8_t> input) {
        auto parsed = Stage::parse(input);
        if (!parsed) {
            w.line("parse", describe(parsed.error()));
            return std::nullopt;
        }
        w.line("parse", "ok");
        return std::move(*parsed);
    }

    struct Fixture {
        std::string name;
        Bytes bytes;
    };

    Context make_context(const std::vector<Fixture>& fixtures, std::ostringstream& out) {
        Context ctx;
        const auto find = [&fixtures](std::string_view name) -> const Fixture* {
            for (const auto& f : fixtures) {
                if (f.name == name) {
                    return &f;
                }
            }
            return nullptr;
        };
        if (const auto* cba = find("cba_9188.bin")) {
            if (auto parsed = BootloaderCb::parse(cba->bytes)) {
                ctx.cba_9188 = parsed->header;
            }
        }
        out << "context cba_9188 "
            << (ctx.cba_9188 ? std::format("flags=0x{:04X}", ctx.cba_9188->header.flags)
                             : std::string{"none"})
            << '\n';
        if (const auto* cf = find("cf_4532.bin")) {
            if (auto parsed = BootloaderCf::parse(cf->bytes)) {
                BootloaderCf open = std::move(*parsed);
                const bool was_decrypted = open.is_decrypted();
                if (!was_decrypted) {
                    (void) open.decrypt(key_1bl);
                }
                ctx.cg_key = open.cg_key();
                out << "context cf_4532 opened=" << (was_decrypted ? "as-parsed" : "decrypt_1bl")
                    << " cg_key=" << cg_key_text(ctx.cg_key) << '\n';
            }
        }
        if (!ctx.cg_key) {
            out << "context cf_4532 cg_key=none\n";
        }
        out << "context smc size=0x" << std::format("{:X}", ctx.smc.size())
            << " sha1=" << sha1(ctx.smc) << '\n';
        return ctx;
    }

    struct Rendered {
        std::string text;
        size_t fixtures = 0;
        size_t parsed = 0;
    };

    Rendered render(const std::vector<Fixture>& fixtures) {
        std::ostringstream out;
        out << "# Wire corpus over tests/gxBuild-support-files/common/*.bin; one line per "
               "fixture and operation.\n";
        out << "fixtures " << fixtures.size() << '\n';
        const Context ctx = make_context(fixtures, out);
        Writer w(out);
        Rendered result;
        result.fixtures = fixtures.size();
        for (const auto& fixture : fixtures) {
            const std::span<const uint8_t> input = fixture.bytes;
            w.item(fixture.name);
            w.line("input", std::format("size=0x{:X} sha1={}", input.size(), sha1(input)));
            const uint16_t magic =
                input.size() >= 2 ? static_cast<uint16_t>((input[0] << 8) | input[1]) : 0;
            switch (magic) {
                case CB:
                case SB:
                    if (auto cb = parse_line<BootloaderCb>(w, input)) {
                        ++result.parsed;
                        render_cb(w, fixture.name, input, *cb, ctx);
                    }
                    break;
                case SC:
                    if (auto sc = parse_line<BootloaderSc>(w, input)) {
                        ++result.parsed;
                        render_sc(w, input, *sc);
                    }
                    break;
                case CD:
                case SD:
                    if (auto cd = parse_line<BootloaderCd>(w, input)) {
                        ++result.parsed;
                        render_cd(w, input, *cd);
                    }
                    break;
                case CE:
                    if (auto ce = parse_line<BootloaderCe>(w, input)) {
                        ++result.parsed;
                        render_ce(w, input, *ce);
                    }
                    break;
                case CF:
                    if (auto cf = parse_line<BootloaderCf>(w, input)) {
                        ++result.parsed;
                        render_cf(w, input, *cf);
                    }
                    break;
                case CG:
                    if (auto cg = parse_line<BootloaderCg>(w, input)) {
                        ++result.parsed;
                        render_cg(w, input, *cg, ctx);
                    }
                    break;
                default:
                    w.line("parse", std::format("unknown magic=0x{:04X}", magic));
                    break;
            }
        }
        result.text = out.str();
        return result;
    }

} // namespace

int main(int argc, char** argv) {
    const auto options = test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }

    std::filesystem::path support{GXBUILD3_SUPPORT_DIR};
    if (const char* override_dir = std::getenv("GXBUILD3_WIRE_CORPUS_SUPPORT");
        override_dir != nullptr && *override_dir != '\0') {
        support = override_dir;
        std::cerr << "note: support directory overridden by GXBUILD3_WIRE_CORPUS_SUPPORT\n";
    }
    const auto common = support / "common";

    std::vector<Fixture> fixtures;
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(common, error)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".bin") {
            continue;
        }
        auto bytes = read_file(entry.path());
        if (!bytes) {
            std::cerr << "FAIL: cannot read " << entry.path().string() << '\n';
            return 1;
        }
        fixtures.push_back({entry.path().filename().string(), std::move(*bytes)});
    }
    if (error) {
        std::cerr << "FAIL: cannot list the tracked fixtures in " << common.string() << ": "
                  << error.message() << '\n';
        return 1;
    }
    std::ranges::sort(fixtures, {}, &Fixture::name);

    bool ok = true;
    if (fixtures.size() != kExpectedFixtures) {
        std::cerr << "FAIL: expected " << kExpectedFixtures << " tracked stage fixtures in "
                  << common.string() << ", found " << fixtures.size() << '\n';
        ok = false;
    }

    const Rendered first = render(fixtures);
    const Rendered second = render(fixtures);
    if (first.text != second.text) {
        std::cerr << "FAIL: two in-process renderings differ (nondeterministic seal)\n"
                  << *test::golden_difference(first.text, second.text);
        ok = false;
    }

    std::cout << "fixtures " << first.fixtures << "/" << kExpectedFixtures << ", parsed "
              << first.parsed << "/" << first.fixtures << '\n';
    const bool matched = test::check_golden(*options, "wire_corpus_bootloaders", first.text);
    std::cout << "compared " << (matched ? first.fixtures : 0) << "/" << first.fixtures
              << " fixtures against wire_corpus_bootloaders.txt\n";
    ok = matched && ok;

    std::cout << (ok ? "PASS" : "FAIL") << ": gxbuild3_wire_corpus_tests\n";
    return ok ? 0 : 1;
}
