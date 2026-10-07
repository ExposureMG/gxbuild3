// gxbuild3_flashimage_render, write side: the pieces of a synthetic flashimage_matrix cell
// and the oracle's per-image snapshot (render_snapshot, stdout of tools/FlashImageSnapshot.cpp).
// Moved verbatim from FlashImageGoldenTests.cpp; see FlashImageRender.hpp.

#include "nand/FlashImage.hpp"
#include "support/render/FlashImageRender.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::test::render {

    using namespace gxbuild3::nand;

    namespace {

        bool zero_nonce(std::span<const uint8_t> nonce) {
            return std::all_of(nonce.begin(), nonce.end(), [](uint8_t b) { return b == 0; });
        }

    } // namespace

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
    std::optional<Bytes> render_write(Snapshot& s, std::string_view p, FlashImage& f) {
        auto written = f.write();
        if (!written) {
            s.line(p, "write", "error " + describe_error(written.error()));
            return std::nullopt;
        }
        s.line(p, "write", hex32(written->size()) + " sha256:" + sha256(*written));
        s.line(p, "header", hex(std::as_const(f.flash_driver).read_offset(0, sizeof(nand_header))));
        return std::move(*written);
    }

    namespace {

        size_t differing_bytes(const Bytes& a, const Bytes& b) {
            size_t count = a.size() > b.size() ? a.size() - b.size() : b.size() - a.size();
            const size_t common = std::min(a.size(), b.size());
            for (size_t i = 0; i < common; ++i) {
                count += a[i] != b[i] ? 1 : 0;
            }
            return count;
        }

        void render_rewrite(std::ostringstream& text, std::string_view p, FlashImage& img,
                            const Bytes& input) {
            const auto written = img.write();
            if (!written) {
                text << p << "write=error " << describe_error(written.error()) << '\n';
                return;
            }
            text << p << "size=" << hex32(written->size()) << '\n';
            text << p << "sha256=" << sha256(*written) << '\n';
            text << p << "identity=" << (*written == input ? 1 : 0) << '\n';
            text << p << "differing_bytes=" << hex32(differing_bytes(*written, input)) << '\n';
        }

        Result<FlashImage> read_and_parse(const Bytes& bytes) {
            auto img = FlashImage::read(bytes);
            if (!img) {
                return fail(ErrorCode::Internal, "FlashImage::read returned no image");
            }
            if (auto parsed = img->parse(); !parsed) {
                return std::unexpected(std::move(parsed.error()));
            }
            return std::move(*img);
        }

    } // namespace

    std::string render_snapshot(const Bytes& bytes) {
        std::ostringstream text;
        text << "input.size=" << hex32(bytes.size()) << '\n';
        text << "input.sha256=" << sha256(bytes) << '\n';

        // parse, layout queries, write() straight after parse.
        {
            auto img = read_and_parse(bytes);
            text << "parse=" << outcome(img) << '\n';
            if (!img) {
                return text.str();
            }
            text << render_image(*img, "parse.");
            text << render_layout(*img, nullptr);
            render_rewrite(text, "write.", *img, bytes);
        }

        // parse, decrypt_all (snapshot), encrypt_all, write().
        if (auto img = read_and_parse(bytes)) {
            const auto opened = img->decrypt_all(kCpuKey);
            text << "decrypt=" << outcome(opened) << '\n';
            if (opened) {
                text << render_image(*img, "decrypt.");
                const auto type = img->build_type.value_or(BuildType::Retail);
                text << "roundtrip.encrypt_build_type=" << build_type_name(type) << '\n';
                // encrypt_all draws a random nonce for a zero SC/CD/CE/CG nonce; such an image
                // would not snapshot deterministically, so it is named instead.
                if (const auto zero = zero_random_nonce(*img)) {
                    text << "roundtrip=skipped: zero " << *zero << " nonce\n";
                } else {
                    const auto sealed = img->encrypt_all(kCpuKey, type);
                    text << "roundtrip.encrypt=" << outcome(sealed) << '\n';
                    if (sealed) {
                        render_rewrite(text, "roundtrip.", *img, bytes);
                    }
                }
            }
        }

        // The public summary (extract_all_info) of the same image.
        Snapshot s{text};
        (void) render_info_summary(s, bytes, nullptr);
        return text.str();
    }

} // namespace gxbuild3::test::render
