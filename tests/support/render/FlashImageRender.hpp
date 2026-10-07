#pragma once

// gxbuild3_flashimage_render: the text renderers of a FlashImage, shared by the FlashImage
// goldens (tests/golden/flashimage_golden.txt and flashimage_matrix.txt) and by the oracle's
// snapshot tool (tools/FlashImageSnapshot.cpp, compared with tests/golden/build_all.parse.txt).
// It links gxbuild3_internal only, never GoogleTest, so the tool stays a plain executable.
//
// Every line format, key and number spelling is the one FlashImageGoldenTests.cpp printed:
// the code was moved here verbatim. The renderer's own checks (the donor golden's
// payload_layout(), parse and image.info cross-checks) no longer fail a test themselves: they
// are counted in a RenderChecks and each failed one is appended to its problems list, which
// the caller turns into test failures. The snapshot tool records failures as lines only.
//
//   render_image(img, prefix)    every nand_header field, boot stage, console block, payload,
//                                the filesystem, mobile data, SMC and keyvault of a parsed image
//   render_layout(img, checks)   update_slots_end, patch_slot_offset, the active payload block
//                                ranges and payload_layout() (checks == nullptr: record only)
//   render_info(bytes, info, c)  extract_all_info()'s summary, cross-checked with image.info
//   render_snapshot(bytes)       the oracle's per-image snapshot (parse., layout., write.,
//                                decrypt., roundtrip., info.); stdout of the snapshot tool
//   stage_flags, render_serialized, render_layout_queries, render_fs_entries, render_write
//                                the pieces of one synthetic flashimage_matrix cell
//
// Console identity (serial, console id, OSIG, DVD key, manufacturing date, pairing data) only
// ever appears as a SHA-1. The CPU key is the one already public in build_all.sh.

#include "BuildRunner.hpp"
#include "Error.hpp"
#include "nand/FlashImage.hpp"
#include "support/Keys.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::test::render {

    using Bytes = std::vector<uint8_t>;

    // The CPU key of the tracked mydata/image.bin, public in build_all.sh (-p ...).
    inline constexpr CpuKey kCpuKey = kBuildAllCpuKey;

    // The renderer's checks: each one is counted; a failed one is appended to problems as
    // "<message>" or "<message>: <describe()>".
    struct RenderChecks {
        std::size_t count = 0;
        std::vector<std::string> problems;

        bool check(bool ok, std::string_view message);
        bool check(const Result<void>& result, std::string_view message);
    };

    [[nodiscard]] std::string hex(std::span<const uint8_t> bytes);
    [[nodiscard]] std::string sha1(std::span<const uint8_t> bytes);
    [[nodiscard]] std::string sha1(std::string_view text);
    // tests/support/Sha256.hpp: GxCrypt's ExCryptSha256 does not link.
    [[nodiscard]] std::string sha256(std::span<const uint8_t> bytes);
    [[nodiscard]] std::string hex32(uint64_t value);
    // Printable ASCII as is, everything else (and the backslash) as \xNN.
    [[nodiscard]] std::string escaped(std::string_view text);

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

    [[nodiscard]] std::string_view build_type_name(BuildType type);
    [[nodiscard]] std::string_view driver_mode_name(nand::Driver::DriverMode mode);

    template <class T> const T* opt_ptr(const std::optional<T>& value) {
        return value ? &*value : nullptr;
    }

    [[nodiscard]] std::string describe_error(const Error& error);

    template <class T> std::string outcome(const Result<T>& result) {
        return result ? "ok" : "error " + describe_error(result.error());
    }

    [[nodiscard]] std::optional<Bytes> read_file(const std::filesystem::path& path);

    // ---- Parse-side snapshot (FlashImageRender.cpp) ------------------------------------------

    [[nodiscard]] std::string render_image(const nand::FlashImage& img, std::string_view p);

    // checks != nullptr: count a payload_layout() failure as a problem (the donor golden); the
    // snapshot tool passes nullptr and only records it.
    [[nodiscard]] std::string render_layout(const nand::FlashImage& img, RenderChecks* checks);

    // FlashImage::read and parse of the donor; a failure is a problem and yields nullopt.
    [[nodiscard]] std::optional<nand::FlashImage> parsed_image(const Bytes& bytes,
                                                               RenderChecks& checks);

    // extract_all_info()'s summary of `bytes` under the public CPU key. With checks a failure
    // is a problem (the donor golden); the snapshot tool passes nullptr and only records it.
    std::optional<AllNandInfo> render_info_summary(Snapshot& s, const Bytes& bytes,
                                                   RenderChecks* checks);

    // render_info_summary plus the cross-check against xeBuild's own image.info.
    [[nodiscard]] std::string render_info(const Bytes& bytes, std::string_view image_info,
                                          RenderChecks& checks);

    // ---- Write-side pieces and the oracle snapshot (FlashImageRenderWrite.cpp) ---------------

    // Every nonce encrypt_all would otherwise draw from ExCryptRandom (SC, CD, CE, CG and the
    // JTAG second CD), named when it is zero.
    [[nodiscard]] std::optional<std::string> zero_random_nonce(const nand::FlashImage& f);

    [[nodiscard]] std::string stage_flags(const nand::FlashImage& f);

    template <class Stage>
    void render_serialized(Snapshot& s, std::string_view p, std::string_view name,
                           const Stage* stage) {
        if (stage == nullptr) {
            return;
        }
        const auto bytes = stage->serialize();
        s.line(p, "stage." + std::string{name}, hex32(bytes.size()) + " sha1:" + sha1(bytes));
    }

    void render_layout_queries(Snapshot& s, std::string_view p, const nand::FlashImage& f);
    void render_fs_entries(Snapshot& s, std::string_view p, const nand::FlashImage& f);

    // Records write(): size, SHA-256 and the 0x80 header bytes as laid, or the failure.
    std::optional<Bytes> render_write(Snapshot& s, std::string_view p, nand::FlashImage& f);

    // The parse and round-trip summary of one image build_all.sh wrote, built from
    // mydata/image.bin under the same public CPU key. FlashImageTests.cmake runs the snapshot
    // tool over every image, concatenates the outputs under `== <image>` headers and compares
    // them with the tracked tests/golden/build_all.parse.txt. Failures along the way are
    // recorded as lines, never as test failures: the golden decides.
    [[nodiscard]] std::string render_snapshot(const Bytes& bytes);

} // namespace gxbuild3::test::render
