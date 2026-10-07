#pragma once

// Synthetic FlashImage cells, the fixtures of tests/golden/flashimage_matrix.txt and
// tests/golden/flashimage_failures.txt (tests/snapshots/FlashImageMatrixRender.cpp and
// FlashImageFailureRender.cpp). Moved verbatim from tests/FlashImageGoldenTests.cpp; both
// goldens depend on their bytes. No GoogleTest here.
//
// A cell is one driver shape (Small, Big, Emmc) times one build type, built the way run_build
// builds a fresh image but without a donor: the tracked plaintext stages the 17559 INIs name for
// Jasper, a synthetic SMC and sealed keyvault (pattern bytes, no console identity), the payloads
// the resolver adds for the type, a FlashFS with two files and mobile blobs x31/x32. Every stage
// nonce is pinned, since encrypt_all draws a random nonce for an SC/CD/CE/CG whose nonce is zero.
//
// The stages, patch files and XeLLs are read from a support directory, normally the tracked
// tests/gxBuild-support-files; GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT (kSupportOverride) points the
// goldens at a scratch copy for mutation checks. A fixture that cannot be read, or a fixture step
// that fails, is appended to a problems list (the old check() messages) instead of printing
// "FAIL: ..." on stderr; the caller reports each one as a test failure.

#include "Args.hpp"
#include "Error.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::test::flashimage_cells {

    using Bytes = std::vector<uint8_t>;
    using Nonce = std::array<uint8_t, 16>;
    // What went wrong while building, in order: the old check() messages.
    using Problems = std::vector<std::string>;

    inline constexpr const char* kSupportOverride = "GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT";

    // The FlashFS stamp every cell's filesystem carries.
    inline constexpr uint32_t kFsTimestamp = 0x5B2C3D4E;

    // Distinct, never-zero fixed nonces, one per stage tag.
    [[nodiscard]] Nonce pinned_nonce(uint8_t tag);

    // A tracked support file, read once per (support directory, relative path) and process. A
    // file that cannot be read, or is empty, appends "read tracked fixture <relative>" to
    // problems on every lookup and reads as empty bytes.
    [[nodiscard]] const Bytes& support_file(const std::filesystem::path& support,
                                            const std::string& relative, Problems& problems);

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

    [[nodiscard]] ChainSpec chain_for(BuildType type);

    // Parses support/relative as a Stage into target (a stage or an optional stage); the error
    // carries the relative path as its context.
    template <class Stage, class Target>
    [[nodiscard]] Result<void> load_stage(Target& target, const std::filesystem::path& support,
                                          const char* relative, Problems& problems) {
        auto parsed = Stage::parse(support_file(support, relative, problems));
        if (!parsed) {
            return std::unexpected(std::move(parsed.error()).add_context(relative));
        }
        target = std::move(*parsed);
        return {};
    }

    // A plaintext SMC of 0x3000 pattern bytes.
    [[nodiscard]] nand::Smc synthetic_smc();

    // The stage nonces run_build's apply_nonces sets on a plaintext chain, pinned.
    void pin_nonces(nand::FlashImage& f);

    // run_build's fresh FlashFS: deferred root, files from the first block past the update slots
    // and the payloads, the geometry tail and the payload blocks reserved; then two files.
    [[nodiscard]] Result<void> add_filesystem(nand::FlashImage& f, BuildType type);

    // The image size run_build gives a fresh image of this shape and type.
    [[nodiscard]] nand::Driver::ImageSize image_size_for(nand::Driver::DriverMode mode,
                                                         BuildType type);

    // Builds one cell into `f` in place: its filesystem points at f.flash_driver, so `f` is
    // never moved afterwards. with_update adds CF/CG 4532 to slot 0.
    [[nodiscard]] Result<void> build_cell(nand::FlashImage& f, const std::filesystem::path& support,
                                          nand::Driver::DriverMode mode, BuildType type,
                                          bool with_update, Problems& problems);

    // ---- Failure-table fixtures ------------------------------------------------------------

    // A sealed Small Retail cell, written; nullopt (and a problem) when it cannot be made.
    [[nodiscard]] std::optional<Bytes> sealed_retail_bytes(const std::filesystem::path& support,
                                                           Problems& problems);

    // Parses `bytes` after rewriting slot 0's CF continuation table through `edit`.
    [[nodiscard]] Result<void>
    parse_with_cf_table(const Bytes& bytes, const std::function<void(std::vector<uint8_t>&)>& edit);

    // A plaintext CF of `payload` zero bytes past its header.
    [[nodiscard]] nand::BootloaderCf oversized_cf(size_t payload);

    // A CG of 0x20 zero bytes past its header.
    [[nodiscard]] nand::BootloaderCg small_cg();

    // An image with only its driver shape and build type set.
    [[nodiscard]] std::unique_ptr<nand::FlashImage> bare(nand::Driver::DriverMode mode,
                                                         BuildType type);

} // namespace gxbuild3::test::flashimage_cells
