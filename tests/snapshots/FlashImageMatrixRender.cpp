// tests/golden/flashimage_matrix.txt: synthetic fresh layouts (tests/support/builders/
// FlashImageCells.hpp), one cell per driver shape (Small, Big, Emmc) and build type:
//   header_encode.*  the 0x80-byte header write_to_driver encodes for an all-zero nand_header
//                    on an otherwise empty image, per shape;
//   matrix.<shape>.<type>.plain.*   the cell without an update pair, written straight away
//                                   (stages plaintext);
//   matrix.<shape>.<type>.sealed.*  the cell with CF/CG 4532, whose CG is longer than any slot,
//                                   after encrypt_all under the public CPU key, then written and
//                                   parsed back;
//   matrix.cells     the cell count.
// render_cell and render_matrix are the old FlashImageGoldenTests.cpp ones, verbatim, header
// literal included; their check() calls append to the problems. The seal is skipped (and says
// so) if a stage nonce is still zero, since encrypt_all would draw a random one. The whole file
// is render_header_encode, render_cell over kModes x kTypes and render_trailer, in that order;
// the section tests (FlashImageMatrixGoldenTests.cpp) render the same pieces one at a time.

#include "FlashImageGoldenRender.hpp"
#include "nand/FlashImage.hpp"
#include "support/Env.hpp"
#include "support/Scratch.hpp"
#include "support/builders/FlashImageCells.hpp"
#include "support/render/FlashImageRender.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace gxbuild3::snapshots {

    std::filesystem::path flashimage_cells_support() {
        const auto support = test::support_dir(test::flashimage_cells::kSupportOverride);
        if (support != test::support_dir()) {
            std::cerr << "note: matrix fixtures overridden by GXBUILD3_FLASHIMAGE_GOLDEN_SUPPORT\n";
        }
        return support;
    }

    namespace flashimage_matrix {
        namespace {

            using nand::Driver;
            using nand::FlashImage;
            using test::flashimage_cells::build_cell;
            using test::flashimage_cells::image_size_for;
            using test::flashimage_cells::Problems;
            using test::render::build_type_name;
            using test::render::driver_mode_name;
            using test::render::hex32;
            using test::render::kCpuKey;
            using test::render::opt_ptr;
            using test::render::outcome;
            using test::render::render_fs_entries;
            using test::render::render_layout_queries;
            using test::render::render_serialized;
            using test::render::render_write;
            using test::render::sha1;
            using test::render::Snapshot;
            using test::render::stage_flags;
            using test::render::zero_random_nonce;

            void check(bool ok, const std::string& message, Problems& problems) {
                if (!ok) {
                    problems.push_back(message);
                }
            }

        } // namespace

        std::string render_cell(const std::filesystem::path& support, Driver::DriverMode mode,
                                BuildType type, Problems& problems) {
            const test::PinnedBuildTime pinned{"1791105724", "UTC"};
            std::ostringstream out;
            Snapshot s{out};
            const std::string base = "matrix." + std::string{driver_mode_name(mode)} + '.' +
                                     std::string{build_type_name(type)} + '.';

            // plain: no update pair, written unsealed.
            {
                const std::string p = base + "plain.";
                auto f = std::make_unique<FlashImage>();
                if (auto built = build_cell(*f, support, mode, type, false, problems); !built) {
                    check(false, p + "build", problems);
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
            if (auto built = build_cell(*f, support, mode, type, true, problems); !built) {
                check(false, p + "build", problems);
                s.line(p, "build", outcome(built));
                return out.str();
            }
            s.line(p, "stages", stage_flags(*f));
            if (const auto zero = zero_random_nonce(*f)) {
                check(false, p + "nonce pinned", problems);
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
                s.line(p, "reparse.driver_mode",
                       driver_mode_name(back->flash_driver.driver_mode()));
                // The parsed CG stops at its declared size; the sealed one carries the
                // 16-byte rounding, so the parsed bytes are compared as a prefix.
                if (back->system_update_0.cg && f->system_update_0.cg) {
                    const auto read_back = back->system_update_0.cg->serialize();
                    const auto sealed_cg = f->system_update_0.cg->serialize();
                    s.line(p, "reparse.cg0",
                           hex32(read_back.size()) + " of " + hex32(sealed_cg.size()) +
                               " prefix_match=" +
                               (read_back.size() <= sealed_cg.size() &&
                                        std::equal(read_back.begin(), read_back.end(),
                                                   sealed_cg.begin())
                                    ? "1"
                                    : "0"));
                } else {
                    s.line(p, "reparse.cg0", "absent");
                }
            }
            return out.str();
        }

        std::string render_header_encode() {
            const test::PinnedBuildTime pinned{"1791105724", "UTC"};
            std::ostringstream out;
            out << "# F0c synthetic fresh-layout matrix: see FlashImageGoldenTests.cpp.\n";
            // The 0x80-byte header write_to_driver encodes for an all-zero nand_header on an
            // otherwise empty image.
            for (const auto mode : kModes) {
                FlashImage zeroed{};
                zeroed.flash_driver = Driver(image_size_for(mode, BuildType::Retail), mode);
                Snapshot s{out};
                const std::string p = "header_encode." + std::string{driver_mode_name(mode)} + '.';
                (void) render_write(s, p, zeroed);
            }
            return out.str();
        }

        std::string render_trailer(std::size_t cells) {
            std::ostringstream out;
            out << "matrix.cells=" << cells << '\n';
            return out.str();
        }

        Rendered render(const std::filesystem::path& support) {
            const test::PinnedBuildTime pinned{"1791105724", "UTC"};
            Rendered rendered;
            std::ostringstream out;
            out << render_header_encode();
            size_t cells = 0;
            for (const auto mode : kModes) {
                for (const auto type : kTypes) {
                    out << render_cell(support, mode, type, rendered.problems);
                    ++cells;
                }
            }
            out << render_trailer(cells);
            rendered.text = out.str();
            rendered.cells = cells;
            return rendered;
        }

        Rendered render() {
            return render(flashimage_cells_support());
        }

        Result<std::string> render_file() {
            Rendered rendered = render();
            if (!rendered.problems.empty()) {
                return fail(ErrorCode::Internal,
                            "the flashimage_matrix render reports {} problem(s), first: {}",
                            rendered.problems.size(), rendered.problems.front());
            }
            return std::move(rendered.text);
        }

    } // namespace flashimage_matrix
} // namespace gxbuild3::snapshots
