// tests/golden/flashimage_failures.txt: ErrorCode and describe() of each reachable FlashImage
// exit, in the order the checks run today (the stage splits must keep both), one
// `fail.<case>=<outcome>` line each and the row count last. FailureTable and render_failures
// are the old FlashImageGoldenTests.cpp ones, verbatim, header literal included; the fixtures
// are tests/support/builders/FlashImageCells.hpp, and a fixture step that fails is a problem.

#include "FlashImageGoldenRender.hpp"
#include "nand/FlashImage.hpp"
#include "support/Env.hpp"
#include "support/builders/FlashImageCells.hpp"
#include "support/render/FlashImageRender.hpp"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace gxbuild3::snapshots::flashimage_failures {
    namespace {

        using nand::BootloaderCb;
        using nand::BootloaderCd;
        using nand::BootloaderCe;
        using nand::Driver;
        using nand::FlashImage;
        using nand::MobileData;
        using nand::NANDBootloaderMagic;
        using nand::ParsedPatchSet;
        using nand::PatchSectionTarget;
        using nand::PatchSetKind;
        using nand::XeLL;
        using test::flashimage_cells::bare;
        using test::flashimage_cells::build_cell;
        using test::flashimage_cells::Bytes;
        using test::flashimage_cells::load_stage;
        using test::flashimage_cells::oversized_cf;
        using test::flashimage_cells::parse_with_cf_table;
        using test::flashimage_cells::Problems;
        using test::flashimage_cells::sealed_retail_bytes;
        using test::flashimage_cells::small_cg;
        using test::flashimage_cells::support_file;
        using test::flashimage_cells::synthetic_smc;
        using test::render::describe_error;
        using test::render::driver_mode_name;
        using test::render::kCpuKey;

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

        // The old check(): a failed condition or Result appends its message (and describe())
        // to the problems.
        class Checks {
          public:
            explicit Checks(Problems& problems) : m_problems(problems) {}

            bool check(const Result<void>& result, std::string_view message) {
                if (!result) {
                    m_problems.push_back(std::string{message} + ": " + result.error().describe());
                }
                return result.has_value();
            }

          private:
            Problems& m_problems;
        };

        std::string render_failures(const std::filesystem::path& support, Problems& problems) {
            FailureTable t;
            Checks c{problems};

            // parse(), write_to_driver() and clear_bootloader_chain() on an image with no
            // blocks.
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
            if (const auto bytes = sealed_retail_bytes(support, problems)) {
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
                xell.data = support_file(support, "mydata/xell-gggggg.bin", problems);
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
                t.add("glitch3_without_cb_x.encrypt_all",
                      f->encrypt_all(kCpuKey, BuildType::Glitch3));
            }
            {
                auto f = bare(Driver::Small, BuildType::Devkit);
                c.check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, support,
                                                 "common/SB_10375.bin", problems),
                        "failure fixture loads");
                t.add("devkit_without_sc.encrypt_all", f->encrypt_all(kCpuKey, BuildType::Devkit));
            }
            {
                auto f = bare(Driver::Small, BuildType::Retail);
                c.check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, support,
                                                 "common/cba_6754.bin", problems),
                        "failure fixture loads");
                c.check(load_stage<BootloaderCb>(f->cb_section.cb_B, support, "common/cbb_6754.bin",
                                                 problems),
                        "failure fixture loads");
                t.add("split_chain_without_smc.encrypt_all", f->encrypt_all(kCpuKey));
            }
            {
                auto f = bare(Driver::Small, BuildType::Retail);
                f->smc = synthetic_smc();
                c.check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, support,
                                                 "common/cba_6754.bin", problems),
                        "failure fixture loads");
                c.check(load_stage<BootloaderCb>(f->cb_section.cb_B, support, "common/cbb_6754.bin",
                                                 problems),
                        "failure fixture loads");
                f->cb_section.cb_or_A.decrypted = false;
                f->cb_section.cb_or_A.derived_key.reset();
                t.add("cb_b_without_cb_a_key.encrypt_all", f->encrypt_all(kCpuKey));
            }
            {
                auto f = bare(Driver::Small, BuildType::Glitch);
                c.check(load_stage<BootloaderCb>(f->cb_section.cb_or_A, support,
                                                 "common/cb_6750.bin", problems),
                        "failure fixture loads");
                c.check(load_stage<BootloaderCd>(f->kernel_section.cd, support,
                                                 "common/cd_8453.bin", problems),
                        "failure fixture loads");
                f->kernel_section.cd.decrypted = true;
                f->cb_section.cb_or_A.decrypted = false;
                f->cb_section.cb_or_A.derived_key.reset();
                t.add("cd_without_parent_key.encrypt_all",
                      f->encrypt_all(kCpuKey, BuildType::Glitch));
            }
            {
                auto f = bare(Driver::Small, BuildType::Glitch);
                c.check(load_stage<BootloaderCe>(f->kernel_section.ce, support,
                                                 "common/ce_1888.bin", problems),
                        "failure fixture loads");
                f->kernel_section.ce->decrypted = true;
                t.add("ce_without_cd_key.encrypt_all", f->encrypt_all(kCpuKey, BuildType::Glitch));
            }
            {
                auto f = bare(Driver::Small, BuildType::Jtag);
                c.check(load_stage<BootloaderCd>(f->payloads.extra_cd, support,
                                                 "common/cd_8453.bin", problems),
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
                if (c.check(
                        build_cell(*f, support, Driver::Small, BuildType::Retail, true, problems),
                        "failure fixture: Small Retail cell builds")) {
                    f->filesystem.reset();
                    t.add("cg_tail_without_flashfs.encrypt_all",
                          f->encrypt_all(kCpuKey, BuildType::Retail));
                }
            }
            // An oversized CG that was never given its continuation clusters.
            {
                auto f = std::make_unique<FlashImage>();
                if (c.check(
                        build_cell(*f, support, Driver::Small, BuildType::Retail, true, problems),
                        "failure fixture: Small Retail cell builds")) {
                    t.add("cg_tail_unallocated.write", f->write());
                }
            }
            return "# F0c FlashImage failure table: code | describe().\n" + t.text();
        }

    } // namespace

    Rendered render(const std::filesystem::path& support) {
        const test::PinnedBuildTime pinned{"1791105724", "UTC"};
        Rendered rendered;
        rendered.text = render_failures(support, rendered.problems);
        return rendered;
    }

    Rendered render() {
        return render(flashimage_cells_support());
    }

    Result<std::string> render_file() {
        Rendered rendered = render();
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the flashimage_failures render reports {} problem(s), first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::flashimage_failures
