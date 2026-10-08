// Synthetic FlashImage cells (FlashImageCells.hpp), moved verbatim from
// tests/FlashImageGoldenTests.cpp: the same stages, patterns, nonces, FlashFS geometry and
// payloads, so tests/golden/flashimage_matrix.txt and flashimage_failures.txt keep their bytes.
// The support directory is a parameter in place of the old g_support, and the old check() calls
// append their messages to a Problems list.

#include "support/builders/FlashImageCells.hpp"

#include "nand/objects/Freeboot.hpp"
#include "support/Bytes.hpp"
#include "support/Keys.hpp"
#include "support/Scratch.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <utility>

namespace gxbuild3::test::flashimage_cells {

    using nand::BlockMapStatus;
    using nand::BootloaderCb;
    using nand::BootloaderCd;
    using nand::BootloaderCe;
    using nand::BootloaderCf;
    using nand::BootloaderCg;
    using nand::BootloaderSc;
    using nand::cf_header;
    using nand::cg_header;
    using nand::Driver;
    using nand::FlashFileSystem;
    using nand::FlashImage;
    using nand::freeboot_payload_for;
    using nand::freeboot_rebooter_for;
    using nand::key_1bl;
    using nand::Keyvault;
    using nand::MobileData;
    using nand::NANDBootloaderMagic;
    using nand::parse_patch_set;
    using nand::Smc;
    using nand::XeLL;

    namespace {

        Bytes pattern(size_t size, uint8_t seed) {
            return image_pattern(size, seed);
        }

        bool check(bool ok, std::string_view message, Problems& problems) {
            if (!ok) {
                problems.emplace_back(message);
            }
            return ok;
        }

        bool check(const Result<void>& result, std::string_view message, Problems& problems) {
            if (!result) {
                problems.push_back(std::string{message} + ": " + result.error().describe());
            }
            return result.has_value();
        }

    } // namespace

    Nonce pinned_nonce(uint8_t tag) {
        Nonce nonce{};
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<uint8_t>(tag + i * 0x11);
        }
        return nonce;
    }

    const Bytes& support_file(const std::filesystem::path& support, const std::string& relative,
                              Problems& problems) {
        static const Bytes empty;
        static std::map<std::pair<std::filesystem::path, std::string>, Result<Bytes>> cache;
        auto found = cache.find({support, relative});
        if (found == cache.end()) {
            found =
                cache.emplace(std::pair{support, relative}, read_file(support / relative)).first;
        }
        const Result<Bytes>& bytes = found->second;
        if (!check(bytes.has_value() && !bytes->empty(), "read tracked fixture " + relative,
                   problems)) {
            return empty;
        }
        return *bytes;
    }

    ChainSpec chain_for(BuildType type) {
        constexpr const char* ce = "common/ce_1888.bin";
        switch (type) {
            case BuildType::Retail:
                return {"common/cba_6754.bin",
                        nullptr,
                        "common/cbb_6754.bin",
                        nullptr,
                        "common/cd_6754.bin",
                        ce,
                        nullptr};
            case BuildType::Jtag:
                return {"common/cb_6723.bin",
                        nullptr,
                        nullptr,
                        nullptr,
                        "common/cd_6723.bin",
                        ce,
                        "17559/bin/patches_jasper.bin"};
            case BuildType::Glitch:
                return {
                    "common/cb_6750.bin",       nullptr, nullptr, nullptr, "common/cd_8453.bin", ce,
                    "17559/bin/patches_fat.bin"};
            case BuildType::Glitch2:
                return {"common/cba_6752.bin", nullptr, "common/cbb_6752.bin",           nullptr,
                        "common/cd_9452.bin",  ce,      "17559/bin/patches_g2jasper.bin"};
            case BuildType::Glitch2m:
                return {"common/cba_9188_mfg.bin",
                        nullptr,
                        "common/cbb_6752.bin",
                        nullptr,
                        "common/cd_9452.bin",
                        ce,
                        "17559/bin/patches_g2mjasper.bin"};
            case BuildType::Glitch3:
                return {"rgh3/cba_rgh3.bin",
                        "rgh3/cbx_rgh3.bin",
                        "rgh3/cbb_rgh3_jasper.bin",
                        nullptr,
                        "common/cd_9452.bin",
                        ce,
                        "17559/bin/patches_g2jasper.bin"};
            case BuildType::Devkit:
                return {"common/SB_10375.bin", nullptr, nullptr, "common/SC_17489.bin",
                        "common/SD_17489.bin", ce,      nullptr};
            case BuildType::Devgl:
                return {"common/SB_10375.bin",
                        nullptr,
                        nullptr,
                        "common/SC_17489.bin",
                        "common/cd_9452.bin",
                        ce,
                        "17559/bin/patches_g2mjasper.bin"};
        }
        return {};
    }

    Smc synthetic_smc() {
        Smc smc{};
        smc.encrypted = false;
        smc.data = pattern(0x3000, 0x5A);
        return smc;
    }

    void pin_nonces(FlashImage& f) {
        const auto set_cb = [](BootloaderCb& cb, const Nonce& nonce) {
            std::copy(nonce.begin(), nonce.end(), cb.data.begin());
            std::copy(nonce.begin(), nonce.end(), std::begin(cb.header.key));
        };
        auto& cb_a = f.cb_section.cb_or_A;
        if (cb_a.data.size() >= 0x10) {
            set_cb(cb_a, pinned_nonce(0x10));
        }
        if (!f.cb_section.cb_x && f.cb_section.cb_B && f.cb_section.cb_B->data.size() >= 0x10) {
            set_cb(*f.cb_section.cb_B, pinned_nonce(0x20));
        } else if (f.devkit_chain() && f.cb_section.sc) {
            const auto nonce = pinned_nonce(0x30);
            std::copy(nonce.begin(), nonce.end(), std::begin(f.cb_section.sc->header.key));
        }
        const auto cd_nonce = pinned_nonce(0x40);
        std::copy(cd_nonce.begin(), cd_nonce.end(), std::begin(f.kernel_section.cd.header.key));
        if (f.kernel_section.ce) {
            const auto nonce = pinned_nonce(0x50);
            std::copy(nonce.begin(), nonce.end(), std::begin(f.kernel_section.ce->header.key));
        }
        if (f.payloads.extra_cb && f.payloads.extra_cb->data.size() >= 0x10) {
            set_cb(*f.payloads.extra_cb, pinned_nonce(0x10));
        }
        if (f.payloads.extra_cd) {
            std::copy(cd_nonce.begin(), cd_nonce.end(),
                      std::begin(f.payloads.extra_cd->header.key));
        }
        for (auto* slot : {&f.system_update_0, &f.system_update_1}) {
            if (slot->cf) {
                const auto nonce = pinned_nonce(0x60);
                std::copy(nonce.begin(), nonce.end(), std::begin(slot->cf->header.fixpoint_nonce));
            }
            if (slot->cg) {
                const auto nonce = pinned_nonce(0x70);
                std::copy(nonce.begin(), nonce.end(), std::begin(slot->cg->header.key));
            }
        }
    }

    Result<void> add_filesystem(FlashImage& f, BuildType type) {
        FlashFileSystem fs{};
        fs.set_driver(&f.flash_driver);
        fs.set_larger_filesystem(type == BuildType::Devkit);
        fs.set_timestamp(kFsTimestamp);
        fs.set_big_system_blocks(type == BuildType::Retail
                                     ? static_cast<uint8_t>(f.update_slots_end() / 0x20000)
                                     : uint8_t{0x10});
        const size_t total_blocks = f.flash_driver.block_count();
        const size_t data_limit = f.flash_driver.data_block_limit();
        const size_t block_size = f.flash_driver.block_size_clean();
        size_t first_block = (f.update_slots_end() + block_size - 1) / block_size;
        for (const auto& range : f.active_payload_block_ranges()) {
            first_block = std::max(first_block, range.start_block + range.block_count);
        }
        if (auto formatted = fs.format(total_blocks, FlashFileSystem::kDeferRoot, 1,
                                       static_cast<uint32_t>(first_block));
            !formatted) {
            return with_context(std::move(formatted), "format");
        }
        if (data_limit < total_blocks) {
            const auto mode = f.flash_driver.driver_mode();
            const bool pool =
                mode == Driver::Big ||
                ((mode == Driver::Small || mode == Driver::NewSmall) && total_blocks <= 0x400);
            const size_t held =
                pool ? (mode == Driver::Big ? 0 : std::min<size_t>(4, total_blocks - data_limit))
                     : total_blocks - data_limit;
            if (held > 0) {
                if (auto reserved = fs.reserve_blocks(data_limit, held); !reserved) {
                    return with_context(std::move(reserved), "reserve tail");
                }
            }
            if (data_limit + held < total_blocks) {
                if (auto withheld =
                        fs.withhold_blocks(data_limit + held, total_blocks - data_limit - held,
                                           BlockMapStatus::Unnamed);
                    !withheld) {
                    return with_context(std::move(withheld), "withhold tail");
                }
            }
        }
        for (const auto& range : f.active_payload_block_ranges()) {
            if (auto reserved = fs.reserve_blocks(range.start_block, range.block_count);
                !reserved) {
                return with_context(std::move(reserved), "reserve payload blocks");
            }
        }
        f.filesystem = std::move(fs);
        f.filesystem->set_driver(&f.flash_driver);
        if (auto added = f.filesystem->add_file("gxb_alpha.bin", pattern(0x5123, 0x11)); !added) {
            return with_context(std::move(added), "add gxb_alpha.bin");
        }
        if (auto added = f.filesystem->add_file("gxb_beta.bin", pattern(0x1F0, 0x22)); !added) {
            return with_context(std::move(added), "add gxb_beta.bin");
        }
        return {};
    }

    Driver::ImageSize image_size_for(Driver::DriverMode mode, BuildType type) {
        switch (mode) {
            case Driver::Big:
                return Driver::Bigordevkit;
            case Driver::Emmc:
                return Driver::Emmcblock;
            case Driver::Small:
            case Driver::NewSmall:
                break;
        }
        // run_build: a small-block devkit image is 64 MB.
        return type == BuildType::Devkit ? Driver::Bigordevkit : Driver::Smallblock;
    }

    Result<void> build_cell(FlashImage& f, const std::filesystem::path& support,
                            Driver::DriverMode mode, BuildType type, bool with_update,
                            Problems& problems) {
        f.flash_driver = Driver(image_size_for(mode, type), mode);
        f.build_type = type;
        f.smc = synthetic_smc();
        // A stand-in for the console's sealed keyvault: opaque bytes, written as they are.
        Keyvault keyvault{};
        keyvault.encrypted = true;
        keyvault.raw_data = pattern(Keyvault::kSize, 0x4B);
        f.keyvault = std::move(keyvault);
        const auto spec = chain_for(type);
        if (auto loaded =
                load_stage<BootloaderCb>(f.cb_section.cb_or_A, support, spec.cb_a, problems);
            !loaded) {
            return loaded;
        }
        if (spec.cb_x) {
            if (auto loaded =
                    load_stage<BootloaderCb>(f.cb_section.cb_x, support, spec.cb_x, problems);
                !loaded) {
                return loaded;
            }
            // run_build: a Glitch3 CB_X is supplied plaintext and takes the RGH2to3 v1 fix.
            f.cb_section.cb_x->decrypted = true;
            f.cb_section.cb_x->populate_metadata();
            (void) f.cb_section.cb_x->patch_rgh3_v1_cb_x();
        }
        if (spec.cb_b) {
            if (auto loaded =
                    load_stage<BootloaderCb>(f.cb_section.cb_B, support, spec.cb_b, problems);
                !loaded) {
                return loaded;
            }
        }
        if (spec.sc) {
            if (auto loaded = load_stage<BootloaderSc>(f.cb_section.sc, support, spec.sc, problems);
                !loaded) {
                return loaded;
            }
        }
        if (auto loaded = load_stage<BootloaderCd>(f.kernel_section.cd, support, spec.cd, problems);
            !loaded) {
            return loaded;
        }
        if (auto loaded = load_stage<BootloaderCe>(f.kernel_section.ce, support, spec.ce, problems);
            !loaded) {
            return loaded;
        }
        if (with_update) {
            if (auto loaded = load_stage<BootloaderCf>(f.system_update_0.cf, support,
                                                       "common/cf_4532.bin", problems);
                !loaded) {
                return loaded;
            }
            if (auto loaded = load_stage<BootloaderCg>(f.system_update_0.cg, support,
                                                       "common/cg_4532.bin", problems);
                !loaded) {
                return loaded;
            }
        }
        // run_build: a devkit chain is supplied plaintext.
        if (f.devkit_chain()) {
            f.cb_section.cb_or_A.decrypted = true;
            f.cb_section.cb_or_A.populate_metadata();
            if (f.cb_section.sc) {
                f.cb_section.sc->decrypted = true;
            }
            f.kernel_section.cd.decrypted = true;
            if (f.kernel_section.ce) {
                f.kernel_section.ce->decrypted = true;
            }
        }

        if (spec.patches) {
            auto patches = parse_patch_set(support_file(support, spec.patches, problems), type);
            if (!patches) {
                return std::unexpected(std::move(patches.error()).add_context(spec.patches));
            }
            f.payloads.patchset = std::move(*patches);
        }
        // The payloads the resolver adds: XeLL for JTAG and the glitch family, the freeBOOT
        // core, its loader and the JTAG second chain for JTAG, fuses for JTAG, Glitch2m and
        // devgl.
        const bool jtag = type == BuildType::Jtag;
        const bool glitch_family = type == BuildType::Glitch || type == BuildType::Glitch2 ||
                                   type == BuildType::Glitch2m || type == BuildType::Glitch3;
        if (jtag || glitch_family) {
            auto xell = XeLL::parse(support_file(
                support, jtag ? "mydata/xell-2f.bin" : "mydata/xell-gggggg.bin", problems));
            if (!xell) {
                return std::unexpected(std::move(xell.error()).add_context("XeLL"));
            }
            f.payloads.xell = std::move(*xell);
        }
        if (jtag) {
            f.payloads.rebooter = freeboot_rebooter_for("17559");
            f.payloads.payload = freeboot_payload_for(f.payloads.rebooter->size());
            if (auto loaded = load_stage<BootloaderCb>(f.payloads.extra_cb, support,
                                                       "common/cb_6750.bin", problems);
                !loaded) {
                return loaded;
            }
            if (auto loaded = load_stage<BootloaderCd>(f.payloads.extra_cd, support,
                                                       "common/cd_8453.bin", problems);
                !loaded) {
                return loaded;
            }
        }
        if (jtag || type == BuildType::Glitch2m || type == BuildType::Devgl) {
            f.payloads.fuses = pattern(0x60, 0xF0);
        }

        pin_nonces(f);

        if (auto fs = add_filesystem(f, type); !fs) {
            return with_context(std::move(fs), "FlashFS");
        }
        f.mobile_data = MobileData{};
        f.mobile_data->x31 = pattern(0x1F0, 0x31);
        f.mobile_data->x32 = pattern(0x8C0, 0x32);
        return {};
    }

    std::optional<Bytes> sealed_retail_bytes(const std::filesystem::path& support,
                                             Problems& problems) {
        auto f = std::make_unique<FlashImage>();
        if (!check(build_cell(*f, support, Driver::Small, BuildType::Retail, true, problems),
                   "failure fixture: Small Retail cell builds", problems) ||
            !check(f->encrypt_all(kBuildAllCpuKey, BuildType::Retail),
                   "failure fixture: Small Retail cell seals", problems)) {
            return std::nullopt;
        }
        auto written = f->write();
        if (!check(written.has_value(), "failure fixture: Small Retail cell writes", problems)) {
            return std::nullopt;
        }
        return std::move(*written);
    }

    Result<void> parse_with_cf_table(const Bytes& bytes,
                                     const std::function<void(std::vector<uint8_t>&)>& edit) {
        auto img = FlashImage::read(bytes);
        if (!img || !img->parse() || !img->system_update_0.cf) {
            return fail(ErrorCode::Internal, "test fixture: the sealed cell does not parse");
        }
        auto cf = *img->system_update_0.cf;
        if (auto opened = cf.decrypt(key_1bl); !opened) {
            return opened;
        }
        edit(cf.data);
        if (auto sealed = cf.encrypt(key_1bl); !sealed) {
            return sealed;
        }
        if (!img->flash_driver.write_offset(img->header.cf_offset, cf.serialize())) {
            return fail(ErrorCode::Internal, "test fixture: the CF cannot be laid back");
        }
        auto damaged = FlashImage::read(img->flash_driver.serialize());
        if (!damaged) {
            return fail(ErrorCode::Internal, "test fixture: the damaged image is empty");
        }
        return damaged->parse();
    }

    BootloaderCf oversized_cf(size_t payload) {
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.data.assign(payload, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + payload);
        cf.decrypted = true;
        return cf;
    }

    BootloaderCg small_cg() {
        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.data.assign(0x20, 0);
        cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + 0x20);
        return cg;
    }

    std::unique_ptr<FlashImage> bare(Driver::DriverMode mode, BuildType type) {
        auto f = std::make_unique<FlashImage>();
        f->flash_driver = Driver(image_size_for(mode, type), mode);
        f->build_type = type;
        return f;
    }

} // namespace gxbuild3::test::flashimage_cells
