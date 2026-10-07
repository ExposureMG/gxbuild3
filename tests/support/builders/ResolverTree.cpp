#include "ResolverTree.hpp"

#include "BuildRunner.hpp"
#include "Inputs.hpp"
#include "Patchsets.hpp"
#include "Stages.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/Scratch.hpp"

#include <string>
#include <system_error>
#include <utility>

namespace gxbuild3::test {

    using nand::BootloaderCb;
    using nand::BootloaderCf;
    using nand::BootloaderCg;
    using nand::cb_header;
    using nand::cf_header;
    using nand::cg_header;
    using nand::generic_header;
    using nand::NANDBootloaderMagic;

    namespace {

        // A failed run_build as an Error, labelled.
        std::unexpected<Error> build_failed(std::string_view label, const BuildError& error) {
            return fail(ErrorCode::Internal, "{}: run_build failed ({}): {}", label,
                        static_cast<int>(error.code), error.message);
        }

    } // namespace

    Bytes cb_with_word(uint32_t word) {
        Bytes cb(0x400, 0x00);
        cb[0] = 0x43;
        cb[1] = 0x42;
        cb[0x3B0] = static_cast<uint8_t>(word >> 24);
        cb[0x3B1] = static_cast<uint8_t>(word >> 16);
        cb[0x3B2] = static_cast<uint8_t>(word >> 8);
        cb[0x3B3] = static_cast<uint8_t>(word);
        return cb;
    }

    ResolverTree::ResolverTree(std::filesystem::path root)
        : root_(std::move(root)), working_directory_(root_ / "working") {}

    Result<ResolverTree> ResolverTree::make(std::filesystem::path root) {
        ResolverTree tree{std::move(root)};
        for (const auto& directory :
             {tree.working_directory_, tree.root_ / "first", tree.root_ / "second"}) {
            std::error_code error;
            std::filesystem::create_directories(directory, error);
            if (error) {
                return from_error_code(error, directory);
            }
        }
        return tree;
    }

    std::filesystem::path ResolverTree::path(std::string_view relative) const {
        return root_ / std::filesystem::path(relative);
    }

    Result<> ResolverTree::write_text(std::string_view relative, std::string_view content) const {
        return write_file(
            path(relative),
            std::span{reinterpret_cast<const uint8_t*>(content.data()), content.size()});
    }

    Result<> ResolverTree::write_binary(std::string_view relative,
                                        std::span<const uint8_t> content) const {
        return write_file(path(relative), content);
    }

    cli::BuildArgs ResolverTree::minimum_args() const {
        cli::BuildArgs args{};
        args.source_dirs = {path("first")};
        args.cpu_key = hex(valid_cpu_key());
        args.image_type = ImageType::SmallBlock;
        args.output_path = "result.bin";
        return args;
    }

    Result<cli::BuildArgs> ResolverTree::complete_loose_args(BuildType build_type,
                                                             ImageType image_type) const {
        const auto key = valid_cpu_key();
        const auto write_all = [&]() -> Result<> {
            if (auto written = write_binary("first/kv.bin", encrypted_keyvault(key, 0x72));
                !written) {
                return written;
            }
            if (auto written = write_binary("first/smc.bin", make_smc(0x61)); !written) {
                return written;
            }
            if (auto written = write_binary("first/cb_1.bin", Bytes{0xCB, 0x01}); !written) {
                return written;
            }
            if (auto written = write_binary("first/cd.bin", Bytes{0xCD, 0x01}); !written) {
                return written;
            }
            // Virtual fuses read their CB's word at 0x3B0: CB_B for glitch2m, the second CB
            // for JTAG.
            std::string ini = build_type == BuildType::Jtag ? "[version]\n17559\n\n" : "";
            ini += "[falconbl]\ncb_1.bin\n";
            if (build_type == BuildType::Glitch2m) {
                if (auto written = write_binary("first/cbb_1.bin", cb_with_word(kFuseCbWord));
                    !written) {
                    return written;
                }
                ini += "cbb_1.bin\n";
            }
            ini += "cd.bin\n";
            if (build_type == BuildType::Jtag) {
                if (auto written = write_binary("first/cb_2.bin", cb_with_word(kFuseCbWord));
                    !written) {
                    return written;
                }
                ini += "cb_2.bin\n";
            }
            if (auto written = write_text("working/build.ini", ini); !written) {
                return written;
            }
            return write_text("working/options.ini", "cbldv=2\ncfldv=3\npairing_data=010203\n");
        };
        if (auto written = write_all(); !written) {
            return std::unexpected(std::move(written.error()).add_context("complete_loose_args"));
        }

        auto args = minimum_args();
        args.build_ini = "build.ini";
        args.section = "falcon";
        args.console = ConsoleType::Falcon;
        args.build_type = build_type;
        args.image_type = image_type;
        return args;
    }

    std::expected<cli::BuildRequest, cli::ResolutionError>
    ResolverTree::resolve(const cli::BuildArgs& args) const {
        return cli::BuildInputResolver(working_directory_).resolve(args);
    }

    std::expected<cli::ResolvedFoundations, cli::ResolutionError>
    ResolverTree::resolve_foundations(const cli::BuildArgs& args) const {
        return cli::BuildInputResolver(working_directory_).resolve_foundations(args);
    }

    Result<Bytes> donor_image(ImageType type, std::span<const uint8_t> key) {
        Input input{};
        input.image_type = type;
        input.metadata.cpu_key.assign(key.begin(), key.end());
        input.metadata.smc = make_smc(0x61);
        input.metadata.keyvault = canonical_keyvault_filled(key, 0x72);
        input.bootloaders = valid_bootloaders();
        auto built = run_build(input);
        if (!built) {
            return build_failed("donor_image", built.error());
        }
        return std::move(*built);
    }

    Result<Input> donor_input_with_metadata(ImageType type, std::span<const uint8_t> key) {
        Input input{};
        input.image_type = type;
        input.metadata.cpu_key.assign(key.begin(), key.end());
        input.metadata.smc = make_smc(0x61);
        input.metadata.keyvault = canonical_keyvault_filled(key, 0x72);
        input.bootloaders = valid_bootloaders();

        auto cb = with_context(BootloaderCb::parse(input.bootloaders.cb_or_a),
                               "donor_input_with_metadata");
        if (!cb) {
            return std::unexpected(std::move(cb.error()));
        }
        cb->data.resize(sizeof(cb_header) - sizeof(generic_header), 0);
        cb->header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb->data.size());
        if (auto parsed = with_context(cb->parse_perbox(), "donor_input_with_metadata: CB");
            !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }
        cb->perbox->lockdown_value = 7;
        cb->perbox->pairing_data[0] = 0xA1;
        cb->perbox->pairing_data[1] = 0xB2;
        cb->perbox->pairing_data[2] = 0xC3;
        if (auto serialized = with_context(cb->serialize_perbox(), "donor_input_with_metadata: CB");
            !serialized) {
            return std::unexpected(std::move(serialized.error()));
        }
        input.bootloaders.cb_or_a = cb->serialize();

        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.data.assign(0x340, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = true;
        if (auto parsed = with_context(cf.parse_perbox(), "donor_input_with_metadata: CF");
            !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }
        cf.perbox->lockdown_value = 8;
        if (auto serialized = with_context(cf.serialize_perbox(), "donor_input_with_metadata: CF");
            !serialized) {
            return std::unexpected(std::move(serialized.error()));
        }
        input.bootloaders.cf0 = cf.serialize();
        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.version = 1;
        cg.data.assign(0x40, 0);
        cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg.data.size());
        input.bootloaders.cg0 = cg.serialize();
        input.metadata.cb_ldv = 7;
        input.metadata.cf_ldv = 8;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};
        return input;
    }

    Result<Bytes> donor_image_with_metadata(ImageType type, std::span<const uint8_t> key) {
        auto input = donor_input_with_metadata(type, key);
        if (!input) {
            return std::unexpected(std::move(input.error()));
        }
        auto built = run_build(*input);
        if (!built) {
            return build_failed("donor_image_with_metadata", built.error());
        }
        return std::move(*built);
    }

    Bytes malformed_supported_size_nand() {
        Bytes nand(17'301'504, 0);
        constexpr size_t logical_bootloader_offset = 0x8000;
        constexpr size_t raw_bootloader_offset =
            (logical_bootloader_offset / 512) * 528 + logical_bootloader_offset % 512;
        nand[raw_bootloader_offset] = 0x43;
        nand[raw_bootloader_offset + 1] = 0x44;
        nand[raw_bootloader_offset + 15] = 0x10;
        return nand;
    }

    Input glitch2_donor_input(std::span<const uint8_t> key) {
        Input input{};
        input.image_type = ImageType::SmallBlock;
        input.build_type = BuildType::Glitch2;
        input.metadata.cpu_key.assign(key.begin(), key.end());
        input.metadata.smc = make_smc(0x65);
        input.metadata.keyvault = canonical_keyvault_filled(key, 0x66);
        input.bootloaders = valid_bootloaders();
        input.bootloaders.cb_b = input.bootloaders.cb_or_a;
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", valid_glitch_patchset(0xC5)};
        input.patches = std::move(patches);
        Bytes xell(0x40000, 0x00);
        xell[0] = 0x7F;
        xell[1] = 'E';
        xell[2] = 'L';
        xell[3] = 'F';
        xell[0x100] = 0x58;
        InputPayloads payloads{};
        payloads.xell = std::move(xell);
        input.payloads = std::move(payloads);
        return input;
    }

    Result<Bytes> pinned_donor_image(Input input, std::string_view label) {
        input.metadata.donor_nonces = pinned_donor_nonces();

        const PinnedBuildTime pinned{"1791105724", "UTC0"};
        auto first = run_build(input);
        auto second = run_build(input);
        if (!first) {
            return build_failed(label, first.error());
        }
        if (!second) {
            return build_failed(label, second.error());
        }
        if (*first != *second) {
            return fail(ErrorCode::HashMismatch, "{}: the two donor builds differ", label);
        }
        return std::move(*first);
    }

} // namespace gxbuild3::test
