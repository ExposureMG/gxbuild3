// The resolver's whole BuildRequest for five resolves (ResolverDigestRender.hpp), against
// tests/golden/resolver_build_requests.txt. The old tests/BuildInputResolverTests.cpp
// test_resolution_digests and its digest_* cases, verbatim: the cases write into a ResolverTree
// rooted under the caller's scratch directory instead of a fresh directory under the temporary
// directory, and what the old file printed on stderr or aborted on is a problem now.

#include "ResolverDigestRender.hpp"

#include "cli/BuildInputResolver.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Keys.hpp"
#include "support/Scratch.hpp"
#include "support/XeRsaTestKey.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/render/ExtractProjection.hpp"
#include "utils/XeRsa.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots::resolver_build_requests {
    namespace {

        using Bytes = std::vector<uint8_t>;
        using cli::BuildArgs;
        using test::glitch2_donor_input;
        using test::valid_cpu_key;
        using test::valid_glitch_patchset;

        // One case's ResolverTree (tests/support/builders/ResolverTree.hpp) and the render's
        // problem list. A write that fails is a problem (the old fixture aborted the binary).
        class CaseTree {
          public:
            CaseTree(test::ResolverTree tree, std::vector<std::string>& problems)
                : tree_(std::move(tree)), problems_(problems) {}

            [[nodiscard]] const std::filesystem::path& root() const { return tree_.root(); }

            void write_text(std::string_view relative, std::string_view content) const {
                if (auto written = tree_.write_text(relative, content); !written) {
                    problem(written.error().describe());
                }
            }

            void write_binary(std::string_view relative, std::span<const uint8_t> content) const {
                if (auto written = tree_.write_binary(relative, content); !written) {
                    problem(written.error().describe());
                }
            }

            [[nodiscard]] BuildArgs minimum_args() const { return tree_.minimum_args(); }

            [[nodiscard]] std::expected<cli::BuildRequest, cli::ResolutionError>
            resolve(const BuildArgs& args) const {
                return tree_.resolve(args);
            }

            [[nodiscard]] Result<BuildArgs>
            complete_loose_args(BuildType build_type = BuildType::Retail,
                                ImageType image_type = ImageType::SmallBlock) const {
                return tree_.complete_loose_args(build_type, image_type);
            }

            void problem(std::string message) const { problems_.push_back(std::move(message)); }

          private:
            test::ResolverTree tree_;
            std::vector<std::string>& problems_;
        };

        bool require(bool condition, std::string message, const CaseTree& fixture) {
            if (!condition) {
                fixture.problem(std::move(message));
            }
            return condition;
        }

        // The old require_resolved: a resolution error's code, path, item and message (which
        // went to stderr) ride on the problem.
        bool require_resolved(const std::expected<cli::BuildRequest, cli::ResolutionError>& result,
                              const std::string& message, const CaseTree& fixture) {
            if (!result) {
                fixture.problem(std::format(
                    "{}: RESOLUTION ERROR: code={} path='{}' item='{}' message='{}'", message,
                    static_cast<int>(result.error().code), result.error().path.string(),
                    result.error().item, result.error().message));
                return false;
            }
            return true;
        }

        // A throwaway key whose file states the SB private key's CRC-32, so the resolver takes
        // it.
        Bytes sb_key_stand_in() {
            return test::xe_rsa::with_crc32(test::xe_rsa::shared_private_key(),
                                            utils::kSbPrivateKeyCrc32);
        }

        // A donor image built twice under the pinned build time with every donor nonce pinned;
        // a problem unless both builds succeed and are byte-identical.
        std::optional<Bytes> pinned_donor_image(Result<Input> input, std::string_view label,
                                                const CaseTree& fixture) {
            if (!input) {
                fixture.problem(
                    std::format("{}: DONOR INPUT ERROR: {}", label, input.error().describe()));
                return std::nullopt;
            }
            auto donor = test::pinned_donor_image(std::move(*input), label);
            if (!donor) {
                fixture.problem(
                    std::format("{}: DONOR BUILD ERROR: {}", label, donor.error().describe()));
                return std::nullopt;
            }
            return std::move(*donor);
        }

        // One BuildRequest as golden lines: the output path relative to the fixture root, then
        // every Input field through tests/support/render/ExtractProjection.hpp: options,
        // metadata scalars, the size and SHA-1 of every byte vector, FlashFS names in order,
        // patch file names, payloads, and only the size of an SB key.
        std::string render_request(const std::string& label, const CaseTree& fixture,
                                   const cli::BuildRequest& request) {
            return label + " output_path=" +
                   request.output_path.lexically_relative(fixture.root()).generic_string() + '\n' +
                   test::projection::render(label + ".input", request.input);
        }

        struct DigestCase {
            std::string text;
            bool stable = false;
        };

        // Resolves args twice; both requests must render identically.
        DigestCase digest_resolve(const std::string& label, const CaseTree& fixture,
                                  const BuildArgs& args) {
            const auto first = fixture.resolve(args);
            const auto second = fixture.resolve(args);
            if (!require_resolved(first, label + " resolves", fixture) ||
                !require_resolved(second, label + " resolves again", fixture)) {
                return DigestCase{label + " resolution-error\n", false};
            }
            const auto once = render_request(label, fixture, *first);
            const bool stable =
                require(once == render_request(label, fixture, *second),
                        label + " resolves to an identical BuildRequest twice", fixture);
            return DigestCase{stable ? once : label + " nondeterministic\n", stable};
        }

        // complete_loose_args, or a problem (the old fixture aborted the binary).
        std::optional<BuildArgs> loose_args(const std::string& label, const CaseTree& fixture,
                                            BuildType build_type = BuildType::Retail) {
            auto args = fixture.complete_loose_args(build_type);
            if (!args) {
                fixture.problem(
                    std::format("{}: complete_loose_args: {}", label, args.error().describe()));
                return std::nullopt;
            }
            return std::move(*args);
        }

        // donor.retail: a pinned synthetic donor (CB/CF LDVs, pairing, CF/CG) under a falcon
        // chain of loose CB and CD, a [flashfs] file, a mobile slot, options.ini and a CLI
        // override.
        DigestCase digest_donor_retail(const std::string& label, const CaseTree& fixture) {
            const auto key = valid_cpu_key();
            const auto donor = pinned_donor_image(
                test::donor_input_with_metadata(ImageType::SmallBlock, key), label, fixture);
            if (!donor) {
                return DigestCase{label + " donor-build-error\n", false};
            }
            fixture.write_binary("first/nanddump.bin", *donor);
            fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
            fixture.write_binary("first/cd.bin", Bytes{0xCD});
            fixture.write_binary("first/launch.ini", Bytes{0x41, 0x42});
            fixture.write_binary("first/mobileB.bin", Bytes{0xB2});
            fixture.write_text("working/build.ini",
                               "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\nlaunch.ini\n");
            fixture.write_text("working/options.ini", "nofcrt=true\ncbldv=3\n");
            auto args = fixture.minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.console = ConsoleType::Falcon;
            args.image_type.reset();
            args.config = {"cfldv=5", "nomobile=false"};
            return digest_resolve(label, fixture, args);
        }

        // loose.retail: no donor; kv.bin sealed, smc.bin, options.ini metadata, a sealed
        // secdata.bin in [security], a [flashfs] file and a mobile slot.
        DigestCase digest_loose_retail(const std::string& label, const CaseTree& fixture) {
            auto args = loose_args(label, fixture);
            if (!args) {
                return DigestCase{label + " fixture-error\n", false};
            }
            auto secdata = Bytes(0x20, 0x51);
            if (!nand::crypt_secfile(valid_cpu_key(), secdata)) {
                fixture.problem(label + ": secdata.bin seals under the CPU key");
                return DigestCase{label + " secdata-seal-error\n", false};
            }
            fixture.write_binary("first/secdata.bin", secdata);
            fixture.write_binary("first/launch.ini", Bytes{0x43});
            fixture.write_binary("first/mobileA.bin", Bytes{0xA1, 0xA2});
            fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\n"
                                                    "launch.ini\n[security]\nsecdata.bin\n");
            return digest_resolve(label, fixture, *args);
        }

        // loose.jtag: the falcon JTAG chain (second CB), [version] 17559,
        // patches_falcon_test.bin and xell-2f.bin; payloads carry XeLL, the embedded rebooter
        // and payload, and generated fuses.
        DigestCase digest_loose_jtag(const std::string& label, const CaseTree& fixture) {
            auto args = loose_args(label, fixture, BuildType::Jtag);
            if (!args) {
                return DigestCase{label + " fixture-error\n", false};
            }
            args->patch_extension = "test";
            fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());
            fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));
            return digest_resolve(label, fixture, *args);
        }

        // loose.devgl: the glitch2m patch file and the throwaway stand-in SB key
        // (XeRsaTestKey.hpp, made to state the SB key's CRC-32) found through the resolver's own
        // lookup in a keys folder. The real SB key is never read; the golden records only the
        // key's size.
        DigestCase digest_loose_devgl(const std::string& label, const CaseTree& fixture) {
            auto args = loose_args(label, fixture, BuildType::Devgl);
            if (!args) {
                return DigestCase{label + " fixture-error\n", false};
            }
            args->patch_extension = "test";
            fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
            fixture.write_binary("first/keys/SB_priv.bin", sb_key_stand_in());
            return digest_resolve(label, fixture, *args);
        }

        // donor-glitch2.retail: a retail resolve from the pinned glitch2 donor (see
        // cli.ResolverPayload.RetailFromHackedDonorKeepsDonorPayloadsAsToday).
        DigestCase digest_retail_from_glitch2_donor(const std::string& label,
                                                    const CaseTree& fixture) {
            const auto donor =
                pinned_donor_image(glitch2_donor_input(valid_cpu_key()), label, fixture);
            if (!donor) {
                return DigestCase{label + " donor-build-error\n", false};
            }
            fixture.write_binary("first/nanddump.bin", *donor);
            fixture.write_binary("first/cb_1.bin", Bytes{0xCB});
            fixture.write_binary("first/cd.bin", Bytes{0xCD});
            fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            auto args = fixture.minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.image_type.reset();
            return digest_resolve(label, fixture, args);
        }

    } // namespace

    Rendered render(const std::filesystem::path& scratch) {
        using Digest = DigestCase (*)(const std::string&, const CaseTree&);
        const std::array<std::pair<std::string_view, Digest>, 5> cases{{
            {"donor.retail", digest_donor_retail},
            {"loose.retail", digest_loose_retail},
            {"loose.jtag", digest_loose_jtag},
            {"loose.devgl", digest_loose_devgl},
            {"donor-glitch2.retail", digest_retail_from_glitch2_donor},
        }};
        Rendered out;
        out.cases = cases.size();
        for (const auto& [name, digest] : cases) {
            const std::string label{name};
            auto tree = test::ResolverTree::make(scratch / label);
            if (!tree) {
                out.problems.push_back(
                    std::format("{}: ResolverTree::make: {}", label, tree.error().describe()));
                out.text += label + " fixture-error\n";
                continue;
            }
            const CaseTree fixture{std::move(*tree), out.problems};
            const auto result = digest(label, fixture);
            out.text += result.text;
            out.stable += result.stable ? 1 : 0;
        }
        return out;
    }

    Result<std::string> render_file() {
        const test::ScratchDir scratch;
        Rendered rendered = render(scratch.path());
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the resolver_build_requests render reports {} problem(s), first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::resolver_build_requests
