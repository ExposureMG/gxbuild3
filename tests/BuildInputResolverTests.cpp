#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "TestResult.hpp"
#include "cli/BuildInputResolver.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Bytes.hpp"
#include "support/Keys.hpp"
#include "support/XeRsaTestKey.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/render/ExtractProjection.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::cli::BuildArgs;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    bool require_resolved(
        const std::expected<gxbuild3::cli::BuildRequest, gxbuild3::cli::ResolutionError>& result,
        std::string_view message) {
        if (!result) {
            std::cerr << "RESOLUTION ERROR: code=" << static_cast<int>(result.error().code)
                      << " path='" << result.error().path.string() << "' item='"
                      << result.error().item << "' message='" << result.error().message << "'\n";
        }
        return require(result.has_value(), message);
    }

    // The shared builders (tests/support/builders/), byte for byte what this file defined.
    using gxbuild3::test::glitch2_donor_input;
    using gxbuild3::test::valid_glitch_patchset;

    // The resolver's test key as bytes: valid_cpu_key() (bits 0..52 ECC-encoded), pinned by
    // core.Keys.
    Bytes valid_cpu_key() {
        const auto key = gxbuild3::test::valid_cpu_key();
        return Bytes(key.begin(), key.end());
    }

    // The Result-returning builders, unwrapped as before: a failure aborts the binary with its
    // description. These go as their callers are ported.
    Input donor_input_with_metadata(ImageType type, std::span<const uint8_t> key) {
        return test::must(gxbuild3::test::donor_input_with_metadata(type, key));
    }

    // A donor image built twice under the pinned build time with every donor nonce pinned;
    // nullopt unless both builds succeed and are byte-identical.
    std::optional<Bytes> pinned_donor_image(Input input, std::string_view label) {
        auto donor = gxbuild3::test::pinned_donor_image(std::move(input), label);
        if (!donor) {
            std::cerr << "DONOR BUILD ERROR: " << donor.error().describe() << '\n';
            return std::nullopt;
        }
        return std::move(*donor);
    }

    // ResolverTree (tests/support/builders/ResolverTree.hpp) rooted at a fresh directory under
    // the temporary directory, removed again at scope end. A write that fails aborts the binary.
    struct ResolverFixture : gxbuild3::test::ResolverTree {
        ResolverFixture() : ResolverTree(test::must(ResolverTree::make(fresh_root()))) {}

        ~ResolverFixture() {
            std::error_code error;
            std::filesystem::remove_all(root(), error);
        }

        ResolverFixture(const ResolverFixture&) = delete;
        ResolverFixture& operator=(const ResolverFixture&) = delete;

        void write_text(std::string_view relative, std::string_view content) const {
            test::must(ResolverTree::write_text(relative, content));
        }

        void write_binary(std::string_view relative, std::span<const uint8_t> content) const {
            test::must(ResolverTree::write_binary(relative, content));
        }

        BuildArgs complete_loose_args(BuildType build_type = BuildType::Retail,
                                      ImageType image_type = ImageType::SmallBlock) const {
            return test::must(ResolverTree::complete_loose_args(build_type, image_type));
        }

      private:
        static std::filesystem::path fresh_root() {
            const auto unique =
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
            return std::filesystem::temp_directory_path() / ("gxbuild3-resolver-" + unique);
        }
    };

    // A throwaway key whose file states the SB private key's CRC-32, so the resolver takes it.
    Bytes sb_key_stand_in() {
        return gxbuild3::test::xe_rsa::with_crc32(gxbuild3::test::xe_rsa::shared_private_key(),
                                                  gxbuild3::utils::kSbPrivateKeyCrc32);
    }

    // One BuildRequest as golden lines: the output path relative to the fixture root (the root is
    // a fresh temporary directory), then every Input field through
    // tests/support/render/ExtractProjection.hpp: options, metadata scalars, the size and SHA-1 of
    // every byte vector, FlashFS names in order, patch file names, payloads, and only the size of
    // an SB key.
    std::string render_request(const std::string& label, const ResolverFixture& fixture,
                               const gxbuild3::cli::BuildRequest& request) {
        return label + " output_path=" +
               request.output_path.lexically_relative(fixture.root()).generic_string() + '\n' +
               gxbuild3::test::projection::render(label + ".input", request.input);
    }

    struct DigestCase {
        std::string text;
        bool stable = false;
    };

    // Resolves args twice; both requests must render identically.
    DigestCase digest_resolve(const std::string& label, const ResolverFixture& fixture,
                              const BuildArgs& args) {
        const auto first = fixture.resolve(args);
        const auto second = fixture.resolve(args);
        if (!require_resolved(first, label + " resolves") ||
            !require_resolved(second, label + " resolves again")) {
            return DigestCase{label + " resolution-error\n", false};
        }
        const auto once = render_request(label, fixture, *first);
        const bool stable = require(once == render_request(label, fixture, *second),
                                    label + " resolves to an identical BuildRequest twice");
        return DigestCase{stable ? once : label + " nondeterministic\n", stable};
    }

    // donor.retail: a pinned synthetic donor (CB/CF LDVs, pairing, CF/CG) under a falcon chain
    // of loose CB and CD, a [flashfs] file, a mobile slot, options.ini and a CLI override.
    DigestCase digest_donor_retail(const std::string& label) {
        ResolverFixture fixture;
        const auto key = valid_cpu_key();
        const auto donor =
            pinned_donor_image(donor_input_with_metadata(ImageType::SmallBlock, key), label);
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

    // loose.retail: no donor; kv.bin sealed, smc.bin, options.ini metadata, a sealed secdata.bin
    // in [security], a [flashfs] file and a mobile slot.
    DigestCase digest_loose_retail(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args();
        auto secdata = Bytes(0x20, 0x51);
        if (!gxbuild3::nand::crypt_secfile(valid_cpu_key(), secdata)) {
            return DigestCase{label + " secdata-seal-error\n", false};
        }
        fixture.write_binary("first/secdata.bin", secdata);
        fixture.write_binary("first/launch.ini", Bytes{0x43});
        fixture.write_binary("first/mobileA.bin", Bytes{0xA1, 0xA2});
        fixture.write_text("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n[flashfs]\n"
                                                "launch.ini\n[security]\nsecdata.bin\n");
        return digest_resolve(label, fixture, args);
    }

    // loose.jtag: the falcon JTAG chain (second CB), [version] 17559, patches_falcon_test.bin and
    // xell-2f.bin; payloads carry XeLL, the embedded rebooter and payload, and generated fuses.
    DigestCase digest_loose_jtag(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Jtag);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_falcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/xell-2f.bin", Bytes(0x40000, 0x5A));
        return digest_resolve(label, fixture, args);
    }

    // loose.devgl: the glitch2m patch file and the throwaway stand-in SB key (XeRsaTestKey.hpp,
    // made to state the SB key's CRC-32) found through the resolver's own lookup in a keys
    // folder. The real SB key is never read; the golden records only the key's size.
    DigestCase digest_loose_devgl(const std::string& label) {
        ResolverFixture fixture;
        auto args = fixture.complete_loose_args(BuildType::Devgl);
        args.patch_extension = "test";
        fixture.write_binary("first/bin/patches_g2mfalcon_test.bin", valid_glitch_patchset());
        fixture.write_binary("first/keys/SB_priv.bin", sb_key_stand_in());
        return digest_resolve(label, fixture, args);
    }

    // donor-glitch2.retail: a retail resolve from the pinned glitch2 donor (see
    // cli.ResolverPayload.RetailFromHackedDonorKeepsDonorPayloadsAsToday).
    DigestCase digest_retail_from_glitch2_donor(const std::string& label) {
        ResolverFixture fixture;
        const auto donor = pinned_donor_image(glitch2_donor_input(valid_cpu_key()), label);
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

    // The resolver's whole BuildRequest for a donor, a loose-donor, a JTAG, a devgl and a
    // retail-from-hacked-donor resolve, against tests/golden/resolver_build_requests.txt. Each
    // donor is built twice under a pinned time and nonces, and each case resolves twice; both
    // must be identical.
    bool test_resolution_digests(const gxbuild3::test::GoldenOptions& options) {
        using Digest = DigestCase (*)(const std::string&);
        const std::array<std::pair<std::string_view, Digest>, 5> cases{{
            {"donor.retail", digest_donor_retail},
            {"loose.retail", digest_loose_retail},
            {"loose.jtag", digest_loose_jtag},
            {"loose.devgl", digest_loose_devgl},
            {"donor-glitch2.retail", digest_retail_from_glitch2_donor},
        }};
        std::string rendered;
        size_t stable = 0;
        for (const auto& [label, digest] : cases) {
            const auto result = digest(std::string{label});
            rendered += result.text;
            stable += result.stable ? 1 : 0;
        }
        const bool matched =
            gxbuild3::test::check_golden(options, "resolver_build_requests", rendered);
        std::cout << "resolver BuildRequest digests: resolved twice and identical " << stable << '/'
                  << cases.size() << ", compared " << (matched ? stable : 0) << '/' << cases.size()
                  << " with tests/golden/resolver_build_requests.txt\n";
        return require(matched, "resolver BuildRequest digests match the golden") &&
               require(stable == cases.size(), "every resolver digest case is stable");
    }

} // namespace

int main(int argc, char** argv) {
    const auto options = gxbuild3::test::golden_options(argc, argv);
    if (!options) {
        return 2;
    }
    bool passed = true;
    passed = test_resolution_digests(*options) && passed;
    return passed ? 0 : 1;
}
