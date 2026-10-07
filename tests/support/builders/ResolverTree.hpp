#pragma once

// The source tree the resolver tests resolve against, and the donors they put in it. Moved from
// tests/BuildInputResolverTests.cpp (ResolverFixture and its builders); the tree logic is rooted
// at a directory the caller owns and removes. tests/golden/resolver_build_requests.txt depends on
// the bytes and layout. Writing and building return a Result instead of aborting or failing
// silently. No GoogleTest here.
//
//   <root>/working   the resolver's working directory (build.ini, options.ini)
//   <root>/first     the first source root
//   <root>/second    the second source root

#include "Args.hpp"
#include "Error.hpp"
#include "cli/BuildArgs.hpp"
#include "cli/BuildInputResolver.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace gxbuild3::test {

    using Bytes = std::vector<uint8_t>;

    // xerunner test_build.py: a retail slim CB_B word, type 3 and allow bit 0.
    inline constexpr uint32_t kFuseCbWord = 0x03010001;

    // A 0x400-byte "CB" whose fuse word at 0x3B0 is `word` (big-endian).
    [[nodiscard]] Bytes cb_with_word(uint32_t word);

    class ResolverTree {
      public:
        // Creates <root>/working, <root>/first and <root>/second.
        [[nodiscard]] static Result<ResolverTree> make(std::filesystem::path root);

        [[nodiscard]] const std::filesystem::path& root() const { return root_; }
        [[nodiscard]] const std::filesystem::path& working_directory() const {
            return working_directory_;
        }

        // root / relative.
        [[nodiscard]] std::filesystem::path path(std::string_view relative) const;

        // Writes root / relative, creating its parent directories.
        [[nodiscard]] Result<> write_text(std::string_view relative,
                                          std::string_view content) const;
        [[nodiscard]] Result<> write_binary(std::string_view relative,
                                            std::span<const uint8_t> content) const;

        // The least a resolve needs: the first root, valid_cpu_key() as hex, a small-block
        // layout and result.bin as output.
        [[nodiscard]] cli::BuildArgs minimum_args() const;

        // minimum_args() plus a complete loose falcon donor in the first root: kv.bin sealed
        // under valid_cpu_key(), smc.bin, a CB and CD, the CB_B (glitch2m) or second CB (JTAG,
        // with [version] 17559) carrying kFuseCbWord, working/build.ini and an options.ini with
        // cbldv=2, cfldv=3 and pairing_data=010203.
        [[nodiscard]] Result<cli::BuildArgs>
        complete_loose_args(BuildType build_type = BuildType::Retail,
                            ImageType image_type = ImageType::SmallBlock) const;

        [[nodiscard]] std::expected<cli::BuildRequest, cli::ResolutionError>
        resolve(const cli::BuildArgs& args) const;
        [[nodiscard]] std::expected<cli::ResolvedFoundations, cli::ResolutionError>
        resolve_foundations(const cli::BuildArgs& args) const;

      private:
        explicit ResolverTree(std::filesystem::path root);

        std::filesystem::path root_;
        std::filesystem::path working_directory_;
    };

    // A donor image run_build makes of `type` under `key` (random nonces): make_smc(0x61), a
    // canonical keyvault of 0x72 bytes and valid_bootloaders().
    [[nodiscard]] Result<Bytes> donor_image(ImageType type, std::span<const uint8_t> key);

    // donor_image's input with metadata a donor carries: CB per-box LDV 7 and pairing A1 B2 C3,
    // a CF of LDV 8 and a CG in slot 0, cbldv 7, cfldv 8 and that pairing.
    [[nodiscard]] Result<Input> donor_input_with_metadata(ImageType type,
                                                          std::span<const uint8_t> key);

    // run_build of donor_input_with_metadata(type, key).
    [[nodiscard]] Result<Bytes> donor_image_with_metadata(ImageType type,
                                                          std::span<const uint8_t> key);

    // A 17,301,504-byte image (the small-block size with spare) of zeros with a CD magic and a
    // size byte where the CB belongs: a supported size that is not a NAND.
    [[nodiscard]] Bytes malformed_supported_size_nand();

    // A small-block glitch2 donor whose image carries a XeLL, so extract_all hands back
    // payloads: CB_A and CB_B, SC, CD, a patch file and an ELF-headed 0x40000-byte XeLL.
    [[nodiscard]] Input glitch2_donor_input(std::span<const uint8_t> key);

    // input built twice under the pinned build time (SOURCE_DATE_EPOCH=1791105724, TZ UTC0)
    // with every donor nonce pinned (pinned_donor_nonces()), so no nonce is drawn. An error,
    // labelled, unless both builds succeed and are byte-identical.
    [[nodiscard]] Result<Bytes> pinned_donor_image(Input input, std::string_view label);

} // namespace gxbuild3::test
