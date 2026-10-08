#pragma once

// Renderer of tests/golden/resolver_build_requests.txt, moved from
// tests/BuildInputResolverTests.cpp (test_resolution_digests and its digest_* cases): the
// resolver's whole BuildRequest for
//   donor.retail          a pinned synthetic donor under a falcon chain of loose CB and CD, a
//                         [flashfs] file, a mobile slot, options.ini and a CLI override;
//   loose.retail          no donor: a sealed kv.bin, smc.bin, options.ini metadata, a sealed
//                         secdata.bin in [security], a [flashfs] file and a mobile slot;
//   loose.jtag            the falcon JTAG chain, patches_falcon_test.bin and xell-2f.bin;
//   loose.devgl           the glitch2m patch file and a throwaway stand-in SB key in a keys
//                         folder (the real SB key is never read; only its size is recorded);
//   donor-glitch2.retail  a retail resolve from the pinned glitch2 donor.
// Each donor is built twice under the pinned build time and nonces, and each case resolves
// twice; both must render identically. Every input is synthetic (tests/support/builders/), so
// it renders on a clean clone.
//
// Each case's ResolverTree is rooted at <scratch>/<label>, under a directory the caller owns
// (the test's ScratchDir), and its output path renders relative to that root, so the text does
// not depend on where the scratch directory is. The digest cases and render_request are the old
// ones, verbatim; their require() messages and the resolution, donor-build and fixture errors
// that went to stderr are returned as problems, which the golden test reports one failure each,
// and render_file (registered with GX_GOLDEN) refuses while a problem is reported.

#include "Error.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots::resolver_build_requests {

    inline constexpr std::string_view kGolden = "resolver_build_requests";

    struct Rendered {
        std::string text;
        // The old summary: resolved twice and identical `stable`/`cases`.
        std::size_t cases = 0;
        std::size_t stable = 0;
        std::vector<std::string> problems;
    };

    // The five cases, each in its own tree under scratch.
    [[nodiscard]] Rendered render(const std::filesystem::path& scratch);
    // render() under a fresh test::ScratchDir, registered with GX_GOLDEN; an error while the
    // render reports a problem.
    [[nodiscard]] Result<std::string> render_file();

} // namespace gxbuild3::snapshots::resolver_build_requests
