// tests/golden/resolver_build_requests.txt: the resolver's whole BuildRequest for a donor, a
// loose-donor, a JTAG, a devgl and a retail-from-hacked-donor resolve (ResolverDigestRender.cpp),
// compared whole. The old tests/BuildInputResolverTests.cpp test_resolution_digests resolved the
// five cases twice each, compared the text with the golden, printed "resolver BuildRequest
// digests: resolved twice and identical N/5, compared N/5 with ..." and failed unless the golden
// matched and every case was stable. That is the one case ResolverDigestGolden.MatchesGolden: the
// five trees live in the test's ScratchDir, then one failure per problem, the golden match and
// the stability count, with the old summary line recorded as a property and repeated in the
// failure message.

#include "ResolverDigestRender.hpp"
#include "support/Scratch.hpp"
#include "support/golden/Golden.hpp"

#include <format>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::snapshots {
    namespace {

        using resolver_build_requests::kGolden;
        using resolver_build_requests::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(ResolverDigestGolden, MatchesGolden) {
            const test::ScratchDir scratch;
            const auto rendered = resolver_build_requests::render(scratch.path());
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto matched = test::matches_golden(kGolden, rendered.text);
            const std::string summary = std::format(
                "resolver BuildRequest digests: resolved twice and identical {}/{}, compared "
                "{}/{} with tests/golden/resolver_build_requests.txt",
                rendered.stable, rendered.cases, matched ? rendered.stable : 0, rendered.cases);
            RecordProperty("summary", summary);
            EXPECT_TRUE(matched) << "resolver BuildRequest digests match the golden (" << summary
                                 << ")";
            EXPECT_EQ(rendered.stable, rendered.cases)
                << "every resolver digest case is stable (" << summary << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
