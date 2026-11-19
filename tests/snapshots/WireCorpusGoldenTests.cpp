// tests/golden/wire_corpus_bootloaders.txt: the wire-corpus snapshot over the tracked
// bootloader stage fixtures in tests/gxBuild-support-files/common, compared whole. The old
// WireCorpusTests.cpp main() checks are the three cases: the tracked fixture count, two
// in-process renders agreeing, and the golden match. The fixtures are read once per process on
// first use (wire_corpus::tracked_fixtures); a fixture directory that cannot be listed or a
// fixture that cannot be read fails every case.

#include "WireCorpusRender.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"
#include "support/golden/GoldenSnapshot.hpp"

#include <gtest/gtest.h>

namespace gxbuild3::snapshots {
    namespace {

        using wire_corpus::kExpectedFixtures;
        using wire_corpus::kGolden;
        using wire_corpus::render_file;
        using wire_corpus::Rendered;

        GX_GOLDEN(kGolden, render_file);

        TEST(WireCorpusGolden, TrackedFixtureCountIs145) {
            const auto& loaded = wire_corpus::tracked_fixtures();
            ASSERT_OK(loaded);
            const auto& fixtures = *loaded;
            EXPECT_EQ(fixtures.size(), kExpectedFixtures)
                << "expected " << kExpectedFixtures << " tracked stage fixtures in common/, found "
                << fixtures.size();
        }

        TEST(WireCorpusGolden, RenderIsDeterministic) {
            const auto& loaded = wire_corpus::tracked_fixtures();
            ASSERT_OK(loaded);
            const auto& fixtures = *loaded;
            const Rendered first = wire_corpus::render(fixtures);
            const Rendered second = wire_corpus::render(fixtures);
            const auto difference = test::golden_difference(first.text, second.text);
            EXPECT_FALSE(difference.has_value())
                << "two in-process renderings differ (nondeterministic seal)\n"
                << difference.value_or("");
        }

        TEST(WireCorpusGolden, MatchesGolden) {
            const auto& loaded = wire_corpus::tracked_fixtures();
            ASSERT_OK(loaded);
            const auto& fixtures = *loaded;
            const Rendered rendered = wire_corpus::render(fixtures);
            EXPECT_TRUE(test::matches_golden(kGolden, rendered.text))
                << kGolden << ".txt does not match HEAD output (fixtures " << rendered.fixtures
                << "/" << kExpectedFixtures << ", parsed " << rendered.parsed << "/"
                << rendered.fixtures << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
