// tests/golden/flashimage_golden.txt: the tracked donor mydata/image.bin parsed, written,
// decrypted, round-tripped and summarized (FlashImageDonorRender.cpp), compared whole. The old
// FlashImageGoldenTests.cpp main() read the donor and image.info (failing at once when either
// was missing), counted every check of the render and compared the text; that is the one case
// FlashImageDonorGolden.MatchesGolden: the inputs read, then one failure per problem the render
// reports (the old check() messages: write() after parse, decrypt_all, encrypt_all, the round
// trip's write() and the image.info cross-check among them), then the golden match.

#include "FlashImageGoldenRender.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"

#include <algorithm>
#include <cstddef>
#include <gtest/gtest.h>

namespace gxbuild3::snapshots {
    namespace {

        using flashimage_golden::kGolden;
        using flashimage_golden::render_file;

        GX_GOLDEN(kGolden, render_file);

        TEST(FlashImageDonorGolden, MatchesGolden) {
            ASSERT_OK_AND_ASSIGN(const auto inputs, flashimage_golden::load_inputs());
            const auto rendered = flashimage_golden::render(inputs);
            for (const auto& problem : rendered.problems) {
                ADD_FAILURE() << problem;
            }
            const auto lines = static_cast<std::size_t>(std::ranges::count(rendered.text, '\n'));
            EXPECT_TRUE(test::matches_golden(kGolden, rendered.text))
                << kGolden << ".txt does not match HEAD output (snapshot lines " << lines
                << ", render checks " << rendered.checks - rendered.problems.size() << '/'
                << rendered.checks << " passed)";
        }

    } // namespace
} // namespace gxbuild3::snapshots
