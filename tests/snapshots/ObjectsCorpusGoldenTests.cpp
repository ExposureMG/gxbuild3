// tests/golden/objects_corpus.txt: the NAND-object codec snapshot over the tracked fixtures in
// tests/gxBuild-support-files, compared whole. The old ObjectsCorpusTests.cpp main() checks are
// the eight cases: the tracked fixtures load, the patch-file and add-on counts, two in-process
// renders agreeing, the XConfig region round trip, the xboxupd split, the image SMC and the golden
// match. They share one render per process (objects_corpus::tracked_render), so they run as one
// bundled entry, golden.ObjectsCorpusGolden; a fixture that cannot be listed or read fails every
// case. MatchesGolden records the old summary lines as the patchsets and objects properties.

#include "ObjectsCorpusRender.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"
#include "support/golden/GoldenSnapshot.hpp"

#include <algorithm>
#include <cstddef>
#include <format>
#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::snapshots {
    namespace {

        using objects_corpus::kExpectedAddons;
        using objects_corpus::kExpectedPatchFiles;
        using objects_corpus::kGolden;
        using objects_corpus::kPatchTypeCount;
        using objects_corpus::render_file;
        using objects_corpus::Rendered;

        GX_GOLDEN(kGolden, render_file);

        TEST(ObjectsCorpusGolden, TrackedFixturesLoad) {
            EXPECT_OK(objects_corpus::tracked_corpus())
                << "gxbuild3_objects_corpus_tests (tracked fixtures missing)";
        }

        TEST(ObjectsCorpusGolden, PatchFileCountIs25) {
            const auto& loaded = objects_corpus::tracked_corpus();
            ASSERT_OK(loaded);
            EXPECT_EQ(loaded->patches.size(), kExpectedPatchFiles)
                << "expected " << kExpectedPatchFiles << " tracked patches_*.bin, found "
                << loaded->patches.size();
        }

        TEST(ObjectsCorpusGolden, AddonCountIs14) {
            const auto& loaded = objects_corpus::tracked_corpus();
            ASSERT_OK(loaded);
            EXPECT_EQ(loaded->addons.size(), kExpectedAddons)
                << "expected " << kExpectedAddons << " tracked add-on .bin files, found "
                << loaded->addons.size();
        }

        TEST(ObjectsCorpusGolden, RenderIsDeterministic) {
            const auto& loaded = objects_corpus::tracked_corpus();
            ASSERT_OK(loaded);
            const auto& first = objects_corpus::tracked_render();
            ASSERT_OK(first);
            const Rendered second = objects_corpus::render(*loaded);
            const auto difference = test::golden_difference(first->text, second.text);
            EXPECT_FALSE(difference.has_value())
                << "two in-process renderings differ (nondeterministic)\n"
                << difference.value_or("");
        }

        TEST(ObjectsCorpusGolden, XconfigRoundTripsInsideItsRegion) {
            const auto& rendered = objects_corpus::tracked_render();
            ASSERT_OK(rendered);
            std::string problems;
            for (const auto& problem : rendered->problems) {
                problems += problem + '\n';
            }
            EXPECT_TRUE(rendered->problems.empty()) << problems;
        }

        TEST(ObjectsCorpusGolden, XboxupdFromSu20076000SplitsIntoCfAndCg) {
            const auto& rendered = objects_corpus::tracked_render();
            ASSERT_OK(rendered);
            EXPECT_TRUE(rendered->counters.xboxupd_split)
                << "xboxupd.bin from su20076000 splits into CF and CG";
        }

        TEST(ObjectsCorpusGolden, ImageBinYieldsAnSmc) {
            const auto& rendered = objects_corpus::tracked_render();
            ASSERT_OK(rendered);
            EXPECT_TRUE(rendered->counters.image_smc) << "mydata/image.bin yields an SMC";
        }

        TEST(ObjectsCorpusGolden, MatchesGolden) {
            const auto& loaded = objects_corpus::tracked_corpus();
            ASSERT_OK(loaded);
            const auto& rendered = objects_corpus::tracked_render();
            ASSERT_OK(rendered);
            const auto& n = rendered->counters;
            const std::string patchsets =
                std::format("patchsets {} files x {} build types: parsed {}/{}, add-ons {}",
                            loaded->patches.size(), kPatchTypeCount, n.patch_parses_ok,
                            n.patch_parses, loaded->addons.size());
            const std::string objects = std::format(
                "xell parsed {}/{}, secured files {}/5, xboxupd split {}/1, image smc {}/1, "
                "synthetic smc cases {}",
                n.xells_ok, loaded->xells.size(), n.secured_files, n.xboxupd_split ? 1 : 0,
                n.image_smc ? 1 : 0, n.smc_cases);
            RecordProperty("patchsets", patchsets);
            RecordProperty("objects", objects);
            const auto lines = static_cast<std::size_t>(std::ranges::count(rendered->text, '\n'));
            EXPECT_TRUE(test::matches_golden(kGolden, rendered->text))
                << kGolden << ".txt does not match HEAD output (" << lines << " snapshot lines; "
                << patchsets << "; " << objects << ")";
        }

    } // namespace
} // namespace gxbuild3::snapshots
