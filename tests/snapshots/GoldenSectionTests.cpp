// Section slices of a golden (matches_golden_slice) and the partition check that every line is
// owned by exactly one section in table order (golden_is_partitioned), over a small golden
// written to a scratch golden directory.

#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "support/golden/Golden.hpp"

#include <array>
#include <gtest/gtest.h>
#include <string_view>

namespace gxbuild3::snapshots {
    namespace {

        bool contains(std::string_view text, std::string_view needle) {
            return text.find(needle) != std::string_view::npos;
        }

        constexpr std::string_view kGolden = "small.retail a\n"
                                             "small.glitch b\n"
                                             "big.retail c\n"
                                             "trailer x\n";

        constexpr std::array<std::string_view, 1> kSmall{"small."};
        constexpr std::array<std::string_view, 1> kBig{"big."};
        constexpr std::array<std::string_view, 1> kTrailer{"trailer "};
        constexpr std::array<std::string_view, 2> kGlitchAndTrailer{"trailer ", "small.glitch"};
        constexpr std::array<std::string_view, 1> kSmallRetail{"small.re"};
        constexpr std::array<std::string_view, 1> kNone{"none."};
        constexpr std::array<std::string_view, 1> kEmpty{""};

        constexpr test::Section kSmallSection{"small", kSmall};
        constexpr test::Section kBigSection{"big", kBig};
        constexpr test::Section kTrailerSection{"trailer", kTrailer};

        class GoldenSection : public test::ScratchTest {
          protected:
            void SetUp() override {
                ScratchTest::SetUp();
                write("sections.txt", kGolden);
            }
        };

        // ---- matches_golden_slice -------------------------------------------------------

        TEST_F(GoldenSection, SliceMatchesTheLinesOfItsPrefixes) {
            EXPECT_TRUE(test::matches_golden_slice(root(), "sections", kSmallSection,
                                                   "small.retail a\nsmall.glitch b\n"));
            EXPECT_TRUE(
                test::matches_golden_slice(root(), "sections", kBigSection, "big.retail c\n"));
        }

        TEST_F(GoldenSection, SliceWithSeveralPrefixesKeepsFileOrder) {
            EXPECT_TRUE(test::matches_golden_slice(root(), "sections",
                                                   {"glitch_trailer", kGlitchAndTrailer},
                                                   "small.glitch b\ntrailer x\n"));
        }

        TEST_F(GoldenSection, SliceOfACrlfGoldenMatches) {
            write("crlf.txt", std::string_view{"small.retail a\r\nbig.retail c\r\n"});
            EXPECT_TRUE(test::matches_golden_slice(root(), "crlf", kBigSection, "big.retail c\n"));
        }

        TEST_F(GoldenSection, SliceDifferenceNamesTheGoldenFileLine) {
            const auto result =
                test::matches_golden_slice(root(), "sections", kBigSection, "big.retail C\n");
            EXPECT_FALSE(result);
            const std::string_view message = result.message();
            EXPECT_TRUE(contains(message, "GOLDEN FAIL: sections section big differs")) << message;
            EXPECT_TRUE(contains(message, "  - big.retail c\n  + big.retail C\n")) << message;
            EXPECT_TRUE(contains(message, "slice line 1 is golden line 3")) << message;
        }

        TEST_F(GoldenSection, SliceWithAnExtraLineNamesWhereItFollows) {
            const auto result = test::matches_golden_slice(root(), "sections", kBigSection,
                                                           "big.retail c\nbig.extra d\n");
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "slice line 2 follows golden line 3"))
                << result.message();
        }

        TEST_F(GoldenSection, SliceThatOwnsNoLineFails) {
            const auto result = test::matches_golden_slice(root(), "sections", {"none", kNone}, "");
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "section none owns no line"))
                << result.message();
        }

        TEST_F(GoldenSection, SliceRefusesAnEmptyPrefix) {
            const auto result =
                test::matches_golden_slice(root(), "sections", {"all", kEmpty}, kGolden);
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "section all needs at least one prefix"))
                << result.message();
        }

        TEST_F(GoldenSection, SliceOfAMissingGoldenFails) {
            const auto result =
                test::matches_golden_slice(root(), "absent", kBigSection, "big.retail c\n");
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "absent: missing golden")) << result.message();
        }

        // ---- golden_is_partitioned ------------------------------------------------------

        TEST_F(GoldenSection, PartitionAcceptsEveryLineOwnedOnceInTableOrder) {
            const std::array sections{kSmallSection, kBigSection, kTrailerSection};
            EXPECT_TRUE(test::golden_is_partitioned(root(), "sections", sections));
        }

        TEST_F(GoldenSection, PartitionRejectsAnUnownedLine) {
            const std::array sections{kSmallSection, kBigSection};
            const auto result = test::golden_is_partitioned(root(), "sections", sections);
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "line 4 is owned by no section: trailer x"))
                << result.message();
        }

        TEST_F(GoldenSection, PartitionRejectsALineOwnedTwice) {
            const std::array sections{kSmallSection, test::Section{"retail", kSmallRetail},
                                      kBigSection, kTrailerSection};
            const auto result = test::golden_is_partitioned(root(), "sections", sections);
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "line 1 is owned by sections small and retail"))
                << result.message();
        }

        TEST_F(GoldenSection, PartitionRejectsSectionsOutOfTableOrder) {
            const std::array sections{kBigSection, kSmallSection, kTrailerSection};
            const auto result = test::golden_is_partitioned(root(), "sections", sections);
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(),
                                 "line 3 belongs to section big but follows section small"))
                << result.message();
        }

        TEST_F(GoldenSection, PartitionRejectsASectionThatOwnsNoLine) {
            const std::array sections{kSmallSection, kBigSection, kTrailerSection,
                                      test::Section{"none", kNone}};
            const auto result = test::golden_is_partitioned(root(), "sections", sections);
            EXPECT_FALSE(result);
            EXPECT_TRUE(contains(result.message(), "section none owns no line"))
                << result.message();
        }

    } // namespace
} // namespace gxbuild3::snapshots
