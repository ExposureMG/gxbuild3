// The golden compare core, support/golden/GoldenSnapshot.hpp: the difference report
// (golden_difference) and check_golden on a scratch copy of the selftest golden (missing,
// matching, perturbed, rewritten, CRLF and escaping names). Never touches tests/golden.

#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "support/golden/Golden.hpp"
#include "support/golden/GoldenSnapshot.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>

namespace gxbuild3::snapshots {
    namespace {

        bool contains(std::string_view text, std::string_view needle) {
            return text.find(needle) != std::string_view::npos;
        }

        // ---- golden_difference ----------------------------------------------------------

        TEST(GoldenDifference, IdenticalTextsHaveNone) {
            EXPECT_FALSE(test::golden_difference("a\nb\n", "a\nb\n").has_value());
        }

        TEST(GoldenDifference, ChangedLineNamesLineAndPrintsBothSides) {
            const auto diff = test::golden_difference("a\nb\nc\nd\n", "a\nb\nC\nd\n");
            ASSERT_TRUE(diff.has_value());
            EXPECT_TRUE(contains(*diff, "first difference at line 3")) << *diff;
            EXPECT_TRUE(contains(*diff, "  - c\n")) << *diff;
            EXPECT_TRUE(contains(*diff, "  + C\n")) << *diff;
            EXPECT_FALSE(contains(*diff, "- a")) << *diff;
            EXPECT_FALSE(contains(*diff, "- d")) << *diff;
        }

        TEST(GoldenDifference, CapsAtMaxLinesAndCountsTheRest) {
            std::string many_want;
            std::string many_have;
            for (int i = 0; i < 9; ++i) {
                many_want += "w" + std::to_string(i) + '\n';
                many_have += "h" + std::to_string(i) + '\n';
            }
            const auto truncated = test::golden_difference(many_want, many_have, 3);
            ASSERT_TRUE(truncated.has_value());
            EXPECT_TRUE(contains(*truncated, "- w2")) << *truncated;
            EXPECT_FALSE(contains(*truncated, "- w3")) << *truncated;
            EXPECT_TRUE(contains(*truncated, "... 6 more differing line(s)")) << *truncated;
        }

        TEST(GoldenDifference, ExtraActualLine) {
            const auto longer = test::golden_difference("a\n", "a\nextra\n");
            ASSERT_TRUE(longer.has_value());
            EXPECT_TRUE(contains(*longer, "line 2")) << *longer;
            EXPECT_TRUE(contains(*longer, "- <no line in golden>")) << *longer;
            EXPECT_TRUE(contains(*longer, "+ extra")) << *longer;
        }

        TEST(GoldenDifference, MissingActualLine) {
            const auto shorter = test::golden_difference("a\ngone\n", "a\n");
            ASSERT_TRUE(shorter.has_value());
            EXPECT_TRUE(contains(*shorter, "- gone")) << *shorter;
            EXPECT_TRUE(contains(*shorter, "+ <no line in actual>")) << *shorter;
        }

        TEST(GoldenDifference, TrailingNewlineOnlyIsExplained) {
            const auto newline = test::golden_difference("a\n", "a");
            ASSERT_TRUE(newline.has_value());
            EXPECT_TRUE(contains(*newline, "differ only in the trailing newline")) << *newline;
        }

        // ---- check_golden on a scratch copy ---------------------------------------------

        constexpr std::string_view kGoldenName = "golden_snapshot_selftest";

        class GoldenScratch : public test::ScratchTest {};

        std::string text_of(const std::filesystem::path& path) {
            const auto bytes = test::read_file(path);
            return bytes ? std::string(bytes->begin(), bytes->end()) : std::string{};
        }

        // One ordered scenario on one scratch file: each step mutates what the next one reads.
        TEST_F(GoldenScratch, CompareNeverWritesAndUpdateWrites) {
            const auto registry = test::registered_goldens();
            const auto* entry = test::find_golden(registry, kGoldenName);
            ASSERT_NE(entry, nullptr);
            ASSERT_OK_AND_ASSIGN(const std::string rendered, entry->render());

            const std::filesystem::path scratch = root();
            EXPECT_TRUE(std::filesystem::is_directory(scratch));
            const test::GoldenOptions compare{scratch, false};
            const auto golden = scratch / (std::string{kGoldenName} + ".txt");

            std::ostringstream missing_report;
            EXPECT_FALSE(test::check_golden(compare, kGoldenName, rendered, missing_report));
            EXPECT_TRUE(contains(missing_report.str(), "missing golden")) << missing_report.str();
            EXPECT_FALSE(std::filesystem::exists(golden));

            std::error_code error;
            std::filesystem::copy_file(
                test::default_golden_directory() / (std::string{kGoldenName} + ".txt"), golden,
                std::filesystem::copy_options::overwrite_existing, error);
            ASSERT_FALSE(error) << error.message();
            std::ostringstream clean_report;
            EXPECT_TRUE(test::check_golden(compare, kGoldenName, rendered, clean_report))
                << clean_report.str();

            // Perturb one line: "must.value: 42" -> "must.value: 43".
            std::string perturbed = text_of(golden);
            const auto at = perturbed.find("must.value: 42");
            ASSERT_NE(at, std::string::npos);
            perturbed[at + std::string_view{"must.value: 4"}.size()] = '3';
            write(golden.filename(), perturbed);

            std::ostringstream report;
            EXPECT_FALSE(test::check_golden(compare, kGoldenName, rendered, report));
            const auto text = report.str();
            EXPECT_TRUE(contains(text, "GOLDEN FAIL: golden_snapshot_selftest differs")) << text;
            EXPECT_TRUE(contains(text, "first difference at line 3")) << text;
            EXPECT_TRUE(contains(text, "  - must.value: 43\n")) << text;
            EXPECT_TRUE(contains(text, "  + must.value: 42\n")) << text;
            EXPECT_EQ(text_of(golden), perturbed);

            std::ostringstream update_report;
            EXPECT_TRUE(test::check_golden({scratch, true}, kGoldenName, rendered, update_report))
                << update_report.str();
            EXPECT_EQ(text_of(golden), rendered);
            EXPECT_TRUE(test::check_golden(compare, kGoldenName, rendered, update_report))
                << update_report.str();

            std::string crlf;
            for (const char c : rendered) {
                if (c == '\n') {
                    crlf += '\r';
                }
                crlf += c;
            }
            write(golden.filename(), crlf);
            EXPECT_TRUE(test::check_golden(compare, kGoldenName, rendered, update_report))
                << update_report.str();

            std::ostringstream name_report;
            EXPECT_FALSE(test::check_golden(compare, "../escape", rendered, name_report));
            EXPECT_TRUE(contains(name_report.str(), "invalid golden name")) << name_report.str();
        }

    } // namespace
} // namespace gxbuild3::snapshots
