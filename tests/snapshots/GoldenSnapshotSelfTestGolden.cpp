// tests/golden/golden_snapshot_selftest.txt: the golden that pins the golden helpers themselves.
// Its text unwraps planted Results (the "must.*" lines, kept from the old must() self-test) and
// prints Error::describe() and every ErrorCode name. The header lines are emitted verbatim,
// including the old binary's name.

#include "support/golden/Golden.hpp"

#include "Error.hpp"
#include "support/Expect.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3::snapshots {
    namespace {

        constexpr std::string_view kGoldenName = "golden_snapshot_selftest";

        Result<int> planted(bool ok) {
            if (!ok) {
                return with_context(Result<int>{fail(ErrorCode::Malformed, "planted failure")},
                                    "inner");
            }
            return 42;
        }

        Result<std::unique_ptr<int>> planted_move_only() {
            return std::make_unique<int>(7);
        }

        Result<void> planted_void(bool ok) {
            if (!ok) {
                return fail(ErrorCode::Truncated, "planted void failure");
            }
            return {};
        }

        // The text pinned by the tracked golden. The planted successes are unwrapped on the way,
        // so a failed one fails the render instead of printing.
        Result<std::string> render_selftest_text() {
            auto value = planted(true);
            if (!value) {
                return std::unexpected(std::move(value.error()));
            }
            auto move_only = planted_move_only();
            if (!move_only) {
                return std::unexpected(std::move(move_only.error()));
            }
            if (auto done = planted_void(true); !done) {
                return std::unexpected(std::move(done.error()));
            }
            std::ostringstream out;
            out << "# GoldenSnapshot self-test golden.\n";
            out << "# Regenerate: gxbuild3_golden_snapshot_tests --update\n";
            out << "must.value: " << *value << '\n';
            out << "must.move_only: " << **move_only << '\n';
            out << "must.void: ok\n";
            out << "error.describe: " << with_context(planted(false), "outer").error().describe()
                << '\n';
            out << '\n';
            for (int code = 0; code <= static_cast<int>(ErrorCode::Internal); ++code) {
                out << "error_code[" << code << "]: " << to_string(static_cast<ErrorCode>(code))
                    << '\n';
            }
            return out.str();
        }

        GX_GOLDEN(kGoldenName, render_selftest_text);

        TEST(GoldenSnapshotSelfTest, RenderIsDeterministic) {
            ASSERT_OK_AND_ASSIGN(const std::string first, render_selftest_text());
            ASSERT_OK_AND_ASSIGN(const std::string second, render_selftest_text());
            EXPECT_EQ(first, second);
        }

        TEST(GoldenSnapshotSelfTest, MatchesGolden) {
            ASSERT_OK_AND_ASSIGN(const std::string text, render_selftest_text());
            EXPECT_TRUE(test::matches_golden(kGoldenName, text));
        }

    } // namespace
} // namespace gxbuild3::snapshots
