// src/Error.hpp: Error::describe and its context chain, fail(), with_context() on Result<T>
// and Result<>, from_error_code() and to_string() over every ErrorCode.

#include "Error.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <gtest/gtest.h>
#include <set>
#include <string_view>
#include <system_error>
#include <utility>

namespace gxbuild3::core {
    namespace {

        Result<int> parse_inner(bool ok) {
            if (!ok) {
                return fail(ErrorCode::Truncated, "need {} bytes, have {}", 16, 4);
            }
            return 7;
        }

        Result<int> parse_outer(bool ok) {
            return with_context(with_context(parse_inner(ok), "parsing CF at 0x8000"),
                                "building image");
        }

        TEST(ErrorResult, DescribeRendersMessageOrFallsBackToCodeName) {
            const Error error(ErrorCode::Malformed, "bad magic");
            const Error empty(ErrorCode::NotFound, "");
            EXPECT_EQ(error.describe(), "bad magic") << "describe renders the bare message";
            EXPECT_EQ(empty.describe(), "not found")
                << "describe falls back to the code name when the message is empty";
        }

        TEST(ErrorResult, ContextIsStoredInnermostFirstAndRenderedOutermostFirst) {
            Error error(ErrorCode::HashMismatch, "digest differs");
            error.add_context("inner").add_context("middle");
            const auto outer = Error(std::move(error)).add_context("outer");
            ASSERT_EQ(outer.context.size(), 3u) << "every layer is kept";
            EXPECT_EQ(outer.context.front(), "inner") << "context is stored innermost first";
            EXPECT_EQ(outer.describe(), "outer: middle: inner: digest differs")
                << "describe renders outer: inner: message";
        }

        TEST(ErrorResult, FailFormatsArgumentsAndStartsWithoutContext) {
            const auto result = parse_inner(false);
            ASSERT_FALSE(result.has_value()) << "fail produces an error";
            EXPECT_EQ(result.error().code, ErrorCode::Truncated) << "fail keeps the code";
            EXPECT_EQ(result.error().message, "need 16 bytes, have 4")
                << "fail formats its arguments";
            EXPECT_TRUE(result.error().context.empty()) << "fail starts without context";
        }

        TEST(ErrorResult, WithContextAddsLayersOutward) {
            const auto good = parse_outer(true);
            const auto bad = parse_outer(false);
            ASSERT_OK(good) << "success passes through with_context";
            EXPECT_EQ(*good, 7) << "success passes through with_context";
            ASSERT_FALSE(bad.has_value()) << "failure passes through with_context";
            EXPECT_EQ(bad.error().describe(),
                      "building image: parsing CF at 0x8000: need 16 bytes, have 4")
                << "with_context adds layers outward";
        }

        TEST(ErrorResult, VoidResultCarriesErrorsAndContext) {
            const Result<> ok{};
            const Result<> bad = fail(ErrorCode::Unsupported, "no");
            const auto wrapped = with_context(Result<>{bad}, "step");
            EXPECT_TRUE(ok.has_value()) << "Result<> defaults to success";
            EXPECT_ERROR(bad, ErrorCode::Unsupported) << "Result<> carries an error";
            ASSERT_FALSE(wrapped.has_value()) << "with_context works on Result<>";
            EXPECT_EQ(wrapped.error().describe(), "step: no") << "with_context works on Result<>";
        }

        TEST(ErrorResult, FromErrorCodeMapsEnoentToNotFoundOtherwiseIoError) {
            const auto missing = from_error_code(
                std::make_error_code(std::errc::no_such_file_or_directory), "data/nanddump.bin");
            const auto denied = from_error_code(std::make_error_code(std::errc::permission_denied),
                                                "data/nanddump.bin");
            EXPECT_EQ(missing.error().code, ErrorCode::NotFound)
                << "a missing file maps to NotFound";
            EXPECT_EQ(denied.error().code, ErrorCode::IoError)
                << "other filesystem errors map to IoError";
            EXPECT_TRUE(missing.error().message.starts_with("data/nanddump.bin: "))
                << "the path leads the message: " << missing.error().message;
        }

        TEST(ErrorResult, ToStringNamesEveryCodeDistinctly) {
            std::set<std::string_view> names;
            for (int value = 0; value <= static_cast<int>(ErrorCode::Internal); ++value) {
                const auto name = to_string(static_cast<ErrorCode>(value));
                ASSERT_FALSE(name.empty()) << "every code has a name (code " << value << ")";
                ASSERT_NE(name, "unknown error") << "every code has a name (code " << value << ")";
                names.insert(name);
            }
            EXPECT_EQ(names.size(), static_cast<size_t>(ErrorCode::Internal) + 1)
                << "every code name is distinct";
        }

    } // namespace
} // namespace gxbuild3::core
