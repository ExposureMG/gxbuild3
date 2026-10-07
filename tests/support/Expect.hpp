#pragma once

// Result-aware gtest assertions for gxbuild3 tests.
//
//   EXPECT_OK(expr) / ASSERT_OK(expr)            the result holds a value (or void success)
//   ASSERT_OK_AND_ASSIGN(lhs, expr)              ASSERT_OK, then `lhs = std::move(*result)`;
//                                                a statement sequence, only in void bodies
//   EXPECT_ERROR(expr, code) / ASSERT_ERROR      the result failed with `code`
//   EXPECT_ERROR_MSG(expr, code, exact)          ... and its description equals `exact`
//   EXPECT_ERROR_HAS(expr, code, substring)      ... and its description contains `substring`
//   EXPECT_BYTES_EQ(a, b) / ASSERT_BYTES_EQ      byte equality reporting sizes and the first
//                                                differing offset, never the contents
//
// A result is anything with has_value() and error(): Result<T>, the public BuildResult,
// cli::ParseError and cli::ResolutionError results and utils::FileLookupResult. The description
// of an error is describe() when it has one (gxbuild3::Error and FileLookupError), else its
// message member.
//
// Table rows: declare GX_PRINT_ROW_AS_NAME(Row) next to the row struct and instantiate with
// test::RowName{}, so a row prints and lists as its name and never as raw bytes.

#include "Error.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <iterator>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace gxbuild3 {
    // Found by ADL: gtest prints an ErrorCode as its name and an Error as
    // "[<code>] <describe()>" instead of raw bytes.
    void PrintTo(ErrorCode code, std::ostream* os);
    void PrintTo(const Error& error, std::ostream* os);
} // namespace gxbuild3

namespace gxbuild3::test {

    using Bytes = std::vector<uint8_t>;

    template <class R>
    concept ResultLike = requires(const R& result) {
        { result.has_value() } -> std::convertible_to<bool>;
        result.error();
    };

    // describe() when the error type has one, else its message member.
    template <class E> [[nodiscard]] std::string describe_error(const E& error) {
        if constexpr (requires { error.describe(); }) {
            return error.describe();
        } else {
            return std::string{error.message};
        }
    }

    // The error code printed for a failure message: to_string for ErrorCode, gtest's own
    // printer (the enumerator's value) for the other code enums.
    template <class Code> [[nodiscard]] std::string code_text(const Code& code) {
        if constexpr (std::same_as<Code, ErrorCode>) {
            return std::string{to_string(code)};
        } else {
            return ::testing::PrintToString(code);
        }
    }

    namespace detail {
        template <ResultLike R>
        ::testing::AssertionResult is_ok(const char* expression, const R& result) {
            if (result.has_value()) {
                return ::testing::AssertionSuccess();
            }
            return ::testing::AssertionFailure()
                   << expression << " failed with [" << code_text(result.error().code) << "] "
                   << describe_error(result.error());
        }

        enum class MessageMatch : uint8_t {
            Any,
            Exact,
            Contains,
        };

        template <ResultLike R, class Code>
        ::testing::AssertionResult fails_with(const char* expression, const R& result,
                                              const Code& code, MessageMatch match,
                                              std::string_view text) {
            if (result.has_value()) {
                return ::testing::AssertionFailure()
                       << expression << " succeeded; expected a failure with [" << code_text(code)
                       << "]";
            }
            const auto& error = result.error();
            const std::string described = describe_error(error);
            const bool code_matches = error.code == code;
            const bool text_matches = match == MessageMatch::Any ||
                                      (match == MessageMatch::Exact && described == text) ||
                                      (match == MessageMatch::Contains && described.contains(text));
            if (code_matches && text_matches) {
                return ::testing::AssertionSuccess();
            }
            auto failure = ::testing::AssertionFailure();
            failure << expression << " failed with [" << code_text(error.code) << "] \""
                    << described << "\"; expected [" << code_text(code) << "]";
            if (match == MessageMatch::Exact) {
                failure << " \"" << text << "\"";
            } else if (match == MessageMatch::Contains) {
                failure << " containing \"" << text << "\"";
            }
            return failure;
        }

        ::testing::AssertionResult bytes_equal(const char* expected_expression,
                                               const char* actual_expression,
                                               std::span<const uint8_t> expected,
                                               std::span<const uint8_t> actual);

        // Any contiguous range of uint8_t or std::byte, viewed as uint8_t.
        template <class Range> std::span<const uint8_t> as_u8(const Range& range) {
            using Value = std::remove_cvref_t<decltype(*std::data(range))>;
            static_assert(std::same_as<Value, uint8_t> || std::same_as<Value, std::byte>,
                          "EXPECT_BYTES_EQ compares uint8_t or std::byte ranges");
            return {reinterpret_cast<const uint8_t*>(std::data(range)), std::size(range)};
        }

        template <class A, class B>
        ::testing::AssertionResult bytes_equal_format(const char* expected_expression,
                                                      const char* actual_expression,
                                                      const A& expected, const B& actual) {
            return bytes_equal(expected_expression, actual_expression, as_u8(expected),
                               as_u8(actual));
        }
    } // namespace detail

    // Name generator for INSTANTIATE_TEST_SUITE_P over rows that carry a `name` member.
    struct RowName {
        template <class Row>
        std::string operator()(const ::testing::TestParamInfo<Row>& info) const {
            return std::string{info.param.name};
        }
    };

} // namespace gxbuild3::test

#define GX_TEST_CONCAT_INNER_(a, b) a##b
#define GX_TEST_CONCAT_(a, b) GX_TEST_CONCAT_INNER_(a, b)

#define EXPECT_OK(expr) EXPECT_TRUE(::gxbuild3::test::detail::is_ok(#expr, (expr)))
#define ASSERT_OK(expr) ASSERT_TRUE(::gxbuild3::test::detail::is_ok(#expr, (expr)))

#define GX_ASSERT_OK_AND_ASSIGN_(holder, lhs, expr)                                                \
    auto holder = (expr);                                                                          \
    ASSERT_TRUE(::gxbuild3::test::detail::is_ok(#expr, holder));                                   \
    lhs = std::move(*holder)
#define ASSERT_OK_AND_ASSIGN(lhs, expr)                                                            \
    GX_ASSERT_OK_AND_ASSIGN_(GX_TEST_CONCAT_(gx_result_, __LINE__), lhs, expr)

#define GX_FAILS_WITH_(expr, code, match, text)                                                    \
    ::gxbuild3::test::detail::fails_with(#expr, (expr), (code),                                    \
                                         ::gxbuild3::test::detail::MessageMatch::match, (text))
#define EXPECT_ERROR(expr, code) EXPECT_TRUE(GX_FAILS_WITH_(expr, code, Any, ""))
#define ASSERT_ERROR(expr, code) ASSERT_TRUE(GX_FAILS_WITH_(expr, code, Any, ""))
#define EXPECT_ERROR_MSG(expr, code, exact) EXPECT_TRUE(GX_FAILS_WITH_(expr, code, Exact, exact))
#define ASSERT_ERROR_MSG(expr, code, exact) ASSERT_TRUE(GX_FAILS_WITH_(expr, code, Exact, exact))
#define EXPECT_ERROR_HAS(expr, code, substring)                                                    \
    EXPECT_TRUE(GX_FAILS_WITH_(expr, code, Contains, substring))
#define ASSERT_ERROR_HAS(expr, code, substring)                                                    \
    ASSERT_TRUE(GX_FAILS_WITH_(expr, code, Contains, substring))

#define EXPECT_BYTES_EQ(expected, actual)                                                          \
    EXPECT_PRED_FORMAT2(::gxbuild3::test::detail::bytes_equal_format, expected, actual)
#define ASSERT_BYTES_EQ(expected, actual)                                                          \
    ASSERT_PRED_FORMAT2(::gxbuild3::test::detail::bytes_equal_format, expected, actual)

// Prints a table row as its name only: without it gtest prints a row struct as raw bytes in
// failure output and as "N-byte object" in --gtest_list_tests, which leaks key material.
#define GX_PRINT_ROW_AS_NAME(Row)                                                                  \
    [[maybe_unused]] inline void PrintTo(const Row& row, std::ostream* os) {                       \
        *os << row.name;                                                                           \
    }
