// Self-tests of tests/support/Expect.hpp. The fatal and non-fatal pins use gtest-spi's
// EXPECT_FATAL_FAILURE / EXPECT_NONFATAL_FAILURE on static helpers: no death test and no
// captured stream. They replace the abort checks of the retired MustAbortTest.cmake: a failed
// unwrap is fatal and carries Error::describe().

#include "Error.hpp"
#include "GxBuildTypes.hpp"
#include "support/Expect.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace gxbuild3::core {
    namespace {

        Result<int> planted(bool succeed) {
            if (succeed) {
                return 42;
            }
            return with_context(Result<int>{fail(ErrorCode::Truncated, "planted failure")},
                                "inner");
        }

        Result<> planted_void() {
            return fail(ErrorCode::Malformed, "planted void failure");
        }

        Result<std::unique_ptr<int>> planted_move_only() {
            return std::make_unique<int>(7);
        }

        GxBuild::BuildResult planted_build_failure() {
            return std::unexpected(
                GxBuild::BuildError{GxBuild::BuildErrorCode::InvalidKeyvault, "keyvault refused"});
        }

        void assert_ok_on_contexted_failure() {
            ASSERT_OK(with_context(planted(false), "outer"));
        }

        void assert_ok_on_void_failure() {
            ASSERT_OK(planted_void());
        }

        void assert_ok_and_assign_on_failure() {
            ASSERT_OK_AND_ASSIGN(const int value, planted(false));
            EXPECT_EQ(value, 42);
        }

        void expect_ok_on_contexted_failure() {
            EXPECT_OK(with_context(planted(false), "outer"));
        }

        void expect_error_with_wrong_code() {
            EXPECT_ERROR(planted(false), ErrorCode::Malformed);
        }

        void expect_error_on_success() {
            EXPECT_ERROR(planted(true), ErrorCode::Truncated);
        }

        void expect_error_msg_with_a_substring_only() {
            EXPECT_ERROR_MSG(planted(false), ErrorCode::Truncated, "planted failure");
        }

        void expect_error_has_with_a_missing_substring() {
            EXPECT_ERROR_HAS(planted(false), ErrorCode::Truncated, "absent words");
        }

        void expect_build_error_with_wrong_message() {
            EXPECT_ERROR_MSG(planted_build_failure(), GxBuild::BuildErrorCode::InvalidKeyvault,
                             "keyvault accepted");
        }

        constexpr std::array<uint8_t, 4> kExpectedBytes{0xDE, 0xAD, 0xBE, 0xEF};
        constexpr std::array<uint8_t, 4> kDifferentBytes{0xDE, 0xAD, 0x00, 0xEF};
        constexpr std::array<uint8_t, 2> kPrefixBytes{0xDE, 0xAD};

        void expect_bytes_eq_on_different_bytes() {
            EXPECT_BYTES_EQ(kExpectedBytes, kDifferentBytes);
        }

        void assert_bytes_eq_on_a_prefix() {
            ASSERT_BYTES_EQ(kExpectedBytes, kPrefixBytes);
        }

        struct NamedRow {
            const char* name;
            int value;
        };
        GX_PRINT_ROW_AS_NAME(NamedRow)

        TEST(SupportExpect, AssertOkFailureIsFatalAndCarriesDescribe) {
            EXPECT_FATAL_FAILURE(assert_ok_on_contexted_failure(), "outer: inner: planted failure");
            EXPECT_FATAL_FAILURE(assert_ok_on_contexted_failure(), "[truncated]");
        }

        TEST(SupportExpect, AssertOkVoidFailureIsFatal) {
            EXPECT_FATAL_FAILURE(assert_ok_on_void_failure(), "planted void failure");
            ASSERT_OK(Result<>{});
        }

        TEST(SupportExpect, AssertOkAndAssignUnwrapsValue) {
            ASSERT_OK_AND_ASSIGN(const int value, planted(true));
            EXPECT_EQ(value, 42);
            EXPECT_FATAL_FAILURE(assert_ok_and_assign_on_failure(), "inner: planted failure");
        }

        TEST(SupportExpect, AssertOkAndAssignUnwrapsMoveOnly) {
            ASSERT_OK_AND_ASSIGN(const auto pointer, planted_move_only());
            ASSERT_NE(pointer, nullptr);
            EXPECT_EQ(*pointer, 7);
        }

        TEST(SupportExpect, ExpectOkFailureIsNonFatalAndCarriesDescribe) {
            EXPECT_OK(planted(true));
            EXPECT_NONFATAL_FAILURE(expect_ok_on_contexted_failure(),
                                    "outer: inner: planted failure");
        }

        TEST(SupportExpect, ExpectErrorChecksTheCodeAndRejectsSuccess) {
            EXPECT_ERROR(planted(false), ErrorCode::Truncated);
            ASSERT_ERROR(planted_void(), ErrorCode::Malformed);
            EXPECT_NONFATAL_FAILURE(expect_error_with_wrong_code(),
                                    "failed with [truncated] \"inner: planted failure\"; "
                                    "expected [malformed]");
            EXPECT_NONFATAL_FAILURE(expect_error_on_success(),
                                    "succeeded; expected a failure with [truncated]");
        }

        TEST(SupportExpect, ExpectErrorMsgComparesTheDescriptionExactly) {
            EXPECT_ERROR_MSG(planted(false), ErrorCode::Truncated, "inner: planted failure");
            EXPECT_NONFATAL_FAILURE(expect_error_msg_with_a_substring_only(),
                                    "expected [truncated] \"planted failure\"");
            EXPECT_ERROR_MSG(planted_build_failure(), GxBuild::BuildErrorCode::InvalidKeyvault,
                             "keyvault refused");
            EXPECT_NONFATAL_FAILURE(expect_build_error_with_wrong_message(),
                                    "\"keyvault refused\"");
        }

        TEST(SupportExpect, ExpectErrorHasMatchesASubstring) {
            EXPECT_ERROR_HAS(planted(false), ErrorCode::Truncated, "planted");
            EXPECT_ERROR_HAS(planted_build_failure(), GxBuild::BuildErrorCode::InvalidKeyvault,
                             "refused");
            EXPECT_NONFATAL_FAILURE(expect_error_has_with_a_missing_substring(),
                                    "containing \"absent words\"");
        }

        TEST(SupportExpect, BytesEqReportsSizesAndFirstOffsetOnly) {
            EXPECT_BYTES_EQ(kExpectedBytes, kExpectedBytes);
            const std::array<std::byte, 2> as_bytes{std::byte{0xDE}, std::byte{0xAD}};
            EXPECT_BYTES_EQ(kPrefixBytes, as_bytes);
            EXPECT_NONFATAL_FAILURE(expect_bytes_eq_on_different_bytes(),
                                    "0x4 bytes against 0x4 bytes, first difference at offset 0x2");
            EXPECT_FATAL_FAILURE(assert_bytes_eq_on_a_prefix(),
                                 "0x4 bytes against 0x2 bytes, equal over the first 0x2 bytes");

            const auto report =
                test::detail::bytes_equal("expected", "actual", kExpectedBytes, kDifferentBytes);
            ASSERT_FALSE(report);
            const std::string message = report.message();
            for (const char* content :
                 {"de", "DE", "ad", "AD", "be", "BE", "ef", "EF", "222", "173", "190", "239"}) {
                EXPECT_FALSE(message.contains(content)) << content << " in: " << message;
            }
        }

        TEST(SupportExpect, PrintToShowsNamesNeverBytes) {
            Error error{ErrorCode::Truncated, "planted failure"};
            error.add_context("inner").add_context("outer");
            EXPECT_EQ(::testing::PrintToString(error), "[truncated] outer: inner: planted failure");
            EXPECT_EQ(::testing::PrintToString(ErrorCode::HashMismatch), "hash mismatch");
            EXPECT_EQ(::testing::PrintToString(NamedRow{"NamedRow", 0x55}), "NamedRow");
            EXPECT_EQ(test::RowName{}(::testing::TestParamInfo<NamedRow>(NamedRow{"Row7", 7}, 0)),
                      "Row7");
        }

    } // namespace
} // namespace gxbuild3::core
