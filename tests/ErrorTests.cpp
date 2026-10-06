#include "Error.hpp"

#include <iostream>
#include <set>
#include <string>
#include <string_view>
#include <system_error>

namespace {

    using gxbuild3::Error;
    using gxbuild3::ErrorCode;
    using gxbuild3::Result;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    Result<int> parse_inner(bool ok) {
        if (!ok) {
            return gxbuild3::fail(ErrorCode::Truncated, "need {} bytes, have {}", 16, 4);
        }
        return 7;
    }

    Result<int> parse_outer(bool ok) {
        return gxbuild3::with_context(
            gxbuild3::with_context(parse_inner(ok), "parsing CF at 0x8000"), "building image");
    }

    bool test_describe_without_context() {
        const Error error(ErrorCode::Malformed, "bad magic");
        const Error empty(ErrorCode::NotFound, "");
        return require(error.describe() == "bad magic", "describe renders the bare message") &&
               require(empty.describe() == "not found",
                       "describe falls back to the code name when the message is empty");
    }

    bool test_context_ordering() {
        Error error(ErrorCode::HashMismatch, "digest differs");
        error.add_context("inner").add_context("middle");
        const auto outer = Error(std::move(error)).add_context("outer");
        return require(outer.context.size() == 3, "every layer is kept") &&
               require(outer.context.front() == "inner", "context is stored innermost first") &&
               require(outer.describe() == "outer: middle: inner: digest differs",
                       "describe renders outer: inner: message");
    }

    bool test_fail_formats_the_message() {
        const auto result = parse_inner(false);
        return require(!result, "fail produces an error") &&
               require(result.error().code == ErrorCode::Truncated, "fail keeps the code") &&
               require(result.error().message == "need 16 bytes, have 4",
                       "fail formats its arguments") &&
               require(result.error().context.empty(), "fail starts without context");
    }

    bool test_with_context() {
        const auto good = parse_outer(true);
        const auto bad = parse_outer(false);
        return require(good.has_value() && *good == 7, "success passes through with_context") &&
               require(!bad, "failure passes through with_context") &&
               require(bad.error().describe() ==
                           "building image: parsing CF at 0x8000: need 16 bytes, have 4",
                       "with_context adds layers outward");
    }

    bool test_void_result() {
        const Result<> ok{};
        const Result<> bad = gxbuild3::fail(ErrorCode::Unsupported, "no");
        const auto wrapped = gxbuild3::with_context(Result<>{bad}, "step");
        return require(ok.has_value(), "Result<> defaults to success") &&
               require(!bad && bad.error().code == ErrorCode::Unsupported,
                       "Result<> carries an error") &&
               require(!wrapped && wrapped.error().describe() == "step: no",
                       "with_context works on Result<>");
    }

    bool test_from_error_code() {
        const auto missing = gxbuild3::from_error_code(
            std::make_error_code(std::errc::no_such_file_or_directory), "data/nanddump.bin");
        const auto denied = gxbuild3::from_error_code(
            std::make_error_code(std::errc::permission_denied), "data/nanddump.bin");
        return require(missing.error().code == ErrorCode::NotFound,
                       "a missing file maps to NotFound") &&
               require(denied.error().code == ErrorCode::IoError,
                       "other filesystem errors map to IoError") &&
               require(missing.error().message.starts_with("data/nanddump.bin: "),
                       "the path leads the message");
    }

    bool test_to_string_is_distinct() {
        std::set<std::string_view> names;
        for (int value = 0; value <= static_cast<int>(ErrorCode::Internal); ++value) {
            const auto name = gxbuild3::to_string(static_cast<ErrorCode>(value));
            if (!require(!name.empty() && name != "unknown error", "every code has a name")) {
                return false;
            }
            names.insert(name);
        }
        return require(names.size() == static_cast<size_t>(ErrorCode::Internal) + 1,
                       "every code name is distinct");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_describe_without_context() && passed;
    passed = test_context_ordering() && passed;
    passed = test_fail_formats_the_message() && passed;
    passed = test_with_context() && passed;
    passed = test_void_result() && passed;
    passed = test_from_error_code() && passed;
    passed = test_to_string_is_distinct() && passed;
    if (!passed) {
        return 1;
    }
    std::cout << "Error tests passed\n";
    return 0;
}
