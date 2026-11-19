#include "Expect.hpp"

#include <algorithm>
#include <format>

namespace gxbuild3 {

    void PrintTo(ErrorCode code, std::ostream* os) {
        *os << to_string(code);
    }

    void PrintTo(const Error& error, std::ostream* os) {
        *os << '[' << to_string(error.code) << "] " << error.describe();
    }

} // namespace gxbuild3

namespace gxbuild3::test::detail {

    ::testing::AssertionResult bytes_equal(const char* expected_expression,
                                           const char* actual_expression,
                                           std::span<const uint8_t> expected,
                                           std::span<const uint8_t> actual) {
        const auto mismatch = std::ranges::mismatch(expected, actual);
        const auto offset = static_cast<size_t>(mismatch.in1 - expected.begin());
        if (expected.size() == actual.size() && offset == expected.size()) {
            return ::testing::AssertionSuccess();
        }
        auto failure = ::testing::AssertionFailure();
        failure << expected_expression << " and " << actual_expression << " differ: "
                << std::format("0x{:X} bytes against 0x{:X} bytes", expected.size(), actual.size());
        if (offset < std::min(expected.size(), actual.size())) {
            failure << std::format(", first difference at offset 0x{:X}", offset);
        } else {
            failure << std::format(", equal over the first 0x{:X} bytes", offset);
        }
        return failure;
    }

} // namespace gxbuild3::test::detail
