// Fails gxbuild3::test::must() (tests/TestResult.hpp) on purpose, so that
// tests/scripts/MustAbortTest.cmake can check it aborts with Error::describe() and the call
// site on stderr. Usage: gxbuild3_must_abort_demo --must-abort-demo [void]
// Retired together with TestResult.hpp once no test unwraps with must().

#include "Error.hpp"
#include "TestResult.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace gxbuild3::test {
    namespace {

        Result<int> planted(bool ok) {
            if (!ok) {
                return with_context(Result<int>{fail(ErrorCode::Malformed, "planted failure")},
                                    "inner");
            }
            return 42;
        }

        Result<void> planted_void(bool ok) {
            if (!ok) {
                return fail(ErrorCode::Truncated, "planted void failure");
            }
            return {};
        }

        [[noreturn]] void must_abort_demo(bool void_overload) {
            if (void_overload) {
                must(planted_void(false));
            } else {
                [[maybe_unused]] const int value = must(with_context(planted(false), "outer"));
            }
            std::cerr << "must() returned on a failed Result\n";
            std::exit(0);
        }

    } // namespace
} // namespace gxbuild3::test

int main(int argc, char** argv) {
    if (argc >= 2 && std::string_view{argv[1]} == "--must-abort-demo") {
        gxbuild3::test::must_abort_demo(argc >= 3 && std::string_view{argv[2]} == "void");
    }
    std::cerr << "usage: gxbuild3_must_abort_demo --must-abort-demo [void]\n";
    return 2;
}
