#pragma once

// Interim unwrap helper for tests: must() hands back the value of a successful Result and, on
// failure, prints Error::describe() with the call site to stderr and aborts the test binary.
// An abort fails the test like any other crash. The later test-framework rewrite replaces this
// with the framework's own assertion.

#include "Error.hpp"

#include <cstdlib>
#include <iostream>
#include <source_location>
#include <utility>

namespace gxbuild3::test {

    namespace detail {
        [[noreturn]] inline void must_failed(const Error& error,
                                             const std::source_location& location) {
            std::cerr << "must() failed at " << location.file_name() << ':' << location.line()
                      << " in " << location.function_name() << ": " << error.describe()
                      << std::endl;
            std::abort();
        }
    } // namespace detail

    template <class T>
    [[nodiscard]] T must(Result<T>&& result,
                         std::source_location location = std::source_location::current()) {
        if (!result) {
            detail::must_failed(result.error(), location);
        }
        return std::move(*result);
    }

    inline void must(Result<void>&& result,
                     std::source_location location = std::source_location::current()) {
        if (!result) {
            detail::must_failed(result.error(), location);
        }
    }

} // namespace gxbuild3::test
