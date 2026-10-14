#pragma once

// Shared error vocabulary for gxbuild3.
//
// Policy:
//  - Every fallible library function returns Result<T> and is marked [[nodiscard]].
//  - std::optional means real absence (a lookup that found nothing), never failure.
//  - A function that returns an Error does not log it. The boundary that consumes the
//    Error (public entry points, the CLI resolver, main) logs or prints it once.
//  - As an Error travels up, callers add context with with_context() or add_context().
//    The domain (STFS, CF, KV, ...) lives in the context chain, not in the code.
//
// This header is std-only on purpose so any internal header can include it.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace gxbuild3 {

    enum class ErrorCode : uint8_t {
        InvalidArgument,
        Truncated,
        Malformed,
        Unsupported,
        NotFound,
        IoError,
        AuthFailed,
        HashMismatch,
        SignatureMismatch,
        OutOfRange,
        Exhausted,
        Internal,
    };

    [[nodiscard]] constexpr std::string_view to_string(ErrorCode code) noexcept {
        switch (code) {
            case ErrorCode::InvalidArgument:
                return "invalid argument";
            case ErrorCode::Truncated:
                return "truncated";
            case ErrorCode::Malformed:
                return "malformed";
            case ErrorCode::Unsupported:
                return "unsupported";
            case ErrorCode::NotFound:
                return "not found";
            case ErrorCode::IoError:
                return "I/O error";
            case ErrorCode::AuthFailed:
                return "authentication failed";
            case ErrorCode::HashMismatch:
                return "hash mismatch";
            case ErrorCode::SignatureMismatch:
                return "signature mismatch";
            case ErrorCode::OutOfRange:
                return "out of range";
            case ErrorCode::Exhausted:
                return "exhausted";
            case ErrorCode::Internal:
                return "internal error";
        }
        return "unknown error";
    }

    struct [[nodiscard]] Error {
        ErrorCode code = ErrorCode::Internal;
        std::string message;
        // Stored innermost first: each add_context() appends an outer layer.
        std::vector<std::string> context;

        Error() = default;
        Error(ErrorCode error_code, std::string error_message)
            : code(error_code), message(std::move(error_message)) {}

        Error& add_context(std::string layer) & {
            context.push_back(std::move(layer));
            return *this;
        }

        Error&& add_context(std::string layer) && {
            context.push_back(std::move(layer));
            return std::move(*this);
        }

        // Renders "outer: inner: message". An empty message falls back to the code name.
        [[nodiscard]] std::string describe() const {
            std::string text;
            for (auto it = context.rbegin(); it != context.rend(); ++it) {
                text += *it;
                text += ": ";
            }
            if (message.empty()) {
                text += to_string(code);
            } else {
                text += message;
            }
            return text;
        }
    };

    template <class T = void> using Result = std::expected<T, Error>;

    // Builds a failed Result: `return fail(ErrorCode::Truncated, "need {} bytes", n);`
    template <class... Args>
    [[nodiscard]] std::unexpected<Error> fail(ErrorCode code, std::format_string<Args...> format,
                                              Args&&... args) {
        return std::unexpected<Error>(std::in_place, code,
                                      std::format(format, std::forward<Args>(args)...));
    }

    // Adds a context layer on the error path; a successful Result passes through unchanged.
    template <class T> [[nodiscard]] Result<T> with_context(Result<T>&& result, std::string layer) {
        if (!result) {
            result.error().add_context(std::move(layer));
        }
        return std::move(result);
    }

    // Converts the error_code of a non-throwing <filesystem> overload into an Error.
    [[nodiscard]] inline std::unexpected<Error> from_error_code(const std::error_code& error,
                                                                const std::filesystem::path& path) {
        const auto code = error == std::errc::no_such_file_or_directory ? ErrorCode::NotFound
                                                                        : ErrorCode::IoError;
        return std::unexpected<Error>(std::in_place, code,
                                      std::format("{}: {}", path.string(), error.message()));
    }

} // namespace gxbuild3
