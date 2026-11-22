#pragma once

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

    template <class... Args>
    [[nodiscard]] std::unexpected<Error> fail(ErrorCode code, std::format_string<Args...> format,
                                              Args&&... args) {
        return std::unexpected<Error>(std::in_place, code,
                                      std::format(format, std::forward<Args>(args)...));
    }

    template <class T> [[nodiscard]] Result<T> with_context(Result<T>&& result, std::string layer) {
        if (!result) {
            result.error().add_context(std::move(layer));
        }
        return std::move(result);
    }

    [[nodiscard]] inline std::unexpected<Error> from_error_code(const std::error_code& error,
                                                                const std::filesystem::path& path) {
        const auto code = error == std::errc::no_such_file_or_directory ? ErrorCode::NotFound
                                                                        : ErrorCode::IoError;
        return std::unexpected<Error>(std::in_place, code,
                                      std::format("{}: {}", path.string(), error.message()));
    }

} // namespace gxbuild3
