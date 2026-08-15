#pragma once

#include "Args.hpp"

#include <array>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace Ini {

    enum class ParseError {
        FileNotFound,
        ReadError,
        SectionNotFound,
        MalformedEntry,
    };

    constexpr std::string_view ParseErrorString(ParseError e) {
        switch (e) {
            case ParseError::FileNotFound:
                return "File not found";
            case ParseError::ReadError:
                return "Failed to read file";
            case ParseError::SectionNotFound:
                return "Section not found";
            case ParseError::MalformedEntry:
                return "Malformed entry";
        }
        return "Unknown";
    }

    struct Entry {
        std::string key;
        std::string value;
        std::string hash; // may be empty
        uint8_t chain{0};
    };

    using Section = std::vector<Entry>;

    struct Document {
        std::unordered_map<std::string, Section> sections;

        [[nodiscard]] const Section* get(std::string_view name) const;

        [[nodiscard]] std::expected<const Section*, ParseError>
        require(std::string_view name) const;
    };

    [[nodiscard]] std::expected<Document, ParseError> Parse(std::string_view content);
    [[nodiscard]] std::expected<Document, ParseError> ParseFile(const std::filesystem::path& path);

    enum class OptionsError {
        BadFormat,
    };

    constexpr std::string_view OptionsErrorString(OptionsError e) {
        switch (e) {
            case OptionsError::BadFormat:
                return "Incorrect formatting in options.ini";
        }
        return "Unknown";
    }

    void ApplyOption(OptionsArgs& options, std::string_view key, std::string_view value);

    [[nodiscard]] std::expected<OptionsArgs, OptionsError> ParseOptionsIni(std::string_view content);

    using OptionsResult = std::expected<OptionsArgs, std::variant<ParseError, OptionsError>>;
    [[nodiscard]] OptionsResult ParseOptionsIniFile(const std::filesystem::path& path);

} // namespace Ini
