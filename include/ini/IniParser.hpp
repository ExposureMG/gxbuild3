#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Ini {

    enum class ParseError {
        FileNotFound,
        ReadError,
        MalformedEntry,
    };

    constexpr std::string_view ParseErrorString(ParseError e) {
        switch (e) {
            case ParseError::FileNotFound:
                return "File not found";
            case ParseError::ReadError:
                return "Failed to read file";
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
    };

    [[nodiscard]] std::expected<Document, ParseError> Parse(std::string_view content);
    [[nodiscard]] std::expected<Document, ParseError> ParseFile(const std::filesystem::path& path);

} // namespace Ini
