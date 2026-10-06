#pragma once

#include "Error.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace gxbuild3::ini {

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

    // Parsing is permissive: comments, entries before the first section and entries with an
    // empty key are skipped rather than reported. Only real failures produce an Error.
    [[nodiscard]] Result<Document> parse(std::string_view content);

    // Reads and parses an INI file. Fails with NotFound when the file does not exist and with
    // IoError when it cannot be opened or read. The Error is returned, not logged.
    [[nodiscard]] Result<Document> parse_file(const std::filesystem::path& path);

} // namespace gxbuild3::ini
