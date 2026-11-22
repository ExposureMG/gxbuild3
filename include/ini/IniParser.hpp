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
        std::string hash;
        uint8_t chain{0};
    };

    using Section = std::vector<Entry>;

    struct Document {
        std::unordered_map<std::string, Section> sections;

        [[nodiscard]] const Section* get(std::string_view name) const;
    };

    [[nodiscard]] Result<Document> parse(std::string_view content);

    [[nodiscard]] Result<Document> parse_file(const std::filesystem::path& path);

} // namespace gxbuild3::ini
