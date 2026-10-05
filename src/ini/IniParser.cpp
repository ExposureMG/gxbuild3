#include "ini/IniParser.hpp"

#include "utils/Log.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace Ini {

    namespace {

        std::string ToLower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        std::string_view Trim(std::string_view sv) {
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())))
                sv.remove_prefix(1);
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())))
                sv.remove_suffix(1);
            return sv;
        }

        std::string_view StripInlineSemicolon(std::string_view sv) {
            if (auto pos = sv.find(';'); pos != std::string_view::npos)
                sv = sv.substr(0, pos);
            return Trim(sv);
        }

    } // namespace

    const Section* Document::get(std::string_view name) const {
        auto it = sections.find(ToLower(std::string(name)));
        return it != sections.end() ? &it->second : nullptr;
    }

    std::expected<Document, ParseError> Parse(std::string_view content) {
        Document doc;
        std::string current_section;

        std::unordered_map<std::string, std::unordered_map<std::string, uint8_t>> chain_counters;

        std::string_view remaining = content;

        while (!remaining.empty()) {
            auto newline = remaining.find('\n');
            std::string_view raw_line =
                (newline != std::string_view::npos) ? remaining.substr(0, newline) : remaining;
            remaining = (newline != std::string_view::npos) ? remaining.substr(newline + 1) : "";

            if (!raw_line.empty() && raw_line.back() == '\r')
                raw_line.remove_suffix(1);

            std::string_view line = Trim(raw_line);

            if (line.empty() || line.front() == ';' || line.front() == '#')
                continue;

            if (line.front() == '[' && line.back() == ']') {
                current_section = ToLower(std::string(line.substr(1, line.size() - 2)));
                continue;
            }

            if (current_section.empty())
                continue;

            Entry entry;

            auto comma_pos = line.find(',');
            auto equals_pos = line.find('=');

            if (comma_pos != std::string_view::npos &&
                (equals_pos == std::string_view::npos || comma_pos < equals_pos)) {
                // --- Format 1: key , value [, hash] ---
                entry.key = std::string(Trim(StripInlineSemicolon(line.substr(0, comma_pos))));

                std::string_view rest = line.substr(comma_pos + 1);
                auto second_comma = rest.find(',');

                if (second_comma != std::string_view::npos) {
                    entry.value =
                        std::string(Trim(StripInlineSemicolon(rest.substr(0, second_comma))));
                    entry.hash =
                        std::string(Trim(StripInlineSemicolon(rest.substr(second_comma + 1))));
                } else {
                    entry.value = std::string(Trim(StripInlineSemicolon(rest)));
                }
            } else if (equals_pos != std::string_view::npos) {
                // --- Format 2: key = value ---
                entry.key = std::string(Trim(line.substr(0, equals_pos)));
                std::string_view val = Trim(line.substr(equals_pos + 1));
                entry.value = std::string(StripInlineSemicolon(val));
            } else {
                entry.key = std::string(Trim(StripInlineSemicolon(line)));
            }

            if (entry.key.empty())
                continue;

            std::string key_lower = ToLower(entry.key);
            std::string prefix;
            {
                auto us = key_lower.find('_');
                auto dot = key_lower.find('.');
                auto end = std::min(us, dot);
                prefix = (end != std::string::npos) ? key_lower.substr(0, end) : key_lower;
            }

            auto& section_counters = chain_counters[current_section];
            entry.chain = section_counters[prefix];
            section_counters[prefix]++;

            doc.sections[current_section].push_back(std::move(entry));
        }

        return doc;
    }

    std::expected<Document, ParseError> ParseFile(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) {
            Log::Error("INI file not found: '{}'", path.string());
            return std::unexpected(ParseError::FileNotFound);
        }

        std::ifstream file(path, std::ios::binary);
        if (!file) {
            Log::Error("Failed to open INI file: '{}'", path.string());
            return std::unexpected(ParseError::ReadError);
        }

        std::ostringstream ss;
        ss << file.rdbuf();
        if (file.fail() && !file.eof()) {
            Log::Error("Failed to read INI file: '{}'", path.string());
            return std::unexpected(ParseError::ReadError);
        }

        auto res = Parse(ss.str());
        if (res) {
            Log::Debug("Parsed INI file '{}' ({} sections)", path.string(), res->sections.size());
        }
        return res;
    }

} // namespace Ini
