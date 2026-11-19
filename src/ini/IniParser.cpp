#include "ini/IniParser.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <variant>

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

    std::expected<const Section*, ParseError> Document::require(std::string_view name) const {
        const Section* s = get(name);
        if (!s)
            return std::unexpected(ParseError::SectionNotFound);
        return s;
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
        if (!std::filesystem::exists(path))
            return std::unexpected(ParseError::FileNotFound);

        std::ifstream file(path, std::ios::binary);
        if (!file)
            return std::unexpected(ParseError::ReadError);

        std::ostringstream ss;
        ss << file.rdbuf();
        if (file.fail() && !file.eof())
            return std::unexpected(ParseError::ReadError);

        return Parse(ss.str());
    }

    namespace {

        bool ParseBool(std::string_view v) {
            return v == "true" || v == "True" || v == "TRUE" || v == "1";
        }

    } // namespace

    void ApplyOption(OptionsArgs& opt, std::string_view key_sv, std::string_view value_sv) {
        const std::string key = ToLower(std::string(Trim(key_sv)));
        const std::string value{Trim(value_sv)};
        const bool b = ParseBool(Trim(value_sv));

        if (key == "type")
            opt.type = value;
        else if (key == "rev")
            opt.rev = value;
        else if (key == "1blkey")
            opt.key_1bl = value;
        else if (key == "cpukey")
            opt.cpukey = value;
        else if (key == "cfldv")
            opt.cfldv = value;

        else if (key == "nosecurity")
            opt.nosecurity = b;
        else if (key == "nosusecurity")
            opt.nosusecurity = b;
        else if (key == "nofcrt")
            opt.nofcrt = b;
        else if (key == "noremap")
            opt.noremap = b;
        else if (key == "nandmu")
            opt.nandmu = b;
        else if (key == "nomobile")
            opt.nomobile = b;
        else if (key == "noecdremap")
            opt.noecdremap = b;
        else if (key == "smcnocheck")
            opt.smcnocheck = b;
        else if (key == "noblpatch")
            opt.noblpatch = b;
        else if (key == "xellbutton")
            opt.xellbutton = value;
        else if (key == "xellbutton2")
            opt.xellbutton2 = value;
        else if (key == "addon") {
            std::string_view rem = value_sv;
            while (!rem.empty()) {
                auto colon = rem.find(':');
                std::string_view tok =
                    Trim((colon != std::string_view::npos) ? rem.substr(0, colon) : rem);
                rem = (colon != std::string_view::npos) ? rem.substr(colon + 1) : "";
                if (!tok.empty()) {
                    opt.addons.emplace_back(tok);
                }
            }
        }

        else if (key == "cygnos")
            opt.cygnos = b;
        else if (key == "demon")
            opt.demon = b;
        else if (key == "olddvd")
            opt.olddvd = b;
        else if (key == "nodvd")
            opt.nodvd = b;
        else if (key == "dualboot")
            opt.dualboot = value;

        else if (key == "cputemp")
            opt.cputemp = value;
        else if (key == "gputemp")
            opt.gputemp = value;
        else if (key == "edramtemp")
            opt.edramtemp = value;
        else if (key == "overcputemp")
            opt.overcputemp = value;
        else if (key == "overgputemp")
            opt.overgputemp = value;
        else if (key == "overedramtemp")
            opt.overedramtemp = value;
        else if (key == "cpufan")
            opt.cpufan = value;
        else if (key == "gpufan")
            opt.gpufan = value;

        else if (key == "avregion" || key == "region")
            opt.avregion = value;
        else if (key == "gameregion")
            opt.gameregion = value;
        else if (key == "dvdregion")
            opt.dvdregion = value;
        else if (key == "macid" || key == "mac")
            opt.macid = value;
        else if (key == "dvdkey")
            opt.dvdkey = value;
    }

    std::expected<OptionsArgs, OptionsError> ParseOptionsIni(std::string_view content) {
        OptionsArgs opt{};

        std::string_view remaining = content;

        while (!remaining.empty()) {
            auto newline = remaining.find('\n');
            std::string_view raw =
                (newline != std::string_view::npos) ? remaining.substr(0, newline) : remaining;
            remaining = (newline != std::string_view::npos) ? remaining.substr(newline + 1) : "";

            if (!raw.empty() && raw.back() == '\r')
                raw.remove_suffix(1);

            std::string_view line = Trim(raw);

            if (line.empty() || line.front() == ';' || line.front() == '#')
                continue;

            if (line.front() == '[' && line.back() == ']')
                return std::unexpected(OptionsError::BadFormat);

            std::string_view key_sv, val_sv;
            {
                constexpr std::string_view kDelimSpaced = " = ";
                auto pos = line.find(kDelimSpaced);
                if (pos != std::string_view::npos) {
                    key_sv = Trim(line.substr(0, pos));
                    val_sv = Trim(line.substr(pos + kDelimSpaced.size()));
                } else if (auto eq = line.find('='); eq != std::string_view::npos) {
                    key_sv = Trim(line.substr(0, eq));
                    val_sv = Trim(line.substr(eq + 1));
                } else {
                    continue;
                }
            }

            val_sv = StripInlineSemicolon(val_sv);
            ApplyOption(opt, key_sv, val_sv);
        }

        return opt;
    }

    OptionsResult ParseOptionsIniFile(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path))
            return std::unexpected(ParseError::FileNotFound);

        std::ifstream file(path, std::ios::binary);
        if (!file)
            return std::unexpected(ParseError::ReadError);

        std::ostringstream ss;
        ss << file.rdbuf();
        if (file.fail() && !file.eof())
            return std::unexpected(ParseError::ReadError);

        auto result = ParseOptionsIni(ss.str());
        if (!result)
            return std::unexpected(result.error());
        return result.value();
    }

} // namespace Ini
