#include "nand/objects/XeLL.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string_view>

namespace gxbuild3::NAND {

    namespace {

        constexpr uint8_t kElfMagic[4] = {0x7F, 'E', 'L', 'F'};

        bool is_valid_date(std::string_view s) {
            if (s.size() != 10 || s[4] != '-' || s[7] != '-') {
                return false;
            }
            for (size_t i : {0, 1, 2, 3, 5, 6, 8, 9}) {
                if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
                    return false;
                }
            }
            int year = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
            int month = (s[5] - '0') * 10 + (s[6] - '0');
            int day = (s[8] - '0') * 10 + (s[9] - '0');
            return year >= 2000 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 &&
                   day <= 31;
        }

        void extract_metadata(std::span<const uint8_t> bytes, XeLLMetadata& meta) {
            std::string_view raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());

            for (size_t i = 0; i + 10 <= raw.size(); ++i) {
                std::string_view candidate = raw.substr(i, 10);
                if (is_valid_date(candidate)) {
                    meta.date = std::string(candidate);

                    size_t open_paren = raw.find('(', i + 10);
                    if (open_paren != std::string_view::npos && open_paren <= i + 15) {
                        size_t close_paren = raw.find(')', open_paren);
                        if (close_paren != std::string_view::npos && close_paren > open_paren + 1 &&
                            close_paren <= open_paren + 64) {
                            meta.author = std::string(
                                raw.substr(open_paren + 1, close_paren - open_paren - 1));
                        }
                    }

                    if (i > 0) {
                        size_t v_end = i;
                        while (v_end > 0 &&
                                std::isspace(static_cast<unsigned char>(raw[v_end - 1]))) {
                            --v_end;
                        }
                        size_t v_start = v_end;
                        while (v_start > 0 &&
                               !std::isspace(static_cast<unsigned char>(raw[v_start - 1])) &&
                               raw[v_start - 1] != '"' && raw[v_start - 1] != '\0') {
                            --v_start;
                        }
                        if (v_end > v_start) {
                            meta.version = std::string(raw.substr(v_start, v_end - v_start));
                        }
                    }
                    break;
                }
            }

            if (meta.author.empty()) {
                if (raw.find("LibXenon") != std::string_view::npos) {
                    meta.author = "LibXenon.org";
                } else if (raw.find("Free60") != std::string_view::npos) {
                    meta.author = "Free60.org";
                }
            }

            if (meta.version.empty()) {
                static constexpr std::string_view kVersionPrefixes[] = {
                    "XeLL - Xenon linux loader second stage ",
                    "Free60.org XeLL - Xenon Linux Loader ", "XeLL Reloaded ", "XeLL-Reloaded ",
                    "XeLL "};
                for (auto prefix : kVersionPrefixes) {
                    size_t pos = raw.find(prefix);
                    if (pos != std::string_view::npos) {
                        size_t start = pos + prefix.size();
                        size_t end = start;
                        while (end < raw.size() && raw[end] != ' ' && raw[end] != '\n' &&
                               raw[end] != '\r' && raw[end] != '\0' && raw[end] != '"') {
                            ++end;
                        }
                        if (end > start) {
                            meta.version = std::string(raw.substr(start, end - start));
                            break;
                        }
                    }
                }
            }
        }

    } // namespace

    std::optional<XeLL> XeLL::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() != kSize) {
            return std::nullopt;
        }

        auto it =
            std::search(bytes.begin(), bytes.end(), std::begin(kElfMagic), std::end(kElfMagic));
        if (it == bytes.end()) {
            return std::nullopt;
        }

        XeLL xell;
        xell.data.assign(bytes.begin(), bytes.end());
        extract_metadata(bytes, xell.metadata);
        Log::Debug("Parsed XeLL: version='{}', author='{}', date='{}'",
                   xell.metadata.version, xell.metadata.author, xell.metadata.date);
        return xell;
    }

    std::optional<XeLL> XeLL::parse(const std::vector<uint8_t>& bytes) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

} // namespace gxbuild3::NAND
