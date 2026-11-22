#include "Args.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <limits>
#include <utility>

namespace gxbuild3 {

    namespace {

        std::string normalize_key(std::string_view raw) {
            while (!raw.empty() &&
                   (raw.front() == '-' || std::isspace(static_cast<unsigned char>(raw.front())))) {
                raw.remove_prefix(1);
            }
            while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) {
                raw.remove_suffix(1);
            }

            std::string result;
            result.reserve(raw.size());
            for (char c : raw) {
                result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            return result;
        }

        std::string_view trim_view(std::string_view raw) {
            while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.front()))) {
                raw.remove_prefix(1);
            }
            while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) {
                raw.remove_suffix(1);
            }
            return raw;
        }

        std::string trim_str(std::string_view raw) {
            return std::string(trim_view(raw));
        }

        template <size_t N>
        std::optional<std::array<uint8_t, N>> decode_hex_bytes(std::string_view hex) {
            if (hex.size() != N * 2) {
                return std::nullopt;
            }
            const auto nibble = [](char c) -> std::optional<uint8_t> {
                if (c >= '0' && c <= '9') {
                    return static_cast<uint8_t>(c - '0');
                }
                if (c >= 'a' && c <= 'f') {
                    return static_cast<uint8_t>(c - 'a' + 10);
                }
                if (c >= 'A' && c <= 'F') {
                    return static_cast<uint8_t>(c - 'A' + 10);
                }
                return std::nullopt;
            };
            std::array<uint8_t, N> out{};
            for (size_t i = 0; i < N; ++i) {
                const auto hi = nibble(hex[i * 2]);
                const auto lo = nibble(hex[i * 2 + 1]);
                if (!hi || !lo) {
                    return std::nullopt;
                }
                out[i] = static_cast<uint8_t>((*hi << 4) | *lo);
            }
            return out;
        }

        template <typename ParseFn>
        bool set_validated_option(std::optional<std::string>& target, const std::string& val,
                                  ParseFn&& parse_fn) {
            if (val.empty()) {
                target.reset();
                return true;
            }
            if (!parse_fn(val)) {
                return false;
            }
            target = val;
            return true;
        }

        std::optional<bool> parse_bool_value(std::string_view val) {
            std::string lower;
            lower.reserve(val.size());
            for (char c : val) {
                lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }

            if (lower.empty() || lower == "true" || lower == "1" || lower == "yes" ||
                lower == "on") {
                return true;
            }
            if (lower == "false" || lower == "0" || lower == "no" || lower == "off") {
                return false;
            }
            return std::nullopt;
        }

        // merges cb, cd, and khv into a canonical '+' separated string
        std::optional<std::string> add_nopatch_stage(const std::optional<std::string>& current,
                                                     std::string_view value) {
            const std::string stage = normalize_key(value);
            const bool is_cb = stage == "cb" || stage == "cbb";
            if (!is_cb && stage != "cd" && stage != "khv") {
                return std::nullopt;
            }
            const std::string name = is_cb ? "cb" : stage;
            const std::string existing = current.value_or("");
            const auto named = [&existing](std::string_view candidate) {
                return existing.find(candidate) != std::string::npos;
            };
            std::string canonical;
            for (const std::string_view candidate : {"cb", "cd", "khv"}) {
                if (named(candidate) || candidate == name) {
                    canonical += canonical.empty() ? "" : "+";
                    canonical += candidate;
                }
            }
            return canonical;
        }

    } // namespace

    NoPatch resolve_no_patch(const OptionsArgs& options) {
        const std::string named = options.nopatch.value_or("");
        NoPatch stages;
        stages.cb = named.find("cb") != std::string::npos;
        stages.cd = named.find("cd") != std::string::npos;
        stages.khv = named.find("khv") != std::string::npos;
        if (options.noblpatch.value_or(false)) {
            stages.cb = stages.cd = true;
        }
        return stages;
    }

    OptionsManager::OptionsManager(OptionsArgs args) : m_args(std::move(args)) {}

    bool OptionsManager::is_known_option(std::string_view name) {
        const std::string key = normalize_key(name);
        return key == "cygnos" || key == "demon" || key == "olddvd" || key == "nodvd" ||
               key == "nomobile" || key == "nofcrt" || key == "noremap" || key == "noecdremap" ||
               key == "nandmu" || key == "nosecurity" || key == "nosusecurity" ||
               key == "smcnocheck" || key == "nochecksmc" || key == "noblpatch" ||
               key == "nosmcpatch" || key == "nopatch" || key == "cbldv" || key == "pairing_data" ||
               key == "pairingdata" || key == "pd" || key == "cfldv" || key == "xellbutton" ||
               key == "xellbutton2" || key == "dualboot" || key == "cputemp" || key == "gputemp" ||
               key == "edramtemp" || key == "overcputemp" || key == "overgputemp" ||
               key == "overedramtemp" || key == "cpufan" || key == "gpufan" || key == "dvdkey" ||
               key == "avregion" || key == "gameregion" || key == "dvdregion" || key == "macid";
    }

    bool OptionsManager::is_bool_option(std::string_view name) {
        const std::string key = normalize_key(name);
        return key == "cygnos" || key == "demon" || key == "olddvd" || key == "nodvd" ||
               key == "nomobile" || key == "nofcrt" || key == "noremap" || key == "noecdremap" ||
               key == "nandmu" || key == "nosecurity" || key == "nosusecurity" ||
               key == "smcnocheck" || key == "nochecksmc" || key == "noblpatch" ||
               key == "nosmcpatch";
    }

    // Maps button names to their power-on reason byte.
    std::optional<uint8_t> OptionsManager::power_on_reason(std::string_view name) {
        static constexpr std::array<std::pair<std::string_view, uint8_t>, 13> kReasons{{
            {"power", 0x11},
            {"eject", 0x12},
            {"remopower", 0x20},
            {"remox", 0x22},
            {"winbutton", 0x24},
            {"kiosk", 0x41},
            {"wirelessx", 0x55},
            {"wiredxf1", 0x56},
            {"wiredxf2", 0x57},
            {"wiredxb2", 0x58},
            {"wiredxb1", 0x59},
            {"wiredx", 0x5A},
            {"wiredxb3", 0x5A},
        }};
        std::string key = trim_str(name);
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const auto found = std::find_if(kReasons.begin(), kReasons.end(),
                                        [&key](const auto& reason) { return reason.first == key; });
        if (found == kReasons.end()) {
            return std::nullopt;
        }
        return found->second;
    }

    std::optional<uint32_t> OptionsManager::parse_u32(std::string_view raw) {
        std::string_view text = trim_view(raw);
        if (text.empty()) {
            return std::nullopt;
        }
        int base = 10;
        if (text.starts_with("0x") || text.starts_with("0X")) {
            base = 16;
            text.remove_prefix(2);
        }
        if (text.empty()) {
            return std::nullopt;
        }
        uint32_t value = 0;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
            return std::nullopt;
        }
        return value;
    }

    std::optional<uint16_t> OptionsManager::parse_u16(std::string_view raw) {
        const auto value = parse_u32(raw);
        if (!value || *value > std::numeric_limits<uint16_t>::max()) {
            return std::nullopt;
        }
        return static_cast<uint16_t>(*value);
    }

    std::optional<std::array<uint8_t, 6>> OptionsManager::parse_mac_id(std::string_view raw) {
        const std::string_view trimmed = trim_view(raw);
        std::string stripped;
        stripped.reserve(trimmed.size());
        for (char c : trimmed) {
            if (c != ':') {
                stripped.push_back(c);
            }
        }
        return decode_hex_bytes<6>(stripped);
    }

    std::optional<std::array<uint8_t, 16>> OptionsManager::parse_dvd_key(std::string_view raw) {
        return decode_hex_bytes<16>(trim_view(raw));
    }

    bool OptionsManager::has(std::string_view name) const {
        const std::string key = normalize_key(name);
        if (key == "cygnos")
            return m_args.cygnos.has_value();
        if (key == "demon")
            return m_args.demon.has_value();
        if (key == "olddvd")
            return m_args.olddvd.has_value();
        if (key == "nodvd")
            return m_args.nodvd.has_value();
        if (key == "nomobile")
            return m_args.nomobile.has_value();
        if (key == "nofcrt")
            return m_args.nofcrt.has_value();
        if (key == "noremap")
            return m_args.noremap.has_value();
        if (key == "noecdremap")
            return m_args.noecdremap.has_value();
        if (key == "nandmu")
            return m_args.nandmu.has_value();
        if (key == "nosecurity")
            return m_args.nosecurity.has_value();
        if (key == "nosusecurity")
            return m_args.nosusecurity.has_value();
        if (key == "smcnocheck" || key == "nochecksmc")
            return m_args.smcnocheck.has_value();
        if (key == "noblpatch")
            return m_args.noblpatch.has_value();
        if (key == "nosmcpatch")
            return m_args.nosmcpatch.has_value();
        if (key == "nopatch")
            return m_args.nopatch.has_value();

        if (key == "cbldv")
            return m_args.cbldv.has_value();
        if (key == "pairing_data" || key == "pairingdata" || key == "pd")
            return m_args.pairing_data.has_value();
        if (key == "cfldv")
            return m_args.cfldv.has_value();
        if (key == "xellbutton")
            return m_args.xellbutton.has_value();
        if (key == "xellbutton2")
            return m_args.xellbutton2.has_value();
        if (key == "dualboot")
            return m_args.dualboot.has_value();
        if (key == "cputemp")
            return m_args.cputemp.has_value();
        if (key == "gputemp")
            return m_args.gputemp.has_value();
        if (key == "edramtemp")
            return m_args.edramtemp.has_value();
        if (key == "overcputemp")
            return m_args.overcputemp.has_value();
        if (key == "overgputemp")
            return m_args.overgputemp.has_value();
        if (key == "overedramtemp")
            return m_args.overedramtemp.has_value();
        if (key == "cpufan")
            return m_args.cpufan.has_value();
        if (key == "gpufan")
            return m_args.gpufan.has_value();
        if (key == "dvdkey")
            return m_args.dvdkey.has_value();
        if (key == "avregion")
            return m_args.avregion.has_value();
        if (key == "gameregion")
            return m_args.gameregion.has_value();
        if (key == "dvdregion")
            return m_args.dvdregion.has_value();
        if (key == "macid")
            return m_args.macid.has_value();

        return false;
    }

    bool OptionsManager::set_bool(std::string_view name, bool value) {
        const std::string key = normalize_key(name);
        if (key == "cygnos") {
            m_args.cygnos = value;
            return true;
        }
        if (key == "demon") {
            m_args.demon = value;
            return true;
        }
        if (key == "olddvd") {
            m_args.olddvd = value;
            return true;
        }
        if (key == "nodvd") {
            m_args.nodvd = value;
            return true;
        }
        if (key == "nomobile") {
            m_args.nomobile = value;
            return true;
        }
        if (key == "nofcrt") {
            m_args.nofcrt = value;
            return true;
        }
        if (key == "noremap") {
            m_args.noremap = value;
            return true;
        }
        if (key == "noecdremap") {
            m_args.noecdremap = value;
            return true;
        }
        if (key == "nandmu") {
            m_args.nandmu = value;
            return true;
        }
        if (key == "nosecurity") {
            m_args.nosecurity = value;
            return true;
        }
        if (key == "nosusecurity") {
            m_args.nosusecurity = value;
            return true;
        }
        if (key == "smcnocheck" || key == "nochecksmc") {
            m_args.smcnocheck = value;
            return true;
        }
        if (key == "nosmcpatch") {
            m_args.nosmcpatch = value;
            return true;
        }
        if (key == "noblpatch") {
            m_args.noblpatch = value;
            return true;
        }

        return false;
    }

    bool OptionsManager::set(std::string_view name, std::string_view value) {
        const std::string key = normalize_key(name);
        const std::string val = trim_str(value);

        if (is_bool_option(key)) {
            auto parsed_b = parse_bool_value(val);
            if (parsed_b.has_value()) {
                return set_bool(key, *parsed_b);
            }
            return false;
        }

        if (key == "nopatch") {
            if (val.empty()) {
                m_args.nopatch.reset();
                return true;
            }
            const auto stages = add_nopatch_stage(m_args.nopatch, val);
            if (!stages) {
                return false;
            }
            m_args.nopatch = *stages;
            return true;
        }

        if (key == "cbldv") {
            m_args.cbldv = val;
            return true;
        }
        if (key == "pairing_data" || key == "pairingdata" || key == "pd") {
            m_args.pairing_data = val;
            return true;
        }
        if (key == "cfldv") {
            m_args.cfldv = val;
            return true;
        }
        if (key == "xellbutton" || key == "xellbutton2" || key == "dualboot") {
            auto& button = key == "xellbutton"    ? m_args.xellbutton
                           : key == "xellbutton2" ? m_args.xellbutton2
                                                  : m_args.dualboot;
            if (val.empty()) {
                button.reset();
                return true;
            }
            if (!power_on_reason(val)) {
                return false;
            }
            button = val;
            return true;
        }
        static constexpr std::array<
            std::pair<std::string_view, std::optional<std::string> OptionsArgs::*>, 10>
            kU32Options{{
                {"cputemp", &OptionsArgs::cputemp},
                {"gputemp", &OptionsArgs::gputemp},
                {"edramtemp", &OptionsArgs::edramtemp},
                {"overcputemp", &OptionsArgs::overcputemp},
                {"overgputemp", &OptionsArgs::overgputemp},
                {"overedramtemp", &OptionsArgs::overedramtemp},
                {"cpufan", &OptionsArgs::cpufan},
                {"gpufan", &OptionsArgs::gpufan},
                {"avregion", &OptionsArgs::avregion},
                {"dvdregion", &OptionsArgs::dvdregion},
            }};
        for (const auto& [opt_name, member] : kU32Options) {
            if (key == opt_name) {
                return set_validated_option(m_args.*member, val, parse_u32);
            }
        }
        if (key == "gameregion") {
            return set_validated_option(m_args.gameregion, val, parse_u16);
        }
        if (key == "macid") {
            return set_validated_option(m_args.macid, val, parse_mac_id);
        }
        if (key == "dvdkey") {
            return set_validated_option(m_args.dvdkey, val, parse_dvd_key);
        }

        return false;
    }

    std::optional<bool> OptionsManager::get_bool(std::string_view name) const {
        const std::string key = normalize_key(name);
        if (key == "cygnos")
            return m_args.cygnos;
        if (key == "demon")
            return m_args.demon;
        if (key == "olddvd")
            return m_args.olddvd;
        if (key == "nodvd")
            return m_args.nodvd;
        if (key == "nomobile")
            return m_args.nomobile;
        if (key == "nofcrt")
            return m_args.nofcrt;
        if (key == "noremap")
            return m_args.noremap;
        if (key == "noecdremap")
            return m_args.noecdremap;
        if (key == "nandmu")
            return m_args.nandmu;
        if (key == "nosecurity")
            return m_args.nosecurity;
        if (key == "nosusecurity")
            return m_args.nosusecurity;
        if (key == "smcnocheck" || key == "nochecksmc")
            return m_args.smcnocheck;
        if (key == "noblpatch")
            return m_args.noblpatch;
        if (key == "nosmcpatch")
            return m_args.nosmcpatch;

        return std::nullopt;
    }

    std::optional<std::string> OptionsManager::get_string(std::string_view name) const {
        const std::string key = normalize_key(name);
        if (key == "nopatch")
            return m_args.nopatch;
        if (key == "cbldv")
            return m_args.cbldv;
        if (key == "pairing_data" || key == "pairingdata" || key == "pd")
            return m_args.pairing_data;
        if (key == "cfldv")
            return m_args.cfldv;
        if (key == "xellbutton")
            return m_args.xellbutton;
        if (key == "xellbutton2")
            return m_args.xellbutton2;
        if (key == "dualboot")
            return m_args.dualboot;
        if (key == "cputemp")
            return m_args.cputemp;
        if (key == "gputemp")
            return m_args.gputemp;
        if (key == "edramtemp")
            return m_args.edramtemp;
        if (key == "overcputemp")
            return m_args.overcputemp;
        if (key == "overgputemp")
            return m_args.overgputemp;
        if (key == "overedramtemp")
            return m_args.overedramtemp;
        if (key == "cpufan")
            return m_args.cpufan;
        if (key == "gpufan")
            return m_args.gpufan;
        if (key == "dvdkey")
            return m_args.dvdkey;
        if (key == "avregion")
            return m_args.avregion;
        if (key == "gameregion")
            return m_args.gameregion;
        if (key == "dvdregion")
            return m_args.dvdregion;
        if (key == "macid")
            return m_args.macid;

        return std::nullopt;
    }

    bool OptionsManager::parse(std::string_view raw_args) {
        bool all_ok = true;
        size_t start = 0;
        while (start < raw_args.size()) {
            size_t end = raw_args.find_first_of(";,", start);
            if (end == std::string_view::npos) {
                end = raw_args.size();
            }

            std::string_view token = raw_args.substr(start, end - start);
            while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front()))) {
                token.remove_prefix(1);
            }
            while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back()))) {
                token.remove_suffix(1);
            }

            if (!token.empty()) {
                size_t eq_pos = token.find('=');
                if (eq_pos != std::string_view::npos) {
                    std::string_view k = token.substr(0, eq_pos);
                    std::string_view v = token.substr(eq_pos + 1);
                    if (!set(k, v)) {
                        all_ok = false;
                    }
                } else if (is_bool_option(token)) {
                    if (!set(token, "true")) {
                        all_ok = false;
                    }
                } else {
                    all_ok = false;
                }
            }

            start = end + 1;
        }
        return all_ok;
    }

} // namespace gxbuild3
