#include "Args.hpp"
#include "ini/IniParser.hpp"

#include <algorithm>
#include <cctype>

namespace {

    std::string normalize_key(std::string_view raw) {
        while (!raw.empty() && (raw.front() == '-' || std::isspace(static_cast<unsigned char>(raw.front())))) {
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

    std::string trim_str(std::string_view raw) {
        while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.front()))) {
            raw.remove_prefix(1);
        }
        while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) {
            raw.remove_suffix(1);
        }
        return std::string(raw);
    }

    std::optional<bool> parse_bool_value(std::string_view val) {
        std::string lower;
        lower.reserve(val.size());
        for (char c : val) {
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        if (lower.empty() || lower == "true" || lower == "1" || lower == "yes" || lower == "on") {
            return true;
        }
        if (lower == "false" || lower == "0" || lower == "no" || lower == "off") {
            return false;
        }
        return std::nullopt;
    }

} // namespace

OptionsManager::OptionsManager(OptionsArgs args) : m_args(std::move(args)) {}

OptionsManager::OptionsManager(std::string_view raw_args) {
    parse(raw_args);
}

bool OptionsManager::is_known_option(std::string_view name) {
    const std::string key = normalize_key(name);
    return key == "cygnos" || key == "demon" || key == "olddvd" || key == "nodvd" ||
           key == "nomobile" || key == "nofcrt" || key == "noremap" || key == "noecdremap" ||
           key == "nandmu" || key == "nosecurity" || key == "nosusecurity" ||
           key == "smcnocheck" || key == "nochecksmc" || key == "noblpatch" ||
           key == "cbldv" || key == "pairing_data" || key == "pairingdata" || key == "pd" ||
           key == "cfldv" || key == "xellbutton" || key == "xellbutton2" ||
           key == "dualboot" || key == "cputemp" || key == "gputemp" ||
           key == "edramtemp" || key == "overcputemp" || key == "overgputemp" ||
           key == "overedramtemp" || key == "cpufan" || key == "gpufan" ||
           key == "dvdkey" || key == "avregion" || key == "gameregion" ||
           key == "dvdregion" || key == "macid";
}

bool OptionsManager::is_bool_option(std::string_view name) {
    const std::string key = normalize_key(name);
    return key == "cygnos" || key == "demon" || key == "olddvd" || key == "nodvd" ||
           key == "nomobile" || key == "nofcrt" || key == "noremap" || key == "noecdremap" ||
           key == "nandmu" || key == "nosecurity" || key == "nosusecurity" ||
           key == "smcnocheck" || key == "nochecksmc" || key == "noblpatch";
}

bool OptionsManager::has(std::string_view name) const {
    const std::string key = normalize_key(name);
    if (key == "cygnos") return m_args.cygnos.has_value();
    if (key == "demon") return m_args.demon.has_value();
    if (key == "olddvd") return m_args.olddvd.has_value();
    if (key == "nodvd") return m_args.nodvd.has_value();
    if (key == "nomobile") return m_args.nomobile.has_value();
    if (key == "nofcrt") return m_args.nofcrt.has_value();
    if (key == "noremap") return m_args.noremap.has_value();
    if (key == "noecdremap") return m_args.noecdremap.has_value();
    if (key == "nandmu") return m_args.nandmu.has_value();
    if (key == "nosecurity") return m_args.nosecurity.has_value();
    if (key == "nosusecurity") return m_args.nosusecurity.has_value();
    if (key == "smcnocheck" || key == "nochecksmc") return m_args.smcnocheck.has_value();
    if (key == "noblpatch") return m_args.noblpatch.has_value();

    if (key == "cbldv") return m_args.cbldv.has_value();
    if (key == "pairing_data" || key == "pairingdata" || key == "pd") return m_args.pairing_data.has_value();
    if (key == "cfldv") return m_args.cfldv.has_value();
    if (key == "xellbutton") return m_args.xellbutton.has_value();
    if (key == "xellbutton2") return m_args.xellbutton2.has_value();
    if (key == "dualboot") return m_args.dualboot.has_value();
    if (key == "cputemp") return m_args.cputemp.has_value();
    if (key == "gputemp") return m_args.gputemp.has_value();
    if (key == "edramtemp") return m_args.edramtemp.has_value();
    if (key == "overcputemp") return m_args.overcputemp.has_value();
    if (key == "overgputemp") return m_args.overgputemp.has_value();
    if (key == "overedramtemp") return m_args.overedramtemp.has_value();
    if (key == "cpufan") return m_args.cpufan.has_value();
    if (key == "gpufan") return m_args.gpufan.has_value();
    if (key == "dvdkey") return m_args.dvdkey.has_value();
    if (key == "avregion") return m_args.avregion.has_value();
    if (key == "gameregion") return m_args.gameregion.has_value();
    if (key == "dvdregion") return m_args.dvdregion.has_value();
    if (key == "macid") return m_args.macid.has_value();

    return false;
}

bool OptionsManager::set_bool(std::string_view name, bool value) {
    const std::string key = normalize_key(name);
    if (key == "cygnos") { m_args.cygnos = value; return true; }
    if (key == "demon") { m_args.demon = value; return true; }
    if (key == "olddvd") { m_args.olddvd = value; return true; }
    if (key == "nodvd") { m_args.nodvd = value; return true; }
    if (key == "nomobile") { m_args.nomobile = value; return true; }
    if (key == "nofcrt") { m_args.nofcrt = value; return true; }
    if (key == "noremap") { m_args.noremap = value; return true; }
    if (key == "noecdremap") { m_args.noecdremap = value; return true; }
    if (key == "nandmu") { m_args.nandmu = value; return true; }
    if (key == "nosecurity") { m_args.nosecurity = value; return true; }
    if (key == "nosusecurity") { m_args.nosusecurity = value; return true; }
    if (key == "smcnocheck" || key == "nochecksmc") { m_args.smcnocheck = value; return true; }
    if (key == "noblpatch") { m_args.noblpatch = value; return true; }

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

    if (key == "cbldv") { m_args.cbldv = val; return true; }
    if (key == "pairing_data" || key == "pairingdata" || key == "pd") { m_args.pairing_data = val; return true; }
    if (key == "cfldv") { m_args.cfldv = val; return true; }
    if (key == "xellbutton") { m_args.xellbutton = val; return true; }
    if (key == "xellbutton2") { m_args.xellbutton2 = val; return true; }
    if (key == "dualboot") { m_args.dualboot = val; return true; }
    if (key == "cputemp") { m_args.cputemp = val; return true; }
    if (key == "gputemp") { m_args.gputemp = val; return true; }
    if (key == "edramtemp") { m_args.edramtemp = val; return true; }
    if (key == "overcputemp") { m_args.overcputemp = val; return true; }
    if (key == "overgputemp") { m_args.overgputemp = val; return true; }
    if (key == "overedramtemp") { m_args.overedramtemp = val; return true; }
    if (key == "cpufan") { m_args.cpufan = val; return true; }
    if (key == "gpufan") { m_args.gpufan = val; return true; }
    if (key == "dvdkey") { m_args.dvdkey = val; return true; }
    if (key == "avregion") { m_args.avregion = val; return true; }
    if (key == "gameregion") { m_args.gameregion = val; return true; }
    if (key == "dvdregion") { m_args.dvdregion = val; return true; }
    if (key == "macid") { m_args.macid = val; return true; }

    return false;
}

bool OptionsManager::unset(std::string_view name) {
    const std::string key = normalize_key(name);
    if (key == "cygnos") { m_args.cygnos.reset(); return true; }
    if (key == "demon") { m_args.demon.reset(); return true; }
    if (key == "olddvd") { m_args.olddvd.reset(); return true; }
    if (key == "nodvd") { m_args.nodvd.reset(); return true; }
    if (key == "nomobile") { m_args.nomobile.reset(); return true; }
    if (key == "nofcrt") { m_args.nofcrt.reset(); return true; }
    if (key == "noremap") { m_args.noremap.reset(); return true; }
    if (key == "noecdremap") { m_args.noecdremap.reset(); return true; }
    if (key == "nandmu") { m_args.nandmu.reset(); return true; }
    if (key == "nosecurity") { m_args.nosecurity.reset(); return true; }
    if (key == "nosusecurity") { m_args.nosusecurity.reset(); return true; }
    if (key == "smcnocheck" || key == "nochecksmc") { m_args.smcnocheck.reset(); return true; }
    if (key == "noblpatch") { m_args.noblpatch.reset(); return true; }

    if (key == "cbldv") { m_args.cbldv.reset(); return true; }
    if (key == "pairing_data" || key == "pairingdata" || key == "pd") { m_args.pairing_data.reset(); return true; }
    if (key == "cfldv") { m_args.cfldv.reset(); return true; }
    if (key == "xellbutton") { m_args.xellbutton.reset(); return true; }
    if (key == "xellbutton2") { m_args.xellbutton2.reset(); return true; }
    if (key == "dualboot") { m_args.dualboot.reset(); return true; }
    if (key == "cputemp") { m_args.cputemp.reset(); return true; }
    if (key == "gputemp") { m_args.gputemp.reset(); return true; }
    if (key == "edramtemp") { m_args.edramtemp.reset(); return true; }
    if (key == "overcputemp") { m_args.overcputemp.reset(); return true; }
    if (key == "overgputemp") { m_args.overgputemp.reset(); return true; }
    if (key == "overedramtemp") { m_args.overedramtemp.reset(); return true; }
    if (key == "cpufan") { m_args.cpufan.reset(); return true; }
    if (key == "gpufan") { m_args.gpufan.reset(); return true; }
    if (key == "dvdkey") { m_args.dvdkey.reset(); return true; }
    if (key == "avregion") { m_args.avregion.reset(); return true; }
    if (key == "gameregion") { m_args.gameregion.reset(); return true; }
    if (key == "dvdregion") { m_args.dvdregion.reset(); return true; }
    if (key == "macid") { m_args.macid.reset(); return true; }

    return false;
}

bool OptionsManager::toggle(std::string_view name) {
    const std::string key = normalize_key(name);
    if (!is_bool_option(key)) {
        return false;
    }

    auto current = get_bool(key);
    bool new_val = !current.value_or(false);
    return set_bool(key, new_val);
}

std::optional<bool> OptionsManager::get_bool(std::string_view name) const {
    const std::string key = normalize_key(name);
    if (key == "cygnos") return m_args.cygnos;
    if (key == "demon") return m_args.demon;
    if (key == "olddvd") return m_args.olddvd;
    if (key == "nodvd") return m_args.nodvd;
    if (key == "nomobile") return m_args.nomobile;
    if (key == "nofcrt") return m_args.nofcrt;
    if (key == "noremap") return m_args.noremap;
    if (key == "noecdremap") return m_args.noecdremap;
    if (key == "nandmu") return m_args.nandmu;
    if (key == "nosecurity") return m_args.nosecurity;
    if (key == "nosusecurity") return m_args.nosusecurity;
    if (key == "smcnocheck" || key == "nochecksmc") return m_args.smcnocheck;
    if (key == "noblpatch") return m_args.noblpatch;

    return std::nullopt;
}

std::optional<std::string> OptionsManager::get_string(std::string_view name) const {
    const std::string key = normalize_key(name);
    if (key == "cbldv") return m_args.cbldv;
    if (key == "pairing_data" || key == "pairingdata" || key == "pd") return m_args.pairing_data;
    if (key == "cfldv") return m_args.cfldv;
    if (key == "xellbutton") return m_args.xellbutton;
    if (key == "xellbutton2") return m_args.xellbutton2;
    if (key == "dualboot") return m_args.dualboot;
    if (key == "cputemp") return m_args.cputemp;
    if (key == "gputemp") return m_args.gputemp;
    if (key == "edramtemp") return m_args.edramtemp;
    if (key == "overcputemp") return m_args.overcputemp;
    if (key == "overgputemp") return m_args.overgputemp;
    if (key == "overedramtemp") return m_args.overedramtemp;
    if (key == "cpufan") return m_args.cpufan;
    if (key == "gpufan") return m_args.gpufan;
    if (key == "dvdkey") return m_args.dvdkey;
    if (key == "avregion") return m_args.avregion;
    if (key == "gameregion") return m_args.gameregion;
    if (key == "dvdregion") return m_args.dvdregion;
    if (key == "macid") return m_args.macid;

    return std::nullopt;
}

std::optional<std::string> OptionsManager::get(std::string_view name) const {
    if (is_bool_option(name)) {
        auto b = get_bool(name);
        if (!b.has_value()) return std::nullopt;
        return *b ? "true" : "false";
    }
    return get_string(name);
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
            } else {
                if (!set(token, "true")) {
                    all_ok = false;
                }
            }
        }

        start = end + 1;
    }
    return all_ok;
}

bool OptionsManager::parse(const std::vector<std::string>& raw_args_list) {
    bool all_ok = true;
    for (const auto& item : raw_args_list) {
        if (!parse(item)) {
            all_ok = false;
        }
    }
    return all_ok;
}

bool OptionsManager::parse_ini(std::string_view content) {
    auto res = Ini::ParseOptionsIni(content);
    if (!res) {
        return false;
    }
    m_args = std::move(res.value());
    return true;
}

bool OptionsManager::parse_file(const std::filesystem::path& path) {
    auto res = Ini::ParseOptionsIniFile(path);
    if (!res) {
        return false;
    }
    m_args = std::move(res.value());
    return true;
}
