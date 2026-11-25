#include "core/Args.hpp"

#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <utility>

namespace gxbuild {

    namespace {

        std::string normalize_key(std::string_view raw) {
            raw = utils::trim_view(raw);
            while (!raw.empty() && raw.front() == '-') {
                raw.remove_prefix(1);
            }
            return utils::to_lower(utils::trim_view(raw));
        }

        std::string trim_str(std::string_view raw) {
            return std::string(utils::trim_view(raw));
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
            const std::string lower = utils::to_lower(val);

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

        struct BoolOptionDesc {
            std::string_view name;
            std::optional<bool> OptionsArgs::* member;
        };

        enum class StringOptionKind : uint8_t {
            Raw,
            Nopatch,
            Button,
            U32,
            U16,
            MacId,
            DvdKey,
        };

        struct StringOptionDesc {
            std::string_view name;
            std::optional<std::string> OptionsArgs::* member;
            StringOptionKind kind;
        };

        constexpr std::array<BoolOptionDesc, 14> kBoolOptions{{
            {"cygnos", &OptionsArgs::cygnos},
            {"demon", &OptionsArgs::demon},
            {"olddvd", &OptionsArgs::olddvd},
            {"nodvd", &OptionsArgs::nodvd},
            {"nomobile", &OptionsArgs::nomobile},
            {"noremap", &OptionsArgs::noremap},
            {"noecdremap", &OptionsArgs::noecdremap},
            {"nandmu", &OptionsArgs::nandmu},
            {"nosecurity", &OptionsArgs::nosecurity},
            {"nosusecurity", &OptionsArgs::nosusecurity},
            {"smcnocheck", &OptionsArgs::smcnocheck},
            {"nochecksmc", &OptionsArgs::smcnocheck},
            {"noblpatch", &OptionsArgs::noblpatch},
            {"nosmcpatch", &OptionsArgs::nosmcpatch},
        }};

        constexpr std::array<StringOptionDesc, 22> kStringOptions{{
            {"nopatch", &OptionsArgs::nopatch, StringOptionKind::Nopatch},
            {"cbldv", &OptionsArgs::cbldv, StringOptionKind::Raw},
            {"pairing_data", &OptionsArgs::pairing_data, StringOptionKind::Raw},
            {"pairingdata", &OptionsArgs::pairing_data, StringOptionKind::Raw},
            {"pd", &OptionsArgs::pairing_data, StringOptionKind::Raw},
            {"cfldv", &OptionsArgs::cfldv, StringOptionKind::Raw},
            {"xellbutton", &OptionsArgs::xellbutton, StringOptionKind::Button},
            {"xellbutton2", &OptionsArgs::xellbutton2, StringOptionKind::Button},
            {"dualboot", &OptionsArgs::dualboot, StringOptionKind::Button},
            {"cputemp", &OptionsArgs::cputemp, StringOptionKind::U32},
            {"gputemp", &OptionsArgs::gputemp, StringOptionKind::U32},
            {"edramtemp", &OptionsArgs::edramtemp, StringOptionKind::U32},
            {"overcputemp", &OptionsArgs::overcputemp, StringOptionKind::U32},
            {"overgputemp", &OptionsArgs::overgputemp, StringOptionKind::U32},
            {"overedramtemp", &OptionsArgs::overedramtemp, StringOptionKind::U32},
            {"cpufan", &OptionsArgs::cpufan, StringOptionKind::U32},
            {"gpufan", &OptionsArgs::gpufan, StringOptionKind::U32},
            {"avregion", &OptionsArgs::avregion, StringOptionKind::U32},
            {"dvdregion", &OptionsArgs::dvdregion, StringOptionKind::U32},
            {"gameregion", &OptionsArgs::gameregion, StringOptionKind::U16},
            {"macid", &OptionsArgs::macid, StringOptionKind::MacId},
            {"dvdkey", &OptionsArgs::dvdkey, StringOptionKind::DvdKey},
        }};

        const BoolOptionDesc* find_bool_option(std::string_view key) {
            for (const auto& desc : kBoolOptions) {
                if (desc.name == key) {
                    return &desc;
                }
            }
            return nullptr;
        }

        const StringOptionDesc* find_string_option(std::string_view key) {
            for (const auto& desc : kStringOptions) {
                if (desc.name == key) {
                    return &desc;
                }
            }
            return nullptr;
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
        return find_bool_option(key) != nullptr || find_string_option(key) != nullptr;
    }

    bool OptionsManager::is_bool_option(std::string_view name) {
        return find_bool_option(normalize_key(name)) != nullptr;
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
        key = utils::to_lower(key);
        const auto found = std::find_if(kReasons.begin(), kReasons.end(),
                                        [&key](const auto& reason) { return reason.first == key; });
        if (found == kReasons.end()) {
            return std::nullopt;
        }
        return found->second;
    }

    std::optional<uint32_t> OptionsManager::parse_u32(std::string_view raw) {
        std::string_view text = utils::trim_view(raw);
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
        const std::string_view trimmed = utils::trim_view(raw);
        std::string stripped;
        stripped.reserve(trimmed.size());
        for (char c : trimmed) {
            if (c != ':') {
                stripped.push_back(c);
            }
        }
        return utils::decode_hex_bytes<6>(stripped);
    }

    std::optional<std::array<uint8_t, 16>> OptionsManager::parse_dvd_key(std::string_view raw) {
        return utils::decode_hex_bytes<16>(utils::trim_view(raw));
    }

    bool OptionsManager::has(std::string_view name) const {
        const std::string key = normalize_key(name);
        if (const auto* bool_opt = find_bool_option(key)) {
            return (m_args.*(bool_opt->member)).has_value();
        }
        if (const auto* str_opt = find_string_option(key)) {
            return (m_args.*(str_opt->member)).has_value();
        }
        return false;
    }

    bool OptionsManager::set_bool(std::string_view name, bool value) {
        const auto* bool_opt = find_bool_option(normalize_key(name));
        if (!bool_opt) {
            return false;
        }
        m_args.*(bool_opt->member) = value;
        return true;
    }

    bool OptionsManager::set(std::string_view name, std::string_view value) {
        const std::string key = normalize_key(name);
        const std::string val = trim_str(value);

        if (const auto* bool_opt = find_bool_option(key)) {
            const auto parsed_b = parse_bool_value(val);
            if (!parsed_b) {
                return false;
            }
            m_args.*(bool_opt->member) = *parsed_b;
            return true;
        }

        const auto* str_opt = find_string_option(key);
        if (!str_opt) {
            return false;
        }

        auto& target = m_args.*(str_opt->member);
        switch (str_opt->kind) {
            case StringOptionKind::Raw:
                target = val;
                return true;
            case StringOptionKind::Nopatch: {
                if (val.empty()) {
                    target.reset();
                    return true;
                }
                const auto stages = add_nopatch_stage(target, val);
                if (!stages) {
                    return false;
                }
                target = *stages;
                return true;
            }
            case StringOptionKind::Button:
                return set_validated_option(target, val, power_on_reason);
            case StringOptionKind::U32:
                return set_validated_option(target, val, parse_u32);
            case StringOptionKind::U16:
                return set_validated_option(target, val, parse_u16);
            case StringOptionKind::MacId:
                return set_validated_option(target, val, parse_mac_id);
            case StringOptionKind::DvdKey:
                return set_validated_option(target, val, parse_dvd_key);
        }
        std::unreachable();
    }

    std::optional<bool> OptionsManager::get_bool(std::string_view name) const {
        const auto* bool_opt = find_bool_option(normalize_key(name));
        return bool_opt ? m_args.*(bool_opt->member) : std::nullopt;
    }

    std::optional<std::string> OptionsManager::get_string(std::string_view name) const {
        const auto* str_opt = find_string_option(normalize_key(name));
        return str_opt ? m_args.*(str_opt->member) : std::nullopt;
    }

    bool OptionsManager::parse(std::string_view raw_args) {
        bool all_ok = true;
        size_t start = 0;
        while (start < raw_args.size()) {
            size_t end = raw_args.find_first_of(";,", start);
            if (end == std::string_view::npos) {
                end = raw_args.size();
            }

            const std::string_view token =
                utils::trim_view(raw_args.substr(start, end - start));

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

} // namespace gxbuild
