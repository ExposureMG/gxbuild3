#include "nand/objects/Patchset.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

    using Bytes = std::vector<uint8_t>;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    void append_be32(Bytes& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>(value >> 24));
        bytes.push_back(static_cast<uint8_t>(value >> 16));
        bytes.push_back(static_cast<uint8_t>(value >> 8));
        bytes.push_back(static_cast<uint8_t>(value));
    }

    Bytes glitch_patchset(std::span<const uint8_t> khv) {
        Bytes bytes;
        append_be32(bytes, 0x20);
        append_be32(bytes, 1);
        append_be32(bytes, 0x11223344);
        append_be32(bytes, 0xFFFFFFFF);
        append_be32(bytes, 0x30);
        append_be32(bytes, 1);
        append_be32(bytes, 0x55667788);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), khv.begin(), khv.end());
        return bytes;
    }

    Bytes jtag_patchset() {
        Bytes bytes{0x10, 0x10, 0x10, 0x10};
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x11);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x12);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x13);
        return bytes;
    }

    const ParsedPatchSection* find_section(const ParsedPatchSet& patchset,
                                           PatchSectionTarget target) {
        const auto found = std::find_if(
            patchset.sections.begin(), patchset.sections.end(),
            [target](const ParsedPatchSection& section) { return section.target == target; });
        return found == patchset.sections.end() ? nullptr : &*found;
    }

    bool test_byte_parser_uses_supplied_data() {
        const auto bytes = glitch_patchset(Bytes{0xA0, 0xA1});
        ParsedPatchSet parsed;
        if (!require(BinaryParser::ParsePatchSet(bytes, BuildType::Glitch2, parsed),
                     "in-memory glitch patchset parses")) {
            return false;
        }

        const auto* cbb = find_section(parsed, PatchSectionTarget::Cbb);
        const auto* cd = find_section(parsed, PatchSectionTarget::Cd);
        const auto* khv = find_section(parsed, PatchSectionTarget::Khv);
        return require(cbb && cbb->entries.size() == 1 && cbb->entries[0].address == 0x20,
                       "Glitch2 section one targets CBB") &&
               require(cd && cd->entries.size() == 1 && cd->entries[0].words[0] == 0x55667788,
                       "section two targets CD") &&
               require(khv && khv->raw_data == Bytes({0xA0, 0xA1}),
                       "raw KHV tail remains byte-exact");
    }

    bool test_glitch_addons_append_in_order() {
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"file-that-must-not-be-opened.bin", glitch_patchset(Bytes{0x10})};
        patches.addons = {{"first", {0x20}}, {"second", {0x30}}};

        const auto parsed = BinaryParser::ParseAndMergePatchSet(patches, BuildType::Glitch2);
        const auto* khv = parsed ? find_section(*parsed, PatchSectionTarget::Khv) : nullptr;
        return require(parsed.has_value(), "glitch patchset parses from supplied bytes") &&
               require(khv && khv->raw_data == Bytes({0x10, 0x20, 0x30}),
                       "glitch add-ons retain command order");
    }

    bool test_jtag_addons_append_in_order() {
        InputPatches patches{};
        patches.automatic = InputPatchFile{"unused-jtag-name.bin", jtag_patchset()};
        patches.addons = {{"first", {0x20}}, {"second", {0x30}}};

        const auto parsed = BinaryParser::ParseAndMergePatchSet(patches, BuildType::Jtag);
        const auto* section4 =
            parsed ? find_section(*parsed, PatchSectionTarget::JtagSection4) : nullptr;
        return require(parsed.has_value(), "JTAG patchset parses from supplied bytes") &&
               require(section4 &&
                           section4->raw_data == Bytes({0x13, 0x13, 0x13, 0x13, 0x20, 0x30}),
                       "JTAG add-ons retain command order in section four");
    }

    bool test_malformed_patchsets_fail_without_partial_output() {
        std::vector<std::pair<std::string_view, Bytes>> malformed;
        malformed.emplace_back("truncated address", Bytes{0x00, 0x00, 0x00});

        Bytes truncated_length;
        append_be32(truncated_length, 0x20);
        malformed.emplace_back("truncated length", truncated_length);

        Bytes truncated_word;
        append_be32(truncated_word, 0x20);
        append_be32(truncated_word, 1);
        truncated_word.insert(truncated_word.end(), {0x11, 0x22, 0x33});
        malformed.emplace_back("truncated patch word", truncated_word);

        Bytes truncated_delimiter;
        append_be32(truncated_delimiter, 0x20);
        append_be32(truncated_delimiter, 1);
        append_be32(truncated_delimiter, 0x11223344);
        truncated_delimiter.insert(truncated_delimiter.end(), {0xFF, 0xFF});
        malformed.emplace_back("truncated section delimiter", truncated_delimiter);

        Bytes partial_second_section;
        append_be32(partial_second_section, 0x20);
        append_be32(partial_second_section, 1);
        append_be32(partial_second_section, 0x11223344);
        append_be32(partial_second_section, 0xFFFFFFFF);
        partial_second_section.insert(partial_second_section.end(), {0x00, 0x00});
        malformed.emplace_back("partial second section", partial_second_section);

        for (const auto& [name, bytes] : malformed) {
            ParsedPatchSet parsed;
            parsed.sections.push_back(
                ParsedPatchSection{PatchSectionTarget::Khv, "sentinel", {0xAA}, {}});
            if (!require(!BinaryParser::ParsePatchSet(bytes, BuildType::Glitch, parsed), name) ||
                !require(parsed.sections.empty(), "failed parse leaves no partial sections")) {
                return false;
            }

            InputPatches patches{};
            patches.automatic = InputPatchFile{"unused", bytes};
            const auto merged =
                BinaryParser::ParseAndMergePatchSet(patches, BuildType::Glitch);
            if (!require(!merged.has_value() && !merged.error().message.empty(),
                         "merge reports deterministic malformed-byte error")) {
                return false;
            }
        }
        return true;
    }

    bool test_jtag_delimiter_count_and_unsupported_type_fail_cleanly() {
        Bytes three_sections(4, 0x10);
        append_be32(three_sections, 0xFFFFFFFF);
        three_sections.insert(three_sections.end(), 4, 0x11);
        append_be32(three_sections, 0xFFFFFFFF);
        three_sections.insert(three_sections.end(), 4, 0x12);

        ParsedPatchSet parsed;
        parsed.sections.push_back(
            ParsedPatchSection{PatchSectionTarget::Khv, "sentinel", {0xAA}, {}});
        if (!require(!BinaryParser::ParsePatchSet(three_sections, BuildType::Jtag, parsed),
                     "JTAG patchset with wrong delimiter count fails") ||
            !require(parsed.sections.empty(), "JTAG failure leaves no partial sections")) {
            return false;
        }

        parsed.sections.push_back(
            ParsedPatchSection{PatchSectionTarget::Khv, "sentinel", {0xAA}, {}});
        return require(
                   !BinaryParser::ParsePatchSet(glitch_patchset(Bytes{0x10}), BuildType::Retail,
                                                parsed),
                   "unsupported build type fails") &&
               require(parsed.sections.empty(), "unsupported type leaves no partial sections");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_byte_parser_uses_supplied_data() && passed;
    passed = test_glitch_addons_append_in_order() && passed;
    passed = test_jtag_addons_append_in_order() && passed;
    passed = test_malformed_patchsets_fail_without_partial_output() && passed;
    passed = test_jtag_delimiter_count_and_unsupported_type_fail_cleanly() && passed;
    return passed ? 0 : 1;
}
