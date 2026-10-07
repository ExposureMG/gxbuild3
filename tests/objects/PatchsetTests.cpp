// src/nand/objects/Patchset.hpp: patchsets parsed from the bytes handed in (never from the file
// name beside them), add-ons appended in command order to the KHV or JTAG section four tail, and
// malformed bytes, a wrong JTAG delimiter count or an unsupported build type refused.

#include "nand/objects/Patchset.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <initializer_list>
#include <span>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using GxBuild::BuildType;
        using GxBuild::InputPatches;
        using GxBuild::InputPatchFile;
        using test::append_be32;
        using test::Bytes;

        // Two one-entry glitch sections (CBB at 0x20, CD at 0x30), then the raw KHV tail.
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

        // Four raw JTAG sections of four bytes each (0x10..0x13), split by three delimiters.
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

        TEST(Patchset, ByteParserUsesSuppliedData) {
            const auto bytes = glitch_patchset(Bytes{0xA0, 0xA1});
            const auto parsed = parse_patch_set(bytes, BuildType::Glitch2);
            ASSERT_OK(parsed) << "in-memory glitch patchset parses";

            const auto* cbb = find_section(*parsed, PatchSectionTarget::Cbb);
            const auto* cd = find_section(*parsed, PatchSectionTarget::Cd);
            const auto* khv = find_section(*parsed, PatchSectionTarget::Khv);

            ASSERT_NE(cbb, nullptr) << "Glitch2 section one targets CBB";
            ASSERT_EQ(cbb->entries.size(), 1u) << "Glitch2 section one targets CBB";
            EXPECT_EQ(cbb->entries[0].address, 0x20u) << "Glitch2 section one targets CBB";

            ASSERT_NE(cd, nullptr) << "section two targets CD";
            ASSERT_EQ(cd->entries.size(), 1u) << "section two targets CD";
            ASSERT_FALSE(cd->entries[0].words.empty()) << "section two targets CD";
            EXPECT_EQ(cd->entries[0].words[0], 0x55667788u) << "section two targets CD";

            ASSERT_NE(khv, nullptr) << "raw KHV tail remains byte-exact";
            EXPECT_EQ(khv->raw_data, (Bytes{0xA0, 0xA1})) << "raw KHV tail remains byte-exact";
        }

        TEST(Patchset, GlitchAddonsAppendInOrder) {
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"file-that-must-not-be-opened.bin", glitch_patchset(Bytes{0x10})};
            patches.addons = {{"first", {0x20}}, {"second", {0x30}}};

            const auto parsed = parse_and_merge_patch_set(patches, BuildType::Glitch2);
            ASSERT_OK(parsed) << "glitch patchset parses from supplied bytes";
            const auto* khv = find_section(*parsed, PatchSectionTarget::Khv);
            ASSERT_NE(khv, nullptr) << "glitch add-ons retain command order";
            EXPECT_EQ(khv->raw_data, (Bytes{0x10, 0x20, 0x30}))
                << "glitch add-ons retain command order";
        }

        TEST(Patchset, JtagAddonsAppendInOrder) {
            InputPatches patches{};
            patches.automatic = InputPatchFile{"unused-jtag-name.bin", jtag_patchset()};
            patches.addons = {{"first", {0x20}}, {"second", {0x30}}};

            const auto parsed = parse_and_merge_patch_set(patches, BuildType::Jtag);
            ASSERT_OK(parsed) << "JTAG patchset parses from supplied bytes";
            const auto* section4 = find_section(*parsed, PatchSectionTarget::JtagSection4);
            ASSERT_NE(section4, nullptr) << "JTAG add-ons retain command order in section four";
            EXPECT_EQ(section4->raw_data, (Bytes{0x13, 0x13, 0x13, 0x13, 0x20, 0x30}))
                << "JTAG add-ons retain command order in section four";
        }

        TEST(Patchset, JtagDelimiterCountAndUnsupportedTypeFailCleanly) {
            Bytes three_sections(4, 0x10);
            append_be32(three_sections, 0xFFFFFFFF);
            three_sections.insert(three_sections.end(), 4, 0x11);
            append_be32(three_sections, 0xFFFFFFFF);
            three_sections.insert(three_sections.end(), 4, 0x12);

            EXPECT_FALSE(parse_patch_set(three_sections, BuildType::Jtag).has_value())
                << "JTAG patchset with wrong delimiter count fails";
            EXPECT_FALSE(
                parse_patch_set(glitch_patchset(Bytes{0x10}), BuildType::Retail).has_value())
                << "unsupported build type fails";
        }

        // A glitch patchset cut short at each field: refused by the parser and by the merge, which
        // reports a message instead of a partial patchset.
        struct MalformedRow {
            const char* name;
            const char* description;
            Bytes bytes;
        };
        GX_PRINT_ROW_AS_NAME(MalformedRow)

        Bytes be32_then(std::initializer_list<uint32_t> words,
                        std::initializer_list<uint8_t> tail) {
            Bytes bytes;
            for (const uint32_t word : words) {
                append_be32(bytes, word);
            }
            bytes.insert(bytes.end(), tail);
            return bytes;
        }

        std::vector<MalformedRow> malformed_rows() {
            return {
                {"TruncatedAddress", "truncated address", Bytes{0x00, 0x00, 0x00}},
                {"TruncatedLength", "truncated length", be32_then({0x20}, {})},
                {"TruncatedPatchWord", "truncated patch word",
                 be32_then({0x20, 1}, {0x11, 0x22, 0x33})},
                {"TruncatedSectionDelimiter", "truncated section delimiter",
                 be32_then({0x20, 1, 0x11223344}, {0xFF, 0xFF})},
                {"PartialSecondSection", "partial second section",
                 be32_then({0x20, 1, 0x11223344, 0xFFFFFFFF}, {0x00, 0x00})},
            };
        }

        class PatchsetMalformed : public ::testing::TestWithParam<MalformedRow> {};

        TEST_P(PatchsetMalformed, FailsWithoutPartialOutput) {
            const auto& row = GetParam();
            ASSERT_FALSE(parse_patch_set(row.bytes, BuildType::Glitch).has_value())
                << row.description;

            InputPatches patches{};
            patches.automatic = InputPatchFile{"unused", row.bytes};
            const auto merged = parse_and_merge_patch_set(patches, BuildType::Glitch);
            ASSERT_FALSE(merged.has_value()) << "merge reports deterministic malformed-byte error";
            EXPECT_FALSE(merged.error().message.empty())
                << "merge reports deterministic malformed-byte error";
        }

        INSTANTIATE_TEST_SUITE_P(Row, PatchsetMalformed, ::testing::ValuesIn(malformed_rows()),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::nand
