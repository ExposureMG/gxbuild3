#pragma once
#include "Args.hpp"
#include "Error.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace gxbuild3::nand {

    struct XePatchEntry {
        uint32_t address;
        uint32_t length;
        std::vector<uint32_t> words;
    };

    struct XePatchSection {
        std::string identifier;
        std::vector<XePatchEntry> entries;
    };

    enum class PatchSetKind {
        Jtag,
        Glitch,
    };

    enum class PatchSectionTarget {
        Unknown,
        JtagSection1,
        JtagSection2,
        JtagSection3,
        JtagSection4,
        Cb,
        Cbb,
        Cd,
        Khv,
    };

    struct ParsedPatchSection {
        PatchSectionTarget target{PatchSectionTarget::Unknown};
        std::string identifier;
        std::vector<uint8_t> raw_data;
        std::vector<XePatchEntry> entries;
    };

    struct ParsedPatchSet {
        PatchSetKind kind{PatchSetKind::Glitch};
        bool manufacturing = false;
        std::vector<ParsedPatchSection> sections;
    };

    [[nodiscard]] Result<ParsedPatchSet> parse_patch_set(std::span<const uint8_t> data,
                                                         GxBuild::BuildType buildType);
    [[nodiscard]] Result<ParsedPatchSet>
    parse_and_merge_patch_set(const GxBuild::InputPatches& patches, GxBuild::BuildType buildType);
    std::vector<uint8_t> serialize_patch_set(const ParsedPatchSet& patchSet);
    std::vector<uint8_t> serialize_khv_payload(const ParsedPatchSection& section);

} // namespace gxbuild3::nand
