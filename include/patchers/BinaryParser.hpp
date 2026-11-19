#pragma once
#include "Args.hpp"
#include "Utils.hpp"

#include <cstdint>
#include <string>
#include <vector>

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

enum class PatchSectionEncoding {
    RawBuffer,
    XePatch,
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
    PatchSectionEncoding encoding{PatchSectionEncoding::RawBuffer};
    std::string identifier;
    std::vector<uint8_t> raw_data;
    std::vector<XePatchEntry> entries;
};

struct ParsedPatchSet {
    PatchSetKind kind{PatchSetKind::Glitch};
    std::vector<ParsedPatchSection> sections;
};

namespace BinaryParser {
    bool ParsePatchFile(const std::string& filePath, std::vector<XePatchSection>& outSections);
    bool ParsePatchSet(const std::string& filePath, BuildType buildType, ParsedPatchSet& outPatchSet);
    std::vector<uint8_t> SerializePatchSet(const ParsedPatchSet& patchSet);
}
