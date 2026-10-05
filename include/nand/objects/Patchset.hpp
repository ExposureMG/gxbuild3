#pragma once
#include "Args.hpp"

#include <cstdint>
#include <expected>
#include <span>
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

struct PatchError {
    std::string message;
};

namespace BinaryParser {
    bool ParsePatchSet(std::span<const uint8_t> data, BuildType buildType,
                       ParsedPatchSet& outPatchSet);
    std::expected<ParsedPatchSet, PatchError> ParseAndMergePatchSet(const InputPatches& patches,
                                                                    BuildType buildType);
    std::vector<uint8_t> SerializePatchSet(const ParsedPatchSet& patchSet);
    std::vector<uint8_t> SerializeKhvPayload(const ParsedPatchSection& section);
} // namespace BinaryParser
