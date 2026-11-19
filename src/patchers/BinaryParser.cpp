#include "patchers/BinaryParser.hpp"

#include "Utils.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>

namespace {

constexpr uint32_t kSectionDelimiter = 0xFFFFFFFFU;

bool ReadFileBytes(const std::string& filePath, std::vector<uint8_t>& outData) {
    outData.clear();

    if (filePath.length() < 4) {
        return false;
    }
    std::string ext = filePath.substr(filePath.length() - 4);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if (ext != ".bin" && ext != "rglp") {
        return false;
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    outData.assign(std::istreambuf_iterator<char>(file), {});
    return static_cast<bool>(file) || file.eof();
}

bool ReadBe32(const std::vector<uint8_t>& data, size_t offset, uint32_t& outValue) {
    if (offset + sizeof(uint32_t) > data.size()) {
        return false;
    }

    std::memcpy(&outValue, data.data() + offset, sizeof(uint32_t));
    outValue = swap32(outValue);
    return true;
}

void AppendBe32(std::vector<uint8_t>& data, uint32_t value) {
    value = swap32(value);
    const auto* value_bytes = reinterpret_cast<const uint8_t*>(&value);
    data.insert(data.end(), value_bytes, value_bytes + sizeof(uint32_t));
}

bool ParseXePatchSectionBytes(const std::vector<uint8_t>& data, size_t startOffset,
                              std::vector<XePatchEntry>& outEntries, size_t& outConsumed) {
    outEntries.clear();
    outConsumed = 0;

    size_t cursor = startOffset;
    while (true) {
        uint32_t address = 0;
        if (!ReadBe32(data, cursor, address)) {
            return false;
        }
        cursor += sizeof(uint32_t);

        if (address == kSectionDelimiter) {
            outConsumed = cursor - startOffset;
            return true;
        }

        uint32_t length = 0;
        if (!ReadBe32(data, cursor, length)) {
            return false;
        }
        cursor += sizeof(uint32_t);

        const uint64_t wordsByteCount = static_cast<uint64_t>(length) * sizeof(uint32_t);
        if (cursor + wordsByteCount > data.size()) {
            return false;
        }

        XePatchEntry entry;
        entry.address = address;
        entry.length = length;
        entry.words.resize(length);

        for (uint32_t i = 0; i < length; ++i) {
            if (!ReadBe32(data, cursor, entry.words[i])) {
                return false;
            }
            cursor += sizeof(uint32_t);
        }

        outEntries.push_back(std::move(entry));
    }
}

bool SplitRawSections(const std::vector<uint8_t>& data, size_t expectedSectionCount,
                      std::vector<std::vector<uint8_t>>& outSections) {
    outSections.clear();

    size_t sectionStart = 0;
    size_t cursor = 0;
    while (cursor + sizeof(uint32_t) <= data.size()) {
        uint32_t word = 0;
        if (!ReadBe32(data, cursor, word)) {
            return false;
        }

        if (word == kSectionDelimiter) {
            outSections.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(sectionStart),
                                     data.begin() + static_cast<std::ptrdiff_t>(cursor));
            cursor += sizeof(uint32_t);
            sectionStart = cursor;
            continue;
        }

        cursor += sizeof(uint32_t);
    }

    outSections.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(sectionStart), data.end());
    return outSections.size() == expectedSectionCount;
}

std::optional<PatchSetKind> ResolvePatchSetKind(BuildType buildType) {
    switch (buildType) {
        case BuildType::Jtag:
            return PatchSetKind::Jtag;
        case BuildType::Glitch:
        case BuildType::Glitch2:
        case BuildType::Glitch2m:
        case BuildType::Glitch3:
            return PatchSetKind::Glitch;
        default:
            return std::nullopt;
    }
}

PatchSectionTarget ResolveGlitchSection1Target(BuildType buildType) {
    return buildType == BuildType::Glitch ? PatchSectionTarget::Cb : PatchSectionTarget::Cbb;
}

} // namespace

namespace BinaryParser {

    bool ParsePatchFile(const std::string& filePath, std::vector<XePatchSection>& outSections) {
        outSections.clear();

        std::vector<uint8_t> fileData;
        if (!ReadFileBytes(filePath, fileData)) {
            return false;
        }

        XePatchSection currentSection;
        size_t cursor = 0;
        while (cursor < fileData.size()) {
            std::vector<XePatchEntry> entries;
            size_t consumed = 0;
            if (!ParseXePatchSectionBytes(fileData, cursor, entries, consumed)) {
                if (cursor == fileData.size()) {
                    break;
                }
                return false;
            }
            cursor += consumed;
            currentSection.entries = std::move(entries);
            if (!currentSection.entries.empty()) {
                outSections.push_back(currentSection);
                currentSection.entries.clear();
            }
            if (cursor >= fileData.size()) {
                break;
            }
        }

        return true;
    }

    bool ParsePatchSet(const std::string& filePath, BuildType buildType,
                       ParsedPatchSet& outPatchSet) {
        outPatchSet.sections.clear();

        const auto patchSetKind = ResolvePatchSetKind(buildType);
        if (!patchSetKind) {
            return false;
        }

        std::vector<uint8_t> fileData;
        if (!ReadFileBytes(filePath, fileData)) {
            return false;
        }

        outPatchSet.kind = *patchSetKind;

        if (*patchSetKind == PatchSetKind::Jtag) {
            std::vector<std::vector<uint8_t>> rawSections;
            if (!SplitRawSections(fileData, 4, rawSections)) {
                return false;
            }

            const PatchSectionTarget targets[4] = {
                PatchSectionTarget::JtagSection1,
                PatchSectionTarget::JtagSection2,
                PatchSectionTarget::JtagSection3,
                PatchSectionTarget::JtagSection4,
            };

            for (size_t i = 0; i < rawSections.size(); ++i) {
                ParsedPatchSection section;
                section.target = targets[i];
                section.encoding = PatchSectionEncoding::RawBuffer;
                section.identifier = "jtag_section_" + std::to_string(i + 1);
                section.raw_data = std::move(rawSections[i]);
                outPatchSet.sections.push_back(std::move(section));
            }

            return true;
        }

        size_t cursor = 0;
        for (size_t i = 0; i < 2; ++i) {
            ParsedPatchSection section;
            section.encoding = PatchSectionEncoding::XePatch;
            section.target = i == 0 ? ResolveGlitchSection1Target(buildType) : PatchSectionTarget::Cd;
            section.identifier = i == 0
                                     ? (section.target == PatchSectionTarget::Cb ? "cb" : "cbb")
                                     : "cd";

            size_t consumed = 0;
            if (!ParseXePatchSectionBytes(fileData, cursor, section.entries, consumed)) {
                return false;
            }
            cursor += consumed;
            outPatchSet.sections.push_back(std::move(section));
        }

        ParsedPatchSection khvSection;
        khvSection.target = PatchSectionTarget::Khv;
        khvSection.encoding = PatchSectionEncoding::RawBuffer;
        khvSection.identifier = "khv";
        khvSection.raw_data.assign(fileData.begin() + static_cast<std::ptrdiff_t>(cursor),
                                   fileData.end());
        outPatchSet.sections.push_back(std::move(khvSection));

        return true;
    }

    std::vector<uint8_t> SerializePatchSet(const ParsedPatchSet& patchSet) {
        std::vector<uint8_t> out;

        for (size_t i = 0; i < patchSet.sections.size(); ++i) {
            const auto& section = patchSet.sections[i];
            if (section.encoding == PatchSectionEncoding::XePatch) {
                for (const auto& entry : section.entries) {
                    AppendBe32(out, entry.address);
                    AppendBe32(out, entry.length);
                    for (const auto word : entry.words) {
                        AppendBe32(out, word);
                    }
                }
            } else {
                out.insert(out.end(), section.raw_data.begin(), section.raw_data.end());
            }

            if (i + 1 < patchSet.sections.size()) {
                AppendBe32(out, kSectionDelimiter);
            }
        }

        return out;
    }

} // namespace BinaryParser
