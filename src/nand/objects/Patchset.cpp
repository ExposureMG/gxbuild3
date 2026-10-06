#include "nand/objects/Patchset.hpp"

#include "Wire.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <span>

namespace gxbuild3::nand {

    namespace {

        constexpr uint32_t kSectionDelimiter = 0xFFFFFFFFU;

        struct XePatchSectionBytes {
            std::vector<XePatchEntry> entries;
            size_t consumed = 0;
        };

        [[nodiscard]] Result<XePatchSectionBytes>
        parse_xe_patch_section_bytes(std::span<const uint8_t> data, size_t startOffset) {
            XePatchSectionBytes parsed;

            wire::Cursor cursor(data.subspan(startOffset), startOffset);
            while (true) {
                const auto address = cursor.take<wire::be32>("patch entry address");
                if (!address) {
                    return std::unexpected(address.error());
                }
                const uint32_t entryAddress = *address;

                if (entryAddress == kSectionDelimiter) {
                    parsed.consumed = cursor.offset() - startOffset;
                    return parsed;
                }

                auto length = cursor.take<wire::be32>("patch entry length");
                if (!length) {
                    return std::unexpected(std::move(length.error())
                                               .add_context(std::format(
                                                   "entry at 0x{:X} has no length", entryAddress)));
                }
                const uint32_t wordCount = *length;

                if (wordCount > cursor.remaining() / sizeof(uint32_t)) {
                    return fail(ErrorCode::Truncated,
                                "entry at 0x{:X} needs {} words but only 0x{:X} bytes remain",
                                entryAddress, wordCount, cursor.remaining());
                }

                XePatchEntry entry;
                entry.address = entryAddress;
                entry.length = wordCount;
                entry.words.resize(wordCount);

                for (auto& word : entry.words) {
                    const auto value = cursor.take<wire::be32>("patch entry word");
                    if (!value) {
                        return std::unexpected(value.error());
                    }
                    word = *value;
                }

                parsed.entries.push_back(std::move(entry));
            }
        }

        std::vector<std::vector<uint8_t>> split_raw_sections(std::span<const uint8_t> data) {
            std::vector<std::vector<uint8_t>> sections;

            size_t sectionStart = 0;
            size_t cursor = 0;
            while (cursor + sizeof(uint32_t) <= data.size()) {
                const auto word = wire::read<wire::be32>(data, cursor, "patchset word");
                if (word && *word == kSectionDelimiter) {
                    sections.emplace_back(data.begin() + sectionStart, data.begin() + cursor);
                    cursor += sizeof(uint32_t);
                    sectionStart = cursor;
                    continue;
                }

                cursor += sizeof(uint32_t);
            }

            if (sectionStart < data.size()) {
                sections.emplace_back(data.begin() + sectionStart, data.end());
            }
            return sections;
        }

        std::optional<PatchSetKind> resolve_patch_set_kind(BuildType buildType) {
            switch (buildType) {
                case BuildType::Jtag:
                    return PatchSetKind::Jtag;
                case BuildType::Glitch:
                case BuildType::Glitch2:
                case BuildType::Glitch2m:
                case BuildType::Glitch3:
                case BuildType::Devgl:
                    return PatchSetKind::Glitch;
                default:
                    return std::nullopt;
            }
        }

        PatchSectionTarget resolve_glitch_section1_target(BuildType buildType) {
            return buildType == BuildType::Glitch ? PatchSectionTarget::Cb
                                                  : PatchSectionTarget::Cbb;
        }

    } // namespace

    Result<ParsedPatchSet> parse_patch_set(std::span<const uint8_t> fileData, BuildType buildType) {
        ParsedPatchSet parsed;

        const auto patchSetKind = resolve_patch_set_kind(buildType);
        if (!patchSetKind) {
            return fail(ErrorCode::Unsupported, "build type {} takes no patchset",
                        static_cast<int>(buildType));
        }

        parsed.kind = *patchSetKind;
        // A devgl image reads the glitch2m patch file and lays its patch slot the same way:
        // fuses first, the KHV payload at 0x60.
        parsed.manufacturing = buildType == BuildType::Glitch2m || buildType == BuildType::Devgl;

        if (*patchSetKind == PatchSetKind::Jtag) {
            auto rawSections = split_raw_sections(fileData);
            if (rawSections.size() != 4) {
                return fail(ErrorCode::Malformed, "JTAG patchset must have 4 sections, found {}",
                            rawSections.size());
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
                section.identifier = "jtag_section_" + std::to_string(i + 1);
                section.raw_data = std::move(rawSections[i]);
                parsed.sections.push_back(std::move(section));
            }

            Log::Debug("Parsed JTAG patchset bytes (4 sections)");
            return parsed;
        }

        const auto glitchSections = split_raw_sections(fileData);
        if (glitchSections.size() != 3) {
            return fail(ErrorCode::Malformed,
                        "Glitch patchset must have 3 sections [CB_B][CD][KHV], found {}",
                        glitchSections.size());
        }

        size_t cursor = 0;
        for (size_t i = 0; i < 2; ++i) {
            ParsedPatchSection section;
            section.target =
                i == 0 ? resolve_glitch_section1_target(buildType) : PatchSectionTarget::Cd;
            section.identifier =
                i == 0 ? (section.target == PatchSectionTarget::Cb ? "cb" : "cbb") : "cd";

            auto sectionBytes = parse_xe_patch_section_bytes(fileData, cursor);
            if (!sectionBytes) {
                return std::unexpected(
                    std::move(sectionBytes.error())
                        .add_context(std::format("{} patch section", section.identifier)));
            }
            section.entries = std::move(sectionBytes->entries);
            cursor += sectionBytes->consumed;
            parsed.sections.push_back(std::move(section));
        }

        ParsedPatchSection khvSection;
        khvSection.target = PatchSectionTarget::Khv;
        khvSection.identifier = "khv";
        khvSection.raw_data.assign(fileData.begin() + cursor, fileData.end());
        if (khvSection.raw_data.size() >= sizeof(uint32_t)) {
            const auto tail = khvSection.raw_data.size() - sizeof(uint32_t);
            const auto word =
                wire::read<wire::be32>(khvSection.raw_data, tail, "KHV section delimiter");
            if (word && *word == kSectionDelimiter) {
                khvSection.raw_data.resize(tail);
            }
        }
        parsed.sections.push_back(std::move(khvSection));

        Log::Debug("Parsed Glitch patchset bytes ({} sections)", glitchSections.size());
        return parsed;
    }

    Result<ParsedPatchSet> parse_and_merge_patch_set(const InputPatches& patches,
                                                     BuildType buildType) {
        if (!patches.automatic) {
            return fail(ErrorCode::InvalidArgument, "An automatic patchset is required");
        }

        auto parsed = with_context(parse_patch_set(patches.automatic->data, buildType),
                                   patches.automatic->name.empty()
                                       ? std::string("automatic patchset")
                                       : "automatic patchset " + patches.automatic->name);
        if (!parsed) {
            return parsed;
        }

        const auto merge_target = parsed->kind == PatchSetKind::Glitch
                                      ? PatchSectionTarget::Khv
                                      : PatchSectionTarget::JtagSection4;
        const auto target = std::find_if(parsed->sections.begin(), parsed->sections.end(),
                                         [merge_target](const ParsedPatchSection& section) {
                                             return section.target == merge_target;
                                         });
        if (target == parsed->sections.end()) {
            return fail(ErrorCode::Internal, "Automatic patchset has no add-on target section");
        }

        for (const auto& addon : patches.addons) {
            target->raw_data.insert(target->raw_data.end(), addon.data.begin(), addon.data.end());
        }
        return parsed;
    }

    std::vector<uint8_t> serialize_patch_set(const ParsedPatchSet& patchSet) {
        std::vector<uint8_t> out;

        for (size_t i = 0; i < patchSet.sections.size(); ++i) {
            const auto& section = patchSet.sections[i];
            for (const auto& entry : section.entries) {
                wire::append(out, wire::be32{entry.address});
                wire::append(out, wire::be32{entry.length});
                for (const auto word : entry.words) {
                    wire::append(out, wire::be32{word});
                }
            }
            out.insert(out.end(), section.raw_data.begin(), section.raw_data.end());

            wire::append(out, wire::be32{kSectionDelimiter});
        }

        return out;
    }

    std::vector<uint8_t> serialize_khv_payload(const ParsedPatchSection& section) {
        std::vector<uint8_t> out = section.raw_data;
        wire::append(out, wire::be32{kSectionDelimiter});
        return out;
    }

} // namespace gxbuild3::nand
