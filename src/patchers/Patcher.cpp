#include "patchers/Patcher.hpp"

#include "Wire.hpp"
#include "utils/Log.hpp"

#include <cstdint>
#include <cstring>
#include <format>
#include <utility>

namespace gxbuild3::patchers {

    Result<> apply_patch(uint8_t* data, uint32_t dataSize, uint32_t address, uint32_t length,
                         const uint32_t* patchWords) {
        if (!data || !patchWords) {
            return fail(ErrorCode::InvalidArgument, "invalid patch arguments (data={}, words={})",
                        data != nullptr, patchWords != nullptr);
        }

        uint64_t endOffset = static_cast<uint64_t>(address) + static_cast<uint64_t>(length) * 4;
        if (endOffset > dataSize) {
            return fail(ErrorCode::OutOfRange,
                        "patch write out of range (address=0x{:X}, length=0x{:X} words, "
                        "end=0x{:X}, buffer=0x{:X})",
                        address, length, endOffset, dataSize);
        }

        for (uint32_t i = 0; i < length; i++) {
            uint32_t targetAddr = address + i * 4;
            const auto image = wire::encode(wire::be32{patchWords[i]});

            std::memcpy(data + targetAddr, image.data(), image.size());
        }

        return {};
    }

    Result<> apply_patch_entry(uint8_t* data, uint32_t dataSize, const nand::XePatchEntry& entry) {
        if (entry.words.size() < entry.length) {
            return fail(ErrorCode::Malformed,
                        "entry word count mismatch (address=0x{:X}, length_words=0x{:X}, "
                        "words_available=0x{:X})",
                        entry.address, entry.length, entry.words.size());
        }

        return apply_patch(data, dataSize, entry.address, entry.length, entry.words.data());
    }

    Result<> apply_patch_section(uint8_t* data, uint32_t dataSize,
                                 const nand::XePatchSection& section) {
        Log::Info("Applying section '{}' with {} entries to buffer 0x{:X} bytes",
                  section.identifier, section.entries.size(), dataSize);

        for (size_t entry_index = 0; entry_index < section.entries.size(); ++entry_index) {
            const auto& entry = section.entries[entry_index];
            Log::Debug(
                "Section '{}' entry {} -> address 0x{:X}, length_words 0x{:X}, length_bytes 0x{:X}",
                section.identifier, entry_index, entry.address, entry.length, entry.length * 4U);

            auto applied = apply_patch_entry(data, dataSize, entry);
            if (!applied) {
                return std::unexpected(
                    std::move(applied.error())
                        .add_context(
                            std::format("section '{}' entry {}", section.identifier, entry_index)));
            }
        }

        Log::Info("Section '{}' applied successfully", section.identifier);
        return {};
    }

} // namespace gxbuild3::patchers
