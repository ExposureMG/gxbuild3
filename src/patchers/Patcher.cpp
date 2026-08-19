#include "patchers/Patcher.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <cstdint>
#include <cstring>

namespace Source {

    bool ApplyPatch(uint8_t* data, uint32_t dataSize, uint32_t offset, const uint8_t* payload,
                    uint32_t payloadSize) {
        if (!data || !payload || payloadSize == 0) {
            return false;
        }

        uint64_t endOffset = static_cast<uint64_t>(offset) + static_cast<uint64_t>(payloadSize);
        if (endOffset > dataSize) {
            return false;
        }

        memcpy(data + offset, payload, payloadSize);
        return true;
    }

} // namespace Source

namespace XePatch {

    bool ApplyPatch(uint8_t* data, uint32_t dataSize, uint32_t address, uint32_t length,
                    const uint32_t* patchWords) {
        if (!data || !patchWords) {
            Log::Error("Invalid patch arguments (data={}, words={})", data != nullptr,
                       patchWords != nullptr);
            return false;
        }

        uint64_t endOffset = static_cast<uint64_t>(address) + static_cast<uint64_t>(length) * 4;
        if (endOffset > dataSize) {
            Log::Error(
                "Patch write out of range (address=0x{:X}, length=0x{:X} words, end=0x{:X}, buffer=0x{:X})",
                address, length, endOffset, dataSize);
            return false;
        }

        for (uint32_t i = 0; i < length; i++) {
            uint32_t targetAddr = address + i * 4;
            uint32_t beWord = swap32(patchWords[i]);

            memcpy(data + targetAddr, &beWord, sizeof(uint32_t));
        }

        return true;
    }

    bool ApplyPatchEntry(uint8_t* data, uint32_t dataSize, const XePatchEntry& entry) {
        if (entry.words.size() < entry.length) {
            Log::Error(
                "Entry word count mismatch (address=0x{:X}, length_words=0x{:X}, words_available=0x{:X})",
                entry.address, entry.length, entry.words.size());
            return false;
        }

        return ApplyPatch(data, dataSize, entry.address, entry.length, entry.words.data());
    }

    bool ApplyPatchSection(uint8_t* data, uint32_t dataSize, const XePatchSection& section) {
        Log::Info("Applying section '{}' with {} entries to buffer 0x{:X} bytes",
                  section.identifier, section.entries.size(), dataSize);

        for (size_t entry_index = 0; entry_index < section.entries.size(); ++entry_index) {
            const auto& entry = section.entries[entry_index];
            Log::Debug(
                "Section '{}' entry {} -> address 0x{:X}, length_words 0x{:X}, length_bytes 0x{:X}",
                section.identifier, entry_index, entry.address, entry.length, entry.length * 4U);

            if (!ApplyPatchEntry(data, dataSize, entry)) {
                Log::Error(
                    "Section '{}' failed at entry {} (address=0x{:X}, length_words=0x{:X}, buffer=0x{:X})",
                    section.identifier, entry_index, entry.address, entry.length, dataSize);
                return false;
            }
        }

        Log::Info("Section '{}' applied successfully", section.identifier);
        return true;
    }

} // namespace XePatch
