#include "patchers/Patcher.hpp"

#include "Log.hpp"
#include "Utils.hpp"

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
            Log::Error("xepatch: invalid patch arguments (data={}, words={})", data != nullptr,
                       patchWords != nullptr);
            return false;
        }

        uint64_t endOffset = static_cast<uint64_t>(address) + static_cast<uint64_t>(length) * 4;
        if (endOffset > dataSize) {
            Log::Error(
                "xepatch: patch write out of range (address=0x{:x}, length_words=0x{:x}, length_bytes=0x{:x}, end=0x{:x}, buffer=0x{:x})",
                address, length, length * 4U, endOffset, dataSize);
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
                "xepatch: entry word count mismatch (address=0x{:x}, length_words=0x{:x}, words_available=0x{:x})",
                entry.address, entry.length, entry.words.size());
            return false;
        }

        return ApplyPatch(data, dataSize, entry.address, entry.length, entry.words.data());
    }

    bool ApplyPatchSection(uint8_t* data, uint32_t dataSize, const XePatchSection& section) {
        Log::Info("xepatch: applying section '{}' with {} entries to buffer 0x{:x} bytes",
                  section.identifier, section.entries.size(), dataSize);

        for (size_t entry_index = 0; entry_index < section.entries.size(); ++entry_index) {
            const auto& entry = section.entries[entry_index];
            Log::Info(
                "xepatch: section '{}' entry {} -> address 0x{:x}, length_words 0x{:x}, length_bytes 0x{:x}",
                section.identifier, entry_index, entry.address, entry.length, entry.length * 4U);

            if (!ApplyPatchEntry(data, dataSize, entry)) {
                Log::Error(
                    "xepatch: section '{}' failed at entry {} (address=0x{:x}, length_words=0x{:x}, length_bytes=0x{:x}, buffer=0x{:x})",
                    section.identifier, entry_index, entry.address, entry.length,
                    entry.length * 4U, dataSize);
                return false;
            }
        }

        Log::Info("xepatch: section '{}' applied successfully", section.identifier);
        return true;
    }

} // namespace XePatch
