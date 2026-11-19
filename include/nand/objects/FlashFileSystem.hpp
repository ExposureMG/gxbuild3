#pragma once

#include "nand/FlashDriver.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::NAND {

    inline constexpr size_t kMaxFilenameLength = 0x16;
    inline constexpr size_t kEntriesPerPage = 16;
    inline constexpr size_t kBlocksPerPage = 256;
    inline constexpr size_t kCleanBlockSize = 0x4000;

    namespace BlockMapStatus {
        inline constexpr uint16_t Free = 0x1FFE;
        inline constexpr uint16_t EndOfChain = 0x1FFF;
        inline constexpr uint16_t Reserved = 0x1FFB;
        inline constexpr uint16_t BadBlock = 0x1FF0;
    }

#pragma pack(push, 1)
    struct FlashFileSystemEntry {
        char filename[kMaxFilenameLength]{};
        uint16_t block_number{};
        uint32_t length{};
        uint32_t timestamp{};

        [[nodiscard]] bool is_valid() const noexcept;
        [[nodiscard]] bool matches(std::string_view name) const noexcept;
    };
    static_assert(sizeof(FlashFileSystemEntry) == 32);
#pragma pack(pop)

    class FlashFileSystem {
      public:
        FlashFileSystem() = default;

        void set_driver(Driver* driver);

        bool format(size_t total_blocks, uint16_t root_block = 0x3E0, uint32_t version = 1,
                    uint32_t reserved_boundary = 0x50);
        bool load(Driver& driver, uint16_t root_block = 0x3E0);
        bool save();

        bool add_file(std::string_view filename, std::span<const uint8_t> data,
                      uint32_t timestamp = 0);
        [[nodiscard]] std::optional<std::vector<uint8_t>> get_file(std::string_view filename) const;
        bool delete_file(std::string_view filename);
        [[nodiscard]] bool exists(std::string_view filename) const;
        [[nodiscard]] std::vector<std::string> list_files() const;
        [[nodiscard]] std::optional<FlashFileSystemEntry> stat(std::string_view filename) const;

        [[nodiscard]] std::vector<uint8_t> serialize_root_block() const;
        [[nodiscard]] const std::vector<uint16_t>& blockmap() const;
        [[nodiscard]] const std::vector<FlashFileSystemEntry>& entries() const;
        [[nodiscard]] uint32_t version() const;
        [[nodiscard]] uint16_t root_block() const;

        [[nodiscard]] std::vector<uint16_t> get_chain(uint16_t start_block) const;
        [[nodiscard]] std::vector<uint16_t> get_all_file_blocks() const;
        std::optional<uint16_t> allocate_chain(size_t bytes_needed);
        void free_chain(uint16_t start_block);

      private:
        Driver* m_driver = nullptr;
        uint32_t m_version = 1;
        uint16_t m_root_block = 0x3E0;
        std::vector<uint16_t> m_blockmap;
        std::vector<FlashFileSystemEntry> m_entries;
        std::map<std::string, std::vector<uint8_t>> m_file_data;

        [[nodiscard]] FlashFileSystemEntry* find_entry(std::string_view filename);
        [[nodiscard]] const FlashFileSystemEntry* find_entry(std::string_view filename) const;
    };

} // namespace gxbuild3::NAND
