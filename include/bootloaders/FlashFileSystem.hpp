#pragma once

#include "Utils.hpp"
#include "utils/FlashBlockDriver.hpp"

#include <Log.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::bootloaders {

    /// @brief Maximum filename length for flash filesystem entries
    inline constexpr size_t kMaxFilenameLength = 0x16;

    /// @brief Maximum entries per page in filesystem
    inline constexpr size_t kMaxEntriesPerPage = 0x10;

    /// @brief Maximum blocks per page in blockmap
    inline constexpr size_t kMaxBlocksPerPage = 0x100;

    /// @brief Filesystem entry structure for Xbox 360 flash filesystem
    struct FlashFileSystemEntry {
        char filename[kMaxFilenameLength]{}; // File name (null-terminated)
        uint16_t block_number{};             // Starting block number in blockmap chain
        uint32_t length{};                   // File length in bytes
        uint32_t timestamp{};                // File timestamp

        /// @brief Check if entry is valid and active (not deleted, valid filename, block number, length)
        bool is_valid() const noexcept {
            if (block_number == 0 || block_number == 0xFFFF) return false;
            if (length == 0 || length == 0xFFFFFFFF) return false;
            const uint8_t first = static_cast<uint8_t>(filename[0]);
            if (first == '\0' || first == 0xFF || first == 0x05) return false; // 0x05 is deleted flag
            for (size_t i = 0; i < kMaxFilenameLength && filename[i] != '\0'; ++i) {
                const uint8_t c = static_cast<uint8_t>(filename[i]);
                if (c < 0x20 || c > 0x7E) return false;
            }
            return true;
        }

        /// @brief Check if filename matches (case-insensitive)
        bool filename_matches(std::string_view name) const noexcept {
            std::string_view self{filename};
            if (self.size() != name.size()) return false;
            for (size_t i = 0; i < self.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(self[i])) !=
                    std::tolower(static_cast<unsigned char>(name[i]))) {
                    return false;
                }
            }
            return true;
        }
    };

    /// @brief Corona filesystem data structure
    struct XeCoronaFsData {
        uint8_t section_digest[0x14]{}; // Digest of all the data
        uint32_t unknown1{};            // Unknown field
        uint32_t fs_version{};          // Filesystem version
        uint16_t fs_block_idx{};        // Filesystem block index
        uint16_t unknown2{};            // Unknown field
        uint16_t mobile1_block_idx{};   // Mobile data 1 block index
        uint16_t mobile1_length{};      // Mobile data 1 length
        uint8_t unknown3[0x8]{};        // Unknown data
        uint16_t mobile2_block_idx{};   // Mobile data 2 block index
        uint16_t mobile2_length{};      // Mobile data 2 length
        uint8_t reserved[0x1D0]{};      // Reserved space
    };

    /// @brief Chain allocation result
    struct ChainAllocationResult {
        bool success{};
        uint16_t block_index{};
    };

    /// @brief Flash filesystem class for managing Xbox 360 NAND flash filesystem operations
    /// This class handles file management on top of the FlashBlockDriver, providing
    /// chain management, file entry management, and filesystem I/O operations.
    class FlashFileSystem {
      public:
        // Construction and initialization

        /// @brief Default constructor
        explicit FlashFileSystem(std::shared_ptr<gxbuild3::utils::FlashBlockDriver> block_driver);

        /// @brief Constructor with Corona FS data
        /// @param block_driver The block driver to use
        /// @param corona_data Optional Corona filesystem data
        explicit FlashFileSystem(std::shared_ptr<gxbuild3::utils::FlashBlockDriver> block_driver,
                                 std::shared_ptr<XeCoronaFsData> corona_data);

        /// @brief Initialize a fresh filesystem layout similar to RGBuild's CreateDefaults()
        /// @param block_idx Root filesystem block index
        /// @param version Filesystem version / sequence
        /// @param sys_update_addr SysUpdateAddress from the NAND header
        /// @param reserve_config_blocks Whether to reserve the 5 config blocks
        /// @return true on success, false on invalid parameters
        bool create_defaults(uint16_t block_idx, uint32_t version, uint32_t sys_update_addr,
                             bool reserve_config_blocks = false);

        // Chain management

        /// @brief Allocate a single block in the chain
        /// @return ChainAllocationResult with success status and block index
        ChainAllocationResult allocate_block();

        /// @brief Allocate multiple contiguous blocks in the chain
        /// @param blocks_needed Number of blocks to allocate
        /// @param min_block Minimum block index to start searching from
        /// @return ChainAllocationResult with success status and starting block index
        ChainAllocationResult allocate_blocks(uint16_t blocks_needed, uint16_t min_block = 0);

        /// @brief Get the chain starting from a given block, following previous pointers
        /// @param start_block Starting block index
        /// @param chain_length Output parameter for chain length
        /// @return Vector of block indices in the chain, or nullopt on error
        std::optional<std::vector<uint16_t>> get_chain_from_start(uint16_t start_block,
                                                                  size_t& chain_length) const;

        /// @brief Get the previous block in a chain
        /// @param block_idx Current block index
        /// @return Previous block index, or 0 if none
        uint16_t get_previous_block(uint16_t block_idx) const;

        /// @brief Free a complete chain of blocks
        /// @param start_block Starting block index of the chain to free
        void free_chain(uint16_t start_block);

        /// @brief Get a chain of blocks starting from a given block
        /// @param start_block Starting block index
        /// @param chain_length Output parameter for chain length
        /// @return Vector of block indices in the chain, or nullopt on error
        std::optional<std::vector<uint16_t>> get_chain(uint16_t start_block,
                                                       size_t& chain_length) const;

        /// @brief Get a chain of blocks with a maximum length limit
        /// @param start_block Starting block index
        /// @param max_length Maximum number of blocks to include
        /// @param chain_length Output parameter for actual chain length
        /// @return Vector of block indices in the chain, or nullopt on error
        std::optional<std::vector<uint16_t>> get_chain(uint16_t start_block, size_t max_length,
                                                       size_t& chain_length) const;

        /// @brief Set data for a complete chain of blocks
        /// @param start_block Starting block index
        /// @param data Data to write
        /// @return Number of bytes written, or 0 on error
        size_t set_chain_data(uint16_t start_block, std::span<const uint8_t> data);

        // File operations

        /// @brief Search for a file entry by name
        /// @param filename Name of the file to search for
        /// @return Pointer to the file entry, or nullptr if not found
        const FlashFileSystemEntry* find_file(std::string_view filename) const;

        /// @brief Get file data
        /// @param entry File entry to read from
        /// @return File data as vector, or nullopt on error
        std::optional<std::vector<uint8_t>> get_file_data(const FlashFileSystemEntry& entry) const;

        /// @brief Set file data
        /// @param entry File entry to write to
        /// @param data Data to write
        /// @return true on success, false on error
        bool set_file_data(FlashFileSystemEntry& entry, std::span<const uint8_t> data);

        /// @brief Add a new file to the filesystem
        /// @param filename Name of the file to add
        /// @param entry Output parameter for the new file entry
        /// @return true on success, false on error (e.g., file already exists)
        bool add_file(std::string_view filename, FlashFileSystemEntry*& entry);

        /// @brief Find a file entry by name (alias for find_file)
        /// @param filename Name of the file to find
        /// @return Pointer to the file entry, or nullptr if not found
        const FlashFileSystemEntry* search_file(std::string_view filename) const;

        // Filesystem I/O

        /// @brief Load filesystem from a block
        /// @param block_idx Block index to load from
        /// @return true on success, false on error
        bool load(uint16_t block_idx);

        /// @brief Save filesystem to a block
        /// @param block_idx Block index to save to
        /// @return true on success, false on error
        bool save(uint16_t block_idx);

        // Accessors

        /// @brief Get the block driver
        const std::shared_ptr<gxbuild3::utils::FlashBlockDriver>& block_driver() const {
            return m_block_driver;
        }

        /// @brief Get filesystem version
        uint32_t version() const { return m_version; }

        /// @brief Get starting block index
        uint16_t start_block_idx() const { return m_start_block_idx; }

        /// @brief Get blockmap size
        size_t blockmap_size() const { return m_blockmap.size(); }

        /// @brief Get file entries
        const std::vector<FlashFileSystemEntry>& entries() const { return m_entries; }

        /// @brief Get number of file entries
        size_t entry_count() const { return m_entries.size(); }

        /// @brief Get Corona FS data
        const std::shared_ptr<XeCoronaFsData>& corona_data() const { return m_corona_data; }

      private:
        // Internal state

        std::shared_ptr<gxbuild3::utils::FlashBlockDriver> m_block_driver;
        std::shared_ptr<XeCoronaFsData> m_corona_data;
        uint32_t m_version{};
        uint16_t m_start_block_idx{};
        std::vector<uint16_t> m_blockmap;            // Block allocation map
        std::vector<FlashFileSystemEntry> m_entries; // File entries

        // Internal helpers

        /// @brief Internal method to find an entry by name
        FlashFileSystemEntry* find_entry_internal(std::string_view filename);

        /// @brief Internal method to find an entry by name (const)
        const FlashFileSystemEntry* find_entry_internal(std::string_view filename) const;
    };

} // namespace gxbuild3::bootloaders
