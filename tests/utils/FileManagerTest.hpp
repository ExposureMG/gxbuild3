#pragma once

// The fixture of the src/utils/FileManager.hpp tests (FileManagerLookup, FileManagerBootloader,
// FileManagerIni, FileManagerScan, FileManagerSymlink, FileManagerUnconfinedPath and
// FileManagerStfsCache, one-line subclasses per file so each suite bundles on its own) and the
// synthetic STFS packages they look assets up in.
//
// FileManagerTest works in its own ScratchDir: SetUp makes it the working directory (the
// read_ini_files convenience overload looks in ./mydata, ./version and ./common), seeds
// version/_test.ini with "[testbl] none, [flashfs] dash.xex" and clears the process-wide STFS,
// directory and derived-bootloader caches; TearDown clears them again and restores the working
// directory, so cases pass in any order in one process.

#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "utils/FileManager.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::utils {

    // STFS entries as {name, data}, in file-table order.
    using StfsFiles = std::vector<std::pair<std::string, test::Bytes>>;

    // One file-table block and one data block per file; no external firmware required. The
    // entry named corrupt_file gets an invalid block chain. Records a test failure and returns
    // an empty package when the files do not fit (fewer than 64 entries, names of at most 40
    // characters, at most 0x1000 bytes each).
    [[nodiscard]] test::Bytes make_simple_package(const StfsFiles& files,
                                                  std::string_view corrupt_file = {});

    // A synthetic xboxupd.bin: a 0x20-byte CF and a 0x20-byte CG, each stating `version`.
    [[nodiscard]] test::Bytes make_xboxupd(uint16_t version = 1);

    // The CF (first 0x20 bytes) and CG (the rest) halves of an xboxupd.bin.
    [[nodiscard]] test::Bytes xboxupd_cf(const test::Bytes& xboxupd);
    [[nodiscard]] test::Bytes xboxupd_cg(const test::Bytes& xboxupd);

    // The bytes of the FlashFS payload stored under `name`, or nullopt when there is none, so
    // a missing payload fails the comparison it is used in instead of being dereferenced.
    [[nodiscard]] std::optional<test::Bytes> payload(const IniFilesResult& result,
                                                     std::string_view name);

    class FileManagerTest : public test::ScratchTest {
      protected:
        void SetUp() override;
        void TearDown() override;

        // make_simple_package written to root() / relative.
        void write_stfs(const std::filesystem::path& relative, const StfsFiles& files,
                        std::string_view corrupt_file = {}) const;

      private:
        std::optional<test::ScopedCurrentPath> working_directory_;
    };

} // namespace gxbuild3::utils
