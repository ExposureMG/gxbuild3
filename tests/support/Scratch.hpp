#pragma once

// Per-test scratch directories and the tracked fixture directory.
//
// ScratchDir creates <GXBUILD3_TEST_SCRATCH_ROOT>/<Suite>.<Test>.<pid>.<n> (n counts the
// directories this process made, so one test may hold several) and removes it again when it
// goes out of scope, unless the test failed and GXBUILD3_KEEP_SCRATCH is set. Tests never
// write to /tmp, ::testing::TempDir(), a fixed name, the working directory or tests/.

#include "Error.hpp"
#include "Expect.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string_view>

namespace gxbuild3::test {

    // The build tree's test-scratch directory every ScratchDir lives under.
    [[nodiscard]] std::filesystem::path scratch_root();

    class ScratchDir {
      public:
        ScratchDir();
        ~ScratchDir();
        ScratchDir(const ScratchDir&) = delete;
        ScratchDir& operator=(const ScratchDir&) = delete;

        [[nodiscard]] const std::filesystem::path& path() const { return path_; }

      private:
        std::filesystem::path path_;
    };

    // Changes the working directory for a scope and restores it in the destructor, so it is
    // restored even when an ASSERT returns early.
    class ScopedCurrentPath {
      public:
        explicit ScopedCurrentPath(const std::filesystem::path& directory);
        ~ScopedCurrentPath();
        ScopedCurrentPath(const ScopedCurrentPath&) = delete;
        ScopedCurrentPath& operator=(const ScopedCurrentPath&) = delete;

      private:
        std::filesystem::path previous_;
    };

    // Fixture with one ScratchDir per test. write() creates parent directories and records a
    // test failure (returning the path anyway) when the file cannot be written.
    class ScratchTest : public ::testing::Test {
      protected:
        void SetUp() override;
        void TearDown() override;

        [[nodiscard]] const std::filesystem::path& root() const;
        std::filesystem::path write(const std::filesystem::path& relative,
                                    std::span<const uint8_t> bytes) const;
        std::filesystem::path write(const std::filesystem::path& relative,
                                    std::string_view text) const;

      private:
        std::optional<ScratchDir> scratch_;
    };

    // Writes bytes to path, creating parent directories.
    [[nodiscard]] Result<> write_file(const std::filesystem::path& path,
                                      std::span<const uint8_t> bytes);
    [[nodiscard]] Result<Bytes> read_file(const std::filesystem::path& path);

    // tests/gxBuild-support-files, or the directory named by env_override when that variable is
    // set and not empty.
    [[nodiscard]] std::filesystem::path support_dir(const char* env_override = nullptr);
    [[nodiscard]] Result<Bytes> read_support_file(const std::filesystem::path& relative,
                                                  const char* env_override = nullptr);

} // namespace gxbuild3::test
