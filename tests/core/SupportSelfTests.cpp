// Self-tests of tests/support: Scratch.hpp (scratch directories, the working-directory guard,
// support files), Env.hpp (scoped environment, pinned build time) and Bytes.hpp.

#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "utils/BuildTime.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>

namespace gxbuild3::core {
    namespace {

        // ---- Scratch ---------------------------------------------------------------------

        class SupportScratch : public test::ScratchTest {};

        void fail_inside_the_scratch_root() {
            const test::ScopedCurrentPath inside{test::scratch_root()};
            FAIL() << "planted failure inside the scratch root";
        }

        TEST_F(SupportScratch, ScratchDirsAreDistinctAndLiveUnderTheScratchRoot) {
            const test::ScratchDir first;
            const test::ScratchDir second;
            EXPECT_NE(first.path(), second.path());
            EXPECT_TRUE(std::filesystem::is_directory(first.path()));
            EXPECT_TRUE(std::filesystem::is_directory(second.path()));
            EXPECT_EQ(first.path().parent_path(), test::scratch_root());
            EXPECT_EQ(root().parent_path(), test::scratch_root());
            const std::string name = first.path().filename().string();
            EXPECT_TRUE(name.starts_with(
                "SupportScratch.ScratchDirsAreDistinctAndLiveUnderTheScratchRoot."))
                << name;
        }

        TEST_F(SupportScratch, ScratchDirIsRemovedAtScopeEnd) {
            std::filesystem::path kept;
            {
                const test::ScratchDir scratch;
                kept = scratch.path();
                ASSERT_OK(test::write_file(kept / "nested" / "file.bin", test::Bytes{1, 2, 3}));
                ASSERT_TRUE(std::filesystem::exists(kept / "nested" / "file.bin"));
            }
            EXPECT_FALSE(std::filesystem::exists(kept)) << kept.string();
        }

        TEST_F(SupportScratch, WriteCreatesParentDirectoriesAndReadsBack) {
            const test::Bytes payload{0x00, 0x7F, 0x80, 0xFF};
            const auto binary = write("a/b/c.bin", payload);
            const auto text = write("notes/options.ini", std::string_view{"key=value\r\n"});
            EXPECT_EQ(binary, root() / "a/b/c.bin");
            ASSERT_OK_AND_ASSIGN(const auto read_binary, test::read_file(binary));
            EXPECT_BYTES_EQ(payload, read_binary);
            ASSERT_OK_AND_ASSIGN(const auto read_text, test::read_file(text));
            EXPECT_EQ(std::string(read_text.begin(), read_text.end()), "key=value\r\n");
            EXPECT_ERROR(test::read_file(root() / "missing.bin"), ErrorCode::NotFound);
        }

        TEST_F(SupportScratch, ScopedCurrentPathIsRestoredAfterAFatalFailure) {
            const auto before = std::filesystem::current_path();
            EXPECT_FATAL_FAILURE(fail_inside_the_scratch_root(), "planted failure");
            EXPECT_EQ(std::filesystem::current_path(), before);
            {
                const test::ScopedCurrentPath inside{root()};
                EXPECT_TRUE(std::filesystem::equivalent(std::filesystem::current_path(), root()));
            }
            EXPECT_EQ(std::filesystem::current_path(), before);
        }

        // ---- Env -------------------------------------------------------------------------

        constexpr const char* kProbe = "GXBUILD3_SUPPORT_ENV_PROBE";

        TEST(SupportEnv, ScopedEnvRestoresAPreviousValue) {
            const test::ScopedEnv outer{kProbe, "outer"};
            {
                const test::ScopedEnv inner{kProbe, "inner"};
                EXPECT_EQ(test::env_value(kProbe), "inner");
            }
            EXPECT_EQ(test::env_value(kProbe), "outer");
            {
                const test::ScopedEnv unset{kProbe, std::nullopt};
                EXPECT_FALSE(test::env_value(kProbe).has_value());
            }
            EXPECT_EQ(test::env_value(kProbe), "outer");
        }

        TEST(SupportEnv, ScopedEnvRestoresAPreviouslyUnsetVariable) {
            const test::ScopedEnv cleared{kProbe, std::nullopt};
            {
                const test::ScopedEnv set{kProbe, "value"};
                EXPECT_EQ(test::env_value(kProbe), "value");
            }
            EXPECT_FALSE(test::env_value(kProbe).has_value());
        }

        TEST(SupportEnv, PinnedBuildTimeSetsEpochAndZoneAndRestoresBoth) {
            const test::ScopedEnv epoch{"SOURCE_DATE_EPOCH", "12345"};
            const test::ScopedTimeZone tokyo{"JST-9"};
            const uint32_t tokyo_stamp = utils::flashfs_build_timestamp(1791105724);
            uint32_t pinned_stamp = 0;
            {
                const test::PinnedBuildTime pinned;
                EXPECT_EQ(test::env_value("SOURCE_DATE_EPOCH"), "1791105724");
                EXPECT_EQ(test::env_value("TZ"), "UTC");
                EXPECT_EQ(utils::build_epoch(), 1791105724);
                pinned_stamp = utils::flashfs_build_timestamp(utils::build_epoch());
            }
            {
                const test::ScopedTimeZone utc{"UTC0"};
                EXPECT_EQ(pinned_stamp, utils::flashfs_build_timestamp(1791105724));
            }
            EXPECT_NE(pinned_stamp, tokyo_stamp);
            EXPECT_EQ(test::env_value("SOURCE_DATE_EPOCH"), "12345");
            EXPECT_EQ(test::env_value("TZ"), "JST-9");
            EXPECT_EQ(utils::flashfs_build_timestamp(1791105724), tokyo_stamp);
            {
                const test::PinnedBuildTime custom{"86400", "JST-9"};
                EXPECT_EQ(utils::build_epoch(), 86400);
                EXPECT_EQ(test::env_value("TZ"), "JST-9");
            }
            EXPECT_EQ(test::env_value("SOURCE_DATE_EPOCH"), "12345");
        }

        TEST(SupportEnv, SupportDirHonoursItsEnvOverride) {
            EXPECT_EQ(test::support_dir(), std::filesystem::path{GXBUILD3_SUPPORT_DIR});
            {
                const test::ScopedEnv empty{kProbe, ""};
                EXPECT_EQ(test::support_dir(kProbe), std::filesystem::path{GXBUILD3_SUPPORT_DIR});
            }
            {
                const test::ScopedEnv elsewhere{kProbe, "/nonexistent/gxbuild3-support"};
                EXPECT_EQ(test::support_dir(kProbe),
                          std::filesystem::path{"/nonexistent/gxbuild3-support"});
                EXPECT_ERROR_HAS(test::read_support_file("17559/_retail.ini", kProbe),
                                 ErrorCode::NotFound, "gxbuild3-support");
            }
            EXPECT_OK(test::read_support_file("17559/_retail.ini"));
        }

        // ---- Bytes -----------------------------------------------------------------------

        void put_be32_past_the_end() {
            test::Bytes bytes(3);
            test::put_be32(bytes, 0, 1u);
            EXPECT_EQ(test::hex(bytes), "000000");
        }

        void read_be16_past_the_end() {
            const test::Bytes bytes(4, 0xFF);
            EXPECT_EQ(test::be16(bytes, 3), 0u);
        }

        TEST(SupportBytes, HexIsLowercaseTwoDigitsPerByte) {
            const std::array<uint8_t, 4> bytes{0x00, 0x0A, 0xB0, 0xFF};
            EXPECT_EQ(test::hex(bytes), "000ab0ff");
            EXPECT_EQ(test::hex({}), "");
        }

        TEST(SupportBytes, Sha1HexMatchesTheFips180Example) {
            const std::array<uint8_t, 3> abc{'a', 'b', 'c'};
            const std::array<std::byte, 3> abc_bytes{std::byte{'a'}, std::byte{'b'},
                                                     std::byte{'c'}};
            EXPECT_EQ(test::sha1_hex(abc), "a9993e364706816aba3e25717850c26c9cd0d89d");
            EXPECT_EQ(test::sha1_hex(abc_bytes), "a9993e364706816aba3e25717850c26c9cd0d89d");
        }

        TEST(SupportBytes, BigEndianFieldsRoundTripMostSignificantByteFirst) {
            test::Bytes bytes(8, 0x00);
            test::put_be16(bytes, 0, 0x1234);
            test::put_be32(bytes, 2, 0x89ABCDEFu);
            EXPECT_EQ(test::hex(bytes), "123489abcdef0000");
            EXPECT_EQ(test::be16(bytes, 0), 0x1234u);
            EXPECT_EQ(test::be32(bytes, 2), 0x89ABCDEFu);
            EXPECT_NONFATAL_FAILURE(put_be32_past_the_end(), "does not fit");
            EXPECT_NONFATAL_FAILURE(read_be16_past_the_end(), "does not fit");
        }

        TEST(SupportBytes, AppendBe32AppendsMostSignificantByteFirst) {
            test::Bytes bytes{0xAA};
            test::append_be32(bytes, 0x01020304u);
            test::append_be32(bytes, 0xFFFFFFFEu);
            EXPECT_EQ(test::hex(bytes), "aa01020304fffffffe");
        }

        TEST(SupportBytes, FlashFsPatternFollowsTheFlashFileSystemTestsFormula) {
            const auto bytes = test::flashfs_pattern(0x4001, 3);
            ASSERT_EQ(bytes.size(), 0x4001u);
            EXPECT_EQ(bytes[0], 0x03u);
            EXPECT_EQ(bytes[1], 0x06u);
            EXPECT_EQ(bytes[0x55], 0x02u);   // 0x55 * 3 + 3 = 0x102
            EXPECT_EQ(bytes[0x200], 0x04u);  // 0x600 + 1 + 3
            EXPECT_EQ(bytes[0x4000], 0x23u); // 0xC000 + 0x20 + 3
            EXPECT_EQ(test::flashfs_pattern(0, 7).size(), 0u);
        }

        TEST(SupportBytes, ImagePatternFollowsTheFlashImageGoldenTestsFormula) {
            const auto bytes = test::image_pattern(0x3000, 0x5A);
            ASSERT_EQ(bytes.size(), 0x3000u);
            EXPECT_EQ(bytes[0], 0x5Au);
            EXPECT_EQ(bytes[1], 0x61u);
            EXPECT_EQ(bytes[0x200], 0x5Bu);  // 0x5A + 0xE00 + 1
            EXPECT_EQ(bytes[0x2FFF], 0x6Au); // 0x5A + 0x14FF9 + 0x17
            EXPECT_NE(test::image_pattern(0x10, 3), test::flashfs_pattern(0x10, 3));
        }

    } // namespace
} // namespace gxbuild3::core
