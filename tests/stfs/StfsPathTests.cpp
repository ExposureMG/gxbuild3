// src/stfs/StfsContainer.hpp and ContainerDetail.hpp: extract_all confines every entry to its
// output directory (relative and absolute escapes, parent cycles, safe_join), checking all
// destinations before it writes anything, and extracts nested directories. StfsSafeJoin (the
// WIN32-only drive and UNC paths) and StfsExtractToDisk (needs /dev/full) can skip, so they are
// suites of their own outside the StfsPath bundle.

#include "PirsPackage.hpp"
#include "stfs/ContainerDetail.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <system_error>

namespace gxbuild3::stfs {
    namespace {

        namespace fs = std::filesystem;
        using pirs::Bytes;
        using pirs::make_package;
        using pirs::pattern;
        using Verify = StfsContainer::Verify;

        // Opens and extracts a package, returning the describe() of whichever of open or
        // extract_all fails (empty if both succeed).
        std::string extract_error(const Bytes& bytes, const fs::path& out) {
            const auto container = StfsContainer::open(bytes);
            if (!container) {
                return container.error().describe();
            }
            if (const auto extracted = container->extract_all(out); !extracted) {
                return extracted.error().describe();
            }
            return {};
        }

        TEST(StfsPath, RelativeEscapeIsRejectedBeforeAnythingIsWritten) {
            const test::ScratchDir dir;
            // A ".." directory entry passes the name checks but escapes once joined.
            const auto dotdot = make_package({{"good.bin", pattern(10, 1)},
                                              {"..", {}, true, -1, true},
                                              {"escaped", pattern(10, 2), true, 1}});
            const auto dotdot_message = extract_error(dotdot, dir.path() / "out");
            EXPECT_TRUE(dotdot_message.contains("escapes"))
                << "a .. entry path is rejected by StfsContainer::extract_all; got \""
                << dotdot_message << "\"";
            EXPECT_FALSE(fs::exists(dir.path() / "escaped"))
                << "nothing is written outside output_dir";
            EXPECT_FALSE(fs::exists(dir.path() / "out" / "good.bin"))
                << "destinations are validated before anything is written";

            const auto slash = make_package({{"../escaped", pattern(10, 2)}});
            EXPECT_FALSE(extract_error(slash, dir.path() / "out").empty())
                << "a ../ entry name is rejected by StfsContainer";
            EXPECT_FALSE(fs::exists(dir.path() / "escaped")) << "a ../ name writes nothing outside";

            const auto nested = make_package(
                {{"sub", {}, true, -1, true}, {"../../escaped", pattern(10, 3), true, 0}});
            EXPECT_FALSE(extract_error(nested, dir.path() / "out").empty())
                << "a ../ entry under a directory is rejected";
            EXPECT_FALSE(fs::exists(dir.path() / "escaped"))
                << "nested escape writes nothing outside";
        }

        TEST(StfsPath, AbsoluteNameIsRejected) {
            const test::ScratchDir dir;
            const auto bytes = make_package({{"/stfs-absolute-escape", pattern(10, 1)}});
            const auto message = extract_error(bytes, dir.path() / "out");
            EXPECT_TRUE(message.contains("absolute") || message.contains("separator"))
                << "an absolute entry name is rejected by StfsContainer; got \"" << message << "\"";
            EXPECT_FALSE(fs::exists("/stfs-absolute-escape"))
                << "nothing is written at the absolute path";
        }

        TEST(StfsPath, ContainerRejectsADotDotDirectory) {
            const test::ScratchDir dir;
            const auto bytes =
                make_package({{"..", {}, true, -1, true}, {"escaped", pattern(10, 2), true, 0}});
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "StfsContainer rejects a .. entry path";
            EXPECT_FALSE(container->extract_all(dir.path() / "out").has_value())
                << "StfsContainer rejects a .. entry path";
            EXPECT_FALSE(fs::exists(dir.path() / "escaped")) << "container writes nothing outside";
        }

        TEST(StfsPath, SafeJoinKeepsSafePathsAndRejectsEscapingOnes) {
            const fs::path out = "out";
            const auto kept = detail::safe_join(out, "a/./b");
            EXPECT_OK(kept) << "safe paths are kept";
            EXPECT_EQ(kept.value_or(fs::path{}), out / "a/b") << "safe paths are kept";
            constexpr auto rejected = ErrorCode::InvalidArgument;
            EXPECT_ERROR(detail::safe_join(out, "/abs"), rejected) << "absolute paths are rejected";
            EXPECT_ERROR(detail::safe_join(out, "a/../../b"), rejected)
                << "escaping paths are rejected";
            EXPECT_ERROR(detail::safe_join(out, "a/.."), rejected)
                << "paths that collapse to the target itself are rejected";
        }

        TEST(StfsPath, ParentCycleIsRejected) {
            const test::ScratchDir dir;
            // Entry 0 names itself as its parent.
            const auto self_bytes = make_package({{"a.bin", pattern(10, 1), true, 0}});
            const auto self = StfsContainer::open(self_bytes);
            ASSERT_OK(self) << "a self-parented entry opens";
            EXPECT_ERROR(self->extract_all(dir.path() / "out"), ErrorCode::Malformed)
                << "an entry that is its own parent is rejected";

            // Entry 0 refers forward to entry 1, which refers back to entry 0.
            const auto loop_bytes =
                make_package({{"a", {}, true, 1, true}, {"b", {}, true, 0, true}});
            const auto loop = StfsContainer::open(loop_bytes);
            ASSERT_OK(loop) << "a forward-parented entry opens";
            EXPECT_ERROR(loop->extract_all(dir.path() / "out"), ErrorCode::Malformed)
                << "a parent cycle through a later entry is rejected";

            const auto bytes = make_package({{"a", {}, true, 1, true}, {"b", {}, true, 0, true}});
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "StfsContainer rejects a forward parent reference";
            EXPECT_FALSE(container->extract_all(dir.path() / "out").has_value())
                << "StfsContainer rejects a forward parent reference";
        }

        TEST(StfsPath, NestedFileExtractsWithVerification) {
            const test::ScratchDir dir;
            const auto data = pattern(5000, 9);
            const auto bytes =
                make_package({{"sub", {}, true, -1, true}, {"inner.bin", data, true, 0}});
            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "a nested package opens";
            ASSERT_OK(container->extract_all(dir.path() / "out", Verify::Yes))
                << "a nested package extracts with verification";
            const auto read = test::read_file(dir.path() / "out" / "sub" / "inner.bin");
            ASSERT_OK(read) << "a nested file extracts with verification";
            EXPECT_BYTES_EQ(data, *read) << "a nested file extracts with verification";
        }

        // The drive-relative and UNC rows of safe_join exist on WIN32 only.
        TEST(StfsSafeJoin, WindowsDriveRelativeAndUncPathsAreRejected) {
#ifdef _WIN32
            const fs::path out = "out";
            constexpr auto rejected = ErrorCode::InvalidArgument;
            EXPECT_ERROR(detail::safe_join(out, "C:foo"), rejected)
                << "drive-relative paths are rejected";
            EXPECT_ERROR(detail::safe_join(out, "\\\\server\\share"), rejected)
                << "UNC paths are rejected";
#else
            GTEST_SKIP() << "drive-relative and UNC paths are WIN32-only";
#endif
        }

        TEST(StfsExtractToDisk, WriteFailuresAreReported) {
            const fs::path full = "/dev/full";
            if (!fs::exists(full)) {
                GTEST_SKIP() << "no /dev/full";
            }
            const auto bytes = make_package({{"a.bin", pattern(10, 1)}});

            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "the package opens";
            const auto& entry = container->entries().at(0);
            EXPECT_ERROR(
                extract_file_to_disk(bytes, entry, Magic::PIRS, container->header_size(), full),
                ErrorCode::IoError)
                << "extract_file_to_disk reports a failed write";

            // StfsContainer::extract_all writing through a planted link to /dev/full.
            const test::ScratchDir dir;
            std::error_code error;
            fs::create_directories(dir.path() / "out", error);
            ASSERT_FALSE(error) << "the output directory is made: " << error.message();
            fs::create_symlink(full, dir.path() / "out" / "a.bin", error);
            ASSERT_FALSE(error) << "the link to /dev/full is planted: " << error.message();
            EXPECT_FALSE(container->extract_all(dir.path() / "out").has_value())
                << "StfsContainer::extract_all reports a failed write";

            EXPECT_ERROR(extract_file_to_disk(bytes, entry, Magic::PIRS, container->header_size(),
                                              dir.path() / "no/dir/x"),
                         ErrorCode::IoError)
                << "an unopenable output path is reported";
        }

    } // namespace
} // namespace gxbuild3::stfs
