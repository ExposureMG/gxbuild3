// src/cli/BuildInputResolver.hpp: the source roots and the working directory. Every declared
// root must be a directory, at least one is required and an empty path is refused; a relative
// root and a relative output path are anchored to the resolver's working directory, and
// resolve() fails with the same errors resolve_foundations() reports.

#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"

#include <filesystem>
#include <gtest/gtest.h>

namespace gxbuild3::cli {
    namespace {

        class ResolverRoots : public ResolverTest {};

        TEST_F(ResolverRoots, EveryDeclaredSourceRootMustBeADirectory) {
            write("not-a-directory", "file");
            auto args = minimum_args();
            args.source_dirs = {path("first"), path("not-a-directory")};
            const auto result = resolve_foundations(args);
            ASSERT_ERROR(result, ResolutionErrorCode::InvalidSourceDirectory)
                << "every declared source root must be a directory";
            EXPECT_EQ(result.error().path, path("not-a-directory"))
                << "invalid source directory error identifies the rejected root";
        }

        TEST_F(ResolverRoots, SourceRootsCannotBeEmpty) {
            auto args = minimum_args();
            args.source_dirs.clear();
            EXPECT_ERROR(resolve_foundations(args), ResolutionErrorCode::InvalidSourceDirectory)
                << "direct resolver callers must provide at least one source root";
        }

        TEST_F(ResolverRoots, EmptySourceRootPathIsRejected) {
            auto args = minimum_args();
            args.source_dirs = {std::filesystem::path{}};
            const auto only_empty = resolve_foundations(args);
            ASSERT_ERROR(only_empty, ResolutionErrorCode::InvalidSourceDirectory)
                << "an empty source-root path is rejected before anchoring";
            ASSERT_TRUE(only_empty.error().path.empty())
                << "an empty source-root path is rejected before anchoring";

            args.source_dirs = {path("first"), std::filesystem::path{}};
            const auto mixed = resolve_foundations(args);
            ASSERT_ERROR(mixed, ResolutionErrorCode::InvalidSourceDirectory)
                << "an empty source-root path is rejected in a mixed list";
            EXPECT_TRUE(mixed.error().path.empty())
                << "an empty source-root path is rejected in a mixed list";
        }

        TEST_F(ResolverRoots, RelativeSourceRootIsAnchoredToTheWorkingDirectory) {
            const auto key = test::valid_cpu_key();
            write("first/cpukey.txt", test::hex(key));
            auto args = minimum_args();
            args.cpu_key.reset();
            args.source_dirs = {"../first"};
            const auto result = resolve_foundations(args);
            ASSERT_OK(result)
                << "relative source roots resolve from the explicit working directory";
            EXPECT_BYTES_EQ(key, result->cpu_key)
                << "relative source roots resolve from the explicit working directory";
        }

        TEST_F(ResolverRoots, ResolveDelegatesToFoundations) {
            auto args = minimum_args();
            args.cpu_key.reset();
            EXPECT_ERROR(BuildInputResolver(working_directory()).resolve(args),
                         ResolutionErrorCode::CpuKeyNotFound)
                << "Resolve exposes foundation failures before Task 7 phases";
        }

        TEST_F(ResolverRoots, ResolveAnchorsARelativeOutputToTheWorkingDirectory) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args());
            args.output_path = "nested/result.bin";
            const auto result = BuildInputResolver(working_directory()).resolve(args);
            ASSERT_OK(result) << "complete output-path fixture resolves";
            EXPECT_EQ(result->output_path, path("working/nested/result.bin"))
                << "Resolve anchors a relative output path to its working directory";
        }

    } // namespace
} // namespace gxbuild3::cli
