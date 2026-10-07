#pragma once

// The fixture of the src/cli/BuildInputResolver.hpp tests (ResolverRoots, ResolverOptions,
// OptionsText, ResolverCpuKey and the suites that join as BuildInputResolverTests.cpp is
// ported, one-line subclasses per file so each suite stands on its own).
//
// ResolverTest owns a ResolverTree (tests/support/builders/ResolverTree.hpp) rooted at the
// test's ScratchDir: <root>/working is the resolver's working directory, <root>/first and
// <root>/second its two source roots. The tree goes with the ScratchDir when the test ends.
// Files are written with ScratchTest::write (relative to the root), which fails the test when
// a write fails.

#include "cli/BuildArgs.hpp"
#include "cli/BuildInputResolver.hpp"
#include "support/Scratch.hpp"
#include "support/builders/ResolverTree.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string_view>

namespace gxbuild3::cli {

    class ResolverTest : public test::ScratchTest {
      protected:
        // ScratchTest::SetUp, then the tree's working, first and second directories; a tree
        // that cannot be made is a fatal failure, so the test body does not run.
        void SetUp() override;

        [[nodiscard]] const test::ResolverTree& tree() const { return *tree_; }

        // root() / relative.
        [[nodiscard]] std::filesystem::path path(std::string_view relative) const {
            return tree().path(relative);
        }
        [[nodiscard]] const std::filesystem::path& working_directory() const {
            return tree().working_directory();
        }

        // The first root, valid_cpu_key() as hex, a small-block layout and result.bin.
        [[nodiscard]] BuildArgs minimum_args() const { return tree().minimum_args(); }

        // BuildInputResolver(working_directory()).resolve / resolve_foundations.
        [[nodiscard]] std::expected<BuildRequest, ResolutionError>
        resolve(const BuildArgs& args) const {
            return tree().resolve(args);
        }
        [[nodiscard]] std::expected<ResolvedFoundations, ResolutionError>
        resolve_foundations(const BuildArgs& args) const {
            return tree().resolve_foundations(args);
        }

      private:
        std::optional<test::ResolverTree> tree_;
    };

} // namespace gxbuild3::cli
