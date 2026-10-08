// src/cli/BuildCommand.hpp: run_build_command maps the resolve, build and write services onto the
// CLI exit codes (3 input resolution, 4 NAND build, 5 output write) and keeps each failure's
// message; the default write service creates the output's parent, and an existing output is
// overwritten.

#include "cli/BuildCommand.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <expected>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <utility>

namespace gxbuild3::cli {
    namespace {

        using test::Bytes;

        BuildArgs minimum_build_args(const std::filesystem::path& output_path) {
            BuildArgs args{};
            args.output_path = output_path;
            return args;
        }

        BuildCommandServices successful_services() {
            BuildCommandServices services{};
            services.resolve = [](const BuildArgs& args) {
                BuildRequest request{};
                request.output_path = args.output_path;
                return std::expected<BuildRequest, ResolutionError>{std::move(request)};
            };
            services.build = [](const Input&) { return BuildResult{Bytes{1, 2, 3}}; };
            services.write = [](const std::filesystem::path&, const Bytes&) {
                return Result<void>{};
            };
            return services;
        }

        TEST(BuildCommand, ResolutionFailureReturnsExitCodeThree) {
            auto services = successful_services();
            services.resolve = [](const BuildArgs&) {
                return std::expected<BuildRequest, ResolutionError>{std::unexpected(ResolutionError{
                    ResolutionErrorCode::AssetNotFound, "missing asset", {}, "build.ini"})};
            };
            const auto result = run_build_command(minimum_build_args("output.bin"), services);
            EXPECT_EQ(result.exit_code, 3) << "resolution failures return exit code 3";
            EXPECT_EQ(result.message, "missing asset")
                << "resolution failure preserves its message";
        }

        TEST(BuildCommand, BuildFailureReturnsExitCodeFour) {
            auto services = successful_services();
            services.build = [](const Input&) {
                return BuildResult{std::unexpected(
                    BuildError{BuildErrorCode::InvalidInput, "invalid build input"})};
            };
            const auto result = run_build_command(minimum_build_args("output.bin"), services);
            EXPECT_EQ(result.exit_code, 4) << "build failures return exit code 4";
            EXPECT_EQ(result.message, "invalid build input")
                << "build failure preserves its message";
        }

        TEST(BuildCommand, WriteFailureReturnsExitCodeFive) {
            auto services = successful_services();
            services.write = [](const std::filesystem::path&, const Bytes&) -> Result<void> {
                return fail(ErrorCode::IoError, "disk full");
            };
            const auto result = run_build_command(minimum_build_args("output.bin"), services);
            EXPECT_EQ(result.exit_code, 5) << "write failures return exit code 5";
            EXPECT_TRUE(result.message.ends_with(": disk full"))
                << "write failure message carries the write service's reason; message: "
                << result.message;
        }

        // The two successful commands write into their own scratch directory.
        class BuildCommandTest : public test::ScratchTest {};

        TEST_F(BuildCommandTest, SuccessCreatesTheOutputParentWithTheDefaultWriter) {
            const auto output_path = root() / "nested" / "updflash.bin";

            // The default write service owns parent creation, so this exercises the real one.
            auto services = successful_services();
            services.write = default_build_command_services(root()).write;
            const auto result = run_build_command(minimum_build_args(output_path), services);
            EXPECT_EQ(result.exit_code, 0) << "successful command returns exit code 0";
            const auto written = test::read_file(output_path);
            const Bytes expected{1, 2, 3};
            ASSERT_OK(written) << "successful command creates the parent before writing bytes";
            EXPECT_BYTES_EQ(expected, *written)
                << "successful command creates the parent before writing bytes";
        }

        TEST_F(BuildCommandTest, SuccessOverwritesAnExistingOutput) {
            const auto output_path = write("updflash.bin", "old");

            bool wrote = false;
            auto services = successful_services();
            services.write = [&](const std::filesystem::path& path,
                                 const Bytes& bytes) -> Result<void> {
                std::ofstream output(path, std::ios::binary | std::ios::trunc);
                output.write(reinterpret_cast<const char*>(bytes.data()),
                             static_cast<std::streamsize>(bytes.size()));
                wrote = static_cast<bool>(output);
                if (!wrote) {
                    return fail(ErrorCode::IoError, "write failed");
                }
                return {};
            };
            const auto result = run_build_command(minimum_build_args(output_path), services);
            EXPECT_EQ(result.exit_code, 0) << "existing output does not block a successful command";
            EXPECT_TRUE(wrote) << "successful command overwrites output bytes";
            const auto written = test::read_file(output_path);
            const Bytes expected{1, 2, 3};
            ASSERT_OK(written) << "successful command overwrites output bytes";
            EXPECT_BYTES_EQ(expected, *written) << "successful command overwrites output bytes";
        }

        // The CLI contract's "-o ... overwritten", pinned through the real write service: the
        // existing output is longer than the three built bytes, so a writer that did not truncate
        // would leave its tail behind.
        TEST_F(BuildCommandTest, SuccessOverwritesAnExistingOutputWithTheDefaultWriter) {
            const auto output_path = write("updflash.bin", "old output");

            auto services = successful_services();
            services.write = default_build_command_services(root()).write;
            const auto result = run_build_command(minimum_build_args(output_path), services);
            EXPECT_EQ(result.exit_code, 0) << "existing output does not block a successful command";
            EXPECT_EQ(result.message, "") << "a successful command carries no message";
            const auto written = test::read_file(output_path);
            const Bytes expected{1, 2, 3};
            ASSERT_OK(written) << "the default writer leaves the output readable";
            EXPECT_BYTES_EQ(expected, *written)
                << "the default writer truncates the old output to the built bytes";
        }

    } // namespace
} // namespace gxbuild3::cli
