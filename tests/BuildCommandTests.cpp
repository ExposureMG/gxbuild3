#include "cli/BuildCommand.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

    using Bytes = std::vector<uint8_t>;
    using gxbuild3::cli::BuildArgs;
    using gxbuild3::cli::BuildCommandServices;
    using gxbuild3::cli::BuildRequest;
    using gxbuild3::cli::ResolutionError;
    using gxbuild3::cli::ResolutionErrorCode;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

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
        services.write = [](const std::filesystem::path&, const Bytes&) { return true; };
        return services;
    }

    bool test_resolution_failure_returns_exit_code_three() {
        auto services = successful_services();
        services.resolve = [](const BuildArgs&) {
            return std::expected<BuildRequest, ResolutionError>{std::unexpected(ResolutionError{
                ResolutionErrorCode::AssetNotFound, "missing asset", {}, "build.ini"})};
        };
        const auto result =
            gxbuild3::cli::RunBuildCommand(minimum_build_args("output.bin"), services);
        return require(result.exit_code == 3, "resolution failures return exit code 3") &&
               require(result.message == "missing asset",
                       "resolution failure preserves its message");
    }

    bool test_build_failure_returns_exit_code_four() {
        auto services = successful_services();
        services.build = [](const Input&) {
            return BuildResult{
                std::unexpected(BuildError{BuildErrorCode::InvalidInput, "invalid build input"})};
        };
        const auto result =
            gxbuild3::cli::RunBuildCommand(minimum_build_args("output.bin"), services);
        return require(result.exit_code == 4, "build failures return exit code 4") &&
               require(result.message == "invalid build input",
                       "build failure preserves its message");
    }

    bool test_write_failure_returns_exit_code_five() {
        auto services = successful_services();
        services.write = [](const std::filesystem::path&, const Bytes&) { return false; };
        const auto result =
            gxbuild3::cli::RunBuildCommand(minimum_build_args("output.bin"), services);
        return require(result.exit_code == 5, "write failures return exit code 5");
    }

    bool test_success_creates_output_parent_and_writes_bytes() {
        const auto root = std::filesystem::temp_directory_path() / "gxbuild3-buildcommand-parent";
        const auto output_path = root / "nested" / "updflash.bin";
        std::error_code error;
        std::filesystem::remove_all(root, error);

        bool wrote = false;
        auto services = successful_services();
        services.write = [&](const std::filesystem::path& path, const Bytes& bytes) {
            wrote = path == output_path && std::filesystem::is_directory(path.parent_path()) &&
                    bytes == Bytes{1, 2, 3};
            return true;
        };
        const auto result =
            gxbuild3::cli::RunBuildCommand(minimum_build_args(output_path), services);
        std::filesystem::remove_all(root, error);
        return require(result.exit_code == 0, "successful command returns exit code 0") &&
               require(wrote, "successful command creates the parent before writing bytes");
    }

    bool test_success_overwrites_existing_output() {
        const auto output_path =
            std::filesystem::temp_directory_path() / "gxbuild3-buildcommand-overwrite.bin";
        {
            std::ofstream existing(output_path, std::ios::binary | std::ios::trunc);
            existing << "old";
        }

        bool wrote = false;
        auto services = successful_services();
        services.write = [&](const std::filesystem::path& path, const Bytes& bytes) {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
            wrote = static_cast<bool>(output);
            return wrote;
        };
        const auto result =
            gxbuild3::cli::RunBuildCommand(minimum_build_args(output_path), services);

        std::ifstream output(output_path, std::ios::binary);
        const Bytes written{std::istreambuf_iterator<char>(output),
                            std::istreambuf_iterator<char>()};
        std::error_code error;
        std::filesystem::remove(output_path, error);
        return require(result.exit_code == 0,
                       "existing output does not block a successful command") &&
               require(wrote && written == Bytes{1, 2, 3},
                       "successful command overwrites output bytes");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_resolution_failure_returns_exit_code_three() && passed;
    passed = test_build_failure_returns_exit_code_four() && passed;
    passed = test_write_failure_returns_exit_code_five() && passed;
    passed = test_success_creates_output_parent_and_writes_bytes() && passed;
    passed = test_success_overwrites_existing_output() && passed;
    return passed ? 0 : 1;
}
