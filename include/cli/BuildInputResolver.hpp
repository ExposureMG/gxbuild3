#pragma once

#include "Args.hpp"
#include "cli/BuildArgs.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::cli {

    enum class ResolutionErrorCode {
        InvalidSourceDirectory,
        OptionsReadFailed,
        InvalidOption,
        CpuKeyNotFound,
        CpuKeyReadFailed,
        InvalidCpuKey,
        InputReadFailed,
        InvalidDonor,
        BlockTypeRequired,
        BuildIniReadFailed,
        SectionNotFound,
        AssetNotFound,
        IncompleteLooseDonor,
        PatchsetNotFound,
        AddonNotFound,
        InvalidInput,
        SigningKeyNotFound,
    };

    struct ResolutionError {
        ResolutionErrorCode code;
        std::string message;
        std::filesystem::path path;
        std::string item;
    };

    struct BuildRequest {
        Input input;
        std::filesystem::path output_path;
    };

    struct ResolvedFoundations {
        OptionsArgs file_options;
        OptionsArgs options;
        OptionsArgs cli_overrides;
        std::vector<uint8_t> cpu_key;
        std::optional<Input> donor;
        ImageType image_type{ImageType::SmallBlock};
    };

    [[nodiscard]] std::expected<OptionsArgs, ResolutionError>
    parse_options_text(std::string_view text, const std::filesystem::path& source);

    class BuildInputResolver {
      public:
        explicit BuildInputResolver(std::filesystem::path working_directory);

        [[nodiscard]] std::expected<ResolvedFoundations, ResolutionError>
        resolve_foundations(const BuildArgs& args) const;

        [[nodiscard]] std::expected<BuildRequest, ResolutionError>
        resolve(const BuildArgs& args) const;

      private:
        std::filesystem::path working_directory_;
    };

} // namespace gxbuild3::cli
