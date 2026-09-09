#pragma once

#include "Args.hpp"
#include "cli/BuildArgs.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
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
        // Values read only from <working_directory>/options.ini, before CLI overlays.
        OptionsArgs file_options;
        OptionsArgs options;
        // Values explicitly supplied by ordered -c entries. Optional members retain
        // presence independently from options.ini, including explicit false values.
        OptionsArgs cli_overrides;
        std::vector<uint8_t> cpu_key;
        std::optional<Input> donor;
        ImageType image_type{ImageType::SmallBlock};
    };

    class BuildInputResolver {
      public:
        explicit BuildInputResolver(std::filesystem::path working_directory);

        [[nodiscard]] std::expected<ResolvedFoundations, ResolutionError>
        ResolveFoundations(const BuildArgs& args) const;

        [[nodiscard]] std::expected<BuildRequest, ResolutionError>
        Resolve(const BuildArgs& args) const;

      private:
        std::filesystem::path working_directory_;
    };

} // namespace gxbuild3::cli
