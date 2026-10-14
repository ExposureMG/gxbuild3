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

    // Decodes the text of an options.ini, without touching the filesystem: one key=value per
    // line (LF or CRLF), lines starting with ';' or '#' and blank lines skipped, the value cut at
    // an inline ';', legacy xeBuild keys ignored. A section header, a line without '=' or an
    // option OptionsManager refuses fails InvalidOption with its line number and `source` as path.
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
