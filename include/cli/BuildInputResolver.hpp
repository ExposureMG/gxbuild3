#pragma once

#include "core/Args.hpp"
#include "cli/BuildArgs.hpp"
#include "cli/OptionsResolver.hpp"
#include "gxbuild/Error.hpp"

#include <filesystem>
#include <optional>
#include <vector>

namespace gxbuild::utils {
    class StfsCache;
}

namespace gxbuild::cli {

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

    class BuildInputResolver {
      public:
        explicit BuildInputResolver(std::filesystem::path working_directory);

        [[nodiscard]] Result<ResolvedFoundations>
        resolve_foundations(const BuildArgs& args) const;

        [[nodiscard]] Result<BuildRequest>
        resolve(const BuildArgs& args) const;

      private:
        [[nodiscard]] Result<ResolvedFoundations>
        resolve_foundations(const BuildArgs& args, utils::StfsCache& stfs_cache) const;

        std::filesystem::path working_directory_;
    };

} // namespace gxbuild::cli
