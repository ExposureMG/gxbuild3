#pragma once

#include "core/Args.hpp"
#include "gxbuild/Error.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild::cli {

    [[nodiscard]] std::unexpected<Error> fail_with(ErrorCode code, std::string message,
                                                   const std::filesystem::path& path = {},
                                                   std::string_view item = {});

    [[nodiscard]] Result<OptionsArgs>
    parse_options_text(std::string_view text, const std::filesystem::path& source);

    [[nodiscard]] Result<OptionsArgs> load_options(const std::filesystem::path& options_path);

    [[nodiscard]] Result<std::pair<OptionsArgs, OptionsArgs>>
    apply_cli_options(OptionsArgs options, const std::vector<std::string>& raw_options);

    [[nodiscard]] Result<void>
    apply_winning_metadata(InputMetadata& metadata, const OptionsArgs& file_options,
                           const OptionsArgs& cli_overrides, bool has_donor,
                           const std::filesystem::path& options_path);

} // namespace gxbuild::cli
