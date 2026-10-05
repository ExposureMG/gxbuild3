#include "cli/BuildCommand.hpp"

#include "utils/Utils.hpp"

#include <system_error>

namespace gxbuild3::cli {

    CommandResult run_build_command(const BuildArgs& args, const BuildCommandServices& services) {
        const auto request = services.resolve(args);
        if (!request) {
            return {.exit_code = 3, .message = request.error().message};
        }

        const auto built = services.build(request->input);
        if (!built) {
            return {.exit_code = 4, .message = built.error().message};
        }

        const auto& output_path = request->output_path;
        if (output_path.has_parent_path()) {
            std::error_code error;
            std::filesystem::create_directories(output_path.parent_path(), error);
            if (error) {
                return {.exit_code = 5,
                        .message = "Could not create output directory '" +
                                   output_path.parent_path().string() + "': " + error.message()};
            }
        }

        if (!services.write(output_path, *built)) {
            return {.exit_code = 5,
                    .message = "Could not write output image to '" + output_path.string() + "'"};
        }
        return {};
    }

    BuildCommandServices default_build_command_services(const std::filesystem::path& cwd) {
        return {
            .resolve = [resolver = BuildInputResolver(cwd)](
                           const BuildArgs& args) { return resolver.resolve(args); },
            .build = [](const Input& input) { return run_build(input); },
            .write =
                [](const std::filesystem::path& path, const std::vector<uint8_t>& data) {
                    return gxbuild3::utils::write_file(path, data);
                },
        };
    }

} // namespace gxbuild3::cli
