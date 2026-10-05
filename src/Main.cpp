#include "cli/BuildCommand.hpp"
#include "cli/CommandLine.hpp"
#include "utils/Log.hpp"

#include <exception>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <variant>
#include <vector>

namespace {

    constexpr std::string_view kProgramName{"gxbuild"};
    constexpr std::string_view kProgramVersion{"3.2.0"};

    void print_help() {
        std::cout << "Usage: " << kProgramName << " [build] [options]\n\n"
                  << "Required build options:\n"
                  << "  -b, --buildini <path>\n"
                  << "  -s, --section <stem>\n"
                  << "  -t, --buildtype <type>[:<blocktype>]\n"
                  << "  -d, --dir <directory-list>\n\n"
                  << "Optional:\n"
                  << "  -i, --input <nand-path>\n"
                  << "  -o, --output <path>\n"
                  << "  -p, --cpukey <32-hex-characters>\n"
                  << "  -e, --ext <patchset-suffix>\n"
                  << "  -c, --config <configuration-list>\n"
                  << "  -a, --addon <addon-list>\n"
                  << "  -v, --verbose\n"
                  << "  -h, --help\n"
                  << "      --version\n";
    }

} // namespace

int main(int argc, char* argv[]) try {
    gxbuild3::Log::Init();

    std::vector<std::string_view> arguments;
    arguments.reserve(static_cast<size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }

    const auto parsed = gxbuild3::cli::parse_command_line(arguments);
    if (!parsed) {
        std::cerr << kProgramName << ": " << parsed.error().message << '\n';
        return 2;
    }
    if (std::holds_alternative<gxbuild3::cli::HelpCommand>(*parsed)) {
        print_help();
        return 0;
    }
    if (std::holds_alternative<gxbuild3::cli::VersionCommand>(*parsed)) {
        std::cout << kProgramName << ' ' << kProgramVersion << '\n';
        return 0;
    }

    const auto& args = std::get<gxbuild3::cli::BuildArgs>(*parsed);
    if (args.verbose) {
        gxbuild3::Log::SetVerbose(true);
        gxbuild3::Log::Debug("Verbose logging enabled");
    }
    const auto result = gxbuild3::cli::run_build_command(
        args, gxbuild3::cli::default_build_command_services(std::filesystem::current_path()));
    if (result.exit_code != 0) {
        std::cerr << kProgramName << ": " << result.message << '\n';
    }
    return result.exit_code;
} catch (const std::exception& exception) {
    std::cerr << kProgramName << ": " << exception.what() << '\n';
    return 1;
} catch (...) {
    std::cerr << kProgramName << ": unknown error\n";
    return 1;
}
