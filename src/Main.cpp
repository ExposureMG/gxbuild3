#include "Ascii.hpp"
#include "BuildRunner.hpp"
#include "FlashImage.hpp"
#include "Log.hpp"
#include "Options.hpp"
#include "Utils.hpp"
#include "bootloaders/2bl.hpp"
#include "bootloaders/Keyvault.hpp"
#include "bootloaders/SMC.hpp"
#include "bootloaders/Xboxupd.hpp"
#include "ini/IniParser.hpp"
#include "patchers/BinaryParser.hpp"
#include "patchers/Patcher.hpp"
#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"
#include "stfs/StfsContainer.hpp"

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#if defined(_MSC_VER)
constexpr const char* compiler = "MSVC";
#elif defined(__clang__)
constexpr const char* compiler = "Clang";
#elif defined(__GNUC__)
constexpr const char* compiler = "GCC";
#else
constexpr const char* compiler = "Unknown";
#endif

static std::optional<BuildType> ParseBuildType(const std::string& s) {
    auto it = kBuildTypeMap.find(s);
    if (it == kBuildTypeMap.end())
        return std::nullopt;
    return it->second;
}

static std::optional<ConsoleType> ParseConsoleType(const std::string& s) {
    auto it = kConsoleTypeMap.find(s);
    if (it == kConsoleTypeMap.end())
        return std::nullopt;
    return it->second;
}

static std::optional<std::vector<uint8_t>> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto hi = hex[i];
        auto lo = hex[i + 1];
        auto from_hex = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        int h = from_hex(hi);
        int l = from_hex(lo);
        if (h < 0 || l < 0)
            return std::nullopt;
        out.push_back(static_cast<uint8_t>((h << 4) | l));
    }
    return out;
}

static std::optional<std::vector<uint8_t>> ReadFile(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

static std::span<const std::byte> AsByteSpan(const std::vector<uint8_t>& data) {
    return {reinterpret_cast<const std::byte*>(data.data()), data.size()};
}

static bool WriteFile(const std::filesystem::path& path, std::span<const std::byte> data) {
    std::ofstream f(path, std::ios::binary);
    if (!f)
        return false;
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(f);
}

int main(int argc, char** argv) {
    Log::Init();

    GxArgs args;

    CLI::App app{"GxBuild3"};
    app.set_help_flag("-?,--help", "Print this help message and exit");
    app.add_flag("-v,--verbose", args.verbose)->description("Enable verbose trace logging");
    app.add_flag("--license", args.license)->description("Show license information");
    app.add_option("-o,--options", "Semicolon-separated key=value option overrides")
        ->each([&args](const std::string& val) {
            std::stringstream ss(val);
            std::string part;
            while (std::getline(ss, part, ';')) {
                if (part.empty())
                    continue;
                if (auto pos = part.find('='); pos != std::string::npos)
                    args.options.emplace_back(part.substr(0, pos), part.substr(pos + 1));
                else
                    args.options.emplace_back(part, "true");
            }
        });

    std::string build_type_str;
    std::string console_str;

    auto* build_sub = app.add_subcommand("build", "Build a NAND image (default)");
    auto* extract_sub = app.add_subcommand("extract", "Extract files from a NAND image");
    auto* stfs_sub = app.add_subcommand("stfs", "Extract files from a PIRS/STFS package");

    // global keys
    app.add_option("-p,--cpukey", args.cpu_key)->description("CPU key (hex)");
    app.add_option("-b,--1blkey", args.bl_key)->description("1BL key (hex)");

    // ini info
    build_sub->add_option("-e,--preset", args.preset)->description("Preset name");
    build_sub->add_option("-t,--type", build_type_str)
        ->required()
        ->description("Build type (retail, jtag, glitch, glitch2, glitch2m, glitch3, devkit)");
    build_sub->add_option("-c,--console", console_str)->description("Console revision")->required();
    build_sub->add_option("-i,--fwext", args.ini_ext)->description("Firmware extension override");
    build_sub->add_option("-r,--iniext", args.bl_ext)->description("INI extension override");

    // build dirs
    build_sub->add_option("-d,--build", args.data_dir)->description("Build data directory");
    build_sub->add_option("-m,--common", args.common_dir)->description("Common files directory");
    build_sub->add_option("-f,--data", args.fw_dir)->description("Firmware directory");

    // build options
    build_sub->add_flag("-x,--xsb", args.xsb)->description("Enable XSB mode");
    build_sub->add_flag("--fullimage", args.full_image)->description("Build full image");
    build_sub->add_flag("--bigblock", args.bigblock)->description("Use big block layout");

    // input data
    build_sub->add_option("-8,--raw", args.raw_patches)->description("Raw patch entries");
    build_sub->add_option("-u,--update", args.xboxupd)->description("xboxupd.bin path");
    build_sub->add_option("-a,--addon", args.addons)->description("Addon packages");
    app.add_option("-l,--image,image", args.source_nand)->description("Source NAND image");
    app.add_option("--ecc", args.ecc)->description("ECC file");
    app.add_option("-s,--sha", args.sha_file)->description("SHA file path");

    build_sub->add_flag("-v,--verbose", args.verbose)->description("Enable verbose trace logging");
    // output options
    build_sub->add_option("output", args.output)->description("Output file");
    app.add_option("--format", args.format)->description("Output format");
    app.add_option("-g,--output-dir", args.output_dir)->description("Output directory");

    build_sub->fallthrough();
    extract_sub->fallthrough();
    stfs_sub->fallthrough();
    build_sub->callback([&args]() { args.mode = "build"; });
    extract_sub->callback([&args]() { args.mode = "extract"; });
    extract_sub->add_flag("--all", args.extract_all, "Extract all files");
    stfs_sub->callback([&args]() { args.mode = "stfs"; });
    stfs_sub->add_option("package", args.stfs_package, "PIRS/STFS package")->required();
    stfs_sub->add_option("-g,--output-dir", args.output_dir, "Output directory");
    stfs_sub->add_flag("--xboxupd", args.stfs_split_xboxupd,
                       "Extract xboxupd.bin and split it into cf.bin/cg.bin");

    app.require_subcommand(0, 1);

    if (argc == 1) {
        std::cout << app.help() << std::endl;
        return 0;
    }

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    Log::SetVerbose(args.verbose);

    if (args.license) {
        std::cout << R"(Copyright (c) 2026, GxOSS

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.)"
                  << std::endl;
        return 0;
    }

    std::filesystem::path cwd = std::filesystem::current_path();
    if (args.mode == "build") {
        if (!args.data_dir) {
            args.data_dir = cwd / "17559";
            if (!std::filesystem::exists(*args.data_dir)) {
                Log::Error("No build dir specified (-d) and default 17559 doesnt exist.");
                return 1;
            }
        }
        if (!args.common_dir) {
            args.common_dir = cwd / "common";
        }
        if (!args.fw_dir) {
            args.fw_dir = cwd / "mydata";
        }
        if (build_type_str.empty()) {
            Log::Warn("No build type specified (-t), defaulting to 'retail'.");
            build_type_str = "retail";
        }
        if (console_str.empty()) {
            Log::Warn("No console type specified (-c), defaulting to 'jasper'.");
            console_str = "jasper";
        }
        if (!args.output_dir) {
            args.output_dir = cwd;
        }
    }

    if (args.mode == "extract" && !args.source_nand) {
        Log::Error("Extract mode requires -l,--image argument");
        return 1;
    }

    std::cout << Ascii::Logo;
    Log::Info("gxbuild3 starting... (Built on: {} {} with {})", __DATE__, __TIME__, compiler);

    if (!build_type_str.empty()) {
        auto bt = ParseBuildType(build_type_str);
        if (!bt) {
            Log::Error("Unknown build type: '{}'", build_type_str);
            return 1;
        }
        args.build_type = bt;
    }

    if (!console_str.empty()) {
        auto ct = ParseConsoleType(console_str);
        if (!ct) {
            Log::Error("Unknown console type: '{}'", console_str);
            return 1;
        }
        args.console = ct;
    }

    if (!app.got_subcommand(build_sub) && !app.got_subcommand(extract_sub) &&
        !app.got_subcommand(stfs_sub))
        Log::Warn("No subcommand specified, defaulting to 'build'.");

    if (args.mode == "stfs") {
        const auto package_path = *args.stfs_package;
        const auto output_dir = args.output_dir.value_or(std::filesystem::current_path());

        auto package_data = ReadFile(package_path);
        if (!package_data) {
            Log::Error("Failed to read STFS package: {}", package_path.string());
            return 1;
        }

        try {
            std::filesystem::create_directories(output_dir);

            if (args.stfs_split_xboxupd) {
                const auto parts = Stfs::extractXboxupdRaw(AsByteSpan(*package_data));
                if (!WriteFile(output_dir / "cf.bin", parts.cf_raw) ||
                    !WriteFile(output_dir / "cg.bin", parts.cg_raw)) {
                    Log::Error("Failed to write xboxupd split output to '{}'", output_dir.string());
                    return 1;
                }

                Log::Info("Extracted xboxupd CF/CG to '{}'", output_dir.string());
            } else {
                const Stfs::StfsContainer container{AsByteSpan(*package_data)};
                container.extractAll(output_dir);
                Log::Info("Extracted STFS package to '{}'", output_dir.string());
            }
        } catch (const std::exception& ex) {
            Log::Error("STFS extraction failed: {}", ex.what());
            return 1;
        }

        return 0;
    }

    // -----------------------------------------------------------------------
    // Extract mode — inline key parsing, then extract.
    // -----------------------------------------------------------------------
    if (args.mode == "extract") {
        std::vector<uint8_t> cpu_key_bytes;
        if (args.cpu_key) {
            auto parsed = HexToBytes(*args.cpu_key);
            if (parsed && parsed->size() == 16)
                cpu_key_bytes = std::move(*parsed);
        }
        if (cpu_key_bytes.empty())
            cpu_key_bytes.assign(16, 0);

        std::vector<uint8_t> bl_key_bytes;
        if (args.bl_key) {
            auto parsed = HexToBytes(*args.bl_key);
            if (parsed && parsed->size() == 16)
                bl_key_bytes = std::move(*parsed);
        }
        if (bl_key_bytes.empty()) {
            auto parsed = HexToBytes("DD88AD0C9ED669E7B56794FB68563EFA");
            if (parsed && parsed->size() == 16)
                bl_key_bytes = std::move(*parsed);
        }

        if (!args.source_nand) {
            static const std::vector<std::string> kDonorCandidates = {
                "nanddump.bin", "nanddump1.bin", "nanddump2.bin", "nand.bin", "dump.bin"};
            std::vector<std::filesystem::path> search_roots;
            if (args.fw_dir)
                search_roots.push_back(*args.fw_dir);
            search_roots.push_back(std::filesystem::current_path());
            for (const auto& candidate : kDonorCandidates) {
                for (const auto& root : search_roots) {
                    if (std::filesystem::exists(root / candidate)) {
                        args.source_nand = (root / candidate).string();
                        break;
                    }
                }
                if (args.source_nand)
                    break;
            }
        }

        if (!args.source_nand) {
            Log::Error("Extraction requires a source NAND image (-l,--image)");
            return 1;
        }

        auto nand_data = ReadFile(*args.source_nand);
        if (!nand_data) {
            Log::Error("Failed to read source NAND image: {}", args.source_nand->string());
            return 1;
        }

        Log::Info("Parsing NAND image...");
        flash_image_t flash;
        try {
            flash = FlashImage::parse(*nand_data);
        } catch (const std::exception& ex) {
            Log::Error("Failed to parse NAND: {}", ex.what());
            return 1;
        }

        const auto output_dir = args.output_dir.value_or(std::filesystem::current_path());
        Log::Info("Extracting components to '{}'...", output_dir.string());
        if (extract_all(flash, output_dir, cpu_key_bytes, bl_key_bytes)) {
            Log::Info("Extraction completed successfully.");
            return 0;
        }
        Log::Error("Extraction failed.");
        return 1;
    }

    // -----------------------------------------------------------------------
    // Build mode — delegate to RunBuild, then write the output file.
    // -----------------------------------------------------------------------
    auto built_image = RunBuild(args);
    if (!built_image)
        return 1;

    if (!args.output)
        args.output = std::filesystem::path{"updflash.bin"};

    std::filesystem::path output_path = *args.output;
    if (args.output_dir && output_path.is_relative())
        output_path = *args.output_dir / output_path;
    if (output_path.has_parent_path())
        std::filesystem::create_directories(output_path.parent_path());

    if (!WriteFile(output_path, AsByteSpan(*built_image))) {
        Log::Error("Failed to write built NAND image: {}", output_path.string());
        return 1;
    }

    Log::Info("Built NAND image '{}' ({} bytes)", output_path.string(), built_image->size());
    return 0;
}

