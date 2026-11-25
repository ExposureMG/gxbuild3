#include "cli/BuildInputResolver.hpp"

#include "core/BuildRunner.hpp"
#include "core/InputValidator.hpp"
#include "cli/OptionsResolver.hpp"
#include "excrypt.h"
#include "ini/IniParser.hpp"
#include "nand/objects/Freeboot.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"
#include "utils/FileManager.hpp"
#include "utils/FusesetGenerator.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace gxbuild::cli {
    namespace {

        std::filesystem::path anchored(const std::filesystem::path& working_directory,
                                       const std::filesystem::path& path) {
            return path.is_absolute() ? path : working_directory / path;
        }

        Result<std::vector<uint8_t>> parse_cpu_key(std::string_view raw,
                                                   const std::filesystem::path& path) {
            raw = utils::trim_view(raw);
            const auto parsed = nand::validate_cpu_key_hex(raw);
            if (parsed.status == nand::CpuKeyStatus::Invalid) {
                return fail_with(ErrorCode::InvalidArgument, parsed.message, path, raw);
            }
            return parsed.key;
        }

        std::vector<std::filesystem::path>
        resolved_roots(const std::filesystem::path& working_directory, const BuildArgs& args) {
            std::vector<std::filesystem::path> roots;
            roots.reserve(args.source_dirs.size());
            for (const auto& root : args.source_dirs) {
                roots.push_back(anchored(working_directory, root));
            }
            return roots;
        }

        std::string lowercase_basename(std::string_view name) {
            return utils::to_lower(std::filesystem::path(name).filename().string());
        }

        Result<std::optional<gxbuild::utils::ResolvedFile>>
        find_asset(std::string_view name, const std::vector<std::filesystem::path>& roots,
                   gxbuild::utils::ScanOptions options = {},
                   gxbuild::utils::AssetKind kind = gxbuild::utils::AssetKind::Regular) {
            auto found = utils::find_file_data_detailed(name, roots, options, kind);
            if (!found) {
                return with_context(std::move(found), std::string(name));
            }
            return std::move(*found);
        }

        std::string patch_name(std::string_view key, const std::optional<std::string>& extension) {
            std::string result = "patches_";
            result += key;
            if (extension) {
                result += '_';
                result += *extension;
            }
            result += ".bin";
            return result;
        }

        bool is_ascii_alphanumeric(char value) {
            return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
                   (value >= 'a' && value <= 'z');
        }

        bool is_filename_component(std::string_view value, bool allow_underscore) {
            if (value.empty() || value == "." || value == ".." ||
                value.find_first_of("/\\") != std::string_view::npos ||
                std::filesystem::path(value).is_absolute()) {
                return false;
            }
            return std::all_of(value.begin(), value.end(), [allow_underscore](char character) {
                return is_ascii_alphanumeric(character) || character == '-' || character == '.' ||
                       (allow_underscore && character == '_');
            });
        }

        bool is_patch_extension(std::string_view value) {
            return !value.empty() && value.front() != '_' &&
                   std::all_of(value.begin(), value.end(), [](char character) {
                       return is_ascii_alphanumeric(character) || character == '_' ||
                              character == '-';
                   });
        }

        Result<void> validate_patch_components(const BuildArgs& args) {
            if (!is_filename_component(args.section, true)) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "Section must be a filename-safe component", {}, args.section);
            }
            if (args.patch_extension && !is_patch_extension(*args.patch_extension)) {
                return fail_with(
                    ErrorCode::InvalidArgument,
                    "Patch extension must be a filename-safe component without a leading underscore",
                    {}, *args.patch_extension);
            }
            for (const auto& addon : args.addons) {
                if (addon.empty() || !std::all_of(addon.begin(), addon.end(), [](char character) {
                        return is_ascii_alphanumeric(character) || character == '_' ||
                               character == '-';
                    })) {
                    return fail_with(
                        ErrorCode::InvalidArgument,
                        "Add-on must be a bare ASCII logical name using letters, digits, '_' or "
                        "'-'",
                        {}, addon);
                }
            }
            return {};
        }

        std::optional<std::string> automatic_patch_name(const BuildArgs& args,
                                                        bool glitch3_fallback = false) {
            switch (args.build_type) {
                case BuildType::Retail:
                case BuildType::Devkit:
                    return std::nullopt;
                case BuildType::Jtag:
                    return patch_name(args.section, args.patch_extension);
                case BuildType::Glitch:
                    // phat boards all share patches_fat.bin on glitch1
                    if (args.section == "trinity" || args.section == "corona" ||
                        args.section == "winchester")
                        return patch_name(args.section, args.patch_extension);
                    return patch_name("fat", args.patch_extension);
                case BuildType::Glitch2:
                    return patch_name("g2" + args.section, args.patch_extension);
                case BuildType::Glitch2m:
                case BuildType::Devgl:
                    return patch_name("g2m" + args.section, args.patch_extension);
                case BuildType::Glitch3:
                    return patch_name((glitch3_fallback ? "g2" : "g3") + args.section,
                                      args.patch_extension);
            }
            return std::nullopt;
        }

        std::string_view smc_type_token(BuildType build_type) {
            switch (build_type) {
                case BuildType::Retail:
                case BuildType::Devkit:
                case BuildType::Devgl:
                    return "retail";
                case BuildType::Jtag:
                    return "jtag";
                case BuildType::Glitch:
                case BuildType::Glitch2:
                case BuildType::Glitch2m:
                case BuildType::Glitch3:
                    return "gg";
            }
            return "retail";
        }

        struct SmcCandidate {
            std::string name;
            bool retail_fallback = false;
        };

        std::vector<SmcCandidate> smc_candidates(const BuildArgs& args) {
            std::vector<SmcCandidate> candidates;
            candidates.push_back({"smc.bin", false});
            const auto add_group = [&](std::string_view type_token, bool retail_fallback) {
                const std::string base =
                    "smc_" + args.section + "_" + std::string(type_token);
                if (args.patch_extension) {
                    candidates.push_back(
                        {base + "_" + *args.patch_extension + ".bin", retail_fallback});
                }
                candidates.push_back({base + ".bin", retail_fallback});
            };
            add_group(smc_type_token(args.build_type), false);
            if (args.build_type == BuildType::Glitch || args.build_type == BuildType::Glitch2) {
                add_group("retail", true);
            }
            return candidates;
        }

        Result<std::optional<gxbuild::utils::ResolvedFile>>
        find_smc(const BuildArgs& args, const std::vector<std::filesystem::path>& roots,
                 gxbuild::utils::ScanOptions options, bool nosmcpatch) {
            for (const auto& candidate : smc_candidates(args)) {
                auto found = find_asset(candidate.name, roots, options);
                if (!found) {
                    return std::unexpected(found.error());
                }
                if (!*found) {
                    continue;
                }
                // auto-patches a retail fallback smc for glitch1/glitch2 unless nosmcpatch is set.
                if (candidate.retail_fallback && !nosmcpatch && !(**found).data.empty()) {
                    const bool was_encrypted = gxbuild::nand::smc_is_encrypted((**found).data);
                    auto plain = was_encrypted ? gxbuild::nand::smc_decrypt((**found).data)
                                               : (**found).data;
                    if (gxbuild::nand::smc_get_type(plain) == gxbuild::nand::SmcType::Retail) {
                        const auto hits = gxbuild::patchers::apply_signature_patch(
                            plain.data(), static_cast<uint32_t>(plain.size()),
                            gxbuild::patchers::Glitch.addr, gxbuild::patchers::Glitch.value);
                        if (!hits) {
                            return fail_with(hits.error().code,
                                             "Failed to apply the SMC reboot patch: " +
                                                 hits.error().describe(),
                                             (**found).source_path, candidate.name);
                        }
                        if (*hits == 0) {
                            Log::Warn("SMC reboot patch site not found - "
                                      "SMC may not be a supported retail variant");
                        } else {
                            Log::Info("Applied glitch reboot patch to retail SMC");
                        }
                        (**found).data =
                            was_encrypted ? gxbuild::nand::smc_encrypt(plain) : std::move(plain);
                    }
                }
                return std::move(*found);
            }
            return std::optional<gxbuild::utils::ResolvedFile>{};
        }

        struct DirectFile {
            std::filesystem::path path;
            std::vector<uint8_t> data;
        };

        Result<std::optional<DirectFile>>
        find_bin_file(std::string_view filename, const std::vector<std::filesystem::path>& roots) {
            for (const auto& root : roots) {
                const auto bin_directory = (root / "bin").lexically_normal();
                const auto candidate = (bin_directory / filename).lexically_normal();
                if (candidate.parent_path() != bin_directory ||
                    candidate.filename() != std::filesystem::path(filename)) {
                    return fail_with(ErrorCode::InvalidArgument,
                                     "Resolved patch or add-on must be an immediate child of the "
                                     "source bin directory",
                                     candidate, filename);
                }
                std::error_code status_error;
                const auto status = std::filesystem::status(candidate, status_error);
                if (status.type() == std::filesystem::file_type::not_found) {
                    continue;
                }
                if (status_error) {
                    return fail_with(ErrorCode::IoError,
                                     "Could not inspect '" + candidate.string() +
                                         "': " + status_error.message(),
                                     candidate, filename);
                }
                if (!std::filesystem::is_regular_file(status)) {
                    return fail_with(ErrorCode::IoError,
                                     "Resolved asset is not a readable regular file", candidate,
                                     filename);
                }
                auto data = utils::read_file(candidate);
                if (!data) {
                    return fail_with(data.error().code,
                                     "Could not read resolved asset: " + data.error().describe(),
                                     candidate, filename);
                }
                return std::optional<DirectFile>{DirectFile{candidate, std::move(*data)}};
            }
            return std::optional<DirectFile>{};
        }

        // hunts for sb_priv.bin or sb_prv.bin in the source roots and keys/ folders by size and crc32
        Result<std::vector<uint8_t>>
        find_sb_private_key(const std::vector<std::filesystem::path>& roots) {
            static constexpr std::array<std::string_view, 2> kNames{"sb_priv.bin", "sb_prv.bin"};
            bool passed_over = false;
            for (const auto& root : roots) {
                for (const auto& directory : {root, root / "keys"}) {
                    std::error_code status_error;
                    if (!std::filesystem::is_directory(directory, status_error)) {
                        continue;
                    }
                    std::vector<std::filesystem::path> entries;
                    std::filesystem::directory_iterator entry(directory, status_error);
                    for (; !status_error && entry != std::filesystem::directory_iterator();
                         entry.increment(status_error)) {
                        entries.push_back(entry->path());
                    }
                    if (status_error) {
                        return fail_with(ErrorCode::IoError,
                                         "Could not list '" + directory.string() +
                                             "': " + status_error.message(),
                                         directory, "SB_priv.bin");
                    }
                    std::sort(entries.begin(), entries.end());
                    for (const auto name : kNames) {
                        for (const auto& path : entries) {
                            if (lowercase_basename(path.filename().string()) != name ||
                                !std::filesystem::is_regular_file(path, status_error)) {
                                continue;
                            }
                            auto data = utils::read_file(path, sizeof(EXCRYPT_RSAPRV_2048) + 1);
                            if (data && data->size() == sizeof(EXCRYPT_RSAPRV_2048) &&
                                gxbuild::utils::crc32(*data) ==
                                    gxbuild::utils::kSbPrivateKeyCrc32) {
                                Log::Info("Using the SB private key {}", path.string());
                                return std::move(*data);
                            }
                            Log::Warn("{} is not the SB private key (size or CRC-32 differs); it "
                                      "is passed over",
                                      path.string());
                            passed_over = true;
                        }
                    }
                }
            }
            return fail_with(
                ErrorCode::NotFound,
                std::string(passed_over ? "No candidate SB_priv.bin is the SB private key"
                                        : "No SB_priv.bin (or SB_prv.bin) was found") +
                    ": a devgl image's patched SD is signed again with the SB private key. Put "
                    "SB_priv.bin in a source root or a keys folder inside one",
                {}, "SB_priv.bin");
        }

        void overlay_flashfs(std::vector<std::pair<std::string, std::vector<uint8_t>>>& destination,
                             std::pair<std::string, std::vector<uint8_t>> file,
                             std::unordered_map<std::string, size_t>& positions) {
            const auto key = lowercase_basename(file.first);
            const auto [position, inserted] = positions.emplace(key, destination.size());
            if (inserted) {
                destination.push_back(std::move(file));
            } else {
                destination[position->second] = std::move(file);
            }
        }

        // sorts files into ini [flashfs] then [security] order, ignoring any trailing slot digit
        void order_flashfs(std::vector<std::pair<std::string, std::vector<uint8_t>>>& files,
                           const ini::Document& ini) {
            std::unordered_map<std::string, size_t> ranks;
            for (const auto section_name : {"flashfs", "security"}) {
                if (const auto* section = ini.get(section_name)) {
                    for (const auto& entry : *section) {
                        const auto key = lowercase_basename(utils::ini_asset_name(entry.key));
                        if (!key.empty() && key != "none") {
                            ranks.emplace(key, ranks.size());
                        }
                    }
                }
            }
            static constexpr std::array<std::string_view, 5> kSecured{
                "crl.bin", "dae.bin", "extended.bin", "secdata.bin", "fcrt.bin"};
            const auto rank = [&ranks](const std::string& name) {
                auto key = lowercase_basename(name);
                if (const auto it = ranks.find(key); it != ranks.end()) {
                    return it->second;
                }
                if (!key.empty() && key.back() >= '0' && key.back() <= '9') {
                    key.pop_back();
                    if (const auto it = ranks.find(key); it != ranks.end()) {
                        return it->second;
                    }
                }
                const auto secured = std::find(kSecured.begin(), kSecured.end(), key);
                return ranks.size() + static_cast<size_t>(secured - kSecured.begin());
            };
            std::stable_sort(files.begin(), files.end(),
                             [&rank](const auto& left, const auto& right) {
                                 return rank(left.first) < rank(right.first);
                             });
        }

        void weigh_missing_fcrt(const ini::Document& ini,
                                const std::optional<std::vector<uint8_t>>& keyvault,
                                BuildType build_type) {
            bool listed = false;
            if (const auto* security = ini.get("security")) {
                listed = std::any_of(security->begin(), security->end(), [](const auto& entry) {
                    return lowercase_basename(utils::ini_asset_name(entry.key)) == "fcrt.bin";
                });
            }
            const auto requirement = keyvault ? gxbuild::nand::fcrt_requirement(*keyvault)
                                              : gxbuild::nand::FcrtRequirement::NotRequired;
            if (requirement == gxbuild::nand::FcrtRequirement::NotRequired) {
                if (listed) {
                    Log::Info("fcrt.bin was not found and the keyvault does not require it; it "
                              "is left out");
                }
                return;
            }
            if (!listed) {
                Log::Warn("The keyvault flags fcrt.bin as required, but the INI's [security] does "
                          "not list it; it is left out");
                return;
            }
            Log::Error("fcrt.bin was not found; the keyvault flags it as required, and it is left "
                       "out");
            if (build_type != BuildType::Retail && build_type != BuildType::Devkit) {
                if (requirement == gxbuild::nand::FcrtRequirement::Required) {
                    Log::Warn("On a hacked image a nofcrt patch (-a nofcrt) should let the drive "
                              "and the console work");
                } else {
                    Log::Warn("On a hacked image a nofcrt patch (-a nofcrt) will not let the "
                              "drive work, but should let the console boot");
                }
            }
        }

        Result<ini::Document> validate_build_ini_inputs(const BuildArgs& args,
                                                        const std::filesystem::path& ini_path,
                                                        std::string_view target_section) {
            std::error_code ini_status_error;
            const auto ini_status = std::filesystem::status(ini_path, ini_status_error);
            if (ini_status.type() == std::filesystem::file_type::not_found || ini_status_error ||
                !std::filesystem::is_regular_file(ini_status)) {
                std::string message = "Build INI is not a readable regular file";
                if (ini_status_error &&
                    ini_status.type() != std::filesystem::file_type::not_found) {
                    message += ": " + ini_status_error.message();
                }
                return fail_with(ini_status.type() == std::filesystem::file_type::not_found
                                     ? ErrorCode::NotFound
                                     : ErrorCode::IoError,
                                 std::move(message), ini_path);
            }

            auto ini_document = ini::parse_file(ini_path);
            if (!ini_document) {
                return fail_with(ini_document.error().code,
                                 "Could not read build INI: " + ini_document.error().describe(),
                                 ini_path);
            }
            if (args.section.empty()) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "A build INI section stem is required", ini_path);
            }
            if (!ini_document->get(target_section)) {
                return fail_with(ErrorCode::NotFound,
                                 "Required build INI section [" + std::string(target_section) +
                                     "] was not found",
                                 ini_path, target_section);
            }
            return ini_document;
        }

        Result<void> verify_ini_assets(const ini::Document& ini_document,
                                       std::string_view target_section,
                                       const std::filesystem::path& ini_path,
                                       const std::vector<std::filesystem::path>& roots,
                                       const gxbuild::utils::ScanOptions& scan_options,
                                       const std::optional<Input>& donor) {
            std::unordered_set<std::string> donor_flashfs_names;
            if (donor && donor->flashfs_sec) {
                for (const auto& file : *donor->flashfs_sec) {
                    donor_flashfs_names.insert(lowercase_basename(file.first));
                }
            }
            const auto* section = ini_document.get(target_section);
            for (const auto& entry : *section) {
                const auto key = lowercase_basename(entry.key);
                if (key.empty() || key == "none") {
                    continue;
                }
                auto found = find_asset(entry.key, roots, scan_options,
                                        gxbuild::utils::AssetKind::Bootloader);
                if (!found) {
                    return std::unexpected(found.error());
                }
                if (!*found) {
                    return fail_with(ErrorCode::NotFound,
                                     "Required INI bootloader '" + entry.key + "' from '" +
                                         ini_path.string() + "' was not found",
                                     ini_path, entry.key);
                }
            }
            for (const auto section_name : {"security", "flashfs"}) {
                const auto* payload_section = ini_document.get(section_name);
                if (!payload_section) {
                    continue;
                }
                for (const auto& entry : *payload_section) {
                    const auto key = lowercase_basename(entry.key);
                    if (key.empty() || key == "none") {
                        continue;
                    }
                    const bool outside = utils::ini_asset_is_outside(entry.key);
                    auto loose_options = scan_options;
                    loose_options.nosu = true;
                    const auto name = utils::ini_asset_name(entry.key);
                    auto found = outside ? find_asset(name, roots, loose_options)
                                         : find_asset(entry.key, roots, scan_options);
                    if (outside && found && !*found) {
                        found = find_asset(std::filesystem::path(name).filename().string(), roots,
                                           loose_options);
                    }
                    if (!found) {
                        return std::unexpected(found.error());
                    }
                    const bool made_up = std::string_view(section_name) == "security" &&
                                         !scan_options.nosusecurity &&
                                         (key == "extended.bin" || key == "secdata.bin");
                    const bool is_security = std::string_view(section_name) == "security";
                    uint32_t listed_crc = 0;
                    {
                        auto digits = utils::trim_view(entry.value);
                        if (digits.starts_with("0x") || digits.starts_with("0X"))
                            digits.remove_prefix(2);
                        if (!digits.empty())
                            std::from_chars(digits.data(), digits.data() + digits.size(), listed_crc,
                                            16);
                    }
                    // security files and flashfs entries without a crc are optional if missing
                    const bool optional =
                        outside || is_security || key == "fcrt.bin" || made_up || listed_crc == 0;
                    if (!*found && !optional && !donor_flashfs_names.contains(key)) {
                        return fail_with(ErrorCode::NotFound,
                                         "Required INI payload '" + entry.key + "' from '" +
                                             ini_path.string() +
                                             "' was not found in the donor or source roots",
                                         ini_path, entry.key);
                    }
                }
            }
            return {};
        }

        Result<void> apply_loose_donor_assets(const BuildArgs& args,
                                              const ResolvedFoundations& foundations,
                                              const std::vector<std::filesystem::path>& roots,
                                              const gxbuild::utils::ScanOptions& scan_options,
                                              Input& input) {
            auto keyvault = find_asset("kv.bin", roots, scan_options);
            if (!keyvault) {
                return std::unexpected(keyvault.error());
            }
            auto smc = find_smc(args, roots, scan_options,
                                foundations.options.nosmcpatch.value_or(false));
            if (!smc) {
                return std::unexpected(smc.error());
            }

            if (!foundations.donor) {
                if (!*keyvault) {
                    return fail_with(ErrorCode::NotFound, "Loose donor requires kv.bin", {},
                                     "kv.bin");
                }
                if (!*smc) {
                    return fail_with(ErrorCode::NotFound, "Loose donor requires smc.bin", {},
                                     "smc.bin");
                }
                if (!foundations.file_options.cbldv && !foundations.cli_overrides.cbldv) {
                    return fail_with(ErrorCode::InvalidArgument, "Loose donor requires cbldv", {},
                                     "cbldv");
                }
                if (!foundations.file_options.cfldv && !foundations.cli_overrides.cfldv) {
                    return fail_with(ErrorCode::InvalidArgument, "Loose donor requires cfldv", {},
                                     "cfldv");
                }
                if (!foundations.file_options.pairing_data &&
                    !foundations.cli_overrides.pairing_data) {
                    return fail_with(ErrorCode::InvalidArgument,
                                     "Loose donor requires pairing_data", {}, "pairing_data");
                }
            }

            // decrypts kv.bin if it matches the cpu key, otherwise treats it as already decrypted
            if (*keyvault) {
                auto opened =
                    gxbuild::nand::open_loose_keyvault(foundations.cpu_key, (**keyvault).data);
                if (!opened) {
                    return fail_with(opened.error().code, opened.error().describe(),
                                     (**keyvault).source_path, "kv.bin");
                }
                using Form = gxbuild::nand::LooseKeyvault::Form;
                if (opened->form == Form::StaleNonce) {
                    Log::Warn("kv.bin is in the clear, but its nonce is not one the CPU key "
                              "derives; it is taken as it stands. Make sure it is this console's");
                } else if (opened->form == Form::Unopened) {
                    Log::Error("kv.bin looks sealed but does not open under the CPU key; it is "
                               "taken as the keyvault in the clear, as xeBuild takes it, and the "
                               "image will not boot unless it is this console's keyvault");
                }
                input.metadata.keyvault = std::move(opened->plain);
            } else if (foundations.donor && !input.metadata.keyvault) {
                return fail_with(ErrorCode::AuthFailed,
                                 "The donor's keyvault does not open under the CPU "
                                 "key; supply the console's kv.bin",
                                 {}, "kv.bin");
            }
            if (*smc) {
                input.metadata.smc = std::move((**smc).data);
            }

            for (size_t index = 0; index < input.mobiles.slots.size(); ++index) {
                const std::string name =
                    "mobile" + std::string(1, static_cast<char>('A' + index)) + ".bin";
                auto mobile = find_asset(name, roots, scan_options);
                if (!mobile) {
                    return std::unexpected(mobile.error());
                }
                if (*mobile) {
                    input.mobiles.slots[index] = std::move((**mobile).data);
                }
            }
            return {};
        }

        Result<void> merge_flashfs_entries(const ini::Document& ini_document,
                                           const std::filesystem::path& ini_path,
                                           const ResolvedFoundations& foundations,
                                           const gxbuild::utils::ScanOptions& scan_options,
                                           const gxbuild::utils::IniFilesResult& ini_files,
                                           BuildType build_type, Input& input) {
            std::unordered_set<std::string> ini_flashfs_names;
            for (const auto section_name : {"security", "flashfs"}) {
                if (const auto* payload_section = ini_document.get(section_name)) {
                    for (const auto& entry : *payload_section) {
                        const auto key = lowercase_basename(entry.key);
                        if (!key.empty() && key != "none") {
                            ini_flashfs_names.insert(key);
                        }
                    }
                }
            }
            std::vector<std::pair<std::string, std::vector<uint8_t>>> flashfs;
            std::unordered_map<std::string, size_t> flashfs_positions;
            // carry over donor flashfs files only if they're in the ini and we didn't find a replacement
            if (input.flashfs_sec) {
                for (auto& file : *input.flashfs_sec) {
                    const auto key = lowercase_basename(file.first);
                    if (ini_flashfs_names.contains(key)) {
                        overlay_flashfs(flashfs, std::move(file), flashfs_positions);
                    }
                }
            }
            for (auto file : ini_files.flashfs_sec) {
                const auto key = lowercase_basename(file.first);
                if ((key == "secdata.bin" || key == "extended.bin") && file.second.size() >= 0x10) {
                    auto opened =
                        key == "extended.bin"
                            ? gxbuild::nand::open_loose_extended(file.second, foundations.cpu_key)
                            : gxbuild::nand::open_loose_secdata(file.second, foundations.cpu_key);
                    if (!opened) {
                        return fail_with(
                            opened.error().code,
                            "Could not decrypt secure INI file at the Input boundary: " +
                                opened.error().describe(),
                            ini_path, file.first);
                    }
                    file.second = std::move(*opened);
                }
                overlay_flashfs(flashfs, std::move(file), flashfs_positions);
            }
            // inserts an empty placeholder for missing extended.bin or secdata.bin
            if (!scan_options.nosusecurity) {
                if (const auto* security = ini_document.get("security")) {
                    for (const auto& entry : *security) {
                        const auto key = lowercase_basename(utils::ini_asset_name(entry.key));
                        if ((key == "extended.bin" || key == "secdata.bin") &&
                            !flashfs_positions.contains(key)) {
                            overlay_flashfs(flashfs, {key, {}}, flashfs_positions);
                        }
                    }
                }
            }
            order_flashfs(flashfs, ini_document);
            if (!flashfs_positions.contains("fcrt.bin")) {
                weigh_missing_fcrt(ini_document, input.metadata.keyvault, build_type);
            }
            input.flashfs_sec = std::move(flashfs);
            return {};
        }

        Result<std::optional<InputPatches>>
        resolve_patch_inputs(const BuildArgs& args, const std::vector<std::filesystem::path>& roots) {
            if ((args.build_type == BuildType::Retail || args.build_type == BuildType::Devkit) &&
                !args.addons.empty()) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "Add-ons require an automatic patchset and are not supported for "
                                 "retail or devkit builds",
                                 {}, args.addons.front());
            }

            InputPatches patches{};
            bool has_patches = false;
            if (const auto automatic_name = automatic_patch_name(args)) {
                auto automatic = find_bin_file(*automatic_name, roots);
                if (!automatic) {
                    return std::unexpected(automatic.error());
                }
                std::string selected_name = *automatic_name;
                if (!*automatic && args.build_type == BuildType::Glitch3) {
                    selected_name = *automatic_patch_name(args, true);
                    automatic = find_bin_file(selected_name, roots);
                    if (!automatic) {
                        return std::unexpected(automatic.error());
                    }
                }
                if (!*automatic) {
                    const std::string message =
                        args.build_type == BuildType::Glitch3
                            ? "Required automatic patchset was not found (neither " +
                                  *automatic_name + " nor " + selected_name + ")"
                            : "Required automatic patchset was not found";
                    return fail_with(ErrorCode::NotFound, message, {}, selected_name);
                }
                Log::Info("Using patchset {}", (**automatic).path.string());
                patches.automatic = InputPatchFile{selected_name, std::move((**automatic).data)};
                has_patches = true;
            }

            for (const auto& addon : args.addons) {
                const std::string filename = addon + ".bin";
                auto found = find_bin_file(filename, roots);
                if (!found) {
                    return std::unexpected(found.error());
                }
                if (!*found) {
                    return fail_with(ErrorCode::NotFound, "Required add-on was not found", {},
                                     filename);
                }
                patches.addons.push_back(InputPatchFile{filename, std::move((**found).data)});
                has_patches = true;
            }
            if (!has_patches) {
                return std::nullopt;
            }
            return patches;
        }

        Result<void> resolve_payload_inputs(const BuildArgs& args,
                                            const ResolvedFoundations& foundations,
                                            const std::vector<std::filesystem::path>& roots,
                                            const ini::Document& ini_document,
                                            const gxbuild::utils::ScanOptions& scan_options,
                                            Input& input) {
            const bool is_jtag = args.build_type == BuildType::Jtag;
            const bool is_glitch_family =
                args.build_type == BuildType::Glitch || args.build_type == BuildType::Glitch2 ||
                args.build_type == BuildType::Glitch2m || args.build_type == BuildType::Glitch3;
            const bool needs_fuses = is_jtag || args.build_type == BuildType::Glitch2m;
            // skips xell on devgl and generates virtual fuses from a hardcoded 0x01000000 retail console word.
            if (args.build_type == BuildType::Devgl) {
                constexpr uint32_t kRetailConsoleWord = 0x01000000;
                auto fuses = gxbuild::utils::generate_fuseset(
                    kRetailConsoleWord, foundations.cpu_key, input.metadata.cf_ldv.value_or(0));
                if (!fuses) {
                    return fail_with(fuses.error().code,
                                     "Could not generate the virtual fuseset: " +
                                         fuses.error().describe(),
                                     {}, "fuses");
                }
                InputPayloads payloads{};
                payloads.fuses = std::move(*fuses);
                input.payloads = std::move(payloads);

                auto key = find_sb_private_key(roots);
                if (!key) {
                    return std::unexpected(key.error());
                }
                input.sb_private_key = std::move(*key);
                return {};
            }
            if (!is_jtag && !is_glitch_family) {
                return {};
            }

            InputPayloads payloads{};
            const std::string xell_name = is_jtag ? "xell-2f.bin" : "xell-gggggg.bin";
            auto xell = find_asset(xell_name, roots, scan_options);
            if (!xell) {
                return std::unexpected(xell.error());
            }
            if (!*xell) {
                return fail_with(ErrorCode::NotFound,
                                 "JTAG and glitch builds require a XeLL payload (" + xell_name +
                                     ")",
                                 {}, xell_name);
            }
            payloads.xell = std::move((**xell).data);

            if (is_jtag) {
                std::string firmware_version;
                if (const auto* version_section = ini_document.get("version");
                    version_section && !version_section->empty()) {
                    firmware_version = version_section->front().key;
                }
                payloads.rebooter = gxbuild::nand::freeboot_rebooter_for(firmware_version);
                payloads.payload = gxbuild::nand::freeboot_payload_for(payloads.rebooter->size());
            }

            if (needs_fuses) {
                const auto& fuse_cb = is_jtag ? input.bootloaders.extra_cb : input.bootloaders.cb_b;
                if (!fuse_cb) {
                    return fail_with(
                        ErrorCode::InvalidArgument,
                        is_jtag ? "Virtual fuses are built from the second CB, and section '" +
                                      args.section + "' names none"
                                : "Virtual fuses are built from the CB_B, and section '" +
                                      args.section + "' names none",
                        {}, "fuses");
                }
                const auto cb_word = gxbuild::utils::read_cb_word(*fuse_cb);
                if (!cb_word) {
                    return fail_with(cb_word.error().code,
                                     "Could not read the console word of the CB "
                                     "the virtual fuses are built from: " +
                                         cb_word.error().describe(),
                                     {}, "fuses");
                }
                // zero the cb fuse word when se replaces cf1 on jtag
                const uint32_t fuse_word =
                    input.bootloaders.extra_se ? uint32_t{0x00000000} : *cb_word;
                auto fuses = gxbuild::utils::generate_fuseset(
                    fuse_word, foundations.cpu_key, input.metadata.cf_ldv.value_or(0));
                if (!fuses) {
                    return fail_with(fuses.error().code,
                                     "Could not generate the virtual fuseset: " +
                                         fuses.error().describe(),
                                     {}, "fuses");
                }
                payloads.fuses = std::move(*fuses);
            }
            input.payloads = std::move(payloads);
            return {};
        }

    } // namespace

    BuildInputResolver::BuildInputResolver(std::filesystem::path working_directory)
        : working_directory_(std::move(working_directory)) {}

    Result<ResolvedFoundations>
    BuildInputResolver::resolve_foundations(const BuildArgs& args) const {
        if (args.source_dirs.empty()) {
            return fail_with(ErrorCode::InvalidArgument, "At least one source root is required");
        }
        std::vector<std::filesystem::path> roots;
        roots.reserve(args.source_dirs.size());
        for (const auto& root : args.source_dirs) {
            if (root.empty()) {
                return fail_with(ErrorCode::InvalidArgument, "Source root path cannot be empty");
            }
            auto resolved_root = anchored(working_directory_, root);
            std::error_code directory_error;
            if (!std::filesystem::is_directory(resolved_root, directory_error)) {
                std::string message = "Source root is not a directory";
                if (directory_error) {
                    message += ": " + directory_error.message();
                }
                return fail_with(ErrorCode::InvalidArgument, std::move(message),
                                 std::move(resolved_root));
            }
            roots.push_back(std::move(resolved_root));
        }

        auto file_options = load_options(working_directory_ / "options.ini");
        if (!file_options) {
            return std::unexpected(file_options.error());
        }
        auto layered_options = apply_cli_options(*file_options, args.config);
        if (!layered_options) {
            return std::unexpected(layered_options.error());
        }

        utils::StfsCache stfs_cache;
        const utils::ScanOptions foundation_scan{.stfs_cache = &stfs_cache};

        Result<std::vector<uint8_t>> cpu_key = fail_with(
            ErrorCode::NotFound, "No CPU key was supplied and cpukey.txt was not found");
        if (args.cpu_key) {
            cpu_key = parse_cpu_key(*args.cpu_key, {});
        } else {
            auto discovered = utils::find_file_data_detailed("cpukey.txt", roots, foundation_scan);
            if (!discovered) {
                return std::unexpected(std::move(discovered.error()).add_context("cpukey.txt"));
            }
            if (*discovered) {
                const std::string raw_key((*discovered)->data.begin(), (*discovered)->data.end());
                cpu_key = parse_cpu_key(raw_key, (*discovered)->source_path);
            }
        }
        if (!cpu_key) {
            return std::unexpected(cpu_key.error());
        }

        std::optional<std::filesystem::path> nand_path;
        std::optional<std::vector<uint8_t>> nand_data;
        if (args.input_path) {
            nand_path = anchored(working_directory_, *args.input_path);
            auto read = utils::read_file(*nand_path);
            if (!read) {
                return fail_with(read.error().code,
                                 "Could not read explicit donor NAND '" + nand_path->string() +
                                     "': " + read.error().describe());
            }
            nand_data = std::move(*read);
        } else {
            auto discovered =
                utils::find_file_data_detailed("nanddump.bin", roots, foundation_scan);
            if (!discovered) {
                return std::unexpected(std::move(discovered.error()).add_context("nanddump.bin"));
            }
            if (*discovered) {
                nand_path = (*discovered)->source_path;
                nand_data = std::move((*discovered)->data);
            }
        }

        std::optional<Input> donor;
        ImageType image_type{};
        if (nand_data) {
            auto extracted = extract_all(*nand_data, *cpu_key);
            if (!extracted) {
                return fail_with(extracted.error().code,
                                 "Could not extract donor NAND with the resolved CPU key: " +
                                     extracted.error().describe(),
                                 *nand_path);
            }
            donor = std::move(*extracted);

            const ImageType detected_type = donor->image_type;
            image_type = args.image_type.value_or(detected_type);
            if (args.image_type && *args.image_type != detected_type) {
                donor->metadata.nand_image.reset();
                donor->image_type = *args.image_type;
            }
        } else {
            if (!args.image_type) {
                return fail_with(ErrorCode::InvalidArgument,
                                 "A block type is required without a donor NAND");
            }
            image_type = *args.image_type;
        }

        auto [options, cli_overrides] = std::move(*layered_options);
        return ResolvedFoundations{.file_options = std::move(*file_options),
                                   .options = std::move(options),
                                   .cli_overrides = std::move(cli_overrides),
                                   .cpu_key = std::move(*cpu_key),
                                   .donor = std::move(donor),
                                   .image_type = image_type};
    }

    Result<BuildRequest> BuildInputResolver::resolve(const BuildArgs& args) const {
        try {
            auto foundations = resolve_foundations(args);
            if (!foundations) {
                return std::unexpected(foundations.error());
            }
            const auto valid_components = validate_patch_components(args);
            if (!valid_components) {
                return std::unexpected(valid_components.error());
            }
            const auto roots = resolved_roots(working_directory_, args);

            if (args.build_ini.empty()) {
                return fail_with(ErrorCode::InvalidArgument, "A build INI path is required");
            }
            const auto ini_path = anchored(working_directory_, args.build_ini);
            const std::string target_section = args.section + "bl";
            const auto ini_document = validate_build_ini_inputs(args, ini_path, target_section);
            if (!ini_document) {
                return std::unexpected(ini_document.error());
            }

            utils::StfsCache stfs_cache;
            const gxbuild::utils::ScanOptions scan_options{
                .nosusecurity = foundations->options.nosusecurity.value_or(false),
                .stfs_cache = &stfs_cache};
            if (const auto assets = verify_ini_assets(*ini_document, target_section, ini_path,
                                                      roots, scan_options, foundations->donor);
                !assets) {
                return std::unexpected(assets.error());
            }

            const auto ini_files = utils::read_ini_files(ini_path, target_section, roots,
                                                         scan_options, args.build_type);
            if (!ini_files) {
                return fail_with(ini_files.error().code, ini_files.error().describe(), ini_path,
                                 target_section);
            }

            Input input = foundations->donor.value_or(Input{});
            input.build_type = args.build_type;
            input.image_type = foundations->image_type;
            input.console = args.console;
            input.options = foundations->options;
            input.metadata.cpu_key = foundations->cpu_key;

            if (const auto resolved_metadata = apply_winning_metadata(
                    input.metadata, foundations->file_options, foundations->cli_overrides,
                    foundations->donor.has_value(), working_directory_ / "options.ini");
                !resolved_metadata) {
                return std::unexpected(resolved_metadata.error());
            }
            if (const auto loose =
                    apply_loose_donor_assets(args, *foundations, roots, scan_options, input);
                !loose) {
                return std::unexpected(loose.error());
            }

            input.bootloaders = ini_files->bootloaders;
            input.raw_patches = ini_files->raw_patches;
            // zero out cf ldv when an extra se stage replaces cf1 on jtag
            if (input.bootloaders.extra_se) {
                input.metadata.cf_ldv = 0;
            }

            if (const auto flashfs =
                    merge_flashfs_entries(*ini_document, ini_path, *foundations, scan_options,
                                          *ini_files, args.build_type, input);
                !flashfs) {
                return std::unexpected(flashfs.error());
            }

            auto patches = resolve_patch_inputs(args, roots);
            if (!patches) {
                return std::unexpected(patches.error());
            }
            input.patches = std::move(*patches);

            if (const auto payloads = resolve_payload_inputs(args, *foundations, roots,
                                                             *ini_document, scan_options, input);
                !payloads) {
                return std::unexpected(payloads.error());
            }

            if (const auto validation = validate_input(input); !validation) {
                return std::unexpected(validation.error());
            }
            return BuildRequest{.input = std::move(input),
                                .output_path = anchored(working_directory_, args.output_path)};
        } catch (const std::exception& exception) {
            return fail(ErrorCode::Internal, "Input resolution failed: {}", exception.what());
        }
    }

} // namespace gxbuild::cli
