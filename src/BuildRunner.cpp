#include "BuildRunner.hpp"
#include "nand/FlashImageLayout.hpp"

#include "InputValidator.hpp"
#include "Wire.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "nand/objects/XConfig.hpp"
#include "nand/objects/XeLL.hpp"
#include "patchers/Patcher.hpp"
#include "patchers/Patches.hpp"
#include "patchers/Signature.hpp"
#include "utils/BuildTime.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <exception>
#include <expected>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace gxbuild3 {

    using namespace nand;

    namespace {

        // A devkit image on a small-block console is 64 MB with that console's spare layout
        // (xeBuild 1.21: "NAND size: 64MiB (small block)"); every other shape is the console's own.
        std::pair<Driver::ImageSize, Driver::DriverMode> driver_config(ImageType type,
                                                                       BuildType build_type) {
            const auto small_size = build_type == BuildType::Devkit ? Driver::ImageSize::Bigordevkit
                                                                    : Driver::ImageSize::Smallblock;
            switch (type) {
                case ImageType::SmallBlock:
                    return {small_size, Driver::DriverMode::Small};
                case ImageType::NewSmallBlock:
                    return {small_size, Driver::DriverMode::NewSmall};
                case ImageType::BigBlock:
                    return {Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big};
                case ImageType::Emmc:
                    return {Driver::ImageSize::Emmcblock, Driver::DriverMode::Emmc};
            }
            std::unreachable();
        }

        ImageType image_type_from_driver(Driver::DriverMode mode) {
            switch (mode) {
                case Driver::DriverMode::Small:
                    return ImageType::SmallBlock;
                case Driver::DriverMode::NewSmall:
                    return ImageType::NewSmallBlock;
                case Driver::DriverMode::Big:
                    return ImageType::BigBlock;
                case Driver::DriverMode::Emmc:
                    return ImageType::Emmc;
            }
            std::unreachable();
        }

        // FlashFS files sealed under the CPU key: plaintext inside Input, encrypted in the NAND.
        bool is_cpu_keyed_secfile(std::string_view name) {
            std::string lower{name};
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return lower == "secdata.bin" || lower == "extended.bin";
        }

        std::string lowercase_name(std::string_view name) {
            std::string lower{name};
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return lower;
        }

        bool is_console_secured_file(std::string_view name) {
            const auto lower = lowercase_name(name);
            return lower == "crl.bin" || lower == "dae.bin" || lower == "secdata.bin";
        }

        const std::vector<uint8_t>* console_secured_file(const InputMetadata& metadata,
                                                         std::string_view lower_name) {
            for (const auto& [name, data] : metadata.console_secured_files) {
                if (lowercase_name(name) == lower_name) {
                    return &data;
                }
            }
            return nullptr;
        }

        // A FlashFS file as the image carries it. crl.bin, dae.bin, extended.bin and secdata.bin
        // are sealed for this build as xeBuild 1.21 seals them: the content is the file supplied,
        // the sealing the console's own copy's (or, with none, the supplied file's own when it is a
        // console copy, or drawn), and crl.bin, dae.bin and secdata.bin state the build's time and
        // the CF lockdown value. A crl.bin or dae.bin that does not open is written as supplied,
        // and so is a secdata.bin that does not open unless it is the console's own copy. An
        // extended.bin or secdata.bin that is empty (nothing supplied it) or of the wrong length,
        // an extended.bin that does not open and the console's own secdata.bin when it does not
        // open are replaced by a clean one, as xeBuild makes one up. fcrt.bin is sealed under the
        // CPU key when it is in the clear, written as its failed opening when it opens under no key
        // (the console's own copy is then carried as it stands) and otherwise written as supplied.
        // Every other file is written as supplied. An Error when a file cannot be sealed at all.
        Result<std::vector<uint8_t>> sealed_flashfs_file(std::string_view name,
                                                         const std::vector<uint8_t>& data,
                                                         const Input& input,
                                                         const SecuredFileBuild& build) {
            const auto& cpu_key = input.metadata.cpu_key;
            const auto lower = lowercase_name(name);
            if (cpu_key.size() < 16) {
                return data;
            }
            const auto* own = console_secured_file(input.metadata, lower);
            if (lower == "crl.bin") {
                std::optional<CrlSealing> sealing;
                if (own) {
                    if (auto own_sealing = crl_sealing(*own, cpu_key)) {
                        sealing = *own_sealing;
                    } else {
                        Log::Warn(
                            "The console's crl.bin does not open under its CPU key; its sealing is "
                            "not used");
                        Log::Debug("crl.bin sealing: {}", own_sealing.error().describe());
                    }
                }
                if (!sealing) {
                    if (auto supplied_sealing = crl_sealing(data, cpu_key)) {
                        sealing = *supplied_sealing;
                    }
                }
                if (!sealing) {
                    Log::Info("crl.bin is sealed under a drawn vector and file key");
                    sealing = random_crl_sealing();
                }
                auto sealed = reseal_crl(data, cpu_key, *sealing, build);
                if (sealed) {
                    return std::move(*sealed);
                }
                Log::Warn(
                    "crl.bin opens under no key it is tried under; it is written as supplied");
                Log::Debug("crl.bin not resealed: {}", sealed.error().describe());
                return data;
            }
            if (lower == "dae.bin") {
                std::optional<DaeSealing> sealing;
                if (own) {
                    if (auto own_sealing = dae_sealing(*own, cpu_key)) {
                        sealing = *own_sealing;
                    } else {
                        Log::Warn(
                            "The console's dae.bin does not open under its CPU key; its sealing is "
                            "not used");
                        Log::Debug("dae.bin sealing: {}", own_sealing.error().describe());
                    }
                }
                if (!sealing) {
                    if (auto supplied_sealing = dae_sealing(data, cpu_key)) {
                        sealing = *supplied_sealing;
                    }
                }
                if (!sealing) {
                    Log::Info("dae.bin is sealed under a drawn head and field");
                    sealing = random_dae_sealing();
                }
                auto sealed = reseal_dae(data, cpu_key, *sealing, build);
                if (sealed) {
                    return std::move(*sealed);
                }
                Log::Warn(
                    "dae.bin opens under no key it is tried under; it is written as supplied");
                Log::Debug("dae.bin not resealed: {}", sealed.error().describe());
                return data;
            }
            if (lower == "extended.bin") {
                // Its head is the keyvault's; with no keyvault, a copy that opens keeps its own and
                // a clean one has a zero head.
                const auto& keyvault = input.metadata.keyvault;
                const bool keyvault_head = keyvault && keyvault->size() >= 0x18;
                if (data.size() == kExtendedSize && extended_opened(data, cpu_key)) {
                    const auto head_source = keyvault_head ? std::span<const uint8_t>(*keyvault)
                                                           : std::span<const uint8_t>(data);
                    return reseal_extended(data, cpu_key, head_source.subspan(0x10).first<8>());
                }
                if (data.empty()) {
                    Log::Info("extended.bin was not supplied; a clean one is made up");
                } else if (data.size() != kExtendedSize) {
                    Log::Warn("extended.bin is 0x{:X} bytes, not 0x{:X}; a clean one is made up",
                              data.size(), kExtendedSize);
                } else {
                    Log::Warn("extended.bin opens under no key; a clean one is made up");
                }
                std::array<uint8_t, 8> head{};
                if (keyvault_head) {
                    std::copy_n(keyvault->begin() + 0x10, head.size(), head.begin());
                }
                return clean_extended(cpu_key, head);
            }
            if (lower == "secdata.bin") {
                // Its head is the console's own copy's; with none, a copy that opens keeps its own
                // and a clean one takes a drawn head.
                std::optional<std::array<uint8_t, 8>> own_head;
                if (own && secdata_opened(*own, cpu_key)) {
                    if (auto head = secdata_head(*own)) {
                        own_head = *head;
                    }
                }
                if (data.size() == kSecdataSize && secdata_opened(data, cpu_key)) {
                    return reseal_secdata(data, cpu_key, own_head, build);
                }
                // The console's own copy is used only when it opens; a supplied copy of the right
                // length that does not open is written as it stands.
                const bool unopened_own = own && data == *own;
                if (data.size() == kSecdataSize && !unopened_own) {
                    Log::Warn(
                        "secdata.bin did not open under the CPU key; it is sealed again under "
                        "the nonce it carries");
                    std::vector<uint8_t> file_data = data;
                    if (auto crypted = crypt_secfile(cpu_key, file_data); !crypted) {
                        return std::unexpected(std::move(crypted.error()));
                    }
                    return file_data;
                }
                if (data.empty()) {
                    Log::Info("secdata.bin was not supplied; a clean one is made up");
                } else if (data.size() != kSecdataSize) {
                    Log::Warn("secdata.bin is 0x{:X} bytes, not 0x{:X}; a clean one is made up",
                              data.size(), kSecdataSize);
                } else {
                    Log::Warn(
                        "The console's secdata.bin does not open under its CPU key; a clean one "
                        "is made up");
                }
                auto head = own_head;
                if (!head) {
                    Log::Info("secdata.bin is made up under a drawn head");
                    head = random_secdata_head();
                }
                return clean_secdata(cpu_key, *head, build);
            }
            if (lower == "fcrt.bin") {
                auto sealed = seal_fcrt(data, cpu_key);
                switch (sealed.sealing) {
                    case FcrtSealing::Sealed:
                        Log::Debug("fcrt.bin was in the clear; it is sealed under the CPU key");
                        break;
                    case FcrtSealing::Carried:
                        Log::Debug("fcrt.bin is sealed under the CPU key already; it is carried");
                        break;
                    case FcrtSealing::InvalidSize:
                        Log::Warn("fcrt.bin is 0x{:X} bytes, not 0x4000; it is written as supplied",
                                  data.size());
                        break;
                    case FcrtSealing::InvalidOffset:
                        Log::Warn(
                            "fcrt.bin's header puts its sealed part past its end; it is written "
                            "as supplied");
                        break;
                    case FcrtSealing::Damaged:
                        // The console's own copy is carried as it stands (xeBuild would discard
                        // it).
                        if (own && data == *own) {
                            Log::Warn(
                                "The console's fcrt.bin does not open under the CPU key; it is "
                                "carried as it stands");
                            return data;
                        }
                        Log::Warn(
                            "fcrt.bin is neither in the clear nor opens under the CPU key; it is "
                            "written as its failed opening, as xeBuild writes it");
                        break;
                }
                return std::move(sealed.data);
            }
            return data;
        }

        // The one point where an internal Error becomes the public BuildError: the context chain
        // is flattened into the message, outermost layer first ("outer: inner: message").
        std::unexpected<BuildError> to_build_error(BuildErrorCode code, const Error& error) {
            return std::unexpected(BuildError{code, error.describe()});
        }

        const ParsedPatchSection* find_patch_section(const ParsedPatchSet& patchset,
                                                     PatchSectionTarget target) {
            const auto section = std::find_if(patchset.sections.begin(), patchset.sections.end(),
                                              [target](const ParsedPatchSection& candidate) {
                                                  return candidate.target == target;
                                              });
            return section == patchset.sections.end() ? nullptr : &*section;
        }

        size_t align_16(size_t value) {
            return (value + 0x0F) & ~size_t{0x0F};
        }

        [[nodiscard]] Result<size_t> patched_bootloader_size(size_t current_size,
                                                             const ParsedPatchSection& section,
                                                             std::string_view stage_name) {
            uint64_t required_end = current_size;
            for (const auto& entry : section.entries) {
                if (entry.words.size() < entry.length) {
                    return fail(ErrorCode::Malformed, "{} patch entry has too few words",
                                stage_name);
                }
                const uint64_t entry_end = static_cast<uint64_t>(entry.address) +
                                           static_cast<uint64_t>(entry.length) * sizeof(uint32_t);
                required_end = std::max(required_end, entry_end);
            }
            if (required_end > std::numeric_limits<uint32_t>::max()) {
                return fail(ErrorCode::OutOfRange, "{} patch exceeds the 32-bit address space",
                            stage_name);
            }
            return static_cast<size_t>(required_end);
        }

        [[nodiscard]] Result<std::vector<uint8_t>>
        apply_bootloader_patch(std::vector<uint8_t> bytes, const ParsedPatchSection& section,
                               size_t target_capacity, std::string_view stage_name) {
            const auto required_end = patched_bootloader_size(bytes.size(), section, stage_name);
            if (!required_end) {
                return std::unexpected(required_end.error());
            }
            if (align_16(*required_end) > target_capacity) {
                return fail(ErrorCode::OutOfRange, "{} patch exceeds its boot-chain capacity",
                            stage_name);
            }

            // A patched stage is as long as its greatest patched end rounded up to 0x10, the
            // rounding zero, and its header states that length (xeBuild: glitch2m CD 9452 0x52A8
            // of patched bytes states 0x52B0). The padding is sealed with the stage.
            bytes.resize(align_16(*required_end), 0);
            const XePatchSection xe_section{section.identifier, section.entries};
            const auto applied = gxbuild3::patchers::apply_patch_section(
                bytes.data(), static_cast<uint32_t>(bytes.size()), xe_section);
            if (!applied) {
                return std::unexpected(
                    Error(applied.error())
                        .add_context(std::format("Failed to apply {} patch section", stage_name)));
            }

            if (bytes.size() < sizeof(generic_header)) {
                return fail(ErrorCode::Truncated, "{} patch target has no bootloader header",
                            stage_name);
            }
            const auto patched_size = static_cast<uint32_t>(bytes.size());
            if (auto patched = wire::patch<generic_header>(
                    bytes, 0, "patched bootloader header",
                    [patched_size](generic_header& header) { header.size = patched_size; });
                !patched) {
                return std::unexpected(std::move(patched.error()));
            }
            return bytes;
        }

        // CF LDV and pairing come from the slot the console booted last: the one stating the
        // largest LDV.
        void extract_cf_metadata(const FlashImage& image, InputMetadata& metadata) {
            const auto slot = nand::detail::max_ldv_slot(image);
            if (!slot) {
                return;
            }
            const auto& perbox =
                *(*slot == 0 ? image.system_update_0 : image.system_update_1).cf->perbox;
            metadata.cf_ldv = perbox.lockdown_value;
            std::array<uint8_t, 3> pairing{};
            std::memcpy(pairing.data(), perbox.pairing_data, pairing.size());
            metadata.cf_pairing_data = pairing;
        }

        // The CB fields a donor's build metadata carries: the console type, sequence and allow
        // word from CB_A's header, and the LDV and pairing from CB_A's per-box block, which CB_B's
        // per-box block overrides when CB_B is present (whether or not CB_A parsed).
        struct CbMetadata {
            uint8_t ldv = 0;
            std::array<uint8_t, 3> pairing{};
            uint8_t console_type = 0;
            uint8_t console_sequence = 0;
            uint16_t console_sequence_allow = 0;
        };

        CbMetadata read_cb_metadata(const CbSection& cb) {
            CbMetadata metadata{};
            const auto& cb_a = cb.cb_or_A;
            if (!cb_a.data.empty()) {
                if (cb_a.perbox.has_value()) {
                    metadata.ldv = cb_a.perbox->lockdown_value;
                    std::memcpy(metadata.pairing.data(), cb_a.perbox->pairing_data,
                                metadata.pairing.size());
                }
                metadata.console_type = cb_a.header.console_seq_allow.console_type;
                metadata.console_sequence = cb_a.header.console_seq_allow.console_sequence;
                metadata.console_sequence_allow =
                    cb_a.header.console_seq_allow.console_sequence_allow.get();
            }
            if (cb.cb_B.has_value() && !cb.cb_B->data.empty() && cb.cb_B->perbox.has_value()) {
                // Build metadata keeps the per-box LDV; the byte cb_b_display_ldv shows is for
                // display only and is never written into per-box data.
                metadata.ldv = cb.cb_B->perbox->lockdown_value;
                std::memcpy(metadata.pairing.data(), cb.cb_B->perbox->pairing_data,
                            metadata.pairing.size());
            }
            return metadata;
        }

        // The CB_B console-sequence byte (header 0x3B1), as an offset into the stage data, which
        // starts after the generic header.
        constexpr std::size_t kCbConsoleSequenceInData =
            offsetof(cb_header, console_seq_allow) +
            offsetof(ConsoleTypeSeqAllow, console_sequence) - sizeof(generic_header);
        static_assert(kCbConsoleSequenceInData == 0x3A1);

        // extract_all_info shows CB_B's LDV as its console-sequence byte when that byte reads as
        // an LDV (16 or less), else the per-box LDV. Pinned quirk: the shown value can disagree
        // with the per-box LDV that extract_metadata and extract_all report. Requires the per-box
        // block.
        uint8_t cb_b_display_ldv(const BootloaderCb& cb_b) {
            const auto sequence =
                wire::read<uint8_t>(cb_b.data, kCbConsoleSequenceInData, "CB_B console sequence");
            if (sequence && *sequence <= 16) {
                return *sequence;
            }
            return cb_b.perbox->lockdown_value;
        }

        // Parses one supplied stage into its place in the image; the stage's name goes on the
        // error.
        template <class Bootloader, class Target>
        [[nodiscard]] Result<void> parse_stage_into(Target& target, std::span<const uint8_t> bytes,
                                                    std::string_view name) {
            auto parsed = Bootloader::parse(bytes);
            if (!parsed) {
                return std::unexpected(
                    std::move(parsed.error()).add_context(std::format("Failed to parse {}", name)));
            }
            target = std::move(*parsed);
            return {};
        }

        // Parses the supplied boot chain and update slots into an image whose chain was cleared.
        [[nodiscard]] Result<void> parse_input_bootloaders(FlashImage& flash_image,
                                                           const Input& input) {
            const auto& bootloaders = input.bootloaders;
            const auto supplied = [](const std::optional<std::vector<uint8_t>>& bytes) {
                return bytes && !bytes->empty();
            };
            if (auto parsed = parse_stage_into<BootloaderCb>(flash_image.cb_section.cb_or_A,
                                                             bootloaders.cb_or_a, "CB/A");
                !parsed) {
                return parsed;
            }
            if (supplied(bootloaders.cb_x)) {
                if (auto parsed = parse_stage_into<BootloaderCb>(flash_image.cb_section.cb_x,
                                                                 *bootloaders.cb_x, "CB_X");
                    !parsed) {
                    return parsed;
                }
                if (input.build_type == BuildType::Glitch3) {
                    // Input CB_X is explicitly plaintext. It can contain instructions
                    // in the region the retail-CB parser uses for plaintext detection.
                    flash_image.cb_section.cb_x->decrypted = true;
                    flash_image.cb_section.cb_x->populate_metadata();
                    // Its nonce stays as supplied, so it is sealed under the key its input names.
                    if (flash_image.cb_section.cb_x->patch_rgh3_v1_cb_x()) {
                        Log::Info("Applied the RGH2to3 v1 fix to the RGH3 CB_X");
                    }
                }
            }
            if (supplied(bootloaders.cb_b)) {
                if (auto parsed = parse_stage_into<BootloaderCb>(flash_image.cb_section.cb_B,
                                                                 *bootloaders.cb_b, "CB_B");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.sc)) {
                if (auto parsed = parse_stage_into<BootloaderSc>(flash_image.cb_section.sc,
                                                                 *bootloaders.sc, "SC");
                    !parsed) {
                    return parsed;
                }
            }
            if (auto parsed = parse_stage_into<BootloaderCd>(flash_image.kernel_section.cd,
                                                             bootloaders.cd, "CD");
                !parsed) {
                return parsed;
            }
            if (supplied(bootloaders.ce)) {
                if (auto parsed = parse_stage_into<BootloaderCe>(flash_image.kernel_section.ce,
                                                                 *bootloaders.ce, "CE");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cf0)) {
                if (auto parsed = parse_stage_into<BootloaderCf>(flash_image.system_update_0.cf,
                                                                 *bootloaders.cf0, "CF0");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cg0)) {
                if (auto parsed = parse_stage_into<BootloaderCg>(flash_image.system_update_0.cg,
                                                                 *bootloaders.cg0, "CG0");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cf1)) {
                if (auto parsed = parse_stage_into<BootloaderCf>(flash_image.system_update_1.cf,
                                                                 *bootloaders.cf1, "CF1");
                    !parsed) {
                    return parsed;
                }
            }
            if (supplied(bootloaders.cg1)) {
                if (auto parsed = parse_stage_into<BootloaderCg>(flash_image.system_update_1.cg,
                                                                 *bootloaders.cg1, "CG1");
                    !parsed) {
                    return parsed;
                }
            }
            // A devkit chain is supplied plaintext, as a release ships it and extract_all returns
            // it; the parsers' plaintext tests are for retail stages. The header states the SE
            // build (xeBuild 1.21 devkit: 0x4451 for SE 17489).
            if (flash_image.devkit_chain()) {
                auto& sb = flash_image.cb_section.cb_or_A;
                sb.decrypted = true;
                sb.populate_metadata();
                if (flash_image.cb_section.sc) {
                    flash_image.cb_section.sc->decrypted = true;
                }
                flash_image.kernel_section.cd.decrypted = true;
                if (auto& se = flash_image.kernel_section.ce; se) {
                    se->decrypted = true;
                    if (input.build_type == BuildType::Devkit) {
                        flash_image.header.version = se->header.header.version;
                    }
                }
            }
            return {};
        }

        std::optional<ConsoleType> console_of(SmcMotherboard board) {
            switch (board) {
                case SmcMotherboard::Xenon:
                    return ConsoleType::Xenon;
                case SmcMotherboard::Zephyr:
                    return ConsoleType::Zephyr;
                case SmcMotherboard::Falcon:
                    return ConsoleType::Falcon;
                case SmcMotherboard::Jasper:
                    return ConsoleType::Jasper;
                case SmcMotherboard::Trinity:
                    return ConsoleType::Trinity;
                case SmcMotherboard::Corona:
                    return ConsoleType::Corona;
                case SmcMotherboard::Winchester:
                    return ConsoleType::Winchester;
                case SmcMotherboard::Unknown:
                    return std::nullopt;
            }
            return std::nullopt;
        }

        // The year xeBuild states for each board. A JTAG Jasper boots the 2008 CB 6723.
        uint16_t copyright_year(ConsoleType console, BuildType build_type) {
            switch (console) {
                case ConsoleType::Xenon:
                case ConsoleType::Zephyr:
                    return 2005;
                case ConsoleType::Falcon:
                    return 2007;
                case ConsoleType::Jasper:
                    return build_type == BuildType::Jtag ? 2008 : 2009;
                case ConsoleType::Trinity:
                case ConsoleType::Corona:
                case ConsoleType::Winchester:
                    return 2010;
            }
            std::unreachable();
        }

        // A devkit image states 2010 on every board (xeBuild 1.21 devkit Jasper).
        constexpr uint16_t kDevkitCopyrightYear = 2010;

        // Header 0x10..0x47 holds the copyright notice; 0x48..0x4F are boot flags.
        constexpr size_t kCopyrightLength = sizeof(nand_header::copyright);

        // The types whose CB/CD (devgl: SD) are patched: their header states 0x48 = 1 and the boot
        // flags.
        bool is_hacked(BuildType build_type) {
            switch (build_type) {
                case BuildType::Jtag:
                case BuildType::Glitch:
                case BuildType::Glitch2:
                case BuildType::Glitch2m:
                case BuildType::Glitch3:
                case BuildType::Devgl:
                    return true;
                case BuildType::Retail:
                case BuildType::Devkit:
                    return false;
            }
            std::unreachable();
        }

        // Header 0x4C..0x4F from the options, as xeBuild builds them (xerunner build.py
        // boot_options): 0x4F is the XeLL button, eject unless one is named, none for nodvd or
        // olddvd; 0x4E the second XeLL button, zero when it is the first; 0x4D is 1 for cygnos or
        // demon, and on JTAG adds 2 for nodvd, otherwise 4 unless olddvd; 0x4C is the dualboot
        // button, JTAG only, zero when it is either XeLL button. Zero on retail and devkit.
        uint32_t boot_flags(BuildType build_type, const OptionsArgs& options) {
            if (!is_hacked(build_type)) {
                return 0;
            }
            const auto button = [](const std::optional<std::string>& name) -> uint8_t {
                return name ? OptionsManager::power_on_reason(*name).value_or(0) : 0;
            };
            constexpr uint8_t kEject = 0x12;
            const bool jtag = build_type == BuildType::Jtag;
            const bool nodvd = options.nodvd.value_or(false);
            const bool olddvd = options.olddvd.value_or(false);

            const uint8_t reason = options.xellbutton  ? button(options.xellbutton)
                                   : (nodvd || olddvd) ? 0
                                                       : kEject;
            const uint8_t second = button(options.xellbutton2);
            uint8_t boot_options =
                (options.cygnos.value_or(false) || options.demon.value_or(false)) ? 1 : 0;
            if (jtag && nodvd) {
                boot_options |= 2;
            } else if (jtag && !olddvd) {
                boot_options |= 4;
            }
            uint8_t dualboot = jtag ? button(options.dualboot) : 0;
            if (dualboot && (dualboot == reason || dualboot == second)) {
                Log::Warn("dualboot names a XeLL button; the setting is ignored");
                dualboot = 0;
            }
            return uint32_t(dualboot) << 24 | uint32_t(boot_options) << 16 |
                   uint32_t(second == reason ? 0 : second) << 8 | reason;
        }

        // The Latin-1 copyright sign, the notice and zeros, over 0x10..0x47 only.
        void write_copyright(nand_header& header, uint16_t year) {
            const std::string text = "\xA9 2004-" + std::to_string(year) +
                                     " Microsoft Corporation. All rights reserved.";
            std::fill_n(header.copyright, kCopyrightLength, uint8_t{0});
            std::memcpy(header.copyright, text.data(), std::min(text.size(), kCopyrightLength - 1));
        }

        // The donor's settings, statistics and manufacturing blocks, carried as bytes.
        void extract_settings_blocks(const FlashImage& img, InputMetadata& meta) {
            if (img.smc_config) {
                meta.smc_config = img.smc_config->serialize();
            } else {
                meta.smc_config.reset();
            }
            if (img.statistics) {
                meta.statistics = img.statistics->serialize();
            } else {
                meta.statistics.reset();
            }
            if (img.manufacturing) {
                meta.manufacturing = img.manufacturing->serialize();
            } else {
                meta.manufacturing.reset();
            }
        }

        bool is_blank_option(const std::optional<std::string>& opt) {
            return !opt || std::all_of(opt->begin(), opt->end(),
                                       [](unsigned char c) { return std::isspace(c) != 0; });
        }

        // Applies xeBuild's 12 SMC config overrides to the parsed settings block, marking
        // `reserialize` only when at least one field actually changes.
        void apply_smc_config_options(std::optional<SmcConfigBlock>& smc_config,
                                      const OptionsArgs& options) {
            static constexpr std::array<std::optional<std::string> OptionsArgs::*, 12>
                kSmcConfigOptions{{
                    &OptionsArgs::cputemp,
                    &OptionsArgs::gputemp,
                    &OptionsArgs::edramtemp,
                    &OptionsArgs::overcputemp,
                    &OptionsArgs::overgputemp,
                    &OptionsArgs::overedramtemp,
                    &OptionsArgs::cpufan,
                    &OptionsArgs::gpufan,
                    &OptionsArgs::avregion,
                    &OptionsArgs::gameregion,
                    &OptionsArgs::dvdregion,
                    &OptionsArgs::macid,
                }};
            const bool any_set =
                std::any_of(kSmcConfigOptions.begin(), kSmcConfigOptions.end(),
                            [&options](auto member) { return !is_blank_option(options.*member); });
            if (!any_set) {
                return;
            }
            if (!smc_config.has_value()) {
                Log::Warn("SMC config options were supplied, but no SMC config block is present; "
                          "skipping");
                return;
            }

            constexpr uint32_t kSmcTempMin = 40;
            constexpr uint32_t kSmcTempMax = 120;
            constexpr uint32_t kSmcFanMin = 40;
            constexpr uint32_t kSmcFanMax = 100;
            constexpr uint8_t kFanOverride = 0x80;
            constexpr uint8_t kFanAuto = 0x7F;

            SmcConfigBlock& cfg = *smc_config;
            bool modified = false;
            struct FieldTarget {
                std::string_view name;
                const std::optional<std::string>* opt;
                uint8_t* field;
            };

            const std::array<FieldTarget, 6> temp_targets{{
                {"cputemp", &options.cputemp, &cfg.static_settings.smc.setpoint.cpu},
                {"gputemp", &options.gputemp, &cfg.static_settings.smc.setpoint.gpu},
                {"edramtemp", &options.edramtemp, &cfg.static_settings.smc.setpoint.edram},
                {"overcputemp", &options.overcputemp, &cfg.static_settings.smc.overload.cpu},
                {"overgputemp", &options.overgputemp, &cfg.static_settings.smc.overload.gpu},
                {"overedramtemp", &options.overedramtemp, &cfg.static_settings.smc.overload.edram},
            }};
            for (const auto& target_item : temp_targets) {
                if (is_blank_option(*target_item.opt)) {
                    continue;
                }
                const auto parsed = OptionsManager::parse_u32(**target_item.opt);
                if (!parsed || *parsed == 0) {
                    continue;
                }
                if (*parsed < kSmcTempMin || *parsed > kSmcTempMax) {
                    Log::Warn("Option {} value {} is out of range ({}-{}), ignoring",
                              target_item.name, *parsed, kSmcTempMin, kSmcTempMax);
                    continue;
                }
                const auto target = static_cast<uint8_t>(*parsed);
                if (*target_item.field != target) {
                    *target_item.field = target;
                    modified = true;
                }
            }

            const std::array<FieldTarget, 2> fan_targets{{
                {"cpufan", &options.cpufan, &cfg.static_settings.smc.cpu_fan},
                {"gpufan", &options.gpufan, &cfg.static_settings.smc.gpu_fan},
            }};
            for (const auto& target_item : fan_targets) {
                if (is_blank_option(*target_item.opt)) {
                    continue;
                }
                const auto parsed = OptionsManager::parse_u32(**target_item.opt);
                if (!parsed) {
                    continue;
                }
                if (*parsed == 0) {
                    if (*target_item.field != kFanAuto) {
                        *target_item.field = kFanAuto;
                        modified = true;
                    }
                    continue;
                }
                if (*parsed < kSmcFanMin || *parsed > kSmcFanMax) {
                    Log::Warn("Option {} value {} is out of range ({}-{}), ignoring",
                              target_item.name, *parsed, kSmcFanMin, kSmcFanMax);
                    continue;
                }
                const auto target = static_cast<uint8_t>(*parsed | kFanOverride);
                if (*target_item.field != target) {
                    *target_item.field = target;
                    modified = true;
                }
            }

            if (!is_blank_option(options.avregion)) {
                if (const auto parsed = OptionsManager::parse_u32(*options.avregion);
                    parsed && cfg.secured_settings.av_region.get() != *parsed) {
                    cfg.secured_settings.av_region = *parsed;
                    modified = true;
                }
            }
            if (!is_blank_option(options.gameregion)) {
                if (const auto parsed = OptionsManager::parse_u16(*options.gameregion);
                    parsed && *parsed != 0 && cfg.secured_settings.game_region.get() != *parsed) {
                    cfg.secured_settings.game_region = *parsed;
                    modified = true;
                }
            }
            if (!is_blank_option(options.dvdregion)) {
                if (const auto parsed = OptionsManager::parse_u32(*options.dvdregion);
                    parsed && cfg.secured_settings.dvd_region.get() != *parsed) {
                    cfg.secured_settings.dvd_region = *parsed;
                    modified = true;
                }
            }
            if (!is_blank_option(options.macid)) {
                if (const auto parsed = OptionsManager::parse_mac_id(*options.macid);
                    parsed && !std::equal(parsed->begin(), parsed->end(),
                                          std::begin(cfg.secured_settings.mac_address))) {
                    std::copy(parsed->begin(), parsed->end(),
                              std::begin(cfg.secured_settings.mac_address));
                    modified = true;
                }
            }

            if (modified) {
                cfg.reserialize = true;
                Log::Info("Patched SMC config block from build options");
            }
        }

        // Patches the keyvault's DVD key on non-retail builds, setting `reserialize` only when
        // the 16-byte key actually changes.
        void apply_keyvault_options(Keyvault& keyvault, const OptionsArgs& options,
                                    BuildType build_type) {
            if (is_blank_option(options.dvdkey)) {
                return;
            }
            const auto dvd_key = OptionsManager::parse_dvd_key(*options.dvdkey);
            if (!dvd_key) {
                return;
            }
            if (build_type == BuildType::Retail) {
                Log::Info("Retail image: skipping dvdkey patch to preserve keyvault signature");
                return;
            }
            if (!std::equal(dvd_key->begin(), dvd_key->end(),
                            std::begin(keyvault.data.b1ADvdKey))) {
                std::copy(dvd_key->begin(), dvd_key->end(), std::begin(keyvault.data.b1ADvdKey));
                keyvault.reserialize = true;
                Log::Info("Patched DVD key into keyvault");
            }
        }

        using StepResult = std::expected<void, BuildError>;

        // Initializes the target FlashImage (from a donor dump when present and shape-compatible,
        // or fresh), parses the console's settings/SMC/keyvault, applies option overrides, and
        // sets the NAND header metadata.
        [[nodiscard]] StepResult init_build_image(const Input& input, FlashImage& flash_image,
                                                  std::optional<DonorNonces>& donor_nonces) {
            bool has_donor = false;
            std::optional<ConsoleType> donor_console;

            if (input.metadata.nand_image && !input.metadata.nand_image->empty()) {
                Log::Info("Building image from donor NAND dump...");
                auto donor_img = FlashImage::read(*input.metadata.nand_image);
                if (!donor_img) {
                    return to_build_error(
                        BuildErrorCode::InvalidDonor,
                        {ErrorCode::InvalidArgument, "Failed to parse donor NAND dump: it is empty"});
                }
                if (auto parsed = donor_img->parse(); !parsed) {
                    return to_build_error(
                        BuildErrorCode::InvalidDonor,
                        std::move(parsed.error()).add_context("Failed to parse donor NAND dump"));
                }
                if (auto decrypted = donor_img->decrypt_all(input.metadata.cpu_key); !decrypted) {
                    return to_build_error(BuildErrorCode::InvalidDonor,
                                          std::move(decrypted.error())
                                              .add_context("Failed to decrypt donor NAND dump "
                                                           "components"));
                }
                if (!donor_nonces) {
                    donor_nonces = donor_img->collect_nonces();
                }
                // A devkit image of another shape than its donor (the 64 MB image a 16 MB console
                // takes) is laid fresh: the donor gives its nonces here and its console data
                // through the Input.
                const auto target = driver_config(input.image_type, input.build_type);
                const bool donor_shape = donor_img->flash_driver.image_size() == target.first &&
                                         donor_img->flash_driver.driver_mode() == target.second;
                if (input.build_type != BuildType::Devkit || donor_shape) {
                    has_donor = true;
                    if (donor_img->smc) {
                        donor_console = console_of(donor_img->smc->motherboard);
                    }
                    flash_image = std::move(*donor_img);
                } else {
                    Log::Debug("Laying the devkit image fresh beside its donor's shape");
                    flash_image = FlashImage::create(target.first, target.second, input.build_type);
                }
            } else {
                Log::Debug("Configuring fresh NAND image layout");
                const auto [image_size, driver_mode] =
                    driver_config(input.image_type, input.build_type);
                flash_image = FlashImage::create(image_size, driver_mode, input.build_type);
            }

            flash_image.build_type = input.build_type;

            // The console's own blocks follow it into whatever layout is built.
            if (input.metadata.smc_config) {
                auto parsed = SmcConfigBlock::parse(*input.metadata.smc_config);
                if (!parsed) {
                    return to_build_error(BuildErrorCode::InvalidInput,
                                          std::move(parsed.error())
                                              .add_context("Failed to parse input SMC config block"));
                }
                flash_image.smc_config = std::move(*parsed);
            }
            if (input.metadata.statistics) {
                auto parsed = StatisticsBlock::parse(*input.metadata.statistics);
                if (!parsed) {
                    return to_build_error(BuildErrorCode::InvalidInput,
                                          std::move(parsed.error())
                                              .add_context("Failed to parse input statistics block"));
                }
                flash_image.statistics = std::move(*parsed);
            }
            if (input.metadata.manufacturing) {
                auto parsed = ManufacturingBlock::parse(*input.metadata.manufacturing);
                if (!parsed) {
                    return to_build_error(BuildErrorCode::InvalidInput,
                                          std::move(parsed.error())
                                              .add_context("Failed to parse input manufacturing "
                                                           "block"));
                }
                flash_image.manufacturing = std::move(*parsed);
            }
            apply_smc_config_options(flash_image.smc_config, input.options);

            const auto smc = Smc::parse(*input.metadata.smc);
            if (!smc) {
                return to_build_error(BuildErrorCode::InvalidSmc,
                                      Error(smc.error()).add_context("Failed to parse input SMC"));
            }
            flash_image.smc = *smc;

            // A JTAG image boots through its SMC's hack, so an SMC carrying no JTAG mark is refused
            // unless smcnocheck waives the check, as xeBuild 1.21 does.
            if (input.build_type == BuildType::Jtag && !input.options.smcnocheck.value_or(false) &&
                !smc_has_jtag_mark(flash_image.smc->data)) {
                return to_build_error(BuildErrorCode::InvalidSmc,
                                      {ErrorCode::Unsupported,
                                       "Clean SMC binary found: a JTAG image needs a hacked SMC "
                                       "(the smcnocheck option builds with this one anyway)"});
            }

            const auto keyvault = Keyvault::parse(*input.metadata.keyvault);
            if (!keyvault) {
                return to_build_error(
                    BuildErrorCode::InvalidKeyvault,
                    Error(keyvault.error()).add_context("Failed to parse input keyvault"));
            }
            flash_image.keyvault = *keyvault;
            flash_image.keyvault->encrypted = false;
            apply_keyvault_options(*flash_image.keyvault, input.options, input.build_type);

            // Header 0x04 carries no pairing; console dumps and xeBuild images hold zero there, and a
            // devkit image 0x8000 (xeBuild 1.21).
            flash_image.header.pairing = input.build_type == BuildType::Devkit ? 0x8000 : 0;

            // A donor of the same board keeps its own notice; any other image states the target's. A
            // JTAG Jasper always states the year of the CB it boots, which no retail donor carries.
            const bool donor_copyright_usable =
                has_donor && !std::all_of(std::begin(flash_image.header.copyright),
                                          std::begin(flash_image.header.copyright) + kCopyrightLength,
                                          [](uint8_t byte) { return byte == 0; });
            const bool jtag_jasper =
                input.build_type == BuildType::Jtag && input.console == ConsoleType::Jasper;
            if (input.build_type == BuildType::Devkit) {
                write_copyright(flash_image.header, kDevkitCopyrightYear);
            } else if (input.console &&
                       (!donor_copyright_usable || donor_console != input.console || jtag_jasper)) {
                write_copyright(flash_image.header, copyright_year(*input.console, input.build_type));
            }
            flash_image.header.hack_flags = is_hacked(input.build_type) ? 1 : 0;
            flash_image.header.boot_flags = boot_flags(input.build_type, input.options);
            return {};
        }

        // Clears donor bootloader records, parses and validates input bootloaders and automatic
        // patches, patches CB/CB_B/CD, re-signs devgl SD, parses JTAG extra stages, and applies
        // per-box bootloader metadata and nonces.
        [[nodiscard]] StepResult populate_and_patch_bootloaders(
            FlashImage& flash_image, const Input& input, const std::optional<DonorNonces>& donor_nonces,
            const std::optional<gxbuild3::utils::XeRsaPrivateKey>& sd_signing_key,
            std::optional<ParsedPatchSet>& parsed_patchset) {
            const auto supplied = [](const std::optional<std::vector<uint8_t>>& bootloader) {
                return bootloader && !bootloader->empty();
            };
            if (supplied(input.bootloaders.cg0) && !supplied(input.bootloaders.cf0)) {
                return to_build_error(
                    BuildErrorCode::InvalidInput,
                    {ErrorCode::InvalidArgument, "CG0 was supplied without its required CF0 parent"});
            }
            if (supplied(input.bootloaders.cg1) && !supplied(input.bootloaders.cf1)) {
                return to_build_error(
                    BuildErrorCode::InvalidInput,
                    {ErrorCode::InvalidArgument, "CG1 was supplied without its required CF1 parent"});
            }

            if (auto cleared = flash_image.clear_bootloader_chain(); !cleared) {
                return to_build_error(
                    BuildErrorCode::SerializationFailure,
                    std::move(cleared.error()).add_context("Failed to clear donor bootloader records"));
            }
            flash_image.preserve_layout = false;
            flash_image.cb_section.cb_x.reset();
            flash_image.cb_section.cb_B.reset();
            flash_image.cb_section.sc.reset();
            flash_image.kernel_section.ce.reset();
            flash_image.system_update_0 = SystemUpdate{};
            flash_image.system_update_1 = SystemUpdate{};
            if (auto parsed = parse_input_bootloaders(flash_image, input); !parsed) {
                return to_build_error(BuildErrorCode::InvalidBootloader, parsed.error());
            }

            if (flash_image.kernel_section.cd.data.empty()) {
                return to_build_error(
                    BuildErrorCode::InvalidBootloader,
                    {ErrorCode::Truncated,
                     "Required CD bootloader has no payload and cannot be serialized"});
            }

            if (input.build_type == BuildType::Glitch3 &&
                (!flash_image.cb_section.cb_x || flash_image.cb_section.cb_x->data.empty() ||
                 flash_image.cb_section.cb_x->header.header.version != 15432 ||
                 !flash_image.cb_section.cb_B || flash_image.cb_section.cb_B->data.empty())) {
                return to_build_error(
                    BuildErrorCode::InvalidBootloader,
                    {ErrorCode::InvalidArgument, "Glitch3 requires CB_A, CB_X (15432), and CB_B"});
            }

            // glitch1 may carry a CB_B (xeBuild builds the trinity 13604/17559 _glitch.ini with
            // CB_A + CB_B); only a CB_X is out of place there.
            if (input.build_type == BuildType::Glitch && flash_image.cb_section.cb_x) {
                return to_build_error(BuildErrorCode::InvalidBootloader,
                                      {ErrorCode::Unsupported,
                                       "glitch1/RGH1 does not support a CB_X (use glitch3)"});
            }

            if (input.patches && input.patches->automatic) {
                auto parsed = parse_and_merge_patch_set(*input.patches, input.build_type);
                if (!parsed) {
                    return to_build_error(BuildErrorCode::PatchFailure, parsed.error());
                }
                parsed_patchset = std::move(*parsed);
            }

            // A devgl chain has no CB_B: the glitch2m patch file's first section is not applied, and
            // its CD section patches the SD (xeBuild 1.21 devgl: SB, SC and SE as the release ships
            // them).
            const bool devgl = input.build_type == BuildType::Devgl;
            const NoPatch no_patch = resolve_no_patch(input.options);
            if (parsed_patchset && parsed_patchset->kind == PatchSetKind::Glitch && no_patch.khv) {
                // The slot keeps its glitch layout and holds an empty KHV list, with no add-ons either.
                for (auto& section : parsed_patchset->sections) {
                    if (section.target == PatchSectionTarget::Khv) {
                        section.raw_data.clear();
                    }
                }
            }
            if (parsed_patchset && parsed_patchset->kind == PatchSetKind::Glitch &&
                !(no_patch.cb && no_patch.cd)) {
                // A single-CB glitch1 patches its CB; with a CB_B (CB_A + CB_B, as the trinity
                // glitch1 INIs list) the first section goes to the CB_B, as in glitch2 and xeBuild.
                // (the patchset parser labels glitch1's first section Cb either way).
                const bool glitch1_cbb =
                    input.build_type == BuildType::Glitch && flash_image.cb_section.cb_B;
                const auto first_target = input.build_type == BuildType::Glitch
                                              ? PatchSectionTarget::Cb
                                              : PatchSectionTarget::Cbb;
                const auto* first_section =
                    devgl || no_patch.cb ? nullptr : find_patch_section(*parsed_patchset, first_target);
                const auto* cd_section =
                    no_patch.cd ? nullptr
                                : find_patch_section(*parsed_patchset, PatchSectionTarget::Cd);
                if ((!devgl && !no_patch.cb && !first_section) || (!no_patch.cd && !cd_section)) {
                    return to_build_error(BuildErrorCode::PatchFailure,
                                          {ErrorCode::Malformed,
                                           "Glitch patchset is missing a bootloader patch section"});
                }
                if (!devgl && !no_patch.cb && first_target == PatchSectionTarget::Cbb &&
                    !flash_image.cb_section.cb_B) {
                    return to_build_error(BuildErrorCode::PatchFailure,
                                          {ErrorCode::InvalidArgument,
                                           "Automatic patchset targets CBB, but no CBB was supplied"});
                }

                constexpr size_t kStageCount = 6;
                std::array<size_t, kStageCount> stage_sizes{};
                FlashImage::for_each_present_stage(
                    flash_image,
                    [&stage_sizes](BootStageId id, std::string_view, const auto& stage) {
                        stage_sizes[static_cast<size_t>(id)] = stage.serialize().size();
                    });
                // A chain that already runs past XeLL's slot (a hybrid glitch2m with an SB/SD/SE
                // chain) is laid as xeBuild lays it: XeLL is skipped and the update slots follow
                // the chain, so the usual limit does not apply to it.
                size_t unpatched_total = 0;
                for (const size_t size : stage_sizes)
                    unpatched_total += align_16(size);
                const size_t cb_a_index = static_cast<size_t>(BootStageId::CbA);
                const size_t cb_b_index = static_cast<size_t>(BootStageId::CbB);
                const size_t cd_index = static_cast<size_t>(BootStageId::Cd);
                const size_t first_index =
                    (first_target == PatchSectionTarget::Cb && !glitch1_cbb) ? cb_a_index
                                                                             : cb_b_index;
                if (first_section) {
                    const auto first_size = patched_bootloader_size(
                        stage_sizes[first_index], *first_section,
                        (first_target == PatchSectionTarget::Cb && !glitch1_cbb) ? "CB" : "CBB");
                    if (!first_size) {
                        return to_build_error(BuildErrorCode::PatchFailure, first_size.error());
                    }
                    stage_sizes[first_index] = *first_size;
                }
                if (cd_section) {
                    const auto cd_size =
                        patched_bootloader_size(stage_sizes[cd_index], *cd_section, "CD");
                    if (!cd_size) {
                        return to_build_error(BuildErrorCode::PatchFailure, cd_size.error());
                    }
                    stage_sizes[cd_index] = *cd_size;
                }

                const bool is_big_or_emmc =
                    flash_image.flash_driver.driver_mode() == Driver::DriverMode::Big ||
                    flash_image.flash_driver.driver_mode() == Driver::DriverMode::Emmc;
                // A devgl chain runs past its first update slot, which it never fills, up to the KHV
                // patch slot.
                const size_t boot_chain_limit = devgl            ? flash_image.patch_slot_offset()
                                                : is_big_or_emmc ? 0xC0000
                                                                 : 0x70000;
                constexpr size_t boot_chain_start = 0x8000;
                const size_t boot_chain_capacity = boot_chain_limit - boot_chain_start;
                size_t aligned_total = 0;
                for (const size_t size : stage_sizes) {
                    aligned_total += align_16(size);
                }
                if (aligned_total > boot_chain_capacity && unpatched_total <= boot_chain_capacity) {
                    return to_build_error(
                        BuildErrorCode::PatchFailure,
                        {ErrorCode::OutOfRange,
                         "Patched bootloader chain exceeds the space before patch slots"});
                }
                const size_t effective_capacity =
                    unpatched_total > boot_chain_capacity
                        ? flash_image.flash_driver.block_size_clean() *
                                  flash_image.flash_driver.block_count() -
                              boot_chain_start
                        : boot_chain_capacity;
                const auto target_capacity = [&](size_t target_index) {
                    size_t other_total = 0;
                    for (size_t index = 0; index < stage_sizes.size(); ++index) {
                        if (index != target_index) {
                            other_total += align_16(stage_sizes[index]);
                        }
                    }
                    return effective_capacity - other_total;
                };

                auto patch_and_reparse = [&](auto& bootloader, PatchSectionTarget target,
                                             size_t capacity,
                                             std::string_view stage_name) -> Result<void> {
                    const auto* section = find_patch_section(*parsed_patchset, target);
                    if (!section) {
                        return {};
                    }
                    auto patched =
                        apply_bootloader_patch(bootloader.serialize(), *section, capacity, stage_name);
                    if (!patched) {
                        return std::unexpected(std::move(patched.error()));
                    }
                    auto reparsed = std::decay_t<decltype(bootloader)>::parse(*patched);
                    if (!reparsed) {
                        return std::unexpected(
                            std::move(reparsed.error())
                                .add_context(std::format("Failed to reparse patched {}", stage_name)));
                    }
                    bootloader = std::move(*reparsed);
                    return {};
                };

                if (first_section && first_target == PatchSectionTarget::Cb && glitch1_cbb) {
                    if (auto patched = patch_and_reparse(*flash_image.cb_section.cb_B, first_target,
                                                         target_capacity(cb_b_index), "CBB");
                        !patched) {
                        return to_build_error(BuildErrorCode::PatchFailure, patched.error());
                    }
                } else if (first_section && first_target == PatchSectionTarget::Cb) {
                    if (auto patched = patch_and_reparse(flash_image.cb_section.cb_or_A, first_target,
                                                         target_capacity(cb_a_index), "CB");
                        !patched) {
                        return to_build_error(BuildErrorCode::PatchFailure, patched.error());
                    }
                } else if (first_section) {
                    if (auto patched = patch_and_reparse(*flash_image.cb_section.cb_B, first_target,
                                                         target_capacity(cb_b_index), "CBB");
                        !patched) {
                        return to_build_error(BuildErrorCode::PatchFailure, patched.error());
                    }
                }
                if (cd_section) {
                    if (auto patched =
                            patch_and_reparse(flash_image.kernel_section.cd, PatchSectionTarget::Cd,
                                              target_capacity(cd_index), "CD");
                        !patched) {
                        return to_build_error(BuildErrorCode::PatchFailure, patched.error());
                    }
                }
                // A development SD stays plaintext until it is sealed; the parser's test is for a
                // retail CD.
                if (flash_image.devkit_chain()) {
                    flash_image.kernel_section.cd.decrypted = true;
                }
            }

            // The patched SD no longer matches its signature, so it is signed again with the SB
            // private key, as Xbox-360-Crypto sd_signer.py signs one (xeBuild 1.21 devgl: "SD_17489.bin
            // failed signature check, attempting to resign"). The signature leaves the nonce out, so
            // the donor nonce set below does not disturb it.
            if (sd_signing_key) {
                auto& sd = flash_image.kernel_section.cd;
                auto sd_bytes = sd.serialize();
                if (!gxbuild3::utils::verify_sd_signature(sd_bytes, sd_signing_key->public_key())) {
                    Log::Info(
                        "SD {} failed its signature check; signing it again with the SB private key",
                        sd.header.header.version);
                    auto signed_sd = gxbuild3::utils::sign_sd(sd_bytes, *sd_signing_key);
                    if (signed_sd) {
                        signed_sd = gxbuild3::utils::verify_sd_signature(
                            sd_bytes, sd_signing_key->public_key());
                    }
                    if (!signed_sd) {
                        return to_build_error(
                            BuildErrorCode::PatchFailure,
                            std::move(signed_sd.error())
                                .add_context("Could not sign the SD with the SB private key"));
                    }
                    if (auto reparsed = parse_stage_into<BootloaderCd>(sd, sd_bytes, "the signed SD");
                        !reparsed) {
                        return to_build_error(BuildErrorCode::PatchFailure, reparsed.error());
                    }
                    sd.decrypted = true;
                }
            }

            // The JTAG second CB/CD are captured by the INI reader and placed in the window tail. They
            // are sealed with the main chain, so they are parsed before its metadata and nonces.
            if (input.bootloaders.extra_cb) {
                if (auto parsed = parse_stage_into<BootloaderCb>(
                        flash_image.payloads.extra_cb, *input.bootloaders.extra_cb, "JTAG extra CB");
                    !parsed) {
                    return to_build_error(BuildErrorCode::InvalidBootloader, parsed.error());
                }
            }
            if (input.bootloaders.extra_cd) {
                if (auto parsed = parse_stage_into<BootloaderCd>(
                        flash_image.payloads.extra_cd, *input.bootloaders.extra_cd, "JTAG extra CD");
                    !parsed) {
                    return to_build_error(BuildErrorCode::InvalidBootloader, parsed.error());
                }
            }
            if (input.bootloaders.extra_se) {
                if (auto parsed = parse_stage_into<BootloaderCe>(
                        flash_image.payloads.extra_se, *input.bootloaders.extra_se, "JTAG extra SE");
                    !parsed) {
                    return to_build_error(BuildErrorCode::InvalidBootloader, parsed.error());
                }
            }

            // Patching reparses its targets. Apply the resolved metadata only after that
            // replacement step so the final CB/CF objects, rather than a discarded parse,
            // are serialized and encrypted below.
            if (const auto metadata =
                    flash_image.apply_bootloader_metadata(input.metadata, input.build_type);
                !metadata) {
                return to_build_error(BuildErrorCode::InvalidBootloader, metadata.error());
            }
            if (const auto nonces = flash_image.apply_nonces(donor_nonces); !nonces) {
                return to_build_error(BuildErrorCode::InvalidBootloader, nonces.error());
            }
            return {};
        }

        // Attaches the patchset, XeLL, rebooter, virtual fuses, SMC payload, and raw patches,
        // then validates the resolved payload layout.
        [[nodiscard]] StepResult populate_payloads(FlashImage& flash_image, const Input& input,
                                                   std::optional<ParsedPatchSet> parsed_patchset) {
            if (parsed_patchset) {
                size_t patch_size = 0;
                if (parsed_patchset->kind == PatchSetKind::Jtag) {
                    patch_size = serialize_patch_set(*parsed_patchset).size();
                    if (patch_size > nand::detail::kJtagPatchSize) {
                        return to_build_error(
                            BuildErrorCode::PatchFailure,
                            {ErrorCode::OutOfRange,
                             "JTAG patch payload exceeds the 0x4000-byte region"});
                    }
                } else {
                    const auto* khv = find_patch_section(*parsed_patchset, PatchSectionTarget::Khv);
                    if (!khv) {
                        return to_build_error(
                            BuildErrorCode::PatchFailure,
                            {ErrorCode::Malformed, "Glitch patchset has no KHV payload section"});
                    }
                    patch_size = serialize_khv_payload(*khv).size();
                    const bool is_big_or_emmc =
                        flash_image.flash_driver.driver_mode() == Driver::DriverMode::Big ||
                        flash_image.flash_driver.driver_mode() == Driver::DriverMode::Emmc;
                    const size_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
                    if (patch_size > slot_stride - (parsed_patchset->manufacturing ? 0x60 : 0x10)) {
                        return to_build_error(
                            BuildErrorCode::PatchFailure,
                            {ErrorCode::OutOfRange,
                             "Glitch KHV payload exceeds its patch-slot region"});
                    }
                }
                flash_image.payloads.patchset = std::move(parsed_patchset);
            }

            if (input.payloads) {
                const bool chain_past_xell =
                    input.build_type == BuildType::Glitch2m &&
                    nand::detail::laid_boot_chain_end(flash_image) > nand::detail::kXellOffset;
                if (chain_past_xell && input.payloads->xell && !input.payloads->xell->empty()) {
                    Log::Warn(
                        "Skipping XeLL: the boot chain runs past its slot, there is not enough room");
                } else if (input.payloads->xell && !input.payloads->xell->empty()) {
                    auto xell_parsed = XeLL::parse(*input.payloads->xell);
                    if (!xell_parsed) {
                        return to_build_error(
                            BuildErrorCode::InvalidBootloader,
                            std::move(xell_parsed.error()).add_context("Failed to parse XeLL payload"));
                    }
                    flash_image.payloads.xell = std::move(*xell_parsed);
                    Log::Info("Adding XeLL payload (version='{}', size=0x{:X})",
                              flash_image.payloads.xell->metadata.version,
                              flash_image.payloads.xell->data.size());
                }
                if (input.payloads->rebooter) {
                    flash_image.payloads.rebooter = input.payloads->rebooter;
                    Log::Info("Adding Rebooter payload (size=0x{:X})",
                              flash_image.payloads.rebooter->size());
                }
                if (input.payloads->fuses) {
                    flash_image.payloads.fuses = input.payloads->fuses;
                    Log::Info("Adding virtual fuses payload (size=0x{:X})",
                              flash_image.payloads.fuses->size());
                }
                if (input.payloads->payload) {
                    flash_image.payloads.payload = input.payloads->payload;
                    Log::Info("Adding SMC payload (size=0x{:X})",
                              flash_image.payloads.payload->size());
                }
            }

            if (const auto layout = flash_image.payload_layout(); !layout) {
                return to_build_error(BuildErrorCode::InvalidInput, layout.error());
            }

            flash_image.raw_patches = input.raw_patches;
            return {};
        }

        // Formats the FlashFileSystem, seals secured files, and merges mobile data overrides.
        [[nodiscard]] StepResult populate_storage(FlashImage& flash_image, const Input& input) {
            if (input.flashfs_sec) {
                Log::Info("Populating Flash File System ({} files)", input.flashfs_sec->size());
                // Every directory entry, and crl.bin, dae.bin and secdata.bin within, carry the build's
                // time (SOURCE_DATE_EPOCH when set): the entries on the local clock, as xeBuild stamps
                // them, and the three files in UTC.
                const int64_t build_seconds = gxbuild3::utils::build_epoch();
                if (auto fs = flash_image.format_filesystem(
                        gxbuild3::utils::flashfs_build_timestamp(build_seconds));
                    !fs) {
                    return to_build_error(BuildErrorCode::SerializationFailure, fs.error());
                }

                // xeBuild states 1 when no lockdown value is set anywhere, and 0 under the all-zero CPU
                // key, as the CFs do.
                const SecuredFileBuild secured_build{build_seconds,
                                                     is_zero_cpu_key(input.metadata.cpu_key)
                                                         ? uint8_t{0}
                                                         : input.metadata.cf_ldv.value_or(1)};
                for (const auto& [name, data] : *input.flashfs_sec) {
                    const auto file_data = sealed_flashfs_file(name, data, input, secured_build);
                    if (!file_data) {
                        return to_build_error(
                            BuildErrorCode::EncryptionFailure,
                            Error(file_data.error())
                                .add_context(
                                    std::format("Failed to encrypt secure FlashFS file '{}'", name)));
                    }
                    Log::Debug("Adding FlashFS file: '{}' ({} bytes)", name, file_data->size());
                    if (const auto added = flash_image.filesystem->add_file(name, *file_data); !added) {
                        return to_build_error(
                            BuildErrorCode::SerializationFailure,
                            Error(added.error()).add_context("Failed to add a Flash File System file"));
                    }
                }
            }

            if (!flash_image.mobile_data) {
                for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                    const auto* slot = input.mobiles.slot(block_type);
                    if (slot && *slot) {
                        flash_image.mobile_data = MobileData{};
                        break;
                    }
                }
            }
            if (flash_image.mobile_data) {
                for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                    const auto* override_slot = input.mobiles.slot(block_type);
                    if (override_slot && *override_slot) {
                        *flash_image.mobile_data->get_slot(block_type) = **override_slot;
                    }
                }
                // An eMMC anchor names four blobs, types 0x31-0x34; the rest have nowhere to go.
                if (flash_image.flash_driver.driver_mode() == Driver::DriverMode::Emmc) {
                    for (uint8_t block_type = 0x35; block_type <= 0x39; ++block_type) {
                        auto* slot = flash_image.mobile_data->get_slot(block_type);
                        if (*slot && !(*slot)->empty()) {
                            Log::Warn("Mobile data type 0x{:02X} has no slot in an eMMC anchor block; "
                                      "it is left out",
                                      block_type);
                        }
                        slot->reset();
                    }
                }
            }
            return {};
        }

    } // namespace

    BuildResult run_build(const Input& input) try {
        if (const auto validation = validate_input(input); !validation) {
            return to_build_error(BuildErrorCode::InvalidInput,
                                  {ErrorCode::InvalidArgument, validation.error().message});
        }

        // A devgl image's SD is patched, so it is signed again with the SB private key.
        std::optional<gxbuild3::utils::XeRsaPrivateKey> sd_signing_key;
        if (input.build_type == BuildType::Devgl) {
            auto parsed_key = gxbuild3::utils::XeRsaPrivateKey::parse(*input.sb_private_key);
            if (!parsed_key) {
                return to_build_error(
                    BuildErrorCode::InvalidInput,
                    std::move(parsed_key.error())
                        .add_context("The SB private key is not a well-formed XeCrypt RSA-2048 "
                                     "private key"));
            }
            sd_signing_key = std::move(*parsed_key);
        }

        FlashImage flash_image{};
        std::optional<DonorNonces> donor_nonces = input.metadata.donor_nonces;
        if (auto init = init_build_image(input, flash_image, donor_nonces); !init) {
            return std::unexpected(std::move(init.error()));
        }

        std::optional<ParsedPatchSet> parsed_patchset;
        if (auto boot = populate_and_patch_bootloaders(flash_image, input, donor_nonces,
                                                       sd_signing_key, parsed_patchset);
            !boot) {
            return std::unexpected(std::move(boot.error()));
        }
        if (auto payloads = populate_payloads(flash_image, input, std::move(parsed_patchset));
            !payloads) {
            return std::unexpected(std::move(payloads.error()));
        }
        if (auto storage = populate_storage(flash_image, input); !storage) {
            return std::unexpected(std::move(storage.error()));
        }

        Log::Debug("Encrypting NAND image components");
        if (auto encrypted = flash_image.encrypt_all(input.metadata.cpu_key, input.build_type);
            !encrypted) {
            return to_build_error(BuildErrorCode::EncryptionFailure,
                                  std::move(encrypted.error())
                                      .add_context("Failed to encrypt NAND image components"));
        }

        auto output = flash_image.write();
        if (!output) {
            return to_build_error(BuildErrorCode::SerializationFailure,
                                  std::move(output.error())
                                      .add_context("Failed to write/serialize built NAND image"));
        }

        return std::move(*output);
    } catch (const std::exception& exception) {
        // Only std (allocation) failures reach here; every expected failure is a Result above.
        return to_build_error(BuildErrorCode::Internal, {ErrorCode::Internal, exception.what()});
    }

    namespace {

        // Reads and parses a NAND image into `image`. Its FlashFS keeps a pointer to the image's
        // driver; copying or moving a FlashImage rebinds that pointer to the new object's driver.
        [[nodiscard]] Result<void> parse_nand(FlashImage& image,
                                              std::span<const uint8_t> nand_image) {
            auto read =
                FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
            if (!read) {
                return fail(ErrorCode::InvalidArgument, "the NAND image is empty");
            }
            image = std::move(*read);
            return with_context(image.parse(), "Failed to parse the NAND image structure");
        }

        [[nodiscard]] Result<void> check_cpu_key(std::span<const uint8_t> cpu_key) {
            if (cpu_key.size() != 16) {
                return fail(ErrorCode::InvalidArgument, "the CPU key must be 16 bytes (got {})",
                            cpu_key.size());
            }
            return {};
        }

        [[nodiscard]] Result<void> decrypt_nand(FlashImage& image,
                                                std::span<const uint8_t> cpu_key) {
            return with_context(image.decrypt_all(cpu_key),
                                "Failed to decrypt the NAND image components with the CPU key");
        }

        // Checks the CPU key, then parses and opens the image under it.
        [[nodiscard]] Result<void> open_nand(FlashImage& image, std::span<const uint8_t> nand_image,
                                             std::span<const uint8_t> cpu_key) {
            if (auto checked = check_cpu_key(cpu_key); !checked) {
                return checked;
            }
            if (auto parsed = parse_nand(image, nand_image); !parsed) {
                return parsed;
            }
            return decrypt_nand(image, cpu_key);
        }

        // The text of a fixed-size, NUL-padded on-disk string field: its bytes up to the first
        // NUL, or all of them when there is none.
        std::string fixed_string(std::span<const uint8_t> bytes) {
            const auto end = std::ranges::find(bytes, uint8_t{0});
            return std::string(bytes.begin(), end);
        }

        // The NAND header fields the extract cores show.
        void project_header(const nand_header& header, AllNandInfo& info) {
            info.header_magic = header.magic.get();
            info.header_version = header.version.get();
            info.header_flags = header.flags.get();
            info.header_size = header.size.get();
            info.copyright = fixed_string(header.copyright);
        }

        // One stage's line in the extracted bootloader chain: its header fields and whether it is
        // decrypted, which `decrypted_override` replaces when set (extract_all_info shows SC as
        // decrypted whatever its state). The caller decides presence and adds any per-box values.
        template <class Stage>
        BootloaderEntryInfo summarize_stage(std::string_view name, const Stage& stage,
                                            std::optional<bool> decrypted_override = {}) {
            BootloaderEntryInfo entry{};
            entry.name = name;
            entry.version = stage.header.header.version.get();
            entry.size = stage.header.header.size.get();
            entry.flags = stage.header.header.flags.get();
            entry.entrypoint = stage.header.header.entrypoint.get();
            entry.present = true;
            entry.decrypted = decrypted_override ? *decrypted_override : stage.is_decrypted();
            return entry;
        }

        SmcSummaryInfo summarize_smc(const Smc& smc) {
            SmcSummaryInfo summary{};
            summary.present = true;
            summary.version = smc.version;
            summary.motherboard_name = std::string(smc_motherboard_name(smc.motherboard));
            summary.type_name = std::string(smc_type_name(smc.variant));
            summary.size = static_cast<uint32_t>(smc.data.size());
            summary.decrypted = !smc.encrypted;
            return summary;
        }

        std::optional<BootloaderEntryInfo>& stage_entry_slot(BootloaderChainInfo& chain,
                                                             BootStageId id) {
            switch (id) {
                case BootStageId::CbA:
                    return chain.cb_a;
                case BootStageId::CbX:
                    return chain.cb_x;
                case BootStageId::CbB:
                    return chain.cb_b;
                case BootStageId::Sc:
                    return chain.sc;
                case BootStageId::Cd:
                    return chain.cd;
                case BootStageId::Ce:
                    return chain.ce;
            }
            std::unreachable();
        }

        void populate_extracted_metadata(const FlashImage& img, InputMetadata& meta) {
            const auto cb = read_cb_metadata(img.cb_section);
            meta.cb_ldv = cb.ldv;
            meta.pairing_data = cb.pairing;
            meta.console_type = cb.console_type;
            meta.console_sequence = cb.console_sequence;
            meta.console_sequence_allow = cb.console_sequence_allow;
            extract_cf_metadata(img, meta);
            meta.donor_nonces = img.collect_nonces();
            extract_settings_blocks(img, meta);
        }

    } // namespace

    Result<AllNandInfo> extract_some_info(std::span<const uint8_t> nand_image) {
        FlashImage img{};
        if (auto parsed = parse_nand(img, nand_image); !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }

        AllNandInfo info{};
        project_header(img.header, info);
        info.block_type = image_type_from_driver(img.flash_driver.driver_mode());

        FlashImage::for_each_present_stage(
            img, [&info](BootStageId id, std::string_view name, const auto& stage) {
                if (!stage.data.empty()) {
                    stage_entry_slot(info.bootloaders, id) = summarize_stage(name, stage);
                }
            });
        if (img.system_update_0.cf && !img.system_update_0.cf->data.empty()) {
            info.bootloaders.cf_0 = summarize_stage("CF_0", *img.system_update_0.cf);
        }
        if (img.system_update_0.cg && !img.system_update_0.cg->data.empty()) {
            info.bootloaders.cg_0 = summarize_stage("CG_0", *img.system_update_0.cg);
        }
        if (img.system_update_1.cf && !img.system_update_1.cf->data.empty()) {
            info.bootloaders.cf_1 = summarize_stage("CF_1", *img.system_update_1.cf);
        }
        if (img.system_update_1.cg && !img.system_update_1.cg->data.empty()) {
            info.bootloaders.cg_1 = summarize_stage("CG_1", *img.system_update_1.cg);
        }

        if (img.smc) {
            info.smc = summarize_smc(*img.smc);
        }

        return info;
    }

    Result<AllNandInfo> extract_some_info(const std::vector<uint8_t>& nand_image) {
        return extract_some_info(std::span<const uint8_t>(nand_image));
    }

    Result<InputMetadata> extract_metadata(std::span<const uint8_t> nand_image,
                                           std::span<const uint8_t> cpu_key) {
        if (auto checked = check_cpu_key(cpu_key); !checked) {
            return std::unexpected(std::move(checked.error()));
        }
        FlashImage img{};
        if (auto parsed = parse_nand(img, nand_image); !parsed) {
            return std::unexpected(std::move(parsed.error()));
        }
        if (!img.keyvault.has_value()) {
            return fail(ErrorCode::NotFound, "the NAND image does not contain a valid keyvault");
        }
        if (auto decrypted = decrypt_nand(img, cpu_key); !decrypted) {
            return std::unexpected(std::move(decrypted.error()));
        }

        auto& kv = *img.keyvault;
        if (kv.encrypted) {
            return fail(ErrorCode::AuthFailed, "the keyvault does not open under the CPU key");
        }
        InputMetadata meta{};
        meta.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
        meta.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
        meta.keyvault = kv.serialize();

        populate_extracted_metadata(img, meta);

        Log::Debug(
            "Extracted metadata: CB LDV={}, CF LDV={}, ConsoleType=0x{:02X}, Sequence=0x{:02X}",
            meta.cb_ldv, meta.cf_ldv ? std::to_string(*meta.cf_ldv) : "none", meta.console_type,
            meta.console_sequence);

        return meta;
    }

    Result<InputMetadata> extract_metadata(const std::vector<uint8_t>& nand_image,
                                           const std::vector<uint8_t>& cpu_key) {
        return extract_metadata(std::span<const uint8_t>(nand_image),
                                std::span<const uint8_t>(cpu_key));
    }

    Result<AllNandInfo> extract_all_info(std::span<const uint8_t> nand_image,
                                         std::span<const uint8_t> cpu_key) {
        FlashImage img{};
        if (auto opened = open_nand(img, nand_image, cpu_key); !opened) {
            return std::unexpected(std::move(opened.error()));
        }

        AllNandInfo info{};
        info.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
        info.block_type = image_type_from_driver(img.flash_driver.driver_mode());

        project_header(img.header, info);

        FlashImage::for_each_present_stage(
            img, [&info](BootStageId id, std::string_view name, const auto& stage) {
                if (stage.data.empty()) {
                    return;
                }
                const std::optional<bool> decrypted_override =
                    id == BootStageId::Sc ? std::optional<bool>{true} : std::nullopt;
                auto entry = summarize_stage(name, stage, decrypted_override);
                if constexpr (std::is_same_v<std::decay_t<decltype(stage)>, BootloaderCb>) {
                    if ((id == BootStageId::CbA || id == BootStageId::CbB) &&
                        stage.perbox.has_value()) {
                        const uint8_t ldv = id == BootStageId::CbB
                                                ? cb_b_display_ldv(stage)
                                                : stage.perbox->lockdown_value;
                        const auto pd = std::to_array(stage.perbox->pairing_data);
                        entry.ldv = ldv;
                        entry.pairing_data = pd;
                        info.bootloaders.cb_ldv = ldv;
                        info.bootloaders.cb_pairing_data = pd;
                    }
                }
                stage_entry_slot(info.bootloaders, id) = std::move(entry);
            });

        if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
            const auto& cf_0 = *img.system_update_0.cf;
            auto entry = summarize_stage("CF_0", cf_0);
            if (cf_0.perbox.has_value()) {
                const auto pd = std::to_array(cf_0.perbox->pairing_data);
                entry.ldv = cf_0.perbox->lockdown_value;
                entry.pairing_data = pd;
                info.bootloaders.cf0_ldv = cf_0.perbox->lockdown_value;
                info.bootloaders.cf0_pairing_data = pd;
            }
            info.bootloaders.cf_0 = entry;
        }

        if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
            info.bootloaders.cg_0 = summarize_stage("CG_0", *img.system_update_0.cg);
        }

        if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
            const auto& cf_1 = *img.system_update_1.cf;
            auto entry = summarize_stage("CF_1", cf_1);
            if (cf_1.perbox.has_value()) {
                const auto pd = std::to_array(cf_1.perbox->pairing_data);
                entry.ldv = cf_1.perbox->lockdown_value;
                entry.pairing_data = pd;
                info.bootloaders.cf1_ldv = cf_1.perbox->lockdown_value;
                info.bootloaders.cf1_pairing_data = pd;
            }
            info.bootloaders.cf_1 = entry;
        }

        if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
            info.bootloaders.cg_1 = summarize_stage("CG_1", *img.system_update_1.cg);
        }

        if (img.smc.has_value()) {
            info.smc = summarize_smc(*img.smc);
        }

        if (img.filesystem.has_value()) {
            info.flashfs.present = true;
            auto file_list = img.filesystem->list_files();
            for (const auto& filename : file_list) {
                auto stat_opt = img.filesystem->stat(filename);
                if (stat_opt.has_value()) {
                    FlashFsFileInfo file_info{};
                    file_info.filename = filename;
                    file_info.block_number = stat_opt->block_number;
                    file_info.length = stat_opt->length;
                    file_info.timestamp = stat_opt->timestamp;
                    info.flashfs.files.push_back(file_info);
                }
            }
        }

        if (img.keyvault.has_value()) {
            info.raw_keyvault = img.keyvault->serialize();
            info.keyvault = summarize_keyvault(*img.keyvault);
        }

        return info;
    }

    Result<AllNandInfo> extract_all_info(const std::vector<uint8_t>& nand_image,
                                         const std::vector<uint8_t>& cpu_key) {
        return extract_all_info(std::span<const uint8_t>(nand_image),
                                std::span<const uint8_t>(cpu_key));
    }

    Result<Input> extract_all(std::span<const uint8_t> nand_image,
                              std::span<const uint8_t> cpu_key) {
        FlashImage img{};
        if (auto opened = open_nand(img, nand_image, cpu_key); !opened) {
            return std::unexpected(std::move(opened.error()));
        }

        Input out{};
        if (img.build_type == BuildType::Devkit) {
            out.build_type = BuildType::Devkit;
        }
        if (img.payloads.patchset && img.build_type) {
            out.build_type = *img.build_type;
            out.patches = InputPatches{};
            out.patches->automatic =
                InputPatchFile{"extracted", serialize_patch_set(*img.payloads.patchset)};
        }
        out.metadata.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
        out.metadata.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
        out.image_type = image_type_from_driver(img.flash_driver.driver_mode());

        FlashImage::for_each_present_stage(
            img, [&out](BootStageId id, std::string_view, const auto& stage) {
                if (stage.data.empty()) {
                    return;
                }
                auto bytes = stage.serialize();
                switch (id) {
                    case BootStageId::CbA:
                        out.bootloaders.cb_or_a = std::move(bytes);
                        break;
                    case BootStageId::CbX:
                        out.bootloaders.cb_x = std::move(bytes);
                        break;
                    case BootStageId::CbB:
                        out.bootloaders.cb_b = std::move(bytes);
                        break;
                    case BootStageId::Sc:
                        out.bootloaders.sc = std::move(bytes);
                        break;
                    case BootStageId::Cd:
                        out.bootloaders.cd = std::move(bytes);
                        break;
                    case BootStageId::Ce:
                        out.bootloaders.ce = std::move(bytes);
                        break;
                }
            });

        if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
            out.bootloaders.cf0 = img.system_update_0.cf->serialize();
        }

        if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
            out.bootloaders.cg0 = img.system_update_0.cg->serialize();
        }

        if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
            out.bootloaders.cf1 = img.system_update_1.cf->serialize();
        }

        if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
            out.bootloaders.cg1 = img.system_update_1.cg->serialize();
        }

        populate_extracted_metadata(img, out.metadata);

        if (img.smc.has_value()) {
            out.metadata.smc = img.smc->data;
        }

        // A keyvault left sealed (it does not open under the all-zero CPU key) is not the
        // console's in the clear; the build then needs the console's kv.bin.
        if (img.keyvault.has_value() && !img.keyvault->encrypted) {
            out.metadata.keyvault = img.keyvault->serialize();
        }

        if (img.filesystem.has_value()) {
            std::vector<std::pair<std::string, std::vector<uint8_t>>> files;
            auto file_list = img.filesystem->list_files();
            for (const auto& filename : file_list) {
                auto file_data = img.filesystem->get_file(filename);
                if (!file_data.has_value()) {
                    Log::Warn("FlashFS file '{}' could not be read from the image; it is left out",
                              filename);
                    continue;
                }
                if (is_cpu_keyed_secfile(filename)) {
                    if (auto crypted = crypt_secfile(cpu_key, *file_data); !crypted) {
                        return std::unexpected(
                            std::move(crypted.error())
                                .add_context(std::format(
                                    "Failed to decrypt secure FlashFS file '{}'", filename)));
                    }
                }
                if (is_console_secured_file(filename)) {
                    out.metadata.console_secured_files.emplace_back(filename, *file_data);
                }
                files.emplace_back(filename, std::move(*file_data));
            }
            out.flashfs_sec = std::move(files);
        }

        if (img.mobile_data.has_value()) {
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                const auto* donor_slot = img.mobile_data->get_slot(block_type);
                if (donor_slot && *donor_slot) {
                    *out.mobiles.slot(block_type) = **donor_slot;
                }
            }
        }

        InputPayloads payloads{};
        bool has_payloads = false;
        if (img.payloads.xell.has_value()) {
            payloads.xell = img.payloads.xell->data;
            has_payloads = true;
        }
        if (img.payloads.rebooter.has_value()) {
            payloads.rebooter = img.payloads.rebooter;
            has_payloads = true;
        }
        if (img.payloads.fuses.has_value()) {
            payloads.fuses = img.payloads.fuses;
            has_payloads = true;
        }
        if (img.payloads.payload.has_value()) {
            payloads.payload = img.payloads.payload;
            has_payloads = true;
        }
        if (has_payloads) {
            out.payloads = std::move(payloads);
        }

        return out;
    }

    Result<Input> extract_all(const std::vector<uint8_t>& nand_image,
                              const std::vector<uint8_t>& cpu_key) {
        return extract_all(std::span<const uint8_t>(nand_image), std::span<const uint8_t>(cpu_key));
    }

} // namespace gxbuild3
