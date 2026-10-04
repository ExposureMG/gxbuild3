#include "BuildRunner.hpp"

#include "InputValidator.hpp"
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
#include <cstring>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>

using namespace gxbuild3::NAND;

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

    // A FlashFS file as the image carries it. crl.bin, dae.bin, extended.bin and secdata.bin are
    // sealed for this build as xeBuild 1.21 seals them: the content is the file supplied, the
    // sealing the console's own copy's (or, with none, the supplied file's own when it is a
    // console copy, or drawn), and crl.bin, dae.bin and secdata.bin state the build's time and
    // the CF lockdown value. A crl.bin or dae.bin that does not open is written as supplied, and
    // so is a secdata.bin that does not open unless it is the console's own copy. An extended.bin
    // or secdata.bin that is empty (nothing supplied it) or of the wrong length, an extended.bin
    // that does not open and the console's own secdata.bin when it does not open are replaced by
    // a clean one, as xeBuild makes one up. fcrt.bin is sealed under the CPU key when it is in the
    // clear and otherwise written as supplied. Every other file is written as supplied. Nothing
    // when a file cannot be sealed at all.
    std::optional<std::vector<uint8_t>> sealed_flashfs_file(std::string_view name,
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
            auto sealing = own ? crl_sealing(*own, cpu_key) : std::nullopt;
            if (own && !sealing) {
                Log::Warn("The console's crl.bin does not open under its CPU key; its sealing is "
                          "not used");
            }
            if (!sealing) {
                sealing = crl_sealing(data, cpu_key);
            }
            if (!sealing) {
                Log::Info("crl.bin is sealed under a drawn vector and file key");
                sealing = random_crl_sealing();
            }
            if (auto sealed = reseal_crl(data, cpu_key, *sealing, build)) {
                return std::move(*sealed);
            }
            Log::Warn("crl.bin opens under no key it is tried under; it is written as supplied");
            return data;
        }
        if (lower == "dae.bin") {
            auto sealing = own ? dae_sealing(*own, cpu_key) : std::nullopt;
            if (own && !sealing) {
                Log::Warn("The console's dae.bin does not open under its CPU key; its sealing is "
                          "not used");
            }
            if (!sealing) {
                sealing = dae_sealing(data, cpu_key);
            }
            if (!sealing) {
                Log::Info("dae.bin is sealed under a drawn head and field");
                sealing = random_dae_sealing();
            }
            if (auto sealed = reseal_dae(data, cpu_key, *sealing, build)) {
                return std::move(*sealed);
            }
            Log::Warn("dae.bin opens under no key it is tried under; it is written as supplied");
            return data;
        }
        if (lower == "extended.bin") {
            // Its head is the keyvault's; with no keyvault, a copy that opens keeps its own and a
            // clean one has a zero head.
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
            // Its head is the console's own copy's; with none, a copy that opens keeps its own and
            // a clean one takes a drawn head.
            const auto own_head =
                own && secdata_opened(*own, cpu_key) ? secdata_head(*own) : std::nullopt;
            if (data.size() == kSecdataSize && secdata_opened(data, cpu_key)) {
                return reseal_secdata(data, cpu_key, own_head, build);
            }
            // The console's own copy is used only when it opens; a supplied copy of the right
            // length that does not open is written as it stands.
            const bool unopened_own = own && data == *own;
            if (data.size() == kSecdataSize && !unopened_own) {
                Log::Warn("secdata.bin did not open under the CPU key; it is sealed again under "
                          "the nonce it carries");
                std::vector<uint8_t> file_data = data;
                if (!crypt_secfile(cpu_key, file_data)) {
                    return std::nullopt;
                }
                return file_data;
            }
            if (data.empty()) {
                Log::Info("secdata.bin was not supplied; a clean one is made up");
            } else if (data.size() != kSecdataSize) {
                Log::Warn("secdata.bin is 0x{:X} bytes, not 0x{:X}; a clean one is made up",
                          data.size(), kSecdataSize);
            } else {
                Log::Warn("The console's secdata.bin does not open under its CPU key; a clean one "
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
                    Log::Warn("fcrt.bin's header puts its sealed part past its end; it is written "
                              "as supplied");
                    break;
                case FcrtSealing::Damaged:
                    Log::Warn("fcrt.bin is neither in the clear nor opens under the CPU key; it is "
                              "written as supplied");
                    break;
            }
            return std::move(sealed.data);
        }
        return data;
    }

    BuildResult build_error(BuildErrorCode code, std::string message) {
        return std::unexpected(BuildError{code, std::move(message)});
    }

    const ParsedPatchSection* find_patch_section(const ParsedPatchSet& patchset,
                                                 PatchSectionTarget target) {
        const auto section = std::find_if(
            patchset.sections.begin(), patchset.sections.end(),
            [target](const ParsedPatchSection& candidate) { return candidate.target == target; });
        return section == patchset.sections.end() ? nullptr : &*section;
    }

    bool ranges_overlap(size_t first_offset, size_t first_length, size_t second_offset,
                        size_t second_length) {
        return first_length != 0 && second_length != 0 &&
               first_offset < second_offset + second_length &&
               second_offset < first_offset + first_length;
    }

    size_t align_16(size_t value) {
        return (value + 0x0F) & ~size_t{0x0F};
    }

    std::expected<size_t, PatchError> patched_bootloader_size(size_t current_size,
                                                              const ParsedPatchSection& section,
                                                              std::string_view stage_name) {
        uint64_t required_end = current_size;
        for (const auto& entry : section.entries) {
            if (entry.words.size() < entry.length) {
                return std::unexpected(
                    PatchError{std::string(stage_name) + " patch entry has too few words"});
            }
            const uint64_t entry_end = static_cast<uint64_t>(entry.address) +
                                       static_cast<uint64_t>(entry.length) * sizeof(uint32_t);
            required_end = std::max(required_end, entry_end);
        }
        if (required_end > std::numeric_limits<uint32_t>::max()) {
            return std::unexpected(
                PatchError{std::string(stage_name) + " patch exceeds the 32-bit address space"});
        }
        return static_cast<size_t>(required_end);
    }

    std::expected<std::vector<uint8_t>, PatchError>
    apply_bootloader_patch(std::vector<uint8_t> bytes, const ParsedPatchSection& section,
                           size_t target_capacity, std::string_view stage_name) {
        const auto required_end = patched_bootloader_size(bytes.size(), section, stage_name);
        if (!required_end) {
            return std::unexpected(required_end.error());
        }
        if (align_16(*required_end) > target_capacity) {
            return std::unexpected(
                PatchError{std::string(stage_name) + " patch exceeds its boot-chain capacity"});
        }

        // A patched stage is as long as its greatest patched end rounded up to 0x10, the
        // rounding zero, and its header states that length (xeBuild: glitch2m CD 9452 0x52A8
        // of patched bytes states 0x52B0). The padding is sealed with the stage.
        try {
            bytes.resize(align_16(*required_end), 0);
            XePatchSection xe_section{section.identifier, section.entries};
            if (!XePatch::ApplyPatchSection(bytes.data(), static_cast<uint32_t>(bytes.size()),
                                            xe_section)) {
                return std::unexpected(
                    PatchError{"Failed to apply " + std::string(stage_name) + " patch section"});
            }
        } catch (const std::exception& exception) {
            return std::unexpected(PatchError{"Failed to allocate/apply " +
                                              std::string(stage_name) +
                                              " patch: " + exception.what()});
        }

        if (bytes.size() < sizeof(generic_header)) {
            return std::unexpected(
                PatchError{std::string(stage_name) + " patch target has no bootloader header"});
        }
        const uint32_t be_size = bswap32(static_cast<uint32_t>(bytes.size()));
        std::memcpy(bytes.data() + offsetof(generic_header, size), &be_size, sizeof(be_size));
        return bytes;
    }

    std::expected<void, BuildError> apply_cb_metadata(BootloaderCb& bootloader,
                                                      const InputMetadata& metadata,
                                                      std::string_view name) {
        if (!bootloader.perbox.has_value() && !bootloader.parse_perbox()) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string(name) + " has no writable per-box metadata"});
        }
        bootloader.perbox->lockdown_value = metadata.cb_ldv;
        std::memcpy(bootloader.perbox->pairing_data, metadata.pairing_data.data(),
                    metadata.pairing_data.size());
        if (!bootloader.serialize_perbox()) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string(name) + " could not serialize per-box metadata"});
        }
        return {};
    }

    // A zero-paired CB states no pairing, no LDV and no digest: its whole per-box block is
    // zero, and the CB then keys CD without the CPU key.
    std::expected<void, BuildError> zero_pair_cb(BootloaderCb& bootloader, std::string_view name) {
        if (!bootloader.perbox.has_value() && !bootloader.parse_perbox()) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string(name) + " has no writable per-box metadata"});
        }
        *bootloader.perbox = cb_perbox{};
        if (!bootloader.serialize_perbox()) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string(name) + " could not serialize per-box metadata"});
        }
        return {};
    }

    // A CF bound to the console states its update slot at 0x21B. A paired CF takes the
    // console's pairing; an unpaired one states zero there. Either states the build's CF LDV
    // when it has one.
    std::expected<void, BuildError> apply_cf_metadata(BootloaderCf& bootloader,
                                                      const InputMetadata& metadata,
                                                      std::optional<uint8_t> cf_ldv, bool paired,
                                                      uint8_t slot, std::string_view name) {
        if (!bootloader.perbox.has_value()) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string(name) + " has no writable per-box metadata"});
        }
        bootloader.perbox->update_slot = slot;
        if (cf_ldv) {
            bootloader.perbox->lockdown_value = *cf_ldv;
        }
        const auto pairing = paired ? metadata.cf_pairing_data.value_or(metadata.pairing_data)
                                    : std::array<uint8_t, 3>{};
        std::memcpy(bootloader.perbox->pairing_data, pairing.data(), pairing.size());
        if (!bootloader.serialize_perbox()) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string(name) + " could not serialize per-box metadata"});
        }
        return {};
    }

    // A glitch (RGH1) image boots a single zero-paired CB, so its CD is keyed without the
    // CPU key, and its CFs state no pairing (xeBuild 1.21 glitch Jasper and Falcon). A JTAG
    // image's main chain is zero-paired the same way; its second chain's CB carries the
    // console's pairing and CB LDV instead, and its second CF is paired. A devgl image's SB
    // is zero-paired too (xeBuild 1.21 devgl). Every other chain carries the console's pairing
    // and CB LDV. A JTAG image's first update pair carries nothing of the console and keeps its
    // CF's per-box block as supplied. Under the all-zero CPU key a chain with a CB_B is
    // zero-paired: its CB_B per-box block is zero and its CFs state no pairing (xeBuild 1.21
    // "zeropairing CB_B"); every CF then states LDV 0.
    std::expected<void, BuildError> apply_bootloader_metadata(FlashImage& flash_image,
                                                              const InputMetadata& metadata,
                                                              BuildType build_type) {
        const bool zero_key = is_zero_cpu_key(metadata.cpu_key);
        const bool zero_paired_cb_b = zero_key && flash_image.cb_section.cb_B.has_value();
        const bool paired = build_type != BuildType::Glitch && !zero_paired_cb_b;
        const bool main_cb_paired =
            paired && build_type != BuildType::Jtag && build_type != BuildType::Devgl;
        const auto cf_ldv = zero_key ? std::optional<uint8_t>{0} : metadata.cf_ldv;
        auto& cb_a = flash_image.cb_section.cb_or_A;
        try {
            if (flash_image.cb_section.cb_B.has_value()) {
                auto& cb_b = *flash_image.cb_section.cb_B;
                if (!cb_a.decrypted) {
                    cb_a.decrypt(key_1bl);
                }
                if (!cb_b.decrypted) {
                    if (!cb_a.derived_key.has_value()) {
                        return std::unexpected(
                            BuildError{BuildErrorCode::InvalidBootloader,
                                       "Could not derive CB_A key for replacement CB_B metadata"});
                    }
                    cb_b.decrypt_cb_b(cb_a.header, cb_a.derived_key->data(),
                                      metadata.cpu_key.data());
                }
                auto applied = zero_paired_cb_b ? zero_pair_cb(cb_b, "CB_B")
                                                : apply_cb_metadata(cb_b, metadata, "CB_B");
                if (!applied) {
                    return std::unexpected(applied.error());
                }
            } else {
                if (!cb_a.decrypted) {
                    cb_a.decrypt(key_1bl);
                }
                auto applied = main_cb_paired ? apply_cb_metadata(cb_a, metadata, "CB/A")
                                              : zero_pair_cb(cb_a, "CB/A");
                if (!applied) {
                    return std::unexpected(applied.error());
                }
            }

            if (auto& extra_cb = flash_image.payloads.extra_cb; extra_cb) {
                if (!extra_cb->decrypted) {
                    extra_cb->decrypt(key_1bl);
                }
                if (auto applied = apply_cb_metadata(*extra_cb, metadata, "JTAG second CB");
                    !applied) {
                    return std::unexpected(applied.error());
                }
            }

            if (flash_image.system_update_0.cf.has_value()) {
                auto& cf = *flash_image.system_update_0.cf;
                if (!cf.is_decrypted()) {
                    cf.decrypt(key_1bl);
                }
                if (update_slot_binds_console(build_type, 0)) {
                    if (auto applied = apply_cf_metadata(cf, metadata, cf_ldv, paired, 0, "CF_0");
                        !applied) {
                        return std::unexpected(applied.error());
                    }
                }
            }
            if (flash_image.system_update_1.cf.has_value()) {
                auto& cf = *flash_image.system_update_1.cf;
                if (!cf.is_decrypted()) {
                    cf.decrypt(key_1bl);
                }
                if (update_slot_binds_console(build_type, 1)) {
                    if (auto applied = apply_cf_metadata(cf, metadata, cf_ldv, paired, 1, "CF_1");
                        !applied) {
                        return std::unexpected(applied.error());
                    }
                }
            }
        } catch (const std::exception& exception) {
            return std::unexpected(
                BuildError{BuildErrorCode::InvalidBootloader,
                           std::string("Could not decrypt replacement bootloaders "
                                       "for metadata application: ") +
                               exception.what()});
        }

        return {};
    }

    bool is_zero_nonce(std::span<const uint8_t> nonce) {
        return std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; });
    }

    std::optional<BootloaderNonce> nonce_from(std::span<const uint8_t> bytes) {
        if (bytes.size() < std::tuple_size_v<BootloaderNonce> || is_zero_nonce(bytes.first(16))) {
            return std::nullopt;
        }
        BootloaderNonce nonce{};
        std::copy_n(bytes.begin(), nonce.size(), nonce.begin());
        return nonce;
    }

    // The update slot whose CF states the largest LDV; slot 0 on a tie.
    std::optional<size_t> max_ldv_slot(const FlashImage& image) {
        std::optional<size_t> best;
        uint8_t best_ldv = 0;
        const std::array<const SystemUpdate*, 2> slots{&image.system_update_0,
                                                       &image.system_update_1};
        for (size_t index = 0; index < slots.size(); ++index) {
            const auto& cf = slots[index]->cf;
            if (!cf || cf->data.empty() || !cf->perbox) {
                continue;
            }
            if (!best || cf->perbox->lockdown_value > best_ldv) {
                best = index;
                best_ldv = cf->perbox->lockdown_value;
            }
        }
        return best;
    }

    // Stage nonces sit in clear, so they are read without decrypting. A donor whose chain does
    // not reach CE gives none, and every new stage then takes a random nonce.
    std::optional<DonorNonces> collect_donor_nonces(const FlashImage& image) {
        const auto& cb_a = image.cb_section.cb_or_A;
        const auto& cd = image.kernel_section.cd;
        const auto& ce = image.kernel_section.ce;
        if (cb_a.data.size() < 0x10 || cd.data.empty() || !ce || ce->data.empty()) {
            return std::nullopt;
        }

        DonorNonces nonces{};
        nonces.stages[0] = nonce_from(cb_a.data);
        // A CB_B behind a CB_X carries its plaintext handoff key at +0x10, not a nonce.
        if (!image.cb_section.cb_x && image.cb_section.cb_B &&
            image.cb_section.cb_B->data.size() >= 0x10) {
            nonces.stages[1] = nonce_from(image.cb_section.cb_B->data);
        } else if (image.cb_section.sc) {
            nonces.stages[1] = nonce_from(image.cb_section.sc->header.key);
        }
        nonces.stages[2] = nonce_from(cd.header.key);
        nonces.stages[3] = nonce_from(ce->header.key);

        const auto& slot =
            max_ldv_slot(image).value_or(0) == 0 ? image.system_update_0 : image.system_update_1;
        if (slot.cf && !slot.cf->data.empty()) {
            nonces.cf = nonce_from(slot.cf->header.fixpoint_nonce);
        }
        if (slot.cg && !slot.cg->data.empty()) {
            nonces.cg = nonce_from(slot.cg->header.key);
        }
        return nonces;
    }

    // CF LDV and pairing come from the slot the console booted last: the one stating the
    // largest LDV.
    void extract_cf_metadata(const FlashImage& image, InputMetadata& metadata) {
        const auto slot = max_ldv_slot(image);
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

    BootloaderNonce donor_or_random(const std::optional<BootloaderNonce>& donor) {
        if (donor) {
            return *donor;
        }
        BootloaderNonce nonce{};
        do {
            ::ExCryptRandom(nonce.data(), nonce.size());
        } while (is_zero_nonce(nonce));
        return nonce;
    }

    // Sets the nonce of every stage RunBuild seals, before any key is derived from it. Each
    // boot-chain key derives from its parent's, so a chain with any stage supplied already
    // sealed keeps all its nonces. A CB_X chain keeps its CB_X and the handoff key its
    // plaintext CB_B holds at +0x10. A devkit SC takes the CB_B nonce; any other SC is
    // written as supplied. A JTAG image's second chain takes the first CB's and the CD's
    // nonces again (xeBuild 1.21, xerunner build.py `_nonces`).
    void apply_nonces(FlashImage& image, const std::optional<DonorNonces>& donor) {
        const auto stage = [&donor](size_t index) {
            return donor ? donor->stages[index] : std::optional<BootloaderNonce>{};
        };
        const auto cf_nonce = donor ? donor->cf : std::optional<BootloaderNonce>{};
        const auto cg_nonce = donor ? donor->cg : std::optional<BootloaderNonce>{};

        const auto set_cb = [](BootloaderCb& cb, const BootloaderNonce& nonce) {
            std::copy(nonce.begin(), nonce.end(), cb.data.begin());
            std::copy(nonce.begin(), nonce.end(), std::begin(cb.header.key));
        };

        auto& cb_a = image.cb_section.cb_or_A;
        auto& cb_x = image.cb_section.cb_x;
        auto& cb_b = image.cb_section.cb_B;
        auto& sc = image.cb_section.sc;
        auto& cd = image.kernel_section.cd;
        auto& ce = image.kernel_section.ce;
        // An SC counts as sealed as decrypt_all reads it: not plaintext, with a non-zero nonce.
        const bool sc_sealed = sc && !sc->is_decrypted() && !is_zero_nonce(sc->header.key);
        const bool chain_plaintext =
            cb_a.decrypted && cb_a.data.size() >= 0x10 && (!cb_x || cb_x->decrypted) &&
            (!cb_b || (cb_b->decrypted && cb_b->data.size() >= 0x10)) && !sc_sealed &&
            cd.decrypted && !cd.data.empty() && (!ce || ce->decrypted);
        std::optional<BootloaderNonce> cb_nonce;
        std::optional<BootloaderNonce> cd_nonce;
        if (chain_plaintext) {
            cb_nonce = donor_or_random(stage(0));
            set_cb(cb_a, *cb_nonce);
            if (!cb_x && cb_b) {
                set_cb(*cb_b, donor_or_random(stage(1)));
            } else if (image.devkit_chain() && sc) {
                // A devkit SC sits in the CB_B position (xeBuild 1.21 devkit).
                const auto sc_nonce = donor_or_random(stage(1));
                std::copy(sc_nonce.begin(), sc_nonce.end(), std::begin(sc->header.key));
            }
            cd_nonce = donor_or_random(stage(2));
            std::copy(cd_nonce->begin(), cd_nonce->end(), std::begin(cd.header.key));
            if (ce) {
                const auto ce_nonce = donor_or_random(stage(3));
                std::copy(ce_nonce.begin(), ce_nonce.end(), std::begin(ce->header.key));
            }
        }

        auto& extra_cb = image.payloads.extra_cb;
        auto& extra_cd = image.payloads.extra_cd;
        if (extra_cb && extra_cb->decrypted && extra_cb->data.size() >= 0x10) {
            if (!cb_nonce) {
                cb_nonce = donor_or_random(stage(0));
            }
            set_cb(*extra_cb, *cb_nonce);
        }
        if (extra_cd && extra_cd->decrypted && !extra_cd->data.empty()) {
            if (!cd_nonce) {
                cd_nonce = donor_or_random(stage(2));
            }
            std::copy(cd_nonce->begin(), cd_nonce->end(), std::begin(extra_cd->header.key));
        }

        for (auto* slot : {&image.system_update_0, &image.system_update_1}) {
            auto& cf = slot->cf;
            if (cf && cf->decrypted && !cf->data.empty()) {
                const auto nonce = donor_or_random(cf_nonce);
                std::copy(nonce.begin(), nonce.end(), std::begin(cf->header.fixpoint_nonce));
            }
            // An update package's CG arrives sealed under its CF's 7BL nonce; it is opened
            // here so it can be sealed again under the chosen nonce.
            auto& cg = slot->cg;
            if (cg && !cg->decrypted && !cg->data.empty() && cf && cf->is_decrypted()) {
                if (const auto key = cf->cg_key()) {
                    cg->decrypt(key->data());
                }
            }
            if (cg && cg->decrypted && !cg->data.empty()) {
                const auto nonce = donor_or_random(cg_nonce);
                std::copy(nonce.begin(), nonce.end(), std::begin(cg->header.key));
            }
        }
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
        const std::string text =
            "\xA9 2004-" + std::to_string(year) + " Microsoft Corporation. All rights reserved.";
        std::fill_n(header.copyright, kCopyrightLength, uint8_t{0});
        std::memcpy(header.copyright, text.data(), std::min(text.size(), kCopyrightLength - 1));
    }

    // The donor's settings, statistics and manufacturing blocks, carried as bytes.
    void extract_settings_blocks(const FlashImage& img, InputMetadata& meta) {
        meta.smc_config = img.smc_config;
        meta.statistics = img.statistics;
        meta.manufacturing = img.manufacturing;
    }

} // namespace

BuildResult RunBuild(const Input& input) {
    if (const auto validation = ValidateInput(input); !validation) {
        return build_error(BuildErrorCode::InvalidInput, validation.error().message);
    }

    // A devgl image's SD is patched, so it is signed again with the SB private key.
    std::optional<gxbuild3::utils::XeRsaPrivateKey> sd_signing_key;
    if (input.build_type == BuildType::Devgl) {
        sd_signing_key = gxbuild3::utils::XeRsaPrivateKey::parse(*input.sb_private_key);
        if (!sd_signing_key) {
            return build_error(BuildErrorCode::InvalidInput,
                               "The SB private key is not a well-formed XeCrypt RSA-2048 "
                               "private key");
        }
    }

    FlashImage flash_image{};
    std::optional<DonorNonces> donor_nonces = input.metadata.donor_nonces;
    bool has_donor = false;
    std::optional<ConsoleType> donor_console;

    if (input.metadata.nand_image && !input.metadata.nand_image->empty()) {
        try {
            Log::Info("Building image from donor NAND dump...");
            auto donor_img = FlashImage::read(*input.metadata.nand_image);
            if (!donor_img || !donor_img->parse()) {
                Log::Error("Failed to parse donor NAND dump");
                return build_error(BuildErrorCode::InvalidDonor, "Failed to parse donor NAND dump");
            }
            if (!donor_img->decrypt_all(input.metadata.cpu_key)) {
                Log::Error("Failed to decrypt donor NAND dump components");
                return build_error(BuildErrorCode::InvalidDonor,
                                   "Failed to decrypt donor NAND dump components");
            }
            if (!donor_nonces) {
                donor_nonces = collect_donor_nonces(*donor_img);
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
                flash_image.flash_driver = Driver(target.first, target.second);
            }
        } catch (const std::exception& exception) {
            return build_error(BuildErrorCode::InvalidDonor, exception.what());
        }
    } else {
        Log::Debug("Configuring fresh NAND image layout");
        const auto [image_size, driver_mode] = driver_config(input.image_type, input.build_type);
        flash_image.flash_driver = Driver(image_size, driver_mode);
    }

    flash_image.build_type = input.build_type;

    // The console's own blocks follow it into whatever layout is built.
    if (input.metadata.smc_config) {
        flash_image.smc_config = *input.metadata.smc_config;
    }
    if (input.metadata.statistics) {
        flash_image.statistics = *input.metadata.statistics;
    }
    if (input.metadata.manufacturing) {
        flash_image.manufacturing = *input.metadata.manufacturing;
    }

    const auto smc = Smc::parse(*input.metadata.smc);
    if (!smc) {
        return build_error(BuildErrorCode::InvalidSmc, "Failed to parse input SMC");
    }
    flash_image.smc = *smc;

    // A JTAG image boots through its SMC's hack, so an SMC carrying no JTAG mark is refused
    // unless smcnocheck waives the check, as xeBuild 1.21 does.
    if (input.build_type == BuildType::Jtag && !input.options.smcnocheck.value_or(false) &&
        !smc_has_jtag_mark(flash_image.smc->data)) {
        Log::Error("Clean SMC binary found: a JTAG image needs a hacked SMC");
        return build_error(BuildErrorCode::InvalidSmc,
                           "Clean SMC binary found: a JTAG image needs a hacked SMC "
                           "(the smcnocheck option builds with this one anyway)");
    }

    // A clean retail SMC gets the glitch reboot patch on every glitch type whose SMC it
    // suits: glitch, glitch2 and glitch2m. Glitch3 writes the donor's or smc.bin's SMC as
    // supplied, without checking its type.
    if ((input.build_type == BuildType::Glitch || input.build_type == BuildType::Glitch2 ||
         input.build_type == BuildType::Glitch2m) &&
        flash_image.smc->variant == SmcType::Retail) {

        flash_image.smc->decrypt();

        const uint32_t hits = Signature::ApplyPatch(
            flash_image.smc->data.data(), static_cast<uint32_t>(flash_image.smc->data.size()),
            Glitch.addr, Glitch.value);

        if (hits == 0) {
            Log::Warn("SMC reboot patch site not found - "
                      "SMC may not be a supported retail variant");
        } else {
            Log::Info("Applied glitch reboot patch to retail SMC");
            flash_image.smc->variant = SmcType::Glitch;
        }
    }

    const auto keyvault = Keyvault::parse(*input.metadata.keyvault);
    if (!keyvault) {
        return build_error(BuildErrorCode::InvalidKeyvault, "Failed to parse input keyvault");
    }
    flash_image.keyvault = *keyvault;
    flash_image.keyvault->encrypted = false;

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

    const auto supplied = [](const std::optional<std::vector<uint8_t>>& bootloader) {
        return bootloader && !bootloader->empty();
    };
    if (supplied(input.bootloaders.cg0) && !supplied(input.bootloaders.cf0)) {
        return build_error(BuildErrorCode::InvalidInput,
                           "CG0 was supplied without its required CF0 parent");
    }
    if (supplied(input.bootloaders.cg1) && !supplied(input.bootloaders.cf1)) {
        return build_error(BuildErrorCode::InvalidInput,
                           "CG1 was supplied without its required CF1 parent");
    }

    try {
        if (!flash_image.clear_bootloader_chain()) {
            return build_error(BuildErrorCode::SerializationFailure,
                               "Failed to clear donor bootloader records");
        }
        flash_image.preserve_layout = false;
        flash_image.cb_section.cb_x.reset();
        flash_image.cb_section.cb_B.reset();
        flash_image.cb_section.sc.reset();
        flash_image.kernel_section.ce.reset();
        flash_image.system_update_0 = SystemUpdate{};
        flash_image.system_update_1 = SystemUpdate{};

        flash_image.cb_section.cb_or_A = BootloaderCb::parse(input.bootloaders.cb_or_a);
        if (input.bootloaders.cb_x && !input.bootloaders.cb_x->empty()) {
            flash_image.cb_section.cb_x = BootloaderCb::parse(*input.bootloaders.cb_x);
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
        if (input.bootloaders.cb_b && !input.bootloaders.cb_b->empty()) {
            flash_image.cb_section.cb_B = BootloaderCb::parse(*input.bootloaders.cb_b);
        }
        if (input.bootloaders.sc && !input.bootloaders.sc->empty()) {
            flash_image.cb_section.sc = BootloaderSc::parse(*input.bootloaders.sc);
        }
        flash_image.kernel_section.cd = BootloaderCd::parse(input.bootloaders.cd);
        if (input.bootloaders.ce && !input.bootloaders.ce->empty()) {
            flash_image.kernel_section.ce = BootloaderCe::parse(*input.bootloaders.ce);
        }
        if (input.bootloaders.cf0 && !input.bootloaders.cf0->empty()) {
            flash_image.system_update_0.cf = BootloaderCf::parse(*input.bootloaders.cf0);
        }
        if (input.bootloaders.cg0 && !input.bootloaders.cg0->empty()) {
            flash_image.system_update_0.cg = BootloaderCg::parse(*input.bootloaders.cg0);
        }
        if (input.bootloaders.cf1 && !input.bootloaders.cf1->empty()) {
            flash_image.system_update_1.cf = BootloaderCf::parse(*input.bootloaders.cf1);
        }
        if (input.bootloaders.cg1 && !input.bootloaders.cg1->empty()) {
            flash_image.system_update_1.cg = BootloaderCg::parse(*input.bootloaders.cg1);
        }
        // A devkit chain is supplied plaintext, as a release ships it and ExtractAll returns
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
    } catch (const std::exception& exception) {
        return build_error(BuildErrorCode::InvalidBootloader, exception.what());
    }

    if (flash_image.kernel_section.cd.data.empty()) {
        return build_error(BuildErrorCode::InvalidBootloader,
                           "Required CD bootloader has no payload and cannot be serialized");
    }

    if (input.build_type == BuildType::Glitch3 &&
        (!flash_image.cb_section.cb_x || flash_image.cb_section.cb_x->data.empty() ||
         flash_image.cb_section.cb_x->header.header.version != 15432 ||
         !flash_image.cb_section.cb_B || flash_image.cb_section.cb_B->data.empty())) {
        return build_error(BuildErrorCode::InvalidBootloader,
                           "Glitch3 requires CB_A, CB_X (15432), and CB_B");
    }

    if (input.build_type == BuildType::Glitch &&
        (flash_image.cb_section.cb_B || flash_image.cb_section.cb_x)) {
        return build_error(BuildErrorCode::InvalidBootloader,
                           "glitch1/RGH1 does not support a CB_B (use glitch2) or a CB_X (use "
                           "glitch3)");
    }

    std::optional<ParsedPatchSet> parsed_patchset;
    if (input.patches && input.patches->automatic) {
        auto parsed = BinaryParser::ParseAndMergePatchSet(*input.patches, input.build_type);
        if (!parsed) {
            return build_error(BuildErrorCode::PatchFailure, parsed.error().message);
        }
        parsed_patchset = std::move(*parsed);
    }

    // A devgl chain has no CB_B: the glitch2m patch file's first section is not applied, and its
    // CD section patches the SD (xeBuild 1.21 devgl: SB, SC and SE as the release ships them).
    const bool devgl = input.build_type == BuildType::Devgl;
    const NoPatch no_patch = ResolveNoPatch(input.options);
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
        const auto first_target = input.build_type == BuildType::Glitch ? PatchSectionTarget::Cb
                                                                        : PatchSectionTarget::Cbb;
        const auto* first_section =
            devgl || no_patch.cb ? nullptr : find_patch_section(*parsed_patchset, first_target);
        const auto* cd_section =
            no_patch.cd ? nullptr : find_patch_section(*parsed_patchset, PatchSectionTarget::Cd);
        if ((!devgl && !no_patch.cb && !first_section) || (!no_patch.cd && !cd_section)) {
            return build_error(BuildErrorCode::PatchFailure,
                               "Glitch patchset is missing a bootloader patch section");
        }
        if (!devgl && !no_patch.cb && first_target == PatchSectionTarget::Cbb &&
            !flash_image.cb_section.cb_B) {
            return build_error(BuildErrorCode::PatchFailure,
                               "Automatic patchset targets CBB, but no CBB was supplied");
        }

        enum StageIndex : size_t {
            CbA,
            CbX,
            CbB,
            Sc,
            Cd,
            Ce,
            StageCount
        };
        std::array<size_t, StageCount> stage_sizes{
            flash_image.cb_section.cb_or_A.serialize().size(),
            flash_image.cb_section.cb_x ? flash_image.cb_section.cb_x->serialize().size() : 0,
            flash_image.cb_section.cb_B ? flash_image.cb_section.cb_B->serialize().size() : 0,
            flash_image.cb_section.sc ? flash_image.cb_section.sc->serialize().size() : 0,
            flash_image.kernel_section.cd.serialize().size(),
            flash_image.kernel_section.ce ? flash_image.kernel_section.ce->serialize().size() : 0,
        };
        const size_t first_index = first_target == PatchSectionTarget::Cb ? CbA : CbB;
        if (first_section) {
            const auto first_size =
                patched_bootloader_size(stage_sizes[first_index], *first_section,
                                        first_target == PatchSectionTarget::Cb ? "CB" : "CBB");
            if (!first_size) {
                return build_error(BuildErrorCode::PatchFailure, first_size.error().message);
            }
            stage_sizes[first_index] = *first_size;
        }
        if (cd_section) {
            const auto cd_size = patched_bootloader_size(stage_sizes[Cd], *cd_section, "CD");
            if (!cd_size) {
                return build_error(BuildErrorCode::PatchFailure, cd_size.error().message);
            }
            stage_sizes[Cd] = *cd_size;
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
        if (aligned_total > boot_chain_capacity) {
            return build_error(BuildErrorCode::PatchFailure,
                               "Patched bootloader chain exceeds the space before patch slots");
        }
        const auto target_capacity = [&](size_t target_index) {
            size_t other_total = 0;
            for (size_t index = 0; index < stage_sizes.size(); ++index) {
                if (index != target_index) {
                    other_total += align_16(stage_sizes[index]);
                }
            }
            return boot_chain_capacity - other_total;
        };

        auto patch_and_reparse = [&](auto& bootloader, PatchSectionTarget target, size_t capacity,
                                     std::string_view stage_name) -> std::optional<BuildError> {
            const auto* section = find_patch_section(*parsed_patchset, target);
            if (!section) {
                return std::nullopt;
            }
            auto patched =
                apply_bootloader_patch(bootloader.serialize(), *section, capacity, stage_name);
            if (!patched) {
                return BuildError{BuildErrorCode::PatchFailure, patched.error().message};
            }
            try {
                bootloader = std::decay_t<decltype(bootloader)>::parse(*patched);
            } catch (const std::exception& exception) {
                return BuildError{BuildErrorCode::PatchFailure, "Failed to reparse patched " +
                                                                    std::string(stage_name) + ": " +
                                                                    exception.what()};
            }
            return std::nullopt;
        };

        if (first_section && first_target == PatchSectionTarget::Cb) {
            if (const auto error = patch_and_reparse(flash_image.cb_section.cb_or_A, first_target,
                                                     target_capacity(CbA), "CB")) {
                return std::unexpected(*error);
            }
        } else if (first_section) {
            if (const auto error = patch_and_reparse(*flash_image.cb_section.cb_B, first_target,
                                                     target_capacity(CbB), "CBB")) {
                return std::unexpected(*error);
            }
        }
        if (cd_section) {
            if (const auto error =
                    patch_and_reparse(flash_image.kernel_section.cd, PatchSectionTarget::Cd,
                                      target_capacity(Cd), "CD")) {
                return std::unexpected(*error);
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
            Log::Info("SD {} failed its signature check; signing it again with the SB private key",
                      sd.header.header.version);
            if (!gxbuild3::utils::sign_sd(sd_bytes, *sd_signing_key) ||
                !gxbuild3::utils::verify_sd_signature(sd_bytes, sd_signing_key->public_key())) {
                return build_error(BuildErrorCode::PatchFailure,
                                   "Could not sign the SD with the SB private key");
            }
            try {
                sd = BootloaderCd::parse(sd_bytes);
            } catch (const std::exception& exception) {
                return build_error(BuildErrorCode::PatchFailure,
                                   std::string("Failed to reparse the signed SD: ") +
                                       exception.what());
            }
            sd.decrypted = true;
        }
    }

    // The JTAG second CB/CD are captured by the INI reader and placed in the window tail. They
    // are sealed with the main chain, so they are parsed before its metadata and nonces.
    if (input.bootloaders.extra_cb) {
        try {
            flash_image.payloads.extra_cb = BootloaderCb::parse(*input.bootloaders.extra_cb);
        } catch (const std::exception& exception) {
            return build_error(BuildErrorCode::InvalidBootloader,
                               std::string("Failed to parse JTAG extra CB: ") + exception.what());
        }
    }
    if (input.bootloaders.extra_cd) {
        try {
            flash_image.payloads.extra_cd = BootloaderCd::parse(*input.bootloaders.extra_cd);
        } catch (const std::exception& exception) {
            return build_error(BuildErrorCode::InvalidBootloader,
                               std::string("Failed to parse JTAG extra CD: ") + exception.what());
        }
    }

    // Patching reparses its targets. Apply the resolved metadata only after that
    // replacement step so the final CB/CF objects, rather than a discarded parse,
    // are serialized and encrypted below.
    if (const auto metadata =
            apply_bootloader_metadata(flash_image, input.metadata, input.build_type);
        !metadata) {
        return std::unexpected(metadata.error());
    }
    apply_nonces(flash_image, donor_nonces);

    if (parsed_patchset) {
        size_t patch_size = 0;
        if (parsed_patchset->kind == PatchSetKind::Jtag) {
            patch_size = BinaryParser::SerializePatchSet(*parsed_patchset).size();
            if (patch_size > 0x4000) {
                return build_error(BuildErrorCode::PatchFailure,
                                   "JTAG patch payload exceeds the 0x4000-byte region");
            }
        } else {
            const auto* khv = find_patch_section(*parsed_patchset, PatchSectionTarget::Khv);
            if (!khv) {
                return build_error(BuildErrorCode::PatchFailure,
                                   "Glitch patchset has no KHV payload section");
            }
            patch_size = BinaryParser::SerializeKhvPayload(*khv).size();
            const bool is_big_or_emmc =
                flash_image.flash_driver.driver_mode() == Driver::DriverMode::Big ||
                flash_image.flash_driver.driver_mode() == Driver::DriverMode::Emmc;
            const size_t slot_stride = is_big_or_emmc ? 0x20000 : 0x10000;
            if (patch_size > slot_stride - (parsed_patchset->manufacturing ? 0x60 : 0x10))
                return build_error(BuildErrorCode::PatchFailure,
                                   "Glitch KHV payload exceeds its patch-slot region");
        }
        flash_image.payloads.patchset = std::move(parsed_patchset);
    }

    if (input.payloads) {
        if (input.payloads->xell && !input.payloads->xell->empty()) {
            auto xell_parsed = XeLL::parse(*input.payloads->xell);
            if (!xell_parsed) {
                Log::Error("Failed to parse XeLL payload (invalid executable signature or size)");
                return build_error(BuildErrorCode::InvalidBootloader,
                                   "Failed to parse XeLL payload");
            }
            flash_image.payloads.xell = std::move(xell_parsed);
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
            Log::Info("Adding SMC payload (size=0x{:X})", flash_image.payloads.payload->size());
        }
    }

    if (const auto layout_error = flash_image.payload_layout_error(); layout_error) {
        return build_error(BuildErrorCode::InvalidInput, *layout_error);
    }

    flash_image.raw_patches = input.raw_patches;

    if (input.flashfs_sec) {
        Log::Info("Populating Flash File System ({} files)", input.flashfs_sec->size());
        FlashFileSystem fs{};
        fs.set_driver(&flash_image.flash_driver);
        fs.set_larger_filesystem(input.build_type == BuildType::Devkit);
        // Every directory entry, and crl.bin, dae.bin and secdata.bin within, carry the build's
        // time (SOURCE_DATE_EPOCH when set): the entries on the local clock, as xeBuild stamps
        // them, and the three files in UTC.
        const int64_t build_seconds = gxbuild3::utils::build_epoch();
        fs.set_timestamp(gxbuild3::utils::flashfs_build_timestamp(build_seconds));
        // A big-block filesystem's spare states the system area: all of the first 2 MB on
        // every image but a retail one, whose system area ends with its update slots
        // (xeBuild 1.21: 6 blocks of 0x20000 on a jasperbb retail image).
        fs.set_big_system_blocks(
            input.build_type == BuildType::Retail
                ? static_cast<uint8_t>(flash_image.update_slots_end() / 0x20000)
                : uint8_t{0x10});
        const size_t total_blocks = flash_image.flash_driver.block_count();
        const size_t data_limit = flash_image.flash_driver.data_block_limit();
        if (data_limit == 0 || data_limit > std::numeric_limits<uint16_t>::max()) {
            return build_error(BuildErrorCode::SerializationFailure,
                               "No usable blocks remain for the Flash File System");
        }

        // A new FlashFS starts at root sequence 1. The image writer clears every older root
        // block's metadata, so no donor root can outrank it.
        constexpr uint32_t version = 1;
        // The files start on the first block past the update slots and every payload laid
        // after them, as xeBuild 1.21 lays them: block 0x24 (0x90000) on a 16 MB retail image,
        // 0x34 on a glitch one, past the second chain on a JTAG one, and the filesystem's base
        // on big block, where that is higher.
        const size_t block_size = flash_image.flash_driver.block_size_clean();
        size_t first_block = (flash_image.update_slots_end() + block_size - 1) / block_size;
        for (const auto& range : flash_image.active_payload_block_ranges()) {
            first_block = std::max(first_block, range.start_block + range.block_count);
        }
        if (first_block > data_limit) {
            return build_error(BuildErrorCode::SerializationFailure,
                               "No usable blocks remain for the Flash File System");
        }
        const auto reserved_boundary = static_cast<uint32_t>(first_block);
        // Defer root placement so serialize allocates it once, last, from the same free
        // pool as the files and mobile data. Reserving a root here double-counts it and
        // starves a full image of the final block the root needs.
        if (!fs.format(total_blocks, FlashFileSystem::kDeferRoot, version, reserved_boundary)) {
            return build_error(BuildErrorCode::SerializationFailure,
                               "Failed to format the Flash File System");
        }
        // Past the last usable block, xeBuild's table reserves the settings blocks of a 16 MB
        // part (four) and never names its remap pool after them; a big-block part's settings
        // sit outside the filesystem's numbering, so it names nothing from there on. An eMMC
        // part or a 64 MB small-block devkit part, which keep no pool, reserve every block to
        // the end.
        if (data_limit < total_blocks) {
            const auto mode = flash_image.flash_driver.driver_mode();
            const bool pool =
                mode == Driver::DriverMode::Big ||
                ((mode == Driver::DriverMode::Small || mode == Driver::DriverMode::NewSmall) &&
                 total_blocks <= 0x400);
            const size_t held = pool ? (mode == Driver::DriverMode::Big
                                            ? 0
                                            : std::min<size_t>(4, total_blocks - data_limit))
                                     : total_blocks - data_limit;
            if ((held > 0 && !fs.reserve_blocks(data_limit, held)) ||
                (data_limit + held < total_blocks &&
                 !fs.withhold_blocks(data_limit + held, total_blocks - data_limit - held,
                                     BlockMapStatus::Unnamed))) {
                return build_error(
                    BuildErrorCode::SerializationFailure,
                    "Failed to reserve geometry tail blocks for the Flash File System");
            }
        }
        for (size_t block = 0; block < data_limit; ++block) {
            if (flash_image.flash_driver.is_bad_block(block) && !fs.reserve_blocks(block, 1)) {
                return build_error(BuildErrorCode::SerializationFailure,
                                   "Failed to reserve a bad block in the Flash File System");
            }
        }
        for (const auto& range : flash_image.active_payload_block_ranges()) {
            if (!fs.reserve_blocks(range.start_block, range.block_count)) {
                return build_error(
                    BuildErrorCode::SerializationFailure,
                    "Failed to reserve fixed payload blocks in the Flash File System");
            }
        }
        fs.set_driver(&flash_image.flash_driver);
        flash_image.filesystem = std::move(fs);

        // xeBuild states 1 when no lockdown value is set anywhere, and 0 under the all-zero CPU
        // key, as the CFs do.
        const SecuredFileBuild secured_build{build_seconds,
                                             is_zero_cpu_key(input.metadata.cpu_key)
                                                 ? uint8_t{0}
                                                 : input.metadata.cf_ldv.value_or(1)};
        for (const auto& [name, data] : *input.flashfs_sec) {
            const auto file_data = sealed_flashfs_file(name, data, input, secured_build);
            if (!file_data) {
                return build_error(BuildErrorCode::EncryptionFailure,
                                   "Failed to encrypt secure FlashFS file");
            }
            Log::Debug("Adding FlashFS file: '{}' ({} bytes)", name, file_data->size());
            if (!flash_image.filesystem->add_file(name, *file_data)) {
                return build_error(BuildErrorCode::SerializationFailure,
                                   "Failed to add a Flash File System file");
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

    Log::Debug("Encrypting NAND image components");
    if (!flash_image.encrypt_all(input.metadata.cpu_key, input.build_type)) {
        Log::Error("Failed to encrypt NAND image components");
        return build_error(BuildErrorCode::EncryptionFailure,
                           "Failed to encrypt NAND image components");
    }

    auto output = flash_image.write();
    if (output.empty()) {
        Log::Error("Failed to write/serialize built NAND image");
        return build_error(BuildErrorCode::SerializationFailure,
                           "Failed to write/serialize built NAND image");
    }

    return output;
}

std::optional<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image) {
    if (nand_image.empty()) {
        Log::Error("Cannot extract public NAND info: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse NAND image structure for public info extraction");
        return std::nullopt;
    }

    const auto& img = *img_opt;
    AllNandInfo info{};
    info.header_magic = img.header.magic;
    info.header_version = img.header.version;
    info.header_flags = img.header.flags;
    info.header_size = img.header.size;
    info.copyright = std::string(
        reinterpret_cast<const char*>(img.header.copyright),
        strnlen(reinterpret_cast<const char*>(img.header.copyright), sizeof(img.header.copyright)));
    info.block_type = image_type_from_driver(img.flash_driver.driver_mode());

    const auto summarize = [](const auto& bootloader, std::string_view name) {
        BootloaderEntryInfo entry{};
        entry.name = name;
        entry.version = bootloader.header.header.version;
        entry.size = bootloader.header.header.size;
        entry.flags = bootloader.header.header.flags;
        entry.entrypoint = bootloader.header.header.entrypoint;
        entry.present = true;
        entry.decrypted = bootloader.is_decrypted();
        return entry;
    };

    if (!img.cb_section.cb_or_A.data.empty()) {
        info.bootloaders.cb_a = summarize(img.cb_section.cb_or_A, "CB_A");
    }
    if (img.cb_section.cb_x && !img.cb_section.cb_x->data.empty()) {
        info.bootloaders.cb_x = summarize(*img.cb_section.cb_x, "CB_X");
    }
    if (img.cb_section.cb_B && !img.cb_section.cb_B->data.empty()) {
        info.bootloaders.cb_b = summarize(*img.cb_section.cb_B, "CB_B");
    }
    if (img.cb_section.sc && !img.cb_section.sc->data.empty()) {
        info.bootloaders.sc = summarize(*img.cb_section.sc, "SC");
    }
    if (!img.kernel_section.cd.data.empty()) {
        info.bootloaders.cd = summarize(img.kernel_section.cd, "CD");
    }
    if (img.kernel_section.ce && !img.kernel_section.ce->data.empty()) {
        info.bootloaders.ce = summarize(*img.kernel_section.ce, "CE");
    }
    if (img.system_update_0.cf && !img.system_update_0.cf->data.empty()) {
        info.bootloaders.cf_0 = summarize(*img.system_update_0.cf, "CF_0");
    }
    if (img.system_update_0.cg && !img.system_update_0.cg->data.empty()) {
        info.bootloaders.cg_0 = summarize(*img.system_update_0.cg, "CG_0");
    }
    if (img.system_update_1.cf && !img.system_update_1.cf->data.empty()) {
        info.bootloaders.cf_1 = summarize(*img.system_update_1.cf, "CF_1");
    }
    if (img.system_update_1.cg && !img.system_update_1.cg->data.empty()) {
        info.bootloaders.cg_1 = summarize(*img.system_update_1.cg, "CG_1");
    }

    if (img.smc) {
        info.smc.present = true;
        info.smc.version = img.smc->version;
        info.smc.motherboard_name = std::string(smc_motherboard_name(img.smc->motherboard));
        info.smc.type_name = std::string(smc_type_name(img.smc->variant));
        info.smc.size = static_cast<uint32_t>(img.smc->data.size());
        info.smc.decrypted = !img.smc->encrypted;
    }

    return info;
}

std::optional<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image) {
    return ExtractSomeInfo(std::span<const uint8_t>(nand_image));
}

std::optional<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                             std::span<const uint8_t> cpu_key) {
    if (cpu_key.size() != 16) {
        Log::Error("Cannot extract metadata: CPU key must be 16 bytes (got {})", cpu_key.size());
        return std::nullopt;
    }
    if (nand_image.empty()) {
        Log::Error("Cannot extract metadata: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse donor NAND image structure");
        return std::nullopt;
    }

    auto& img = *img_opt;
    if (!img.keyvault.has_value()) {
        Log::Error("Donor NAND image does not contain a valid keyvault");
        return std::nullopt;
    }

    if (!img.decrypt_all(cpu_key)) {
        Log::Error("Failed to decrypt donor NAND image components during metadata extraction");
        return std::nullopt;
    }

    auto& kv = *img.keyvault;
    if (kv.encrypted) {
        Log::Error("The donor's keyvault does not open under the CPU key");
        return std::nullopt;
    }
    InputMetadata meta{};
    meta.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
    meta.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
    meta.keyvault = kv.serialize();

    uint8_t cb_ldv = 0;
    uint8_t pairing_data[3] = {};
    uint8_t console_type = 0;
    uint8_t console_sequence = 0;
    uint16_t console_sequence_allow = 0;

    auto& cb_a = img.cb_section.cb_or_A;
    if (!cb_a.data.empty()) {
        if (cb_a.perbox.has_value()) {
            cb_ldv = cb_a.perbox->lockdown_value;
            std::memcpy(pairing_data, cb_a.perbox->pairing_data, 3);
        }

        console_type = cb_a.header.console_seq_allow.console_type;
        console_sequence = cb_a.header.console_seq_allow.console_sequence;
        console_sequence_allow = cb_a.header.console_seq_allow.console_sequence_allow;
    }

    // CB_B, when present, overrides CB_A's LDV/pairing data - independent of
    // whether CB_A itself parsed, matching ExtractAll()/ExtractAllInfo().
    if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
        auto& cb_b = *img.cb_section.cb_B;
        if (cb_b.perbox.has_value()) {
            cb_ldv = cb_b.perbox->lockdown_value;
            // Build metadata must preserve the per-box byte at +0x23. The value at
            // +0x3B1 is used for display by ExtractAllInfo, not written into per-box data.
            std::memcpy(pairing_data, cb_b.perbox->pairing_data, 3);
        }
    }

    meta.cb_ldv = cb_ldv;
    std::memcpy(meta.pairing_data.data(), pairing_data, 3);
    meta.console_type = console_type;
    meta.console_sequence = console_sequence;
    meta.console_sequence_allow = console_sequence_allow;

    extract_cf_metadata(img, meta);
    meta.donor_nonces = collect_donor_nonces(img);
    extract_settings_blocks(img, meta);

    Log::Debug("Extracted metadata: CB LDV={}, CF LDV={}, ConsoleType=0x{:02X}, Sequence=0x{:02X}",
               meta.cb_ldv, meta.cf_ldv ? std::to_string(*meta.cf_ldv) : "none", meta.console_type,
               meta.console_sequence);

    return meta;
}

std::optional<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                             const std::vector<uint8_t>& cpu_key) {
    return ExtractMetadata(std::span<const uint8_t>(nand_image), std::span<const uint8_t>(cpu_key));
}

std::optional<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                          std::span<const uint8_t> cpu_key) {
    if (cpu_key.size() != 16) {
        Log::Error("Cannot extract NAND info: CPU key must be 16 bytes (got {})", cpu_key.size());
        return std::nullopt;
    }
    if (nand_image.empty()) {
        Log::Error("Cannot extract NAND info: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse donor NAND image structure");
        return std::nullopt;
    }

    auto& img = *img_opt;

    if (!img.decrypt_all(cpu_key)) {
        Log::Error("Failed to decrypt donor NAND image components with provided CPU key");
        return std::nullopt;
    }

    AllNandInfo info{};
    info.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
    info.block_type = image_type_from_driver(img.flash_driver.driver_mode());

    info.header_magic = img.header.magic;
    info.header_version = img.header.version;
    info.header_flags = img.header.flags;
    info.header_size = img.header.size;
    info.copyright = std::string(
        reinterpret_cast<const char*>(img.header.copyright),
        strnlen(reinterpret_cast<const char*>(img.header.copyright), sizeof(img.header.copyright)));

    if (!img.cb_section.cb_or_A.data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CB_A";
        entry.version = img.cb_section.cb_or_A.header.header.version;
        entry.size = img.cb_section.cb_or_A.header.header.size;
        entry.flags = img.cb_section.cb_or_A.header.header.flags;
        entry.entrypoint = img.cb_section.cb_or_A.header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.cb_section.cb_or_A.is_decrypted();
        if (img.cb_section.cb_or_A.perbox.has_value()) {
            entry.ldv = img.cb_section.cb_or_A.perbox->lockdown_value;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.cb_section.cb_or_A.perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cb_ldv = img.cb_section.cb_or_A.perbox->lockdown_value;
            info.bootloaders.cb_pairing_data = pd;
        }
        info.bootloaders.cb_a = entry;
    }

    if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CB_B";
        entry.version = img.cb_section.cb_B->header.header.version;
        entry.size = img.cb_section.cb_B->header.header.size;
        entry.flags = img.cb_section.cb_B->header.header.flags;
        entry.entrypoint = img.cb_section.cb_B->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.cb_section.cb_B->is_decrypted();
        if (img.cb_section.cb_B->perbox.has_value()) {
            uint8_t ldv = img.cb_section.cb_B->perbox->lockdown_value;
            if (img.cb_section.cb_B->data.size() > 0x3B1 - sizeof(generic_header) &&
                img.cb_section.cb_B->data[0x3B1 - sizeof(generic_header)] <= 16) {
                ldv = img.cb_section.cb_B->data[0x3B1 - sizeof(generic_header)];
            }
            entry.ldv = ldv;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.cb_section.cb_B->perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cb_ldv = ldv;
            info.bootloaders.cb_pairing_data = pd;
        }
        info.bootloaders.cb_b = entry;
    }

    if (img.cb_section.cb_x.has_value() && !img.cb_section.cb_x->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CB_X";
        entry.version = img.cb_section.cb_x->header.header.version;
        entry.size = img.cb_section.cb_x->header.header.size;
        entry.flags = img.cb_section.cb_x->header.header.flags;
        entry.entrypoint = img.cb_section.cb_x->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.cb_section.cb_x->is_decrypted();
        info.bootloaders.cb_x = entry;
    }

    if (img.cb_section.sc.has_value() && !img.cb_section.sc->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "SC";
        entry.version = img.cb_section.sc->header.header.version;
        entry.size = img.cb_section.sc->header.header.size;
        entry.flags = img.cb_section.sc->header.header.flags;
        entry.entrypoint = img.cb_section.sc->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = true;
        info.bootloaders.sc = entry;
    }

    if (!img.kernel_section.cd.data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CD";
        entry.version = img.kernel_section.cd.header.header.version;
        entry.size = img.kernel_section.cd.header.header.size;
        entry.flags = img.kernel_section.cd.header.header.flags;
        entry.entrypoint = img.kernel_section.cd.header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.kernel_section.cd.is_decrypted();
        info.bootloaders.cd = entry;
    }

    if (img.kernel_section.ce.has_value() && !img.kernel_section.ce->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CE";
        entry.version = img.kernel_section.ce->header.header.version;
        entry.size = img.kernel_section.ce->header.header.size;
        entry.flags = img.kernel_section.ce->header.header.flags;
        entry.entrypoint = img.kernel_section.ce->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.kernel_section.ce->is_decrypted();
        info.bootloaders.ce = entry;
    }

    if (img.system_update_0.cf.has_value() && !img.system_update_0.cf->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CF_0";
        entry.version = img.system_update_0.cf->header.header.version;
        entry.size = img.system_update_0.cf->header.header.size;
        entry.flags = img.system_update_0.cf->header.header.flags;
        entry.entrypoint = img.system_update_0.cf->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_0.cf->is_decrypted();
        if (img.system_update_0.cf->perbox.has_value()) {
            entry.ldv = img.system_update_0.cf->perbox->lockdown_value;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.system_update_0.cf->perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cf0_ldv = img.system_update_0.cf->perbox->lockdown_value;
            info.bootloaders.cf0_pairing_data = pd;
        }
        info.bootloaders.cf_0 = entry;
    }

    if (img.system_update_0.cg.has_value() && !img.system_update_0.cg->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CG_0";
        entry.version = img.system_update_0.cg->header.header.version;
        entry.size = img.system_update_0.cg->header.header.size;
        entry.flags = img.system_update_0.cg->header.header.flags;
        entry.entrypoint = img.system_update_0.cg->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_0.cg->is_decrypted();
        info.bootloaders.cg_0 = entry;
    }

    if (img.system_update_1.cf.has_value() && !img.system_update_1.cf->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CF_1";
        entry.version = img.system_update_1.cf->header.header.version;
        entry.size = img.system_update_1.cf->header.header.size;
        entry.flags = img.system_update_1.cf->header.header.flags;
        entry.entrypoint = img.system_update_1.cf->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_1.cf->is_decrypted();
        if (img.system_update_1.cf->perbox.has_value()) {
            entry.ldv = img.system_update_1.cf->perbox->lockdown_value;
            std::array<uint8_t, 3> pd{};
            std::memcpy(pd.data(), img.system_update_1.cf->perbox->pairing_data, 3);
            entry.pairing_data = pd;
            info.bootloaders.cf1_ldv = img.system_update_1.cf->perbox->lockdown_value;
            info.bootloaders.cf1_pairing_data = pd;
        }
        info.bootloaders.cf_1 = entry;
    }

    if (img.system_update_1.cg.has_value() && !img.system_update_1.cg->data.empty()) {
        BootloaderEntryInfo entry{};
        entry.name = "CG_1";
        entry.version = img.system_update_1.cg->header.header.version;
        entry.size = img.system_update_1.cg->header.header.size;
        entry.flags = img.system_update_1.cg->header.header.flags;
        entry.entrypoint = img.system_update_1.cg->header.header.entrypoint;
        entry.present = true;
        entry.decrypted = img.system_update_1.cg->is_decrypted();
        info.bootloaders.cg_1 = entry;
    }

    if (img.smc.has_value()) {
        info.smc.present = true;
        info.smc.version = img.smc->version;
        info.smc.motherboard_name = std::string(smc_motherboard_name(img.smc->motherboard));
        info.smc.type_name = std::string(smc_type_name(img.smc->variant));
        info.smc.size = static_cast<uint32_t>(img.smc->data.size());
        info.smc.decrypted = !img.smc->encrypted;
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
        auto& kv = *img.keyvault;
        info.keyvault.present = true;
        info.keyvault.decrypted = !kv.encrypted;
        info.raw_keyvault = kv.serialize();

        info.keyvault.serial_number = std::string(
            kv.data.sz14ConsoleSerialNumber,
            strnlen(kv.data.sz14ConsoleSerialNumber, sizeof(kv.data.sz14ConsoleSerialNumber)));
        info.keyvault.dvd_key = Utils::bytes_to_hex(kv.data.b1ADvdKey);
        info.keyvault.console_id_raw = Utils::bytes_to_hex(kv.data.b36ConsoleCertificate.ConsoleId);

        uint64_t cid_val =
            (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[0]) << 28) |
            (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[1]) << 20) |
            (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[2]) << 12) |
            (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[3]) << 4) |
            (static_cast<uint64_t>(kv.data.b36ConsoleCertificate.ConsoleId[4]) >> 4);
        uint8_t last_digit = kv.data.b36ConsoleCertificate.ConsoleId[4] & 0x0F;
        char cid_buf[32];
        std::snprintf(cid_buf, sizeof(cid_buf), "%011llu%u",
                      static_cast<unsigned long long>(cid_val), last_digit);
        info.keyvault.console_id_friendly = cid_buf;

        if (kv.raw_data.size() >= 0xCAD) {
            info.keyvault.osig =
                std::string(reinterpret_cast<const char*>(kv.raw_data.data() + 0xC92),
                            strnlen(reinterpret_cast<const char*>(kv.raw_data.data() + 0xC92), 28));
        }
        info.keyvault.mfr_date =
            std::string(kv.data.b36ConsoleCertificate.ManufacturingDate,
                        strnlen(kv.data.b36ConsoleCertificate.ManufacturingDate,
                                sizeof(kv.data.b36ConsoleCertificate.ManufacturingDate)));

        info.keyvault.region_raw = bswap16(kv.data.w16GameRegion);
        switch (info.keyvault.region_raw) {
            case 0x00FF:
                info.keyvault.region_name = "NTSC/US";
                break;
            case 0x01FE:
                info.keyvault.region_name = "NTSC/JAP";
                break;
            case 0x01FF:
                info.keyvault.region_name = "NTSC/JAP";
                break;
            case 0x02FE:
                info.keyvault.region_name = "PAL/EU";
                break;
            case 0x02FF:
                info.keyvault.region_name = "PAL/AUS";
                break;
            case 0x01FC:
                info.keyvault.region_name = "NTSC/KOR";
                break;
            case 0x01FA:
                info.keyvault.region_name = "NTSC/HK";
                break;
            case 0x0101:
                info.keyvault.region_name = "NTSC/CHINA";
                break;
            case 0xFFFF:
                info.keyvault.region_name = "Devkit";
                break;
            default:
                info.keyvault.region_name = "Unknown";
                break;
        }

        bool is_type1 = true;
        for (size_t i = 0; i < 8; ++i) {
            uint8_t b =
                kv.data.b39SpecialKeyVaultSignature[sizeof(kv.data.b39SpecialKeyVaultSignature) -
                                                    8 + i];
            if (b != 0x00 && b != 0xFF) {
                is_type1 = false;
                break;
            }
        }
        info.keyvault.kv_type = is_type1 ? 1 : 2;
        // xeBuild's test, on the big-endian word: the build reads the same flag.
        info.keyvault.fcrt_required =
            fcrt_requirement(*info.raw_keyvault) != FcrtRequirement::NotRequired;
    }

    return info;
}

std::optional<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                          const std::vector<uint8_t>& cpu_key) {
    return ExtractAllInfo(std::span<const uint8_t>(nand_image), std::span<const uint8_t>(cpu_key));
}

std::optional<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                std::span<const uint8_t> cpu_key) {
    if (cpu_key.size() != 16) {
        Log::Error("Cannot extract NAND: CPU key must be 16 bytes (got {})", cpu_key.size());
        return std::nullopt;
    }
    if (nand_image.empty()) {
        Log::Error("Cannot extract NAND: NAND image is empty");
        return std::nullopt;
    }

    auto img_opt = FlashImage::read(std::vector<uint8_t>(nand_image.begin(), nand_image.end()));
    if (!img_opt || !img_opt->parse()) {
        Log::Error("Failed to parse donor NAND image structure");
        return std::nullopt;
    }

    auto& img = *img_opt;

    if (!img.decrypt_all(cpu_key)) {
        Log::Error("Failed to decrypt donor NAND image components with provided CPU key");
        return std::nullopt;
    }

    Input out{};
    if (img.build_type == BuildType::Devkit) {
        out.build_type = BuildType::Devkit;
    }
    if (img.payloads.patchset && img.build_type) {
        out.build_type = *img.build_type;
        out.patches = InputPatches{};
        out.patches->automatic =
            InputPatchFile{"extracted", BinaryParser::SerializePatchSet(*img.payloads.patchset)};
    }
    out.metadata.cpu_key = std::vector<uint8_t>(cpu_key.begin(), cpu_key.end());
    out.metadata.nand_image = std::vector<uint8_t>(nand_image.begin(), nand_image.end());
    switch (img.flash_driver.driver_mode()) {
        case Driver::DriverMode::Small:
            out.image_type = ImageType::SmallBlock;
            break;
        case Driver::DriverMode::NewSmall:
            out.image_type = ImageType::NewSmallBlock;
            break;
        case Driver::DriverMode::Big:
            out.image_type = ImageType::BigBlock;
            break;
        case Driver::DriverMode::Emmc:
            out.image_type = ImageType::Emmc;
            break;
    }

    uint8_t cb_ldv = 0;
    uint8_t pairing_data[3] = {0};
    uint8_t console_type = 0;
    uint8_t console_sequence = 0;
    uint16_t console_sequence_allow = 0;

    if (!img.cb_section.cb_or_A.data.empty()) {
        out.bootloaders.cb_or_a = img.cb_section.cb_or_A.serialize();
        console_type = img.cb_section.cb_or_A.header.console_seq_allow.console_type;
        console_sequence = img.cb_section.cb_or_A.header.console_seq_allow.console_sequence;
        console_sequence_allow =
            img.cb_section.cb_or_A.header.console_seq_allow.console_sequence_allow;
        if (img.cb_section.cb_or_A.perbox.has_value()) {
            cb_ldv = img.cb_section.cb_or_A.perbox->lockdown_value;
            std::memcpy(pairing_data, img.cb_section.cb_or_A.perbox->pairing_data, 3);
        }
    }

    if (img.cb_section.cb_B.has_value() && !img.cb_section.cb_B->data.empty()) {
        out.bootloaders.cb_b = img.cb_section.cb_B->serialize();
        if (img.cb_section.cb_B->perbox.has_value()) {
            cb_ldv = img.cb_section.cb_B->perbox->lockdown_value;
            std::memcpy(pairing_data, img.cb_section.cb_B->perbox->pairing_data, 3);
        }
    }

    if (img.cb_section.cb_x.has_value() && !img.cb_section.cb_x->data.empty()) {
        out.bootloaders.cb_x = img.cb_section.cb_x->serialize();
    }

    if (img.cb_section.sc.has_value() && !img.cb_section.sc->data.empty()) {
        out.bootloaders.sc = img.cb_section.sc->serialize();
    }

    if (!img.kernel_section.cd.data.empty()) {
        out.bootloaders.cd = img.kernel_section.cd.serialize();
    }

    if (img.kernel_section.ce.has_value() && !img.kernel_section.ce->data.empty()) {
        out.bootloaders.ce = img.kernel_section.ce->serialize();
    }

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

    out.metadata.cb_ldv = cb_ldv;
    std::memcpy(out.metadata.pairing_data.data(), pairing_data, 3);
    extract_cf_metadata(img, out.metadata);
    out.metadata.donor_nonces = collect_donor_nonces(img);
    extract_settings_blocks(img, out.metadata);
    out.metadata.console_type = console_type;
    out.metadata.console_sequence = console_sequence;
    out.metadata.console_sequence_allow = console_sequence_allow;

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
            if (file_data.has_value()) {
                if (is_cpu_keyed_secfile(filename) && !crypt_secfile(cpu_key, *file_data)) {
                    Log::Error("Failed to decrypt secure FlashFS file '{}'", filename);
                    return std::nullopt;
                }
                if (is_console_secured_file(filename)) {
                    out.metadata.console_secured_files.emplace_back(filename, *file_data);
                }
                files.emplace_back(filename, std::move(*file_data));
            }
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

std::optional<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                const std::vector<uint8_t>& cpu_key) {
    return ExtractAll(std::span<const uint8_t>(nand_image), std::span<const uint8_t>(cpu_key));
}
