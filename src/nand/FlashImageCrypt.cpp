#include "Wire.hpp"
#include "nand/FlashImage.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/XeLL.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace gxbuild3::nand {

    using namespace detail;

    namespace {

        // How many CG tails (sysupdate.xexpN) open the directory.
        size_t leading_cg_tails(const FlashFileSystem& filesystem) {
            const auto& entries = filesystem.entries();
            const auto first_other =
                std::find_if(entries.begin(), entries.end(), [](const FlashFileSystemEntry& entry) {
                    const std::string_view name(entry.filename,
                                                strnlen(entry.filename, kMaxFilenameLength));
                    return !name.starts_with("sysupdate.xexp");
                });
            return static_cast<size_t>(first_other - entries.begin());
        }

        // Opens CB_A, CB_X, CB_B and SC in that order. CB_X's plaintext CB_B takes its key slot
        // as the handoff key before the CB_B check, so that CB_B is never opened again.
        [[nodiscard]] Result<void> open_cb_chain(CbSection& cb_section,
                                                 std::span<const uint8_t> cpu_key) {
            // Use the parser's full plaintext check, not is_decrypted()'s legacy
            // single-byte hint: encrypted CBs can contain that byte by chance.
            if (!cb_section.cb_or_A.data.empty() && !cb_section.cb_or_A.decrypted) {
                if (auto opened = cb_section.cb_or_A.decrypt(key_1bl); !opened) {
                    return with_context(std::move(opened), "decrypting CB_A");
                }
            }

            if (cb_section.cb_x && !cb_section.cb_x->data.empty() && !cb_section.cb_x->decrypted) {
                if (!cb_section.cb_or_A.derived_key) {
                    return fail(ErrorCode::Malformed,
                                "Cannot decrypt CB_X: CB_A derived key is missing");
                }
                const std::array<uint8_t, 16> zero_cpu_key{};
                auto opened =
                    (cb_section.cb_or_A.header.header.flags & 0x1000) != 0
                        ? cb_section.cb_x->decrypt_v2(cb_section.cb_or_A.header,
                                                      cb_section.cb_or_A.derived_key->data(),
                                                      zero_cpu_key.data())
                        : cb_section.cb_x->decrypt_v1(cb_section.cb_or_A.derived_key->data(),
                                                      zero_cpu_key.data());
                if (!opened) {
                    return with_context(std::move(opened), "decrypting CB_X");
                }
            }

            // CB_X loads the real CB_B as plaintext. Its key slot is already the
            // handoff key (as written by RGH2to3), not a nonce to derive again.
            if (cb_section.cb_x && cb_section.cb_B && cb_section.cb_B->data.size() >= 16) {
                cb_section.cb_B->decrypted = true;
                cb_section.cb_B->populate_metadata();
                std::array<uint8_t, 16> key{};
                std::copy_n(cb_section.cb_B->data.begin(), key.size(), key.begin());
                cb_section.cb_B->derived_key = key;
            }

            if (cb_section.cb_B.has_value() && !cb_section.cb_B->data.empty() &&
                !cb_section.cb_B->decrypted) {
                if (!cb_section.cb_or_A.derived_key.has_value()) {
                    return fail(ErrorCode::Malformed,
                                "Cannot decrypt CB_B: CB_A derived key is missing");
                }
                if (auto opened = cb_section.cb_B->decrypt_cb_b(
                        cb_section.cb_or_A.header, cb_section.cb_or_A.derived_key->data(),
                        cpu_key.data());
                    !opened) {
                    return with_context(std::move(opened), "decrypting CB_B");
                }
            }

            // SC is keyed from sixteen zero bytes, not from its parent. One with a zero nonce
            // is taken as plaintext.
            if (cb_section.sc.has_value() && !cb_section.sc->data.empty() &&
                !cb_section.sc->is_decrypted() &&
                std::any_of(std::begin(cb_section.sc->header.key),
                            std::end(cb_section.sc->header.key),
                            [](uint8_t byte) { return byte != 0; })) {
                if (auto opened = cb_section.sc->decrypt(BootloaderSc::kZeroSecret); !opened) {
                    return with_context(std::move(opened), "decrypting SC");
                }
            }
            return {};
        }

        // Opens CD from its parent's derived key (SC on a devkit chain, else CB_B, else CB_A),
        // then CE from CD.
        [[nodiscard]] Result<void> open_kernel(KernelSection& kernel_section,
                                               const CbSection& cb_section, bool devkit,
                                               std::span<const uint8_t> cpu_key) {
            if (!kernel_section.cd.data.empty() && !kernel_section.cd.is_decrypted()) {
                Result<void> opened{};
                if (devkit) {
                    if (!cb_section.sc || !cb_section.sc->derived_key) {
                        return fail(ErrorCode::Malformed,
                                    "Cannot decrypt SD: the SC key is missing");
                    }
                    opened = kernel_section.cd.decrypt(cb_section.sc->derived_key->data());
                } else if (cb_section.cb_B.has_value() &&
                           cb_section.cb_B->derived_key.has_value()) {
                    opened = kernel_section.cd.decrypt(cb_section.cb_B->derived_key->data());
                } else if (cb_section.cb_or_A.derived_key.has_value()) {
                    const uint8_t* cd_cpu_key = nullptr;
                    if (cb_section.cb_or_A.requires_cpu_key_for_cd()) {
                        if (cpu_key.size() < 16) {
                            return fail(ErrorCode::InvalidArgument,
                                        "Cannot decrypt CD: single-CB chain requires a CPU key");
                        }
                        cd_cpu_key = cpu_key.data();
                    }
                    opened = kernel_section.cd.decrypt(cb_section.cb_or_A.derived_key->data(),
                                                       cd_cpu_key);
                } else {
                    return fail(ErrorCode::Malformed,
                                "Cannot decrypt CD: parent derived key is missing");
                }
                if (!opened) {
                    return with_context(std::move(opened), "decrypting CD");
                }
            }

            if (kernel_section.ce.has_value() && !kernel_section.ce->data.empty() &&
                !kernel_section.ce->is_decrypted()) {
                if (!kernel_section.cd.decrypted) {
                    return fail(ErrorCode::Malformed, "Cannot decrypt CE: CD is not decrypted");
                }
                // When CD arrived plaintext, its key slot is already the handoff
                // key. For encrypted CD, use the key derived during decryption.
                if (auto opened = kernel_section.ce->decrypt(
                        kernel_section.cd.derived_key ? kernel_section.cd.derived_key->data()
                                                      : kernel_section.cd.header.key);
                    !opened) {
                    return with_context(std::move(opened), "decrypting CE");
                }
            }
            return {};
        }

        // Opens CF0 and CF1, then CG0 and CG1 from their CF's 7BL nonce. Both CFs open before
        // either CG, so the first error and the stages left open after it stay as they were.
        [[nodiscard]] Result<void> open_update_slots(SystemUpdate& slot_0, SystemUpdate& slot_1) {
            const std::array<SystemUpdate*, 2> slots{&slot_0, &slot_1};
            for (size_t index = 0; index < slots.size(); ++index) {
                auto& cf = slots[index]->cf;
                if (cf.has_value() && !cf->is_decrypted()) {
                    if (auto opened = cf->decrypt(key_1bl); !opened) {
                        return with_context(std::move(opened),
                                            std::format("decrypting CF{}", index));
                    }
                }
            }
            for (size_t index = 0; index < slots.size(); ++index) {
                const auto& cf = slots[index]->cf;
                auto& cg = slots[index]->cg;
                if (cg.has_value() && !cg->is_decrypted()) {
                    if (!cf.has_value() || !cf->is_decrypted()) {
                        return fail(ErrorCode::Malformed,
                                    "Cannot decrypt CG{}: parent CF{} is missing or not decrypted",
                                    index, index);
                    }
                    const auto cg_key = cf->cg_key();
                    if (!cg_key) {
                        return fail(ErrorCode::Malformed,
                                    "Cannot decrypt CG{}: CF{} payload lacks a 7BL nonce at +0x330",
                                    index, index);
                    }
                    if (auto opened = cg->decrypt(cg_key->data()); !opened) {
                        return with_context(std::move(opened),
                                            std::format("decrypting CG{}", index));
                    }
                }
            }
            return {};
        }

        // Opens the SMC and, under a usable CPU key, the keyvault.
        [[nodiscard]] Result<void> open_smc_kv(std::optional<Smc>& smc,
                                               std::optional<Keyvault>& keyvault,
                                               std::span<const uint8_t> cpu_key) {
            if (smc.has_value() && smc->encrypted) {
                smc->decrypt();
            }

            // A console's keyvault does not open under the all-zero CPU key (only an image built
            // under that key carries one that does), so under it a keyvault that does not open
            // stays sealed and the build takes the console's from a kv.bin instead.
            if (keyvault.has_value() && keyvault->encrypted && !cpu_key.empty()) {
                if (is_zero_cpu_key(cpu_key)) {
                    if (auto opened = open_loose_keyvault(cpu_key, keyvault->raw_data);
                        opened && opened->form == LooseKeyvault::Form::Sealed) {
                        auto record = wire::read<XE_KEYVAULT_DATA>(opened->plain, 0, "keyvault");
                        if (!record) {
                            return std::unexpected(std::move(record.error())
                                                       .add_context("reading the keyvault opened "
                                                                    "under the all-zero CPU key"));
                        }
                        keyvault->raw_data = std::move(opened->plain);
                        keyvault->data = *record;
                        keyvault->encrypted = false;
                    } else {
                        Log::Warn("The keyvault does not open under the all-zero CPU key; it is "
                                  "left sealed");
                    }
                } else if (auto decrypted = keyvault->decrypt(cpu_key); !decrypted) {
                    return with_context(std::move(decrypted),
                                        "decrypting the Keyvault with the provided CPU key");
                }
            }
            return {};
        }

    } // namespace

    Result<void> FlashImage::decrypt_all(std::span<const uint8_t> cpu_key) {
        if (auto opened = open_cb_chain(cb_section, cpu_key); !opened) {
            return opened;
        }
        if (auto opened = open_kernel(kernel_section, cb_section, devkit_chain(), cpu_key);
            !opened) {
            return opened;
        }
        if (auto opened = open_update_slots(system_update_0, system_update_1); !opened) {
            return opened;
        }
        return open_smc_kv(smc, keyvault, cpu_key);
    }

    namespace {

        // What encrypt_all seals and binds for the type being sealed. The flags read the sealed
        // type, never the member build type.
        struct SealPolicy {
            bool plaintext_cb_b;
            bool devkit;
            bool cd_requires_cpu_key;
            bool bind_cb_b;
            bool bind_single_cb;
            bool bind_extra_cb;
        };

        // Decides the seal policy, refusing in this order: a Glitch3 chain without CB_X and a
        // plaintext CB_B, a devkit chain without an SC, a plaintext CD a single CB keys from an
        // absent CPU key, then an SMC binding without a CPU key and an aligned SMC.
        [[nodiscard]] Result<SealPolicy> seal_policy(const FlashImage& image,
                                                     std::span<const uint8_t> cpu_key,
                                                     BuildType seal_type) {
            const auto& cb_section = image.cb_section;
            const auto& kernel_section = image.kernel_section;
            const auto& smc = image.smc;
            const auto& payloads = image.payloads;

            const bool plaintext_cb_b = seal_type == BuildType::Glitch3;
            if (plaintext_cb_b && (!cb_section.cb_x || cb_section.cb_x->data.empty() ||
                                   !cb_section.cb_B || !cb_section.cb_B->decrypted)) {
                return fail(ErrorCode::InvalidArgument,
                            "Glitch3 requires CB_X and a plaintext CB_B");
            }
            const bool devkit = image.devkit_chain();
            if (devkit && (!cb_section.sc || cb_section.sc->data.empty())) {
                return fail(ErrorCode::InvalidArgument, "A devkit chain needs an SC to key its SD");
            }
            const bool cd_requires_cpu_key = !devkit && !cb_section.cb_B.has_value() &&
                                             cb_section.cb_or_A.requires_cpu_key_for_cd();

            if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted() &&
                cd_requires_cpu_key && cpu_key.size() < 16) {
                return fail(ErrorCode::InvalidArgument,
                            "Cannot encrypt CD: single-CB chain requires a CPU key");
            }

            // CB_B binds the final encrypted SMC on every split chain, whatever the image
            // type (xerunner build.py `chain`); a retail single CB binds it as well.
            // Glitch3 emits CB_B plaintext, so it binds nothing here.
            const bool bind_cb_b = cb_section.cb_B.has_value() && !plaintext_cb_b;
            // A devkit SB carries the console's block bound to the SMC, as a retail single CB
            // does (xeBuild 1.21 devkit); a devgl SB is zero-paired and binds nothing.
            const bool bind_single_cb =
                (seal_type == BuildType::Retail && cd_requires_cpu_key) ||
                (devkit && seal_type != BuildType::Devgl && cb_section.cb_or_A.decrypted);
            // A JTAG image's second CB carries the console's block itself, bound to the SMC
            // under its own 1BL-derived key (xerunner build.py `_wears_console`).
            const bool bind_extra_cb = payloads.extra_cb.has_value() &&
                                       !payloads.extra_cb->data.empty() &&
                                       payloads.extra_cb->decrypted;
            if (bind_cb_b || bind_single_cb || bind_extra_cb) {
                if (cpu_key.size() != 16 || !smc || smc->data.empty() ||
                    smc->data.size() % 4 != 0) {
                    return fail(ErrorCode::InvalidArgument,
                                "CB authentication requires a CPU key and an aligned SMC");
                }
            }
            return SealPolicy{
                .plaintext_cb_b = plaintext_cb_b,
                .devkit = devkit,
                .cd_requires_cpu_key = cd_requires_cpu_key,
                .bind_cb_b = bind_cb_b,
                .bind_single_cb = bind_single_cb,
                .bind_extra_cb = bind_extra_cb,
            };
        }

        // Seals CB_A (bound to the SMC when the policy says so), then a Glitch3 CB_X, then
        // gives a plaintext CB_B its handoff key, then seals a split chain's CB_B under CB_A's
        // regime. The SMC is already sealed whenever a CB binds it.
        [[nodiscard]] Result<void> seal_cb_chain(CbSection& cb_section, const SealPolicy& policy,
                                                 std::span<const uint8_t> cpu_key,
                                                 const std::optional<Smc>& smc) {
            if (!cb_section.cb_or_A.data.empty() && cb_section.cb_or_A.decrypted) {
                auto sealed = policy.bind_single_cb
                                  ? cb_section.cb_or_A.encrypt_retail(key_1bl, cpu_key, smc->data)
                                  : cb_section.cb_or_A.encrypt(key_1bl);
                if (!sealed) {
                    return with_context(std::move(sealed), "encrypting CB_A");
                }
            }

            if (policy.plaintext_cb_b && cb_section.cb_x->decrypted) {
                if (!cb_section.cb_or_A.derived_key) {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt CB_X: CB_A derived key is missing");
                }
                const std::array<uint8_t, 16> zero_cpu_key{};
                auto sealed =
                    (cb_section.cb_or_A.header.header.flags & 0x1000) != 0
                        ? cb_section.cb_x->encrypt_v2(cb_section.cb_or_A.header,
                                                      cb_section.cb_or_A.derived_key->data(),
                                                      zero_cpu_key.data())
                        : cb_section.cb_x->encrypt_v1(cb_section.cb_or_A.derived_key->data(),
                                                      zero_cpu_key.data());
                if (!sealed) {
                    return with_context(std::move(sealed), "encrypting CB_X");
                }
            }

            if (policy.plaintext_cb_b) {
                if (cb_section.cb_B->data.size() < 16) {
                    return fail(ErrorCode::Malformed, "Plaintext CB_B has no handoff key");
                }
                if (cb_section.cb_B->derived_key) {
                    // An encrypted replacement CB_B may have been decrypted for metadata.
                    // Preserve its derived handoff key when emitting it in plaintext.
                    std::copy(cb_section.cb_B->derived_key->begin(),
                              cb_section.cb_B->derived_key->end(), cb_section.cb_B->data.begin());
                } else {
                    // Plaintext CB_B already carries its runtime key, as in RGH2to3.
                    // CD is encrypted with this key, not the CB_X key or a new HMAC.
                    cb_section.cb_B->derived_key.emplace();
                    std::copy_n(cb_section.cb_B->data.begin(), 16,
                                cb_section.cb_B->derived_key->begin());
                }
            }

            if (!policy.plaintext_cb_b && cb_section.cb_B.has_value() &&
                !cb_section.cb_B->data.empty() && cb_section.cb_B->decrypted) {
                if (!cb_section.cb_or_A.derived_key.has_value()) {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt CB_B: CB_A derived key is missing");
                }
                // Computes the digest, or zeros it for a manufacturing chain or a zero
                // CPU key, then seals under CB_A's regime.
                if (auto sealed = cb_section.cb_B->encrypt_retail(
                        cb_section.cb_or_A.derived_key->data(), cpu_key, smc->data,
                        &cb_section.cb_or_A.header);
                    !sealed) {
                    return with_context(std::move(sealed), "encrypting CB_B");
                }
            }
            return {};
        }

        // A devkit SC is sealed under the zero secret; its key seals SD. A sealed SC is
        // opened first, so its key is known.
        [[nodiscard]] Result<void> seal_devkit_sc(BootloaderSc& sc) {
            if (!sc.decrypted) {
                if (auto opened = sc.decrypt(BootloaderSc::kZeroSecret); !opened) {
                    return with_context(std::move(opened), "opening the devkit SC");
                }
            }
            if (auto sealed = sc.encrypt(BootloaderSc::kZeroSecret); !sealed) {
                return with_context(std::move(sealed), "encrypting SC");
            }
            return {};
        }

        // Seals CD under its parent's key (the devkit SC, CB_B or CB_A, with the CPU key when a
        // single CB requires it), then CE under CD's.
        [[nodiscard]] Result<void> seal_kernel(KernelSection& kernel_section,
                                               const CbSection& cb_section,
                                               const SealPolicy& policy,
                                               std::span<const uint8_t> cpu_key) {
            // xeBuild's CB_B patches keep CD decryption enabled. Plaintext CD is
            // specific to separate XeLL ECC payloads, not these dashboard builds.
            if (!kernel_section.cd.data.empty() && kernel_section.cd.is_decrypted()) {
                Result<void> sealed{};
                if (policy.devkit) {
                    sealed = kernel_section.cd.encrypt(cb_section.sc->derived_key->data());
                } else if (cb_section.cb_B.has_value()) {
                    if (!cb_section.cb_B->derived_key.has_value()) {
                        return fail(ErrorCode::Malformed,
                                    "Cannot encrypt CD: CB_B derived key is missing");
                    }
                    sealed = kernel_section.cd.encrypt(cb_section.cb_B->derived_key->data());
                } else if (cb_section.cb_or_A.derived_key.has_value()) {
                    sealed = kernel_section.cd.encrypt(cb_section.cb_or_A.derived_key->data(),
                                                       policy.cd_requires_cpu_key ? cpu_key.data()
                                                                                  : nullptr);
                } else {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt CD: parent derived key is missing");
                }
                if (!sealed) {
                    return with_context(std::move(sealed), "encrypting CD");
                }
            }

            if (kernel_section.ce.has_value() && !kernel_section.ce->data.empty() &&
                kernel_section.ce->is_decrypted()) {
                if (!kernel_section.cd.derived_key) {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt CE: CD derived key is missing");
                }
                if (auto sealed = kernel_section.ce->encrypt(kernel_section.cd.derived_key->data());
                    !sealed) {
                    return with_context(std::move(sealed), "encrypting CE");
                }
            }
            return {};
        }

        // The JTAG second chain: its CB sealed under HMAC(1BL key, nonce) with the
        // console's block bound to the SMC, and its CD under HMAC(CB key, nonce) with no
        // CPU-key pass, which only a retail single-CB chain takes.
        [[nodiscard]] Result<void> seal_jtag_extra(Payloads& payloads, const SealPolicy& policy,
                                                   std::span<const uint8_t> cpu_key,
                                                   const std::optional<Smc>& smc) {
            if (policy.bind_extra_cb) {
                if (auto sealed = payloads.extra_cb->encrypt_retail(key_1bl, cpu_key, smc->data);
                    !sealed) {
                    return with_context(std::move(sealed), "encrypting the JTAG second CB");
                }
            }
            if (payloads.extra_cd && !payloads.extra_cd->data.empty() &&
                payloads.extra_cd->is_decrypted()) {
                if (!payloads.extra_cb || !payloads.extra_cb->derived_key) {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt the JTAG second CD: its CB key is missing");
                }
                if (auto sealed =
                        payloads.extra_cd->encrypt(payloads.extra_cb->derived_key->data());
                    !sealed) {
                    return with_context(std::move(sealed), "encrypting the JTAG second CD");
                }
            }
            return {};
        }

        // Seals a slot's plaintext CG under its CF's key and fits the CG into the slot behind
        // its CF. A CG that fits clears the CF's continuation table and any stale tail file; a
        // longer one lays its tail in the filesystem (payload blocks and both update slots
        // reserved first, the slots where `seal_plan` puts them) and names the tail's clusters
        // in the CF's continuation table.
        [[nodiscard]] Result<void> prepare_cg_tail(FlashImage& image, SystemUpdate& slot,
                                                   std::string_view filename,
                                                   const LayoutPlan& seal_plan) {
            if (!slot.cf || !slot.cg)
                return {};
            if (slot.cg->decrypted) {
                if (auto opened = slot.cf->decrypt(key_1bl); !opened) {
                    return with_context(std::move(opened), "opening the CF for its CG key");
                }
                const auto cg_key = slot.cf->cg_key();
                if (!cg_key) {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt CG: CF payload lacks a 7BL nonce at +0x330");
                }
                if (auto sealed = slot.cg->encrypt(cg_key->data()); !sealed) {
                    return with_context(std::move(sealed), "encrypting CG");
                }
            }
            const size_t stride = seal_plan.slot_stride;
            auto& filesystem = image.filesystem;
            const auto cg = slot.cg->serialize();
            const size_t cf_size = align_16(slot.cf->serialize().size());
            if (cf_size + sizeof(cg_header) > stride) {
                return fail(ErrorCode::OutOfRange,
                            "the CF (0x{:X} bytes) leaves no room for its CG in the 0x{:X}-byte "
                            "slot",
                            cf_size, stride);
            }
            const size_t prefix = std::min(cg.size(), stride - cf_size);
            if (prefix == cg.size()) {
                if (auto opened = slot.cf->decrypt(key_1bl); !opened) {
                    return with_context(std::move(opened),
                                        "opening the CF to clear its continuation table");
                }
                if (slot.cf->data.size() >= kCfTableSize) {
                    std::fill_n(slot.cf->data.begin(), kCfTableSize, 0);
                }
                slot.cg_spill_blocks.clear();
                if (filesystem) {
                    filesystem->set_driver(&image.flash_driver);
                    if (filesystem->exists(filename)) {
                        if (auto deleted = filesystem->delete_file(filename); !deleted) {
                            return with_context(std::move(deleted), "deleting a stale CG tail");
                        }
                    }
                }
                return {};
            }
            if (!filesystem) {
                return fail(ErrorCode::Unsupported, "CG continuation requires a Flash File System");
            }
            filesystem->set_driver(&image.flash_driver);
            for (auto range : image.active_payload_block_ranges()) {
                if (auto reserved =
                        filesystem->reserve_blocks(range.start_block, range.block_count);
                    !reserved) {
                    return with_context(std::move(reserved),
                                        "reserving payload blocks for a CG tail");
                }
            }
            // plan_for_seal, not plan_layout: the slots are reserved by the type being sealed.
            const size_t base = seal_plan.update_base;
            if (const auto range =
                    image.flash_driver.block_range_for_byte_interval(base, 2 * stride)) {
                if (auto reserved =
                        filesystem->reserve_blocks(range->start_block, range->block_count);
                    !reserved) {
                    return with_context(std::move(reserved),
                                        "reserving the update slots for a CG tail");
                }
            }
            if (filesystem->exists(filename)) {
                if (auto deleted = filesystem->delete_file(filename); !deleted) {
                    return with_context(std::move(deleted), "deleting a stale CG tail");
                }
            }
            // A built image lists each CG tail first, in slot order, and lays it on the
            // filesystem's first free blocks, directly past the slots (xeBuild 1.21).
            // A parsed image keeps its other files where they are.
            auto added = image.preserve_layout
                             ? filesystem->add_file(filename, std::span(cg).subspan(prefix))
                             : filesystem->insert_file(leading_cg_tails(*filesystem), filename,
                                                       std::span(cg).subspan(prefix));
            if (!added) {
                return with_context(std::move(added), "adding a CG tail");
            }
            auto entry = filesystem->stat(filename);
            if (!entry) {
                return fail(ErrorCode::Internal, "the CG tail {} is missing after it was added",
                            filename);
            }
            auto chain = filesystem->get_chain(entry->block_number);
            const size_t needed = (cg.size() - prefix + kCgClusterSize - 1) / kCgClusterSize;
            if (chain.size() > kMaxCgClusters || chain.size() != needed) {
                return fail(ErrorCode::OutOfRange,
                            "the CG tail {} spans {} clusters; it needs {} and a CF names at most "
                            "{}",
                            filename, chain.size(), needed, kMaxCgClusters);
            }
            if (auto opened = slot.cf->decrypt(key_1bl); !opened) {
                return with_context(std::move(opened),
                                    "opening the CF to write its continuation table");
            }
            if (slot.cf->data.size() < kCfTableSize) {
                return fail(ErrorCode::Malformed,
                            "the CF payload (0x{:X} bytes) is too short for a continuation table",
                            slot.cf->data.size());
            }
            cf_continuation_table table{};
            table.count = static_cast<uint16_t>(chain.size());
            for (size_t i = 0; i < chain.size(); ++i) {
                table.clusters[i] = chain[i];
            }
            if (auto written =
                    wire::write(std::span(slot.cf->data), 0, table, "CF continuation table");
                !written) {
                return written;
            }
            slot.cg_spill_blocks = std::move(chain);
            return {};
        }

        // Writes a plaintext CF's per-box data back and, when its slot binds the console under
        // the sealed type, re-MACs it over what it now states.
        [[nodiscard]] Result<void> bind_cf(BootloaderCf& cf, size_t slot_index,
                                           std::span<const uint8_t> cpu_key, BuildType seal_type) {
            if (cf.perbox.has_value()) {
                if (auto stored = cf.serialize_perbox(); !stored)
                    return stored;
            }
            if (!cpu_key.empty() && update_slot_binds_console(seal_type, slot_index))
                return cf.calc_mac(key_1bl, cpu_key.data());
            return {};
        }

        // Binds and seals update slot `slot_index`'s CF when it is plaintext.
        [[nodiscard]] Result<void> bind_and_seal_cf(SystemUpdate& slot, size_t slot_index,
                                                    std::span<const uint8_t> cpu_key,
                                                    BuildType seal_type) {
            if (slot.cf.has_value() && slot.cf->is_decrypted()) {
                if (auto bound = bind_cf(*slot.cf, slot_index, cpu_key, seal_type); !bound) {
                    return with_context(std::move(bound), std::format("binding CF{}", slot_index));
                }
                if (auto sealed = slot.cf->encrypt(key_1bl); !sealed) {
                    return with_context(std::move(sealed),
                                        std::format("encrypting CF{}", slot_index));
                }
            }
            return {};
        }

        // Seals the SMC, if no CB binding sealed it already, and the keyvault under a CPU key.
        [[nodiscard]] Result<void> seal_smc_kv(std::optional<Smc>& smc,
                                               std::optional<Keyvault>& keyvault,
                                               std::span<const uint8_t> cpu_key) {
            if (smc.has_value() && !smc->encrypted) {
                smc->encrypt();
            }

            if (keyvault.has_value() && !keyvault->encrypted && !cpu_key.empty()) {
                if (auto encrypted = keyvault->encrypt(cpu_key); !encrypted) {
                    return with_context(std::move(encrypted),
                                        "encrypting the Keyvault with the provided CPU key");
                }
            }
            return {};
        }

    } // namespace

    Result<void> FlashImage::encrypt_all(std::span<const uint8_t> cpu_key, BuildType seal_type) {
        const auto policy = seal_policy(*this, cpu_key, seal_type);
        if (!policy) {
            return std::unexpected(policy.error());
        }
        if (policy->bind_cb_b || policy->bind_single_cb || policy->bind_extra_cb) {
            // Authentication covers the exact SMC ciphertext written to NAND.
            if (!smc->encrypted)
                smc->encrypt();
        }

        if (auto sealed = seal_cb_chain(cb_section, *policy, cpu_key, smc); !sealed) {
            return sealed;
        }
        if (policy->devkit) {
            if (auto sealed = seal_devkit_sc(*cb_section.sc); !sealed) {
                return sealed;
            }
        }
        if (auto sealed = seal_kernel(kernel_section, cb_section, *policy, cpu_key); !sealed) {
            return sealed;
        }
        if (auto sealed = seal_jtag_extra(payloads, *policy, cpu_key, smc); !sealed) {
            return sealed;
        }

        const LayoutPlan seal_plan = plan_for_seal(*this, seal_type);
        if (auto prepared = prepare_cg_tail(*this, system_update_0, "sysupdate.xexp1", seal_plan);
            !prepared) {
            return with_context(std::move(prepared), "update slot 0");
        }
        if (auto prepared = prepare_cg_tail(*this, system_update_1, "sysupdate.xexp2", seal_plan);
            !prepared) {
            return with_context(std::move(prepared), "update slot 1");
        }

        if (auto bound = bind_and_seal_cf(system_update_0, 0, cpu_key, seal_type); !bound) {
            return bound;
        }
        if (auto bound = bind_and_seal_cf(system_update_1, 1, cpu_key, seal_type); !bound) {
            return bound;
        }

        return seal_smc_kv(smc, keyvault, cpu_key);
    }

} // namespace gxbuild3::nand
