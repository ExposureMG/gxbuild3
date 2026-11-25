#include "core/Wire.hpp"
#include "nand/FlashImage.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/XeLL.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace gxbuild::nand {

    using namespace detail;

    namespace {

        bool is_zero_nonce(std::span<const uint8_t> nonce) {
            return std::all_of(nonce.begin(), nonce.end(), [](uint8_t byte) { return byte == 0; });
        }

        [[nodiscard]] Result<void> open_cb_chain(CbSection& cb_section,
                                                 std::span<const uint8_t> cpu_key) {
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

            // with cbx present, cbb is already plaintext and its first 16 bytes are the handoff key for cd
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

            if (cb_section.sc.has_value() && !cb_section.sc->data.empty() &&
                !cb_section.sc->is_decrypted() && !is_zero_nonce(cb_section.sc->header.key)) {
                if (auto opened = cb_section.sc->decrypt(BootloaderSc::kZeroSecret); !opened) {
                    return with_context(std::move(opened), "decrypting SC");
                }
            }
            return {};
        }

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
                if (auto opened = kernel_section.ce->decrypt(
                        kernel_section.cd.derived_key ? kernel_section.cd.derived_key->data()
                                                      : kernel_section.cd.header.key);
                    !opened) {
                    return with_context(std::move(opened), "decrypting CE");
                }
            }
            return {};
        }

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

        [[nodiscard]] Result<void> open_smc_kv(std::optional<Smc>& smc,
                                               std::optional<Keyvault>& keyvault,
                                               std::span<const uint8_t> cpu_key) {
            if (smc.has_value() && smc->encrypted) {
                smc->decrypt();
            }

            // with a zero cpu key, leave the kv encrypted unless it was actually sealed with all zeros
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

        struct SealPolicy {
            bool plaintext_cb_b;
            bool devkit;
            bool cd_requires_cpu_key;
            bool bind_cb_b;
            bool bind_single_cb;
            bool bind_extra_cb;
        };

        // figures out which cb stages need smc binding and whether cbb stays plaintext for glitch3
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

            const bool bind_cb_b = cb_section.cb_B.has_value() && !plaintext_cb_b;
            const bool bind_single_cb =
                (seal_type == BuildType::Retail && cd_requires_cpu_key) ||
                (devkit && seal_type != BuildType::Devgl && cb_section.cb_or_A.decrypted);
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

            // stashes the cd handoff key in the first 16 bytes of the plaintext glitch3 cbb
            if (policy.plaintext_cb_b) {
                if (cb_section.cb_B->data.size() < 16) {
                    return fail(ErrorCode::Malformed, "Plaintext CB_B has no handoff key");
                }
                if (cb_section.cb_B->derived_key) {
                    std::copy(cb_section.cb_B->derived_key->begin(),
                              cb_section.cb_B->derived_key->end(), cb_section.cb_B->data.begin());
                } else {
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
                if (auto sealed = cb_section.cb_B->encrypt_retail(
                        cb_section.cb_or_A.derived_key->data(), cpu_key, smc->data,
                        &cb_section.cb_or_A.header);
                    !sealed) {
                    return with_context(std::move(sealed), "encrypting CB_B");
                }
            }
            return {};
        }

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

        [[nodiscard]] Result<void> seal_kernel(KernelSection& kernel_section,
                                               const CbSection& cb_section,
                                               const SealPolicy& policy,
                                               std::span<const uint8_t> cpu_key) {
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
            if (payloads.extra_se && !payloads.extra_se->data.empty() &&
                payloads.extra_se->is_decrypted()) {
                if (!payloads.extra_cd || !payloads.extra_cd->derived_key) {
                    return fail(ErrorCode::Malformed,
                                "Cannot encrypt the JTAG second SE: its CD key is missing");
                }
                if (auto sealed =
                        payloads.extra_se->encrypt(payloads.extra_cd->derived_key->data());
                    !sealed) {
                    return with_context(std::move(sealed), "encrypting the JTAG second SE");
                }
            }
            return {};
        }

        // encrypts cg and spills anything that doesn't fit in the update slot into a sysupdate.xexpN file in flashfs.
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
            for (auto range : image.active_payload_block_ranges()) {
                if (auto reserved =
                        filesystem->reserve_blocks(range.start_block, range.block_count);
                    !reserved) {
                    return with_context(std::move(reserved),
                                        "reserving payload blocks for a CG tail");
                }
            }
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
        const std::array<std::pair<SystemUpdate*, std::string_view>, 2> slots{{
            {&system_update_0, "sysupdate.xexp1"},
            {&system_update_1, "sysupdate.xexp2"},
        }};
        for (size_t index = 0; index < slots.size(); ++index) {
            if (auto prepared =
                    prepare_cg_tail(*this, *slots[index].first, slots[index].second, seal_plan);
                !prepared) {
                return with_context(std::move(prepared), std::format("update slot {}", index));
            }
        }
        for (size_t index = 0; index < slots.size(); ++index) {
            if (auto bound = bind_and_seal_cf(*slots[index].first, index, cpu_key, seal_type);
                !bound) {
                return bound;
            }
        }

        return seal_smc_kv(smc, keyvault, cpu_key);
    }

    namespace {

        [[nodiscard]] Result<void> apply_cb_metadata(BootloaderCb& bootloader,
                                                     const InputMetadata& metadata,
                                                     std::string_view name) {
            if (!bootloader.perbox.has_value()) {
                if (auto parsed = bootloader.parse_perbox(); !parsed) {
                    return std::unexpected(
                        std::move(parsed.error())
                            .add_context(std::format("{} has no writable per-box metadata", name)));
                }
            }
            bootloader.perbox->lockdown_value = metadata.cb_ldv;
            std::memcpy(bootloader.perbox->pairing_data, metadata.pairing_data.data(),
                        metadata.pairing_data.size());
            if (auto serialized = bootloader.serialize_perbox(); !serialized) {
                return std::unexpected(
                    std::move(serialized.error())
                        .add_context(std::format("{} could not serialize per-box metadata", name)));
            }
            return {};
        }

        [[nodiscard]] Result<void> zero_pair_cb(BootloaderCb& bootloader, std::string_view name) {
            if (!bootloader.perbox.has_value()) {
                if (auto parsed = bootloader.parse_perbox(); !parsed) {
                    return std::unexpected(
                        std::move(parsed.error())
                            .add_context(std::format("{} has no writable per-box metadata", name)));
                }
            }
            *bootloader.perbox = cb_perbox{};
            if (auto serialized = bootloader.serialize_perbox(); !serialized) {
                return std::unexpected(
                    std::move(serialized.error())
                        .add_context(std::format("{} could not serialize per-box metadata", name)));
            }
            return {};
        }

        [[nodiscard]] Result<void> apply_cf_metadata(BootloaderCf& bootloader,
                                                     const InputMetadata& metadata,
                                                     std::optional<uint8_t> cf_ldv, bool paired,
                                                     uint8_t slot, std::string_view name) {
            if (!bootloader.perbox.has_value()) {
                return fail(ErrorCode::Malformed, "{} has no writable per-box metadata", name);
            }
            bootloader.perbox->update_slot = slot;
            if (cf_ldv) {
                bootloader.perbox->lockdown_value = *cf_ldv;
            }
            const auto pairing = paired ? metadata.cf_pairing_data.value_or(metadata.pairing_data)
                                        : std::array<uint8_t, 3>{};
            std::memcpy(bootloader.perbox->pairing_data, pairing.data(), pairing.size());
            if (auto serialized = bootloader.serialize_perbox(); !serialized) {
                return std::unexpected(
                    std::move(serialized.error())
                        .add_context(std::format("{} could not serialize per-box metadata", name)));
            }
            return {};
        }

        [[nodiscard]] Result<void> open_for_metadata(Result<void> decrypted,
                                                     std::string_view name) {
            if (!decrypted) {
                return std::unexpected(
                    std::move(decrypted.error())
                        .add_context(std::format("Could not decrypt replacement {} for metadata "
                                                 "application",
                                                 name)));
            }
            return {};
        }

        std::optional<BootloaderNonce> nonce_from(std::span<const uint8_t> bytes) {
            if (bytes.size() < std::tuple_size_v<BootloaderNonce> ||
                is_zero_nonce(bytes.first(16))) {
                return std::nullopt;
            }
            BootloaderNonce nonce{};
            std::copy_n(bytes.begin(), nonce.size(), nonce.begin());
            return nonce;
        }

        BootloaderNonce donor_or_random(const std::optional<BootloaderNonce>& donor) {
            if (donor) {
                return *donor;
            }
            BootloaderNonce nonce{};
            do {
                utils::fill_random(nonce);
            } while (is_zero_nonce(nonce));
            return nonce;
        }

    } // namespace

    // writes or zeroes per-box ldv and pairing data on cb and cf stages depending on the build type
    Result<void> FlashImage::apply_bootloader_metadata(const InputMetadata& metadata,
                                                       BuildType target_type) {
        const bool zero_key = is_zero_cpu_key(metadata.cpu_key);
        const bool zero_paired_cb_b = zero_key && cb_section.cb_B.has_value();
        const bool single_cb_glitch =
            target_type == BuildType::Glitch && !cb_section.cb_B.has_value();
        const bool paired = !single_cb_glitch && !zero_paired_cb_b;
        const bool main_cb_paired =
            paired && target_type != BuildType::Jtag && target_type != BuildType::Devgl;
        const auto cf_ldv = zero_key ? std::optional<uint8_t>{0} : metadata.cf_ldv;
        auto& cb_a = cb_section.cb_or_A;
        if (!cb_a.decrypted) {
            if (auto opened = open_for_metadata(cb_a.decrypt(key_1bl), "CB/A"); !opened) {
                return opened;
            }
        }
        if (cb_section.cb_B.has_value()) {
            auto& cb_b = *cb_section.cb_B;
            if (!cb_b.decrypted) {
                if (!cb_a.derived_key.has_value()) {
                    return fail(ErrorCode::Malformed,
                                "Could not derive CB_A key for replacement CB_B metadata");
                }
                if (auto opened = open_for_metadata(
                        cb_b.decrypt_cb_b(cb_a.header, cb_a.derived_key->data(),
                                          metadata.cpu_key.data()),
                        "CB_B");
                    !opened) {
                    return opened;
                }
            }
            if (auto applied = zero_paired_cb_b ? zero_pair_cb(cb_b, "CB_B")
                                                : apply_cb_metadata(cb_b, metadata, "CB_B");
                !applied) {
                return applied;
            }
        } else if (auto applied = main_cb_paired ? apply_cb_metadata(cb_a, metadata, "CB/A")
                                                 : zero_pair_cb(cb_a, "CB/A");
                   !applied) {
            return applied;
        }

        if (auto& extra_cb = payloads.extra_cb; extra_cb) {
            if (!extra_cb->decrypted) {
                if (auto opened = open_for_metadata(extra_cb->decrypt(key_1bl), "JTAG second CB");
                    !opened) {
                    return opened;
                }
            }
            if (auto applied = apply_cb_metadata(*extra_cb, metadata, "JTAG second CB");
                !applied) {
                return applied;
            }
        }

        const std::array<std::pair<SystemUpdate*, std::string_view>, 2> slots{
            {{&system_update_0, "CF_0"}, {&system_update_1, "CF_1"}}};
        for (uint8_t slot = 0; slot < slots.size(); ++slot) {
            auto& [update, name] = slots[slot];
            if (!update->cf.has_value()) {
                continue;
            }
            auto& cf = *update->cf;
            if (!cf.is_decrypted()) {
                if (auto opened = open_for_metadata(cf.decrypt(key_1bl), name); !opened) {
                    return opened;
                }
            }
            if (update_slot_binds_console(target_type, slot)) {
                if (auto applied = apply_cf_metadata(cf, metadata, cf_ldv, paired, slot, name);
                    !applied) {
                    return applied;
                }
            }
        }
        return {};
    }

    std::optional<DonorNonces> FlashImage::collect_nonces() const {
        const auto& cb_a = cb_section.cb_or_A;
        const auto& cd = kernel_section.cd;
        const auto& ce = kernel_section.ce;
        if (cb_a.data.size() < 0x10 || cd.data.empty() || !ce || ce->data.empty()) {
            return std::nullopt;
        }

        DonorNonces nonces{};
        nonces.stages[0] = nonce_from(cb_a.data);
        if (!cb_section.cb_x && cb_section.cb_B && cb_section.cb_B->data.size() >= 0x10) {
            nonces.stages[1] = nonce_from(cb_section.cb_B->data);
        } else if (cb_section.sc) {
            nonces.stages[1] = nonce_from(cb_section.sc->header.key);
        }
        nonces.stages[2] = nonce_from(cd.header.key);
        nonces.stages[3] = nonce_from(ce->header.key);

        const auto& slot =
            max_ldv_slot(*this).value_or(0) == 0 ? system_update_0 : system_update_1;
        if (slot.cf && !slot.cf->data.empty()) {
            nonces.cf = nonce_from(slot.cf->header.fixpoint_nonce);
        }
        if (slot.cg && !slot.cg->data.empty()) {
            nonces.cg = nonce_from(slot.cg->header.key);
        }
        return nonces;
    }

    // sets donor or random nonces on all plaintext stages and decrypts any sealed cg first
    Result<void> FlashImage::apply_nonces(const std::optional<DonorNonces>& donor) {
        const auto stage = [&donor](size_t index) {
            return donor ? donor->stages[index] : std::optional<BootloaderNonce>{};
        };
        const auto cf_nonce = donor ? donor->cf : std::optional<BootloaderNonce>{};
        const auto cg_nonce = donor ? donor->cg : std::optional<BootloaderNonce>{};

        const auto set_cb = [](BootloaderCb& cb, const BootloaderNonce& nonce) {
            std::copy(nonce.begin(), nonce.end(), cb.data.begin());
            std::copy(nonce.begin(), nonce.end(), std::begin(cb.header.key));
        };

        auto& cb_a = cb_section.cb_or_A;
        auto& cb_x = cb_section.cb_x;
        auto& cb_b = cb_section.cb_B;
        auto& sc = cb_section.sc;
        auto& cd = kernel_section.cd;
        auto& ce = kernel_section.ce;
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
            } else if (devkit_chain() && sc) {
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

        auto& extra_cb = payloads.extra_cb;
        auto& extra_cd = payloads.extra_cd;
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
        if (auto& extra_se = payloads.extra_se;
            extra_se && extra_se->decrypted && !extra_se->data.empty()) {
            const auto se_nonce = donor_or_random(stage(3));
            std::copy(se_nonce.begin(), se_nonce.end(), std::begin(extra_se->header.key));
        }

        for (auto* slot : {&system_update_0, &system_update_1}) {
            auto& cf = slot->cf;
            if (cf && cf->decrypted && !cf->data.empty()) {
                const auto nonce = donor_or_random(cf_nonce);
                std::copy(nonce.begin(), nonce.end(), std::begin(cf->header.fixpoint_nonce));
            }
            auto& cg = slot->cg;
            if (cg && !cg->decrypted && !cg->data.empty() && cf && cf->is_decrypted()) {
                if (const auto key = cf->cg_key()) {
                    if (auto opened = cg->decrypt(key->data()); !opened) {
                        return std::unexpected(std::move(opened.error())
                                                   .add_context("Could not open the supplied "
                                                                "CG to seal it again"));
                    }
                }
            }
            if (cg && cg->decrypted && !cg->data.empty()) {
                const auto nonce = donor_or_random(cg_nonce);
                std::copy(nonce.begin(), nonce.end(), std::begin(cg->header.key));
            }
        }
        return {};
    }

} // namespace gxbuild::nand
