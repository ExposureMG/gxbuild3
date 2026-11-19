#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/XeLL.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {

    using namespace detail;

    namespace {

        // Everything in the JTAG window is counted from kJtagWindowOffset.
        constexpr uint32_t kJTAGPatchesSize = 0x4000;

        // xeBuild lays a built image in 16 KiB blocks on erased flash: the block holding the
        // end of the boot chain is programmed zero past it, and every byte nothing lays stays
        // erased.
        constexpr size_t kLayBlockSize = 0x4000;

        // Lays one of the console's 0x1000-byte blocks (settings, statistics, manufacturing) at
        // the head of its erase block, as xeBuild does: the erase block is erased, the bytes
        // go in and their pages carry a type-0 spare naming the block. A block of all 0xFF
        // stays erased, as on a console that keeps none. A bad block keeps its spare.
        [[nodiscard]] Result<void> lay_settings_block(Driver& driver, size_t offset,
                                                      std::span<const uint8_t> bytes,
                                                      std::string_view what) {
            const size_t block_size = driver.block_size_clean();
            const size_t block = offset / block_size;
            const bool bad = driver.is_bad_block(block);
            if (!bad) {
                driver.erase_block(block);
            }
            if (std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0xFF; })) {
                return {};
            }
            if (auto laid = write_or_fail(driver, offset, bytes, what); !laid) {
                return laid;
            }
            if (!bad && driver.driver_mode() != Driver::DriverMode::Emmc) {
                BlockMetadata meta{};
                meta.logical_block_id = static_cast<uint16_t>(block);
                driver.write_page_metadata(offset / 512, (bytes.size() + 511) / 512, meta);
            }
            return {};
        }

        // What the write_to_driver stages share: the driver they lay into, the layout they lay
        // by and the highest offset the boot chain and the update slots have reached so far;
        // then, for the data area, the usable block limit, the payload blocks kept out of it,
        // the image's filesystem, the allocation block size and cursor and the spare layout
        // the stages record.
        struct WriteContext {
            Driver& driver;
            const LayoutPlan& plan;
            size_t highest_used_offset;
            size_t data_block_limit;
            std::vector<BlockRange> payload_ranges;
            FlashFileSystem* fs;
            size_t fs_blk_size;
            size_t current_blk;
            NandLayout layout;

            // The first run of `requested_blocks` blocks from `start_block` below the data
            // limit that holds no bad block, no payload block and no block the filesystem uses.
            [[nodiscard]] std::optional<size_t> find_data_free_run(size_t start_block,
                                                                   size_t requested_blocks) const {
                if (requested_blocks == 0 || requested_blocks > data_block_limit ||
                    start_block > data_block_limit - requested_blocks) {
                    return std::nullopt;
                }
                for (size_t candidate = start_block;
                     candidate <= data_block_limit - requested_blocks; ++candidate) {
                    bool all_free = true;
                    for (size_t block = candidate; block < candidate + requested_blocks; ++block) {
                        if (driver.is_bad_block(block) ||
                            std::any_of(payload_ranges.begin(), payload_ranges.end(),
                                        [block](const BlockRange& range) {
                                            return range.contains(block);
                                        }) ||
                            (fs && !fs->is_block_free(block))) {
                            all_free = false;
                            break;
                        }
                    }
                    if (all_free) {
                        return candidate;
                    }
                }
                return std::nullopt;
            }
        };

        // The 0x80-byte NAND header a built or written-back image carries. Pure: every field
        // follows `header`, the layout and the SMC placement.
        std::array<uint8_t, sizeof(nand_header)> encode_nand_header(const nand_header& header,
                                                                    const LayoutPlan& plan,
                                                                    uint32_t smc_len,
                                                                    uint32_t smc_offset) {
            nand_header raw = header;
            raw.magic = header.magic ? header.magic.get() : uint16_t{0xFF4F};
            raw.version = header.version ? header.version.get() : uint16_t{0x0760};
            raw.entrypoint = header.entrypoint ? header.entrypoint.get() : kEntryOffset;
            // The legacy bootloader-chain scanner used by tools such as J-Runner
            // advances from the NAND header using this size.  It must therefore
            // terminate at the first system-update slot, not retain a donor image's
            // earlier boot-chain boundary.
            raw.size = plan.update_base;
            raw.kv_size =
                header.kv_size ? header.kv_size.get() : static_cast<uint32_t>(Keyvault::kSize);
            raw.cf_offset = plan.update_base;
            // Two update slots on every image, as xeBuild states them. On a glitch image the
            // second is the KHV patch slot, which the kernel passes over for want of a CF.
            raw.patch_slots = uint16_t{2};
            raw.kv_version = header.kv_version ? header.kv_version.get() : uint16_t{0x0712};
            raw.kv_addr = header.kv_addr ? header.kv_addr.get() : kKeyvaultOffset;
            raw.fs_addr = plan.slot_stride; // Runtime dwSysUpdateSlotSize (header + 0x70).
            // Zero on every image, a donor's value or not: xeBuild never states the settings
            // block here (xerunner build.py `header`), and the three console dumps measured
            // carry zero. The block is found by its place in the layout instead.
            raw.smc_config_offset = uint32_t{0};
            raw.smc_boot_size = smc_len;
            raw.smc_boot_offset = smc_offset;

            std::array<uint8_t, sizeof(nand_header)> encoded{};
            const auto bytes = wire::bytes_of(raw);
            std::copy(bytes.begin(), bytes.end(), encoded.begin());
            return encoded;
        }

        // Lays the NAND header, the zero fill up to the SMC on a built image, the SMC and the
        // keyvault, in that order.
        [[nodiscard]] Result<void> lay_header_and_secure_head(WriteContext& ctx,
                                                              const FlashImage& image,
                                                              uint32_t smc_len,
                                                              uint32_t smc_offset) {
            const auto encoded = encode_nand_header(image.header, ctx.plan, smc_len, smc_offset);
            if (auto laid = write_or_fail(ctx.driver, 0, encoded, "NAND header"); !laid) {
                return laid;
            }
            // On a built image the header block is programmed zero from the header to the SMC.
            if (!image.preserve_layout) {
                if (auto laid = write_or_fail(ctx.driver, encoded.size(),
                                              std::vector<uint8_t>(smc_offset - encoded.size(), 0),
                                              "header block fill");
                    !laid) {
                    return laid;
                }
            }

            if (image.smc) {
                if (auto laid = write_or_fail(ctx.driver, smc_offset, image.smc->data, "SMC");
                    !laid) {
                    return laid;
                }
            }

            if (image.keyvault) {
                auto kv_data = image.keyvault->serialize();
                if (auto laid = write_or_fail(ctx.driver, kKeyvaultOffset, kv_data, "keyvault");
                    !laid) {
                    return laid;
                }
            }
            return {};
        }

        // Lays one boot stage at `cursor` and moves the cursor past it, 16-byte aligned.
        template <class Stage>
        [[nodiscard]] Result<void> lay_stage(Driver& driver, size_t& cursor, const Stage& stage,
                                             std::string_view name) {
            const auto bytes = stage.serialize();
            if (auto laid = write_or_fail(driver, cursor, bytes, name); !laid) {
                return laid;
            }
            cursor += align_16(static_cast<uint32_t>(bytes.size()));
            return {};
        }

        // Lays the boot chain from kEntryOffset (CB/A and CD when they hold data, the rule
        // laid_boot_chain_end follows) and, on a built image, the zero fill to the end of the
        // 16 KiB block holding its end. Returns where the chain ends.
        [[nodiscard]] Result<size_t> lay_boot_chain(WriteContext& ctx, const FlashImage& image) {
            auto& driver = ctx.driver;
            const auto& cb_section = image.cb_section;
            const auto& kernel_section = image.kernel_section;
            size_t cursor = kEntryOffset;
            if (!cb_section.cb_or_A.data.empty()) {
                if (auto laid = lay_stage(driver, cursor, cb_section.cb_or_A, "CB_A"); !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            if (cb_section.cb_x) {
                if (auto laid = lay_stage(driver, cursor, *cb_section.cb_x, "CB_X"); !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            if (cb_section.cb_B) {
                if (auto laid = lay_stage(driver, cursor, *cb_section.cb_B, "CB_B"); !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            if (cb_section.sc) {
                if (auto laid = lay_stage(driver, cursor, *cb_section.sc, "SC"); !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            if (!kernel_section.cd.data.empty()) {
                if (auto laid = lay_stage(driver, cursor, kernel_section.cd, "CD"); !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            if (kernel_section.ce) {
                if (auto laid = lay_stage(driver, cursor, *kernel_section.ce, "CE"); !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            if (!image.preserve_layout) {
                const size_t block_end =
                    (cursor + kLayBlockSize - 1) / kLayBlockSize * kLayBlockSize;
                if (auto laid =
                        write_or_fail(driver, cursor, std::vector<uint8_t>(block_end - cursor, 0),
                                      "boot chain block fill");
                    !laid) {
                    return std::unexpected(std::move(laid.error()));
                }
            }
            return cursor;
        }

        // Lays one update slot at `base_offset`: the CF, then the CG behind it, its prefix in
        // the slot and the rest in its spill clusters. `end_offset` is where the slot's laid
        // bytes end, and the context's highest offset follows it when the slot holds a CF.
        [[nodiscard]] Result<void> lay_update_slot(WriteContext& ctx, uint32_t base_offset,
                                                   const SystemUpdate& slot, size_t& end_offset) {
            auto& driver = ctx.driver;
            const auto& plan = ctx.plan;
            end_offset = base_offset;
            if (slot.cf) {
                auto cf_bytes = slot.cf->serialize();
                if (auto laid = write_or_fail(driver, base_offset, cf_bytes, "CF"); !laid) {
                    return laid;
                }
                end_offset = base_offset + align_16(static_cast<uint32_t>(cf_bytes.size()));
                if (slot.cg) {
                    auto cg_bytes = slot.cg->serialize();
                    if (end_offset > base_offset + plan.slot_stride) {
                        return fail(ErrorCode::OutOfRange,
                                    "the CF (0x{:X} bytes) leaves no room for its CG in the "
                                    "0x{:X}-byte slot",
                                    cf_bytes.size(), plan.slot_stride);
                    }
                    const size_t prefix =
                        slot.cg_spill_blocks.empty()
                            ? cg_bytes.size()
                            : std::min<size_t>(cg_bytes.size(),
                                               base_offset + plan.slot_stride - end_offset);
                    if (end_offset + prefix > base_offset + plan.slot_stride) {
                        return fail(ErrorCode::Internal,
                                    "CG continuation has not been allocated before serialization");
                    }
                    if (auto laid = write_or_fail(driver, end_offset,
                                                  std::span(cg_bytes).first(prefix), "CG");
                        !laid) {
                        return laid;
                    }
                    size_t consumed = prefix;
                    for (uint16_t block : slot.cg_spill_blocks) {
                        const size_t count =
                            std::min<size_t>(kCgClusterSize, cg_bytes.size() - consumed);
                        if (auto laid = write_or_fail(driver, size_t(block) * kCgClusterSize,
                                                      std::span(cg_bytes).subspan(consumed, count),
                                                      "CG continuation cluster");
                            !laid) {
                            return laid;
                        }
                        consumed += count;
                    }
                    if (consumed != cg_bytes.size()) {
                        return fail(ErrorCode::Internal,
                                    "the CG continuation clusters hold 0x{:X} of its 0x{:X} bytes",
                                    consumed, cg_bytes.size());
                    }
                    end_offset += align_16(static_cast<uint32_t>(prefix));
                }
                ctx.highest_used_offset = std::max(ctx.highest_used_offset, end_offset);
            }
            return {};
        }

        // Lays the console's settings block, then its statistics and manufacturing blocks one
        // and two erase blocks below it, each only when the image carries it.
        [[nodiscard]] Result<void> lay_console_blocks(WriteContext& ctx, const FlashImage& image,
                                                      std::optional<size_t> smc_cfg_offset) {
            auto& driver = ctx.driver;
            const size_t block_size = driver.block_size_clean();
            if (image.smc_config) {
                if (!smc_cfg_offset) {
                    return fail(ErrorCode::Unsupported, "this NAND shape has no SMC config block");
                }
                if (image.smc_config->size() != kSmcConfigLength ||
                    !smc_config_sums(*image.smc_config)) {
                    return fail(ErrorCode::Malformed,
                                "SMC config block is not 0x{:X} bytes with a sound checksum",
                                kSmcConfigLength);
                }
                std::vector<uint8_t> cfg_bytes(kSettingsSpan, 0xFF);
                std::copy(image.smc_config->begin(), image.smc_config->end(), cfg_bytes.begin());
                if (auto laid =
                        lay_settings_block(driver, *smc_cfg_offset, cfg_bytes, "SMC config block");
                    !laid) {
                    return laid;
                }
            }
            const std::array<std::pair<const std::optional<std::vector<uint8_t>>*, size_t>, 2>
                console_blocks{{{&image.statistics, 1}, {&image.manufacturing, 2}}};
            for (const auto& [bytes, steps] : console_blocks) {
                if (!*bytes) {
                    continue;
                }
                const std::string_view name =
                    steps == 1 ? "statistics block" : "manufacturing block";
                if (!smc_cfg_offset || *smc_cfg_offset < steps * block_size) {
                    return fail(ErrorCode::Unsupported, "this NAND shape has no {}", name);
                }
                if ((*bytes)->size() != kSettingsSpan) {
                    return fail(ErrorCode::Malformed,
                                "Statistics and manufacturing blocks must be 0x{:X} bytes",
                                kSettingsSpan);
                }
                if (auto laid = lay_settings_block(driver, *smc_cfg_offset - steps * block_size,
                                                   **bytes, name);
                    !laid) {
                    return laid;
                }
            }
            return {};
        }

        // Every older blob copy goes: a donor's mobile blocks are erased before the blobs are
        // laid again, so no stale copy can outrank or trail the new ones.
        void purge_stale_mobile_blocks(Driver& driver) {
            if (driver.driver_mode() == Driver::DriverMode::Emmc) {
                return;
            }
            const size_t total_blocks = driver.block_count();
            for (size_t block = 0; block < total_blocks; ++block) {
                if (!is_mobile_block_type(driver.interpret_block(block).block_type)) {
                    continue;
                }
                if (driver.is_bad_block(block)) {
                    BlockMetadata cleared{};
                    cleared.logical_block_id = static_cast<uint16_t>(block);
                    cleared.is_bad = true;
                    driver.write_block_metadata(block, cleared);
                    continue;
                }
                driver.erase_block(block);
            }
        }

        // On NAND an image with a filesystem clears the spare of every cluster stamped as an
        // older FlashFS root, keeping its bad mark.
        void clear_stale_fs_roots(Driver& driver, bool has_filesystem) {
            if (!has_filesystem || driver.driver_mode() == Driver::DriverMode::Emmc) {
                return;
            }
            const size_t total_blocks = driver.block_count();
            const size_t ratio = driver.block_size_clean() / 0x4000;
            for (size_t cluster = 0; cluster < total_blocks * ratio; ++cluster) {
                const auto old_meta = driver.interpret_cluster(cluster);
                if (old_meta.block_type != 0x2C && old_meta.block_type != 0x30) {
                    continue;
                }
                BlockMetadata cleared{};
                cleared.logical_block_id = static_cast<uint16_t>(cluster / ratio);
                cleared.is_bad = old_meta.is_bad;
                driver.write_cluster_metadata(cluster, cleared);
            }
        }

        // One version of each blob, as xeBuild lays them, in type order. Small block gives
        // each its own block; big block packs them 0x800 apart in one erase block, where
        // the free count is kept in those slots; eMMC gives each its own blocks and
        // names them in the anchors, which hold types 0x31-0x34 only.
        [[nodiscard]] Result<void> lay_mobile_data(WriteContext& ctx, const MobileData& mobile) {
            auto& driver = ctx.driver;
            const size_t fs_blk_size = ctx.fs_blk_size;
            const bool emmc = driver.driver_mode() == Driver::DriverMode::Emmc;
            const bool big = driver.driver_mode() == Driver::DriverMode::Big;
            const size_t pages_per_block = driver.pages_per_block();
            constexpr size_t kBigSlotPages = 0x800 / 512;
            std::optional<size_t> open_block;
            size_t next_page = 0;
            for (uint8_t bt = 0x31; bt <= 0x39; ++bt) {
                const auto* slot = mobile.get_slot(bt);
                if (!slot || !*slot || (*slot)->empty()) {
                    continue;
                }
                if (emmc && size_t(bt - CoronaConfig::kFirstBlobType) >= CoronaConfig::kBlobSlots) {
                    Log::Warn("Mobile data type 0x{:02X} has no slot in an eMMC anchor block; "
                              "it is left out",
                              bt);
                    continue;
                }
                const auto& mdata = **slot;
                const size_t limit =
                    std::min<size_t>(emmc ? std::numeric_limits<uint16_t>::max() : fs_blk_size,
                                     std::numeric_limits<uint16_t>::max());
                if (mdata.size() > limit) {
                    return fail(ErrorCode::OutOfRange,
                                "Mobile data type 0x{:02X} is 0x{:X} bytes; one copy holds at "
                                "most 0x{:X}",
                                bt, mdata.size(), limit);
                }
                const size_t pages = (mdata.size() + 511) / 512;
                const size_t used_pages =
                    big ? (pages + kBigSlotPages - 1) / kBigSlotPages * kBigSlotPages : pages;
                const size_t blocks_needed =
                    emmc ? (mdata.size() + fs_blk_size - 1) / fs_blk_size : 1;
                if (!big || !open_block || next_page + used_pages > pages_per_block) {
                    auto free_start = ctx.find_data_free_run(ctx.current_blk, blocks_needed);
                    if (!free_start || *free_start > std::numeric_limits<uint16_t>::max()) {
                        return fail(ErrorCode::Exhausted,
                                    "Mobile data type 0x{:02X} does not fit below reserved NAND "
                                    "tail",
                                    bt);
                    }
                    for (size_t b = 0; b < blocks_needed; ++b) {
                        driver.erase_block(*free_start + b);
                    }
                    // The table states a blob's blocks free (xeBuild 1.21); they are only
                    // kept from the files and the root here.
                    if (ctx.fs) {
                        if (auto withheld = ctx.fs->withhold_blocks(*free_start, blocks_needed,
                                                                    BlockMapStatus::Free);
                            !withheld) {
                            return with_context(
                                std::move(withheld),
                                std::format("reserving mobile data type 0x{:02X} in FlashFS", bt));
                        }
                    }
                    // On big block the blobs start on an erase block, and the table never
                    // names the clusters stepped over between the last file and them.
                    if (ctx.fs && big && !open_block) {
                        const size_t ratio = driver.block_size_clean() / 0x4000;
                        const size_t blob_cluster = *free_start * ratio;
                        const size_t floor = blob_cluster >= ratio ? blob_cluster - ratio : 0;
                        size_t cluster = blob_cluster;
                        while (cluster > floor &&
                               ctx.fs->blockmap()[cluster - 1] == BlockMapStatus::Free) {
                            --cluster;
                        }
                        if (cluster < blob_cluster) {
                            if (auto withheld = ctx.fs->withhold_clusters(
                                    cluster, blob_cluster - cluster, BlockMapStatus::Unnamed);
                                !withheld) {
                                return with_context(
                                    std::move(withheld),
                                    "withholding the clusters before the mobile data");
                            }
                        }
                    }
                    open_block = *free_start;
                    next_page = 0;
                    ctx.current_blk = *free_start + blocks_needed;
                }
                if (auto laid = write_or_fail(driver, *open_block * fs_blk_size + next_page * 512,
                                              mdata, "mobile data");
                    !laid) {
                    return laid;
                }
                const size_t free_pages = emmc ? 0 : pages_per_block - next_page - used_pages;
                ctx.layout.mobile_blocks.push_back(
                    {bt, static_cast<uint16_t>(*open_block), static_cast<uint16_t>(next_page),
                     static_cast<uint16_t>(pages),
                     static_cast<uint8_t>(big ? free_pages / kBigSlotPages : free_pages), 1,
                     static_cast<uint32_t>(mdata.size())});
                next_page += used_pages;
            }
            return {};
        }

        // Places the FlashFS root in the first free block from the cursor, saves the filesystem
        // and records its root, version, size stamp and data blocks in the layout.
        [[nodiscard]] Result<void> place_and_save_filesystem(WriteContext& ctx,
                                                             FlashFileSystem& fs) {
            auto& driver = ctx.driver;
            auto root_start = ctx.find_data_free_run(ctx.current_blk, 1);
            if (!root_start || *root_start > std::numeric_limits<uint16_t>::max()) {
                return fail(ErrorCode::Exhausted,
                            "no block is free for the FlashFS root after payload allocations");
            }
            if (auto placed = fs.set_root_block(static_cast<uint16_t>(*root_start)); !placed) {
                return with_context(std::move(placed),
                                    "placing the FlashFS root block after payload allocations");
            }
            ctx.layout.fs_root_block = static_cast<uint16_t>(*root_start);
            ctx.layout.fs_version = fs.version();
            ctx.layout.big_fs_size = fs.big_fs_size();
            fs.set_driver(&driver);
            if (auto saved = fs.save(); !saved) {
                return with_context(std::move(saved), "saving the Flash File System");
            }
            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            for (const uint16_t cluster : fs.get_all_file_blocks()) {
                ctx.layout.fs_data_blocks.push_back(
                    static_cast<uint16_t>(cluster / clusters_per_block));
            }
            return {};
        }

        // Records the JTAG programmed range and spare override, then hands the layout to the
        // driver on NAND or writes it as the two anchor blocks on eMMC.
        [[nodiscard]] Result<void> record_spare_layout_or_anchors(WriteContext& ctx,
                                                                  const FlashImage& image) {
            auto& driver = ctx.driver;
            const auto& plan = ctx.plan;
            const auto& payloads = image.payloads;
            auto& layout = ctx.layout;
            // The JTAG patch buffer is programmed whole, its erased tail included.
            if (plan.jtag && payloads.patchset && payloads.patchset->kind == PatchSetKind::Jtag) {
                layout.programmed_ranges.emplace_back(plan.window_base + 0x1000, kJTAGPatchesSize);
            }
            // xeBuild's JTAG image has 0x03 0x50 in spare bytes 10 and 11 of the page holding the
            // SMC payload, in every shape and with the same payload; nothing else stamps them.
            if (plan.jtag && payloads.payload) {
                layout.spare_overrides.push_back({0x200, 10, {0x03, 0x50}});
            }

            if (driver.driver_mode() == Driver::DriverMode::Emmc) {
                CoronaConfig cc{};
                cc.table = layout.fs_root_block.value_or(0);
                for (const auto& mob : layout.mobile_blocks) {
                    const size_t slot = size_t(mob.block_type) - CoronaConfig::kFirstBlobType;
                    cc.blobs[slot] = {mob.start_block, static_cast<uint16_t>(mob.data_size)};
                }

                // The copies are numbered 1 and 2, each given CoronaConfig::kSpan with zeros
                // after the structure; the rest of its block stays erased.
                for (size_t copy = 0; copy < CoronaConfig::kOffsets.size(); ++copy) {
                    cc.number = static_cast<uint32_t>(copy + 1);
                    auto cc_bytes = cc.serialize();
                    cc_bytes.resize(CoronaConfig::kSpan, 0);
                    cc_bytes.resize(CoronaConfig::kBlockSize, 0xFF);
                    if (auto laid = write_or_fail(driver, CoronaConfig::kOffsets[copy], cc_bytes,
                                                  "eMMC anchor block");
                        !laid) {
                        return laid;
                    }
                }
            } else {
                driver.set_layout(layout);
            }
            return {};
        }

        // xeBuild programs the bytes after each JTAG window item zero, up to the next item or the
        // end of the 16 KiB block that holds the item's end.
        [[nodiscard]] Result<void> zero_fill(Driver& driver, size_t from, size_t to) {
            if (from >= to) {
                return {};
            }
            return write_or_fail(driver, from, std::vector<uint8_t>(to - from, 0), "zero fill");
        }

        [[nodiscard]] Result<void> zero_to_block_end(Driver& driver, size_t end) {
            return zero_fill(driver, end,
                             (end + kLayBlockSize - 1) / kLayBlockSize * kLayBlockSize);
        }

        // Lays the patch set: the JTAG patch buffer in the window or the KHV payload in the
        // patch slot, after its capacity and its XeLL, rebooter and fuse overlap checks, then
        // the JTAG buffer's zero and erased tail or the glitch slot's zero fill.
        [[nodiscard]] Result<void> lay_patch_payload(WriteContext& ctx, const Payloads& payloads) {
            auto& driver = ctx.driver;
            const auto& plan = ctx.plan;
            const size_t glitch_patch_offset =
                plan.update_base + plan.slot_stride + plan.khv_prefix;
            std::vector<uint8_t> patch_bytes;
            size_t patch_offset = 0;
            size_t patch_capacity = 0;
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                patch_bytes = serialize_patch_set(*payloads.patchset);
                patch_offset = plan.window_base + 0x1000;
                patch_capacity = kJTAGPatchesSize;
            } else {
                const auto* khv = find_patch_section(*payloads.patchset, PatchSectionTarget::Khv);
                if (!khv) {
                    return fail(ErrorCode::InvalidArgument,
                                "the glitch patch set has no KHV section");
                }
                patch_bytes = serialize_khv_payload(*khv);
                patch_offset = glitch_patch_offset;
                patch_capacity = plan.slot_stride - plan.khv_prefix;
            }
            if (patch_bytes.size() > patch_capacity) {
                return fail(ErrorCode::OutOfRange,
                            "Patch payload (0x{:X} bytes) exceeds its 0x{:X}-byte region",
                            patch_bytes.size(), patch_capacity);
            }
            if (payloads.xell && ranges_overlap(patch_offset, patch_bytes.size(), plan.xell_offset,
                                                payloads.xell->data.size())) {
                return fail(ErrorCode::InvalidArgument,
                            "Patch payload overlaps the reserved XeLL region");
            }
            if (payloads.rebooter && ranges_overlap(patch_offset, patch_bytes.size(),
                                                    plan.window_base, payloads.rebooter->size())) {
                return fail(ErrorCode::InvalidArgument,
                            "Patch payload overlaps the reserved rebooter region");
            }
            if (payloads.fuses && ranges_overlap(patch_offset, patch_bytes.size(), plan.fuse_offset,
                                                 payloads.fuses->size())) {
                return fail(ErrorCode::InvalidArgument,
                            "Patch payload overlaps the reserved virtual-fuse region");
            }
            if (auto laid = write_or_fail(driver, patch_offset, patch_bytes, "patch payload");
                !laid) {
                return laid;
            }
            if (payloads.patchset->kind == PatchSetKind::Jtag) {
                const size_t patch_end = patch_offset + patch_bytes.size();
                const size_t block_end =
                    (patch_end + kLayBlockSize - 1) / kLayBlockSize * kLayBlockSize;
                const size_t region_end = patch_offset + patch_capacity;
                // The patch buffer is programmed whole: zero to the end of its block, then
                // erased bytes, written as pages, up to its fixed length.
                if (auto filled = zero_fill(driver, patch_end, block_end); !filled) {
                    return filled;
                }
                if (block_end < region_end) {
                    if (auto laid = write_or_fail(
                            driver, block_end, std::vector<uint8_t>(region_end - block_end, 0xFF),
                            "erased patch buffer tail");
                        !laid) {
                        return laid;
                    }
                }
            }
            // xeBuild programs the rest of the patch slot's first 0x4000 bytes zero after the
            // KHV terminator; the slot past them stays erased.
            const size_t khv_end = patch_offset + patch_bytes.size();
            const size_t zero_end = size_t(plan.update_base) + plan.slot_stride + kLayBlockSize;
            if (payloads.patchset->kind != PatchSetKind::Jtag && khv_end < zero_end) {
                if (auto filled = zero_fill(driver, khv_end, zero_end); !filled) {
                    return filled;
                }
            }
            return {};
        }

        // Lays the payloads after the filesystem, in this order: the erased glitch patch slot
        // (which drops a donor's CF/CG header and stale bytes from the owned overlay), the SMC
        // payload, the rebooter with its JTAG zero fill, the virtual fuses, XeLL and the patch
        // set. Later writes land over the erased overlay and the zero fills.
        [[nodiscard]] Result<void> lay_payloads(WriteContext& ctx, const Payloads& payloads) {
            auto& driver = ctx.driver;
            const auto& plan = ctx.plan;
            // Direct parsed images retain a recovered patchset, so it is rewritten below.
            if (plan.glitch && payloads.patchset) {
                const std::vector<uint8_t> erased_overlay(plan.slot_stride, 0xFF);
                if (auto laid = write_or_fail(driver, plan.update_base + plan.slot_stride,
                                              erased_overlay, "erased patch slot");
                    !laid) {
                    return laid;
                }
            }
            if (payloads.payload) {
                if (auto laid = write_or_fail(driver, 0x200, *payloads.payload, "SMC payload");
                    !laid) {
                    return laid;
                }
            }
            if (payloads.rebooter) {
                if (auto laid =
                        write_or_fail(driver, plan.window_base, *payloads.rebooter, "rebooter");
                    !laid) {
                    return laid;
                }
                if (plan.jtag) {
                    if (auto filled =
                            zero_fill(driver, plan.window_base + payloads.rebooter->size(),
                                      plan.window_base + 0x1000);
                        !filled) {
                        return filled;
                    }
                }
            }
            if (payloads.fuses) {
                if (auto laid =
                        write_or_fail(driver, plan.fuse_offset, *payloads.fuses, "virtual fuses");
                    !laid) {
                    return laid;
                }
            }
            if (payloads.xell) {
                const auto& xell_bytes = payloads.xell->data;
                if (auto laid = write_or_fail(driver, plan.xell_offset, xell_bytes, "XeLL");
                    !laid) {
                    return laid;
                }
            }
            if (payloads.patchset) {
                if (auto laid = lay_patch_payload(ctx, payloads); !laid) {
                    return laid;
                }
            }
            return {};
        }

        // The JTAG second CB/CD live in the window tail, directly past the fixed-size XeLL; the
        // bytes after the chain are zero to the end of its 16 KiB block. Each stage is
        // serialized once, for its write and for the chain end.
        [[nodiscard]] Result<void> lay_jtag_extra_chain(WriteContext& ctx,
                                                        const Payloads& payloads) {
            auto& driver = ctx.driver;
            const auto extra = jtag_extra_offsets(ctx.plan.window_base, payloads);
            std::optional<std::vector<uint8_t>> cb_bytes;
            std::optional<std::vector<uint8_t>> cd_bytes;
            if (payloads.extra_cb) {
                cb_bytes = payloads.extra_cb->serialize();
                if (auto laid = write_or_fail(driver, extra.cb, *cb_bytes, "JTAG second CB");
                    !laid) {
                    return laid;
                }
            }
            if (payloads.extra_cd) {
                cd_bytes = payloads.extra_cd->serialize();
                if (auto laid = write_or_fail(driver, extra.cd, *cd_bytes, "JTAG second CD");
                    !laid) {
                    return laid;
                }
            }
            const size_t second_chain_end = cd_bytes   ? extra.cd + cd_bytes->size()
                                            : cb_bytes ? extra.cb + cb_bytes->size()
                                                       : 0;
            if (second_chain_end != 0) {
                if (auto filled = zero_to_block_end(driver, second_chain_end); !filled) {
                    return filled;
                }
            }
            return {};
        }

        // Writes each [rawpatch] as it is at its clean offset, in order, after a check that it
        // stays inside the `clean_size`-byte image.
        [[nodiscard]] Result<void> apply_raw_patches(Driver& driver,
                                                     const std::vector<InputRawPatch>& raw_patches,
                                                     size_t clean_size) {
            for (const auto& patch : raw_patches) {
                if (patch.offset > clean_size || patch.data.size() > clean_size - patch.offset) {
                    return fail(ErrorCode::OutOfRange,
                                "[rawpatch] '{}' (0x{:X} bytes at 0x{:X}) runs past the image",
                                patch.name, patch.data.size(), patch.offset);
                }
                if (auto laid = write_or_fail(driver, patch.offset, patch.data,
                                              std::format("[rawpatch] '{}'", patch.name));
                    !laid) {
                    return laid;
                }
            }
            return {};
        }

    } // namespace

    Result<void> FlashImage::write_to_driver() {
        if (flash_driver.block_count() == 0) {
            return fail(ErrorCode::InvalidArgument, "the NAND image has no blocks");
        }

        if (auto layout = payload_layout(); !layout) {
            return layout;
        }

        auto& driver = flash_driver;

        // A built image starts from erased flash, so whatever this writer does not lay (an
        // unused update slot, free filesystem blocks, the remap pool, a donor's old data)
        // stays erased: 0xFF data and, on NAND, an erased spare. A bad block keeps its marker.
        // A parsed dump written back keeps its bytes.
        if (!preserve_layout) {
            for (size_t block = 0; block < driver.block_count(); ++block) {
                if (!driver.is_bad_block(block)) {
                    driver.erase_block(block);
                }
            }
        }

        const LayoutPlan plan = plan_layout(*this);
        const size_t total_blocks = driver.block_count();
        const size_t block_size = driver.block_size_clean();
        const size_t data_block_limit = driver.data_block_limit();
        if (data_block_limit == 0) {
            return fail(ErrorCode::Exhausted,
                        "no usable NAND blocks remain below the geometry-reserved tail");
        }

        auto payload_block_ranges = active_payload_block_ranges();

        const size_t smc_len = smc ? smc->data.size() : 0x3000;
        if (smc_len > kKeyvaultOffset - sizeof(nand_header)) {
            return fail(ErrorCode::OutOfRange,
                        "the SMC (0x{:X} bytes) does not fit before the keyvault", smc_len);
        }
        const uint32_t smc_offset = kKeyvaultOffset - static_cast<uint32_t>(smc_len);
        const auto smc_cfg_offset = smc_config_offset(driver);

        WriteContext ctx{.driver = driver,
                         .plan = plan,
                         .highest_used_offset = 0,
                         .data_block_limit = data_block_limit,
                         .payload_ranges = std::move(payload_block_ranges),
                         .fs = filesystem ? &*filesystem : nullptr,
                         .fs_blk_size = 0,
                         .current_blk = 0,
                         .layout = {}};
        if (auto laid =
                lay_header_and_secure_head(ctx, *this, static_cast<uint32_t>(smc_len), smc_offset);
            !laid) {
            return laid;
        }

        const auto chain_end = lay_boot_chain(ctx, *this);
        if (!chain_end) {
            return std::unexpected(chain_end.error());
        }
        ctx.highest_used_offset = *chain_end;

        // A CG longer than its slot continues in spill blocks, so each slot ends within its
        // own stride.
        size_t slot0_end = plan.update_base;
        if (auto laid = lay_update_slot(ctx, plan.update_base, system_update_0, slot0_end); !laid) {
            return with_context(std::move(laid), "update slot 0");
        }
        size_t slot1_end = plan.update_base + plan.slot_stride;
        if (auto laid = lay_update_slot(ctx, plan.update_base + plan.slot_stride, system_update_1,
                                        slot1_end);
            !laid) {
            return with_context(std::move(laid), "update slot 1");
        }

        if (auto laid = lay_console_blocks(ctx, *this, smc_cfg_offset); !laid) {
            return laid;
        }

        ctx.fs_blk_size = (driver.driver_mode() == Driver::DriverMode::Emmc) ? 0x4000 : block_size;
        const size_t min_blk = (ctx.highest_used_offset + ctx.fs_blk_size - 1) / ctx.fs_blk_size;
        ctx.current_blk = std::max<size_t>(plan.fs_base / ctx.fs_blk_size, min_blk);

        if (ctx.fs) {
            // A donor FlashImage may have been moved since parsing its filesystem.
            // Rebind before checking allocation geometry, not just before saving.
            ctx.fs->set_driver(&driver);
        }

        purge_stale_mobile_blocks(driver);
        clear_stale_fs_roots(driver, ctx.fs != nullptr);

        if (mobile_data) {
            if (auto laid = lay_mobile_data(ctx, *mobile_data); !laid) {
                return laid;
            }
        }

        if (ctx.fs) {
            if (auto saved = place_and_save_filesystem(ctx, *ctx.fs); !saved) {
                return saved;
            }
        }

        if (auto recorded = record_spare_layout_or_anchors(ctx, *this); !recorded) {
            return recorded;
        }

        // Remove any donor CF/CG header and stale bytes from the owned overlay, then lay the
        // payloads, the JTAG second chain and, last, the raw patches.
        if (auto laid = lay_payloads(ctx, payloads); !laid) {
            return laid;
        }

        if (plan.jtag) {
            if (auto laid = lay_jtag_extra_chain(ctx, payloads); !laid) {
                return laid;
            }
        }

        if (auto patched = apply_raw_patches(driver, raw_patches, total_blocks * block_size);
            !patched) {
            return patched;
        }

        return {};
    }

    Result<std::vector<uint8_t>> FlashImage::write() {
        if (auto laid = write_to_driver(); !laid) {
            return std::unexpected(std::move(laid.error()));
        }
        // The mutable serialize() stamps the spare layout write_to_driver recorded.
        return flash_driver.serialize();
    }

} // namespace gxbuild3::nand
