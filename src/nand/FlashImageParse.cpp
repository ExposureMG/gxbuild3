#include "Wire.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/FlashImageLayout.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/MobileData.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/XConfig.hpp"
#include "nand/objects/XeLL.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {

    using namespace detail;

    namespace {

        [[nodiscard]] Result<nand_header> decode_nand_header(const Driver& driver) {
            if (driver.block_count() == 0) {
                return fail(ErrorCode::InvalidArgument, "the NAND image has no blocks");
            }

            const size_t image_size = driver.serialize().size();
            if (image_size < sizeof(nand_header)) {
                return fail(ErrorCode::Truncated,
                            "the NAND image ({} bytes) is smaller than the NAND header",
                            image_size);
            }

            const auto header_span = driver.read_offset(0, sizeof(nand_header));
            if (header_span.size() < sizeof(nand_header)) {
                return fail(ErrorCode::Truncated, "the NAND header could not be read");
            }

            return wire::read<nand_header>(header_span, 0, "NAND header");
        }

        void read_secure_head(const Driver& driver, const nand_header& header,
                              std::optional<Smc>& smc, std::optional<Keyvault>& keyvault) {
            const uint32_t smc_boot_size = header.smc_boot_size.get();
            const uint32_t smc_size =
                (smc_boot_size > 0 && smc_boot_size <= kKeyvaultOffset) ? smc_boot_size : 0x3000;
            const uint32_t smc_offset = kKeyvaultOffset - smc_size;
            auto smc_bytes = driver.read_clean(smc_offset, smc_size);
            if (!smc_bytes.empty()) {
                if (auto parsed = Smc::parse(smc_bytes)) {
                    smc = std::move(*parsed);
                    Log::Debug("Extracted SMC from NAND (0x{:X} bytes)", smc_bytes.size());
                } else {
                    Log::Debug("SMC not extracted: {}", parsed.error().describe());
                }
            }

            auto kv_bytes = driver.read_clean(kKeyvaultOffset, Keyvault::kSize);
            if (!kv_bytes.empty()) {
                if (auto parsed = Keyvault::parse(kv_bytes)) {
                    keyvault = std::move(*parsed);
                    Log::Debug("Extracted Keyvault from NAND (0x{:X} bytes)", kv_bytes.size());
                } else {
                    keyvault.reset();
                    Log::Warn("The NAND's Keyvault is not kept: {}", parsed.error().describe());
                }
            }
        }

        template <class T> struct StageOf {
            using type = T;
        };
        template <class T> struct StageOf<std::optional<T>> {
            using type = T;
        };

        template <class Target>
        [[nodiscard]] Result<void> parse_section(Target& target, std::span<const uint8_t> bytes,
                                                 std::string_view name, size_t offset) {
            auto parsed = StageOf<Target>::type::parse(bytes);
            if (!parsed) {
                return std::unexpected(std::move(parsed.error())
                                           .add_context(std::format("{} at 0x{:X}", name, offset)));
            }
            target = std::move(*parsed);
            return {};
        }

        constexpr uint16_t kCbXVersion = 15432;

        template <class Target>
        [[nodiscard]] Result<std::string_view> parse_named(Target& target,
                                                           std::span<const uint8_t> bytes,
                                                           std::string_view name, size_t offset) {
            if (auto parsed = parse_section(target, bytes, name, offset); !parsed) {
                return std::unexpected(std::move(parsed.error()));
            }
            return name;
        }

        [[nodiscard]] Result<std::string_view>
        parse_boot_record(uint16_t magic, uint16_t version, std::span<const uint8_t> bytes,
                          size_t offset, CbSection& cb_section, KernelSection& kernel_section) {
            switch (magic) {
                case NANDBootloaderMagic::SB:
                    if (!cb_section.cb_or_A.data.empty()) {
                        return std::string_view{};
                    }
                    return parse_named(cb_section.cb_or_A, bytes, "SB", offset);
                case NANDBootloaderMagic::SD:
                    return parse_named(kernel_section.cd, bytes, "SD", offset);
                case NANDBootloaderMagic::SE:
                    return parse_named(kernel_section.ce, bytes, "SE", offset);
                case NANDBootloaderMagic::CB:
                    if (version == kCbXVersion) {
                        return parse_named(cb_section.cb_x, bytes, "CB", offset);
                    }
                    if (cb_section.cb_or_A.data.empty()) {
                        return parse_named(cb_section.cb_or_A, bytes, "CB", offset);
                    }
                    return parse_named(cb_section.cb_B, bytes, "CB", offset);
                case NANDBootloaderMagic::SC:
                    return parse_named(cb_section.sc, bytes, "SC", offset);
                case NANDBootloaderMagic::CD:
                    return parse_named(kernel_section.cd, bytes, "CD", offset);
                case NANDBootloaderMagic::CE:
                    return parse_named(kernel_section.ce, bytes, "CE", offset);
                default:
                    return std::string_view{};
            }
        }

        // walks 16-byte aligned stage headers from 0x8000 until it hits an unknown magic or bogus size
        [[nodiscard]] Result<void> scan_boot_chain(const Driver& driver, size_t image_size,
                                                   CbSection& cb_section,
                                                   KernelSection& kernel_section) {
            size_t cursor = kEntryOffset;
            while (cursor + sizeof(generic_header) <= image_size) {
                const auto bldr_hdr_bytes = driver.read_clean(cursor, sizeof(generic_header));
                const auto bldr_hdr =
                    wire::read<generic_header>(bldr_hdr_bytes, 0, "bootloader stage header");
                if (!bldr_hdr) {
                    break;
                }

                const uint16_t magic = bldr_hdr->magic.get();
                const uint16_t version = bldr_hdr->version.get();
                const uint32_t bldr_size = bldr_hdr->size.get();

                if (bldr_size == 0 || bldr_size > 0x100000 || cursor + bldr_size > image_size) {
                    break;
                }

                auto bldr_data = driver.read_clean(cursor, align_16(bldr_size));

                auto name = parse_boot_record(magic, version, bldr_data, cursor, cb_section,
                                              kernel_section);
                if (!name) {
                    return std::unexpected(std::move(name.error()));
                }
                if (name->empty()) {
                    break;
                }
                Log::Debug("Parsed {} bootloader at offset 0x{:X} (version {}, size 0x{:X})", *name,
                           cursor, version, bldr_size);

                cursor += align_16(bldr_size);
            }
            return {};
        }

        // decrypts a temporary copy of cf to read the spill table and stitch the rest of cg together
        [[nodiscard]] Result<std::vector<uint8_t>>
        read_cg_continuation(const Driver& driver, const BootloaderCf& cf, uint32_t base_offset,
                             size_t cg_offset, uint32_t cg_size, size_t prefix,
                             std::vector<uint16_t>& spill) {
            auto decoded_cf = cf;
            if (auto opened = decoded_cf.decrypt(key_1bl); !opened) {
                auto error = with_context(
                    std::move(opened),
                    std::format("opening the CF at 0x{:X} for its CG continuation table",
                                base_offset));
                return std::unexpected(std::move(error.error()));
            }
            const auto& payload = decoded_cf.data;
            std::array<uint8_t, kCfTableSize> table_bytes{};
            std::copy_n(payload.begin(), std::min(payload.size(), table_bytes.size()),
                        table_bytes.begin());
            const auto table =
                wire::read<cf_continuation_table>(table_bytes, 0, "CF continuation table");
            if (!table) {
                return std::unexpected(table.error());
            }
            const size_t count = table->count.get();
            const size_t needed = (cg_size - prefix + kCgClusterSize - 1) / kCgClusterSize;
            if (count > 0 && count <= kMaxCgClusters && count != needed) {
                return fail(ErrorCode::Malformed,
                            "the CF at 0x{:X} names {} CG continuation clusters; the CG needs {}",
                            base_offset, count, needed);
            }
            if (count != needed || count > kMaxCgClusters || payload.size() < 2 + count * 2) {
                return driver.read_clean(cg_offset, cg_size);
            }

            auto cg_data = driver.read_clean(cg_offset, prefix);
            const size_t data_area = driver.data_block_limit() * driver.block_size_clean();
            for (size_t i = 0; i < count; ++i) {
                const uint16_t block = table->clusters[i].get();
                if (size_t(block) * kCgClusterSize >= data_area ||
                    std::find(spill.begin(), spill.end(), block) != spill.end()) {
                    return fail(ErrorCode::Malformed,
                                "the CF at 0x{:X} names CG continuation cluster 0x{:X} outside "
                                "the data area or twice",
                                base_offset, block);
                }
                const size_t length = std::min<size_t>(kCgClusterSize, cg_size - cg_data.size());
                auto part = driver.read_clean(size_t(block) * kCgClusterSize, length);
                if (part.size() != length) {
                    return fail(ErrorCode::Truncated,
                                "CG continuation cluster 0x{:X} could not be read", block);
                }
                cg_data.insert(cg_data.end(), part.begin(), part.end());
                spill.push_back(block);
            }
            return cg_data;
        }

        [[nodiscard]] Result<void> parse_update_slot(const Driver& driver, size_t image_size,
                                                     uint32_t base_offset, uint32_t slot_stride,
                                                     SystemUpdate& slot) {
            slot = SystemUpdate{};
            if (base_offset + sizeof(generic_header) > image_size) {
                return {};
            }
            const auto slot_hdr_bytes = driver.read_clean(base_offset, sizeof(generic_header));
            const auto slot_hdr =
                wire::read<generic_header>(slot_hdr_bytes, 0, "patch slot CF header");
            if (!slot_hdr || slot_hdr->magic.get() != NANDBootloaderMagic::CF) {
                return {};
            }

            const uint32_t cf_size = slot_hdr->size.get();
            if (cf_size == 0 || base_offset + cf_size > image_size) {
                return {};
            }
            auto cf_data = driver.read_clean(base_offset, cf_size);
            if (auto parsed = parse_section(slot.cf, cf_data, "CF", base_offset); !parsed) {
                return parsed;
            }

            const size_t cg_offset = base_offset + align_16(cf_size);
            if (cg_offset + sizeof(generic_header) > image_size) {
                return {};
            }
            const auto cg_hdr_bytes = driver.read_clean(cg_offset, sizeof(generic_header));
            const auto cg_hdr = wire::read<generic_header>(cg_hdr_bytes, 0, "patch slot CG header");
            if (!cg_hdr || cg_hdr->magic.get() != NANDBootloaderMagic::CG) {
                return {};
            }

            const uint32_t cg_size = cg_hdr->size.get();
            if (cg_size == 0 || cg_offset + cg_size > image_size) {
                return {};
            }
            const uint32_t slot_end = base_offset + slot_stride;
            const size_t prefix =
                std::min<size_t>(cg_size, slot_end > cg_offset ? slot_end - cg_offset : 0);
            std::vector<uint8_t> cg_data;
            if (prefix < cg_size) {
                auto continued = read_cg_continuation(driver, *slot.cf, base_offset, cg_offset,
                                                      cg_size, prefix, slot.cg_spill_blocks);
                if (!continued) {
                    return std::unexpected(std::move(continued.error()));
                }
                cg_data = std::move(*continued);
            } else {
                cg_data = driver.read_clean(cg_offset, cg_size);
            }
            return parse_section(slot.cg, cg_data, "CG", cg_offset);
        }

        [[nodiscard]] Result<void> parse_update_slots(FlashImage& image, size_t image_size,
                                                      uint32_t patchslot_base,
                                                      uint32_t slot_stride) {
            const std::array<std::pair<SystemUpdate*, const char*>, 2> slots{{
                {&image.system_update_0, "update slot 0"},
                {&image.system_update_1, "update slot 1"},
            }};
            for (size_t index = 0; index < slots.size(); ++index) {
                const uint32_t base = patchslot_base + static_cast<uint32_t>(index) * slot_stride;
                if (auto slot = parse_update_slot(image.flash_driver, image_size, base, slot_stride,
                                                  *slots[index].first);
                    !slot) {
                    return with_context(std::move(slot), slots[index].second);
                }
            }
            return {};
        }

        // scans for a valid stream of 4-byte aligned patch records ending in 0xFFFFFFFF
        std::optional<std::vector<uint8_t>> find_khv_stream(const Driver& driver, size_t offset,
                                                            size_t length) {
            const std::vector<uint8_t> bytes = driver.read_clean(offset, length);
            wire::Cursor cursor(bytes, offset);
            size_t records = 0;
            while (true) {
                const auto address = cursor.take<wire::be32>("KHV patch address");
                if (!address) {
                    return std::nullopt;
                }
                const uint32_t target = address->get();
                if (target == 0xFFFFFFFF) {
                    if (records == 0) {
                        return std::nullopt;
                    }
                    const auto stream = cursor.consumed();
                    return std::vector<uint8_t>(stream.begin(), stream.end());
                }
                if ((target & 3) != 0) {
                    return std::nullopt;
                }
                const auto count = cursor.take<wire::be32>("KHV patch word count");
                if (!count) {
                    return std::nullopt;
                }
                const uint32_t words = count->get();
                if (words == 0 || words > cursor.remaining() / 4) {
                    return std::nullopt;
                }
                if (!cursor.skip(size_t(words) * 4, "KHV patch words")) {
                    return std::nullopt;
                }
                ++records;
            }
        }

        struct KhvInference {
            std::optional<BuildType> build_type;
            std::optional<std::vector<uint8_t>> khv;
        };

        // probes +0x10 and +0x60 in the second update slot for a khv patch stream.
        KhvInference infer_khv_build_type(const Driver& driver, const nand_header& header,
                                          bool devkit_chain, size_t overlay, uint32_t slot_stride) {
            const auto khv_after = [&](size_t prefix) {
                return find_khv_stream(driver, overlay + prefix,
                                       slot_stride > prefix ? slot_stride - prefix : 0);
            };
            KhvInference inferred;
            if (devkit_chain) {
                if (header.pairing.get() != 0x8000) {
                    inferred.khv = khv_after(0x60);
                }
                inferred.build_type = inferred.khv ? BuildType::Devgl : BuildType::Devkit;
            } else if ((inferred.khv = khv_after(0x10))) {
                inferred.build_type = BuildType::Glitch2;
            } else if ((inferred.khv = khv_after(0x60))) {
                inferred.build_type = BuildType::Glitch2m;
            }
            return inferred;
        }

        void read_console_blocks(const Driver& driver, FlashImage& image) {
            const auto cfg_offset = smc_config_offset(driver);
            if (!cfg_offset) {
                return;
            }
            const size_t block_size = driver.block_size_clean();
            auto cfg_bytes = driver.read_offset(*cfg_offset, kSmcConfigLength);
            if (auto parsed = SmcConfigBlock::parse(cfg_bytes)) {
                image.smc_config = std::move(*parsed);
            }
            if (*cfg_offset >= 2 * block_size) {
                auto stats = driver.read_clean(*cfg_offset - block_size, kSettingsSpan);
                if (auto parsed = StatisticsBlock::parse(stats)) {
                    image.statistics = std::move(*parsed);
                }
                auto manu = driver.read_clean(*cfg_offset - 2 * block_size, kSettingsSpan);
                if (auto parsed = ManufacturingBlock::parse(manu)) {
                    image.manufacturing = std::move(*parsed);
                }
            }
        }

        void read_emmc_anchors(FlashImage& image) {
            const Driver& readable = image.flash_driver;
            const auto first = readable.read_offset(CoronaConfig::kOffsets[0], CoronaConfig::kSize);
            const auto second =
                readable.read_offset(CoronaConfig::kOffsets[1], CoronaConfig::kSize);
            image.corona_config = CoronaConfig::choose(
                {std::span<const uint8_t>(first), std::span<const uint8_t>(second)});
            if (!image.corona_config) {
                return;
            }

            MobileData mob{};
            for (size_t slot = 0; slot < CoronaConfig::kBlobSlots; ++slot) {
                const auto& blob = image.corona_config->blobs[slot];
                if (blob.length == 0) {
                    continue;
                }
                auto bytes =
                    readable.read_offset(static_cast<size_t>(blob.block) * 0x4000, blob.length);
                auto* target =
                    mob.get_slot(static_cast<uint8_t>(CoronaConfig::kFirstBlobType + slot));
                if (target && bytes.size() == blob.length) {
                    *target = std::vector<uint8_t>(bytes.begin(), bytes.end());
                }
            }
            if (!mob.empty()) {
                image.mobile_data = std::move(mob);
            }

            if (image.corona_config->table != 0) {
                FlashFileSystem fs{};
                if (const auto loaded = fs.load(image.flash_driver, image.corona_config->table)) {
                    image.filesystem = std::move(fs);
                } else {
                    Log::Warn("Flash File System not loaded: {}", loaded.error().describe());
                }
            }
        }

        // scans every block's spare area for the newest copy of each mobile data type (highest sequence, lowest free count)
        std::optional<MobileData> scan_mobile_copies(const Driver& driver) {
            struct MobileCopy {
                bool found = false;
                uint32_t sequence = 0;
                uint8_t free_count = 0;
                size_t first_page = 0;
                size_t page_count = 0;
                uint16_t length = 0;
            };
            std::array<MobileCopy, 9> latest{};
            const size_t total_blocks = driver.block_count();
            const size_t pages_per_block = driver.pages_per_block();
            for (size_t blk = 0; blk < total_blocks; ++blk) {
                if (driver.is_bad_block(blk)) {
                    continue;
                }
                for (size_t page = blk * pages_per_block; page < (blk + 1) * pages_per_block;
                     ++page) {
                    const auto meta = driver.interpret_page(page);
                    if (!is_mobile_block_type(meta.block_type)) {
                        continue;
                    }
                    auto& copy = latest[meta.block_type - 0x31];
                    if (copy.found && copy.sequence == meta.sequence &&
                        copy.free_count == meta.page_count &&
                        copy.first_page + copy.page_count == page) {
                        ++copy.page_count;
                        continue;
                    }
                    if (!copy.found || meta.sequence > copy.sequence ||
                        (meta.sequence == copy.sequence && meta.page_count <= copy.free_count)) {
                        copy =
                            MobileCopy{true, meta.sequence, meta.page_count, page, 1, meta.fs_size};
                    }
                }
            }

            MobileData mob{};
            for (size_t type_idx = 0; type_idx < latest.size(); ++type_idx) {
                const auto& copy = latest[type_idx];
                if (!copy.found) {
                    continue;
                }
                const size_t room = (pages_per_block - copy.first_page % pages_per_block) * 512;
                const size_t length =
                    std::min<size_t>(copy.length != 0 ? copy.length : copy.page_count * 512, room);
                auto data = driver.read_clean(copy.first_page * 512, length);
                auto* slot = mob.get_slot(static_cast<uint8_t>(type_idx + 0x31));
                if (slot && data.size() == length) {
                    *slot = std::move(data);
                }
            }
            if (mob.empty()) {
                return std::nullopt;
            }
            return mob;
        }

        std::optional<size_t> find_fs_root(const Driver& driver) {
            std::optional<size_t> best_root;
            uint32_t best_seq = 0;
            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            for (size_t blk = 0; blk < driver.block_count() * clusters_per_block; ++blk) {
                auto meta = driver.interpret_cluster(blk);
                const bool is_filesystem_root = meta.block_type == FlashFsMetadata::kRootTypeBig ||
                                                meta.block_type == FlashFsMetadata::kRootTypeSmall;
                if (is_filesystem_root && !meta.is_bad && meta.sequence != 0) {
                    if (!best_root || meta.sequence > best_seq) {
                        best_root = blk;
                        best_seq = meta.sequence;
                    }
                }
            }
            return best_root;
        }

        void load_fs_root(FlashImage& image, size_t root_cluster) {
            const size_t clusters_per_block = image.flash_driver.block_size_clean() / 0x4000;
            FlashFileSystem fs{};
            fs.set_larger_filesystem(image.build_type == BuildType::Devkit);
            const auto loaded = fs.load(image.flash_driver,
                                        static_cast<uint16_t>(root_cluster / clusters_per_block),
                                        root_cluster % clusters_per_block);
            if (loaded) {
                image.filesystem = std::move(fs);
            } else {
                Log::Warn("Flash File System not loaded: {}", loaded.error().describe());
            }
        }

        void read_storage_area(FlashImage& image) {
            if (image.flash_driver.driver_mode() == Driver::DriverMode::Emmc) {
                read_emmc_anchors(image);
                return;
            }
            if (auto mob = scan_mobile_copies(image.flash_driver)) {
                image.mobile_data = std::move(*mob);
            }
            if (const auto root = find_fs_root(image.flash_driver)) {
                load_fs_root(image, *root);
            }
        }

        std::optional<XeLL> parse_xell_at(const Driver& driver, size_t image_size, size_t offset) {
            if (offset > image_size || XeLL::kSize > image_size - offset) {
                return std::nullopt;
            }
            auto xell_span = driver.read_offset(offset, XeLL::kSize);
            if (xell_span.size() != XeLL::kSize) {
                return std::nullopt;
            }
            auto parsed = XeLL::parse(xell_span);
            if (!parsed) {
                Log::Debug("No XeLL at 0x{:X}: {}", offset, parsed.error().describe());
                return std::nullopt;
            }
            return std::move(*parsed);
        }

        bool has_payload_bytes(std::span<const uint8_t> bytes) {
            return std::any_of(bytes.begin(), bytes.end(),
                               [](uint8_t b) { return b != 0 && b != 0xFF; });
        }

        void infer_payloads(FlashImage& image, const std::optional<std::vector<uint8_t>>& khv,
                            size_t overlay) {
            const Driver& driver = image.flash_driver;
            auto& build_type = image.build_type;
            auto& payloads = image.payloads;
            if (khv) {
                if (build_type != BuildType::Glitch2m && build_type != BuildType::Devgl) {
                    build_type = image.cb_section.cb_x   ? BuildType::Glitch3
                                 : image.cb_section.cb_B ? BuildType::Glitch2
                                                         : BuildType::Glitch;
                }
                // prepends two empty 0xFFFFFFFF sections to the raw khv stream before parsing it as a patchset
                std::vector<uint8_t> automatic(8, 0xFF);
                automatic.insert(automatic.end(), khv->begin(), khv->end());
                auto recovered = parse_patch_set(automatic, *build_type);
                if (recovered) {
                    payloads.patchset = std::move(*recovered);
                } else {
                    Log::Debug("Recovered patchset not kept: {}", recovered.error().describe());
                }
            }

            const size_t image_size = driver.serialize().size();
            const uint32_t window_base = kJtagWindowOffset;
            payloads.xell = image.devkit_chain() ? std::nullopt
                                                 : parse_xell_at(driver, image_size, kXellOffset);
            if (payloads.xell) {
                if (!build_type) {
                    build_type = BuildType::Glitch2;
                }
            } else if (!build_type &&
                       image.header.cf_offset.get() != glitch_slot_offset(driver.driver_mode())) {
                payloads.xell = parse_xell_at(driver, image_size, window_base + 0x5060);
                if (payloads.xell && !build_type) {
                    build_type = BuildType::Jtag;
                }
            }

            if (build_type == BuildType::Glitch2m || build_type == BuildType::Devgl) {
                auto bytes = driver.read_clean(overlay, 0x60);
                if (bytes.size() == 0x60) {
                    payloads.fuses = std::move(bytes);
                }
            } else if (build_type == BuildType::Jtag) {
                auto rebooter = driver.read_clean(window_base, 0x1000);
                if (rebooter.size() == 0x1000 && has_payload_bytes(rebooter)) {
                    payloads.rebooter = std::move(rebooter);
                }
                auto fuses = driver.read_clean(window_base + 0x5000, 0x60);
                if (fuses.size() == 0x60 && has_payload_bytes(fuses)) {
                    payloads.fuses = std::move(fuses);
                }
            }
        }

    } // namespace

    std::optional<FlashImage> FlashImage::read(std::vector<uint8_t> raw_image) {
        if (raw_image.empty()) {
            return std::nullopt;
        }

        FlashImage image{};
        image.flash_driver = Driver(std::move(raw_image));
        return image;
    }

    Result<void> FlashImage::parse() {
        auto decoded = decode_nand_header(flash_driver);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }

        preserve_layout = true;
        header = *decoded;

        Log::Debug("Parsed NAND header: magic=0x{:04X}, version=0x{:04X}, entry=0x{:08X}, "
                   "kv_addr=0x{:08X}",
                   header.magic, header.version, header.entrypoint, header.kv_addr);

        read_secure_head(flash_driver, header, smc, keyvault);

        const auto& image_bytes = std::as_const(flash_driver).serialize();
        if (auto chain =
                scan_boot_chain(flash_driver, image_bytes.size(), cb_section, kernel_section);
            !chain) {
            return chain;
        }

        const auto slot_mode = flash_driver.driver_mode();
        const uint32_t slot_stride = header_slot_stride(header);
        const uint32_t patchslot_base = donor_update_base(header, slot_mode);

        if (auto slots = parse_update_slots(*this, image_bytes.size(), patchslot_base, slot_stride);
            !slots) {
            return slots;
        }

        const size_t overlay = size_t(patchslot_base) + slot_stride;
        auto inferred =
            infer_khv_build_type(flash_driver, header, devkit_chain(), overlay, slot_stride);
        if (inferred.build_type) {
            build_type = inferred.build_type;
        }

        read_console_blocks(flash_driver, *this);
        read_storage_area(*this);
        infer_payloads(*this, inferred.khv, overlay);

        return {};
    }

} // namespace gxbuild3::nand
