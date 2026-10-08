#include "BuildRunner.hpp"
#include "GoldenSnapshot.hpp"
#include "TestResult.hpp"
#include "excrypt.h"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/Patchset.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/XeRsaTestKey.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/Stages.hpp"
#include "support/render/ExtractProjection.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;

    // The failed extraction a test takes when the image it extracts from did not build.
    const std::unexpected<gxbuild3::Error>
        not_built(std::in_place, gxbuild3::ErrorCode::InvalidArgument, "the image did not build");

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    bool require(const gxbuild3::Result<>& result, std::string_view message) {
        if (!result) {
            std::cerr << "FAIL: " << message << ": " << result.error().describe() << '\n';
            return false;
        }
        return true;
    }

    // The shared builders (tests/support/builders/), byte for byte what this file defined.
    using gxbuild3::test::append_be32;
    using gxbuild3::test::append_patch_entry;
    using gxbuild3::test::canonical_keyvault;
    using gxbuild3::test::clean_retail_smc;
    using gxbuild3::test::devgl_input;
    using gxbuild3::test::devgl_khv;
    using gxbuild3::test::devgl_sd_patch_address;
    using gxbuild3::test::devkit_bootloaders;
    using gxbuild3::test::devkit_input;
    using gxbuild3::test::different_valid_cpu_key;
    using gxbuild3::test::digest_input;
    using gxbuild3::test::filled_nonce;
    using gxbuild3::test::fresh_input;
    using gxbuild3::test::glitch_input;
    using gxbuild3::test::glitch_patchset;
    using gxbuild3::test::invalid_cpu_key;
    using gxbuild3::test::jtag_input;
    using gxbuild3::test::jtag_patchset;
    using gxbuild3::test::kSmcRebootSite;
    using gxbuild3::test::make_jtag_smc;
    using gxbuild3::test::make_smc;
    using gxbuild3::test::mark_jtag_smc;
    using gxbuild3::test::nonce_bytes;
    using gxbuild3::test::pinned_donor_nonces;
    using gxbuild3::test::sha1_hex;
    using gxbuild3::test::valid_bootloaders;
    using gxbuild3::test::valid_ce;
    using gxbuild3::test::valid_cpu_key;
    using gxbuild3::test::valid_system_update;
    using gxbuild3::test::valid_xell;

    // The Result-returning builders, unwrapped as before: a failure aborts the binary with its
    // description. These go as their callers are ported.
    std::optional<Bytes> opened_cg(const Bytes& cf_bytes, const Bytes& cg_bytes) {
        return test::must(gxbuild3::test::opened_cg(cf_bytes, cg_bytes));
    }

    Bytes decrypted_cf(uint8_t lockdown_value, std::array<uint8_t, 3> pairing_data,
                       uint16_t source_version = 0, uint16_t source_qfe = 0,
                       uint16_t target_version = 0, uint16_t target_qfe = 0, uint32_t reserved = 0,
                       uint32_t cg_size = 0) {
        return test::must(gxbuild3::test::decrypted_cf(lockdown_value, pairing_data, source_version,
                                                       source_qfe, target_version, target_qfe,
                                                       reserved, cg_size));
    }

    Bytes make_donor(const Input& source,
                     std::initializer_list<std::pair<uint8_t, Bytes>> mobiles) {
        return test::must(gxbuild3::test::make_donor(source, mobiles));
    }

    uint32_t read_be32(std::span<const uint8_t> bytes, size_t offset) {
        return (static_cast<uint32_t>(bytes[offset]) << 24) |
               (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
               (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
               static_cast<uint32_t>(bytes[offset + 3]);
    }

    uint32_t align_16(uint32_t value) {
        return (value + 0x0F) & ~uint32_t{0x0F};
    }

    bool zero_between(std::span<const uint8_t> bytes, size_t begin, size_t end) {
        return end <= bytes.size() &&
               std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                           bytes.begin() + static_cast<std::ptrdiff_t>(end),
                           [](uint8_t byte) { return byte == 0; });
    }

    uint16_t read_be16(std::span<const uint8_t> bytes, size_t offset) {
        return static_cast<uint16_t>((static_cast<uint16_t>(bytes[offset]) << 8) |
                                     static_cast<uint16_t>(bytes[offset + 1]));
    }

    std::optional<Bytes> read_logical(std::span<const uint8_t> image, size_t offset,
                                      size_t length) {
        auto parsed = FlashImage::read(Bytes(image.begin(), image.end()));
        if (!parsed || !parsed->parse()) {
            return std::nullopt;
        }
        const auto bytes = std::as_const(parsed->flash_driver).read_offset(offset, length);
        return Bytes(bytes.begin(), bytes.end());
    }

    std::optional<FlashImage> parse_image(std::span<const uint8_t> bytes) {
        auto image = FlashImage::read(Bytes(bytes.begin(), bytes.end()));
        if (!image || !image->parse()) {
            return std::nullopt;
        }
        return image;
    }

    void set_source_date_epoch(const char* value) {
#ifdef _WIN32
        _putenv_s("SOURCE_DATE_EPOCH", value ? value : "");
#else
        if (value) {
            setenv("SOURCE_DATE_EPOCH", value, 1);
        } else {
            unsetenv("SOURCE_DATE_EPOCH");
        }
#endif
    }

    bool test_system_update_slot_zero_spills_and_preserves_slot_one() {
        auto input = fresh_input(ImageType::SmallBlock);
        const auto [cf0, ignored_cg0] = valid_system_update(0x51);
        const auto [cf1, cg1] = valid_system_update(0x61);
        BootloaderCg cg0{};
        cg0.header.header.magic = NANDBootloaderMagic::CG;
        cg0.header.header.version = 1;
        cg0.data.assign(0x10000, 0x7A);
        cg0.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg0.data.size());
        input.bootloaders.cf0 = cf0;
        input.bootloaders.cg0 = cg0.serialize();
        input.bootloaders.cf1 = cf1;
        input.bootloaders.cg1 = cg1;

        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        return require(image && image->parse() && image->header.patch_slots == 2 &&
                           !image->system_update_0.cg_spill_blocks.empty() &&
                           image->system_update_1.cf && image->system_update_1.cg &&
                           opened_cg(image->system_update_0.cf->serialize(),
                                     image->system_update_0.cg->serialize()) ==
                               opened_cg(cf0, cg0.serialize()) &&
                           opened_cg(image->system_update_1.cf->serialize(),
                                     image->system_update_1.cg->serialize()) == opened_cg(cf1, cg1),
                       "slot-zero CG spills while both supplied update slots survive");
    }

    bool test_fresh_build_seals_stages_under_random_nonces() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.ce = valid_ce();
        const auto first = run_build(input);
        const auto second = run_build(input);
        auto one = first ? parse_image(*first) : std::nullopt;
        auto two = second ? parse_image(*second) : std::nullopt;
        if (!require(one && two && one->kernel_section.ce && two->kernel_section.ce,
                     "fresh nonce fixtures build and parse")) {
            return false;
        }
        const auto nonces = [](const FlashImage& image) {
            return std::array<Bytes, 3>{nonce_bytes(image.cb_section.cb_or_A.data),
                                        nonce_bytes(image.kernel_section.cd.header.key),
                                        nonce_bytes(image.kernel_section.ce->header.key)};
        };
        const auto first_nonces = nonces(*one);
        const auto second_nonces = nonces(*two);
        bool distinct = true;
        bool non_zero = true;
        for (size_t index = 0; index < first_nonces.size(); ++index) {
            distinct = distinct && first_nonces[index] != second_nonces[index];
            non_zero = non_zero && first_nonces[index] != Bytes(0x10, 0);
        }
        const bool decrypted = one->decrypt_all(input.metadata.cpu_key).has_value();
        return require(non_zero, "fresh CB, CD and CE take non-zero nonces") &&
               require(first_nonces[2] != Bytes(0x10, 0x55),
                       "a fresh CE does not keep its template's nonce") &&
               require(distinct, "each fresh build draws new nonces") &&
               require(decrypted && one->kernel_section.cd.data == Bytes(0x20, 0x42) &&
                           one->kernel_section.ce->data == Bytes(0x20, 0xCE),
                       "stages sealed under fresh nonces decrypt to their payloads");
    }

    bool test_donor_nonces_seal_stages_by_position_and_every_slot_alike() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.ce = valid_ce();
        input.bootloaders.cf0 = decrypted_cf(3, {0x11, 0x12, 0x13});
        input.bootloaders.cg0 = valid_system_update(0x51).second;
        input.bootloaders.cf1 = decrypted_cf(4, {0x11, 0x12, 0x13});
        input.bootloaders.cg1 = valid_system_update(0x61).second;
        DonorNonces nonces{};
        nonces.stages = {filled_nonce(0xA1), filled_nonce(0xA2), filled_nonce(0xA3),
                         filled_nonce(0xA4)};
        nonces.cf = filled_nonce(0xB1);
        nonces.cg = filled_nonce(0xC1);
        input.metadata.donor_nonces = nonces;

        const auto built = run_build(input);
        auto image = built ? parse_image(*built) : std::nullopt;
        if (!require(image && image->kernel_section.ce && image->system_update_0.cf &&
                         image->system_update_0.cg && image->system_update_1.cf &&
                         image->system_update_1.cg,
                     "donor nonce fixture builds and parses")) {
            return false;
        }
        const auto is = [](std::span<const uint8_t> bytes, uint8_t value) {
            return nonce_bytes(bytes) == Bytes(0x10, value);
        };
        const bool decrypted = image->decrypt_all(input.metadata.cpu_key).has_value();
        return require(is(image->cb_section.cb_or_A.data, 0xA1) &&
                           is(image->kernel_section.cd.header.key, 0xA3) &&
                           is(image->kernel_section.ce->header.key, 0xA4),
                       "first CB, CD and CE take the donor nonces of their positions") &&
               require(is(image->system_update_0.cf->header.fixpoint_nonce, 0xB1) &&
                           is(image->system_update_1.cf->header.fixpoint_nonce, 0xB1) &&
                           is(image->system_update_0.cg->header.key, 0xC1) &&
                           is(image->system_update_1.cg->header.key, 0xC1),
                       "every update slot takes the donor CF and CG nonces") &&
               require(decrypted && image->kernel_section.cd.data == Bytes(0x20, 0x42) &&
                           image->kernel_section.ce->data == Bytes(0x20, 0xCE),
                       "stages sealed under donor nonces decrypt to their payloads");
    }

    bool test_extraction_takes_cf_metadata_and_nonces_from_the_max_ldv_slot() {
        auto source = fresh_input(ImageType::SmallBlock);
        source.bootloaders.ce = valid_ce();
        source.bootloaders.cf0 = decrypted_cf(3, {0x11, 0x12, 0x13});
        source.bootloaders.cg0 = valid_system_update(0x51).second;
        source.bootloaders.cf1 = decrypted_cf(7, {0x11, 0x12, 0x13});
        source.bootloaders.cg1 = valid_system_update(0x61).second;
        source.metadata.pairing_data = {0x21, 0x22, 0x23};
        const auto built = run_build(source);

        // Slot 1 states its own pairing, as after an update installed under other pairing.
        auto staged = built ? parse_image(*built) : std::nullopt;
        if (!require(staged && staged->decrypt_all(source.metadata.cpu_key) &&
                         staged->system_update_1.cf && staged->system_update_1.cf->perbox,
                     "max-LDV donor fixture builds and decrypts")) {
            return false;
        }
        const std::array<uint8_t, 3> slot_one_pairing{0x31, 0x32, 0x33};
        std::copy(slot_one_pairing.begin(), slot_one_pairing.end(),
                  staged->system_update_1.cf->perbox->pairing_data);
        if (!require(staged->encrypt_all(source.metadata.cpu_key),
                     "max-LDV donor fixture re-encrypts")) {
            return false;
        }
        const auto donor = staged->write().value_or(Bytes{});
        auto donor_image = parse_image(donor);
        const auto extracted = extract_all(donor, source.metadata.cpu_key);
        const auto metadata = extract_metadata(donor, source.metadata.cpu_key);
        if (!require(donor_image && extracted && metadata && extracted->metadata.donor_nonces &&
                         metadata->donor_nonces,
                     "max-LDV donor fixture extracts")) {
            return false;
        }
        const auto& nonces = *extracted->metadata.donor_nonces;
        const auto equal = [](const std::optional<BootloaderNonce>& nonce,
                              std::span<const uint8_t> bytes) {
            return nonce && Bytes(nonce->begin(), nonce->end()) == nonce_bytes(bytes);
        };
        const bool cf_metadata = extracted->metadata.cf_ldv == 7 &&
                                 extracted->metadata.cf_pairing_data == slot_one_pairing &&
                                 metadata->cf_ldv == 7 &&
                                 metadata->cf_pairing_data == slot_one_pairing;
        const bool slot_nonces =
            equal(nonces.cf, donor_image->system_update_1.cf->header.fixpoint_nonce) &&
            equal(nonces.cg, donor_image->system_update_1.cg->header.key);
        const bool stage_order =
            equal(nonces.stages[0], donor_image->cb_section.cb_or_A.data) && !nonces.stages[1] &&
            equal(nonces.stages[2], donor_image->kernel_section.cd.header.key) &&
            equal(nonces.stages[3], donor_image->kernel_section.ce->header.key);

        auto rebuild = *extracted;
        rebuild.bootloaders = source.bootloaders;
        const auto rebuilt = run_build(rebuild);
        auto image = rebuilt ? parse_image(*rebuilt) : std::nullopt;
        const bool rebuilt_decrypts = image && image->decrypt_all(source.metadata.cpu_key);
        return require(cf_metadata, "CF LDV and pairing come from the max-LDV donor slot") &&
               require(slot_nonces, "donor CF and CG nonces come from the max-LDV slot") &&
               require(stage_order, "donor stage nonces are read by chain position") &&
               require(
                   rebuilt_decrypts &&
                       nonce_bytes(image->cb_section.cb_or_A.data) ==
                           nonce_bytes(donor_image->cb_section.cb_or_A.data) &&
                       nonce_bytes(image->system_update_0.cf->header.fixpoint_nonce) ==
                           nonce_bytes(donor_image->system_update_1.cf->header.fixpoint_nonce) &&
                       nonce_bytes(image->system_update_1.cf->header.fixpoint_nonce) ==
                           nonce_bytes(donor_image->system_update_1.cf->header.fixpoint_nonce) &&
                       nonce_bytes(image->system_update_0.cg->header.key) ==
                           nonce_bytes(donor_image->system_update_1.cg->header.key) &&
                       nonce_bytes(image->system_update_1.cg->header.key) ==
                           nonce_bytes(donor_image->system_update_1.cg->header.key),
                   "a rebuild over the donor reuses its CB and max-LDV CF and CG nonces") &&
               require(image->system_update_0.cf->perbox &&
                           image->system_update_0.cf->perbox->lockdown_value == 7 &&
                           std::equal(slot_one_pairing.begin(), slot_one_pairing.end(),
                                      image->system_update_0.cf->perbox->pairing_data),
                       "the rebuilt CF states the max-LDV slot's LDV and pairing");
    }

    bool test_clear_bootloader_chain_clears_header_only_cb_and_cd_records() {
        const auto source = run_build(fresh_input(ImageType::SmallBlock));
        auto donor = source ? FlashImage::read(*source) : std::nullopt;
        if (!require(donor.has_value() && donor->parse(),
                     "source donor for header-only chain parses")) {
            return false;
        }

        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.header.header.size = sizeof(generic_header);
        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = sizeof(cd_header);
        const auto cb_bytes = cb.serialize();
        const auto cd_bytes = cd.serialize();
        const bool donor_written =
            donor->flash_driver.write_offset(0x8000, Bytes(0x1000, 0)) &&
            donor->flash_driver.write_offset(0x8000, cb_bytes) &&
            donor->flash_driver.write_offset(0x8000 + cb_bytes.size(), cd_bytes);
        const auto header_only_bytes = donor->flash_driver.serialize();
        auto header_only = donor_written ? FlashImage::read(header_only_bytes) : std::nullopt;
        const bool header_only_parsed = header_only && header_only->parse();
        const bool records_are_header_only =
            header_only_parsed && header_only->cb_section.cb_or_A.data.empty() &&
            header_only->cb_section.cb_or_A.header.header.magic == NANDBootloaderMagic::CB &&
            header_only->kernel_section.cd.data.empty() &&
            header_only->kernel_section.cd.header.header.magic == NANDBootloaderMagic::CD;
        const bool cleared = records_are_header_only && header_only->clear_bootloader_chain();
        const auto cleared_bytes = cleared
                                       ? std::as_const(header_only->flash_driver)
                                             .read_offset(0x8000, cb_bytes.size() + cd_bytes.size())
                                       : std::span<const uint8_t>{};
        const bool all_zero = std::all_of(cleared_bytes.begin(), cleared_bytes.end(),
                                          [](uint8_t value) { return value == 0; });

        auto invalid_replacement = fresh_input(ImageType::SmallBlock);
        invalid_replacement.bootloaders.cd = cd_bytes;
        const auto rejected = run_build(invalid_replacement);
        return require(donor_written && records_are_header_only,
                       "raw donor exposes valid parsed header-only CB and CD records") &&
               require(cleared && all_zero,
                       "clearing a donor includes the full header-only CB and CD chain") &&
               require(!rejected && rejected.error().code == BuildErrorCode::InvalidBootloader,
                       "a replacement header-only required CD remains structurally invalid");
    }

    bool all_bytes(std::span<const uint8_t> bytes, uint8_t value) {
        return !bytes.empty() &&
               std::all_of(bytes.begin(), bytes.end(), [value](uint8_t b) { return b == value; });
    }

    // Every page from `first_page` on: 0xFF data and an erased spare.
    bool pages_are_erased(const Driver& driver, size_t first_page, size_t page_count) {
        for (size_t page = first_page; page < first_page + page_count; ++page) {
            if (!all_bytes(driver.read_page(page), 0xFF) ||
                !all_bytes(driver.read_page_spare(page), 0xFF)) {
                return false;
            }
        }
        return true;
    }

    bool test_donor_build_leaves_unlaid_space_erased() {
        const auto initial = run_build(fresh_input(ImageType::SmallBlock));
        auto donor = initial ? FlashImage::read(*initial) : std::nullopt;
        if (!require(donor.has_value(), "erased-fill donor image opens")) {
            return false;
        }

        // A donor's old data in update slot 1, in a free filesystem block and in the remap
        // pool, each block programmed with a data spare; and one block the chip marked bad.
        constexpr size_t kSlotOneBlock = 0x80000 / 0x4000;
        constexpr size_t kStaleBlock = 0x3B0;
        constexpr size_t kPoolBlock = 0x3F0;
        constexpr size_t kBadBlock = 0x3C0;
        for (const size_t block : {kSlotOneBlock, kStaleBlock, kPoolBlock}) {
            BlockMetadata stale{};
            stale.logical_block_id = static_cast<uint16_t>(block);
            stale.block_type = 0x28;
            if (!require(donor->flash_driver.write_block(block, Bytes(0x4000, 0x5A)),
                         "the donor's old data is laid")) {
                return false;
            }
            donor->flash_driver.write_block_metadata(block, stale);
        }
        donor->flash_driver.mark_bad_block(kBadBlock);

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = donor->flash_driver.serialize();
        const auto built = run_build(input);
        const auto image = built ? parse_image(*built) : std::nullopt;
        if (!require(image.has_value(), "a build over a donor with old data parses")) {
            return false;
        }
        const auto& driver = image->flash_driver;
        const size_t pages = driver.pages_per_block();

        // The header block is zero from the header to the SMC; the boot chain's last 16 KiB
        // block is zero past its end; the rest up to the first update slot is erased.
        const auto smc_offset = driver.read_clean(0x7C, 4);
        const size_t smc_at = smc_offset.size() == 4
                                  ? (size_t(smc_offset[0]) << 24) | (size_t(smc_offset[1]) << 16) |
                                        (size_t(smc_offset[2]) << 8) | smc_offset[3]
                                  : 0;
        size_t chain_end = 0x8000;
        const auto account = [&chain_end](const auto& bootloader) {
            chain_end += (bootloader.serialize().size() + 0xF) & ~size_t{0xF};
        };
        account(image->cb_section.cb_or_A);
        if (image->cb_section.cb_x) {
            account(*image->cb_section.cb_x);
        }
        if (image->cb_section.cb_B) {
            account(*image->cb_section.cb_B);
        }
        if (image->cb_section.sc) {
            account(*image->cb_section.sc);
        }
        account(image->kernel_section.cd);
        if (image->kernel_section.ce) {
            account(*image->kernel_section.ce);
        }
        const size_t pad_end = (chain_end + 0x3FFF) / 0x4000 * 0x4000;

        return require(smc_at > 0x80 && all_bytes(driver.read_clean(0x80, smc_at - 0x80), 0),
                       "the header block is zero from the header to the SMC") &&
               require(pad_end < 0x70000 &&
                           all_bytes(driver.read_clean(chain_end, pad_end - chain_end), 0),
                       "the boot chain's last block is zero past the chain") &&
               require(pages_are_erased(driver, pad_end / 512, (0x70000 - pad_end) / 512),
                       "the blocks between the chain and the first update slot stay erased") &&
               require(pages_are_erased(driver, kSlotOneBlock * pages, 4 * pages),
                       "an unused update slot 1 is erased, not zeroed or left to the donor") &&
               require(pages_are_erased(driver, kStaleBlock * pages, pages),
                       "a donor's old filesystem block is erased") &&
               require(pages_are_erased(driver, kPoolBlock * pages, pages),
                       "a donor's remap-pool block is erased") &&
               require(driver.is_bad_block(kBadBlock), "a block marked bad keeps its mark");
    }

    bool test_emmc_build_leaves_anchor_tails_and_unused_blocks_erased() {
        using gxbuild3::nand::CoronaConfig;
        const auto built = run_build(fresh_input(ImageType::Emmc));
        if (!require(built.has_value() && built->size() == 0x3000000, "an eMMC image builds")) {
            return false;
        }
        const std::span<const uint8_t> bytes(*built);
        bool ok = true;
        for (const size_t anchor : CoronaConfig::kOffsets) {
            ok = require(all_bytes(bytes.subspan(anchor + CoronaConfig::kSize,
                                                 CoronaConfig::kSpan - CoronaConfig::kSize),
                                   0),
                         "an anchor's span is zero after its structure") &&
                 require(all_bytes(bytes.subspan(anchor + CoronaConfig::kSpan,
                                                 CoronaConfig::kBlockSize - CoronaConfig::kSpan),
                                   0xFF),
                         "an anchor's block is erased past its span") &&
                 ok;
        }
        return require(all_bytes(bytes.subspan(0x80000, 0x10000), 0xFF),
                       "an unused eMMC update slot 1 is erased") &&
               require(all_bytes(bytes.subspan(0xB00 * 0x4000, 0x4000), 0xFF),
                       "an unused eMMC block is erased") &&
               ok;
    }

    bool test_bigblock_flashfs_stamps_only_the_clusters_it_fills() {
        auto input = fresh_input(ImageType::BigBlock);
        input.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"small.bin", Bytes(0x100, 0x6B)}};
        const auto built = run_build(input);
        const auto image = built ? parse_image(*built) : std::nullopt;
        const auto entry =
            image && image->filesystem ? image->filesystem->stat("small.bin") : std::nullopt;
        if (!require(entry.has_value(), "a big-block image with one small file parses")) {
            return false;
        }
        const auto& driver = image->flash_driver;
        const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
        const size_t file_cluster = entry->block_number;
        const size_t first_cluster = file_cluster / clusters_per_block * clusters_per_block;
        bool rest_erased = true;
        for (size_t cluster = first_cluster; cluster < first_cluster + clusters_per_block;
             ++cluster) {
            if (cluster != file_cluster && !pages_are_erased(driver, cluster * 32, 32)) {
                rest_erased = false;
            }
        }
        return require(driver.interpret_cluster(file_cluster).block_type == 0x2A,
                       "the file's cluster carries the big-block data stamp") &&
               require(rest_erased, "the rest of the file's big block stays erased");
    }

    std::array<uint8_t, 16> hmac_key(std::span<const uint8_t> parent,
                                     std::span<const uint8_t> nonce) {
        uint8_t digest[20];
        ExCryptHmacSha(parent.data(), static_cast<uint32_t>(parent.size()), nonce.data(),
                       static_cast<uint32_t>(nonce.size()), nullptr, 0, nullptr, 0, digest, 20);
        std::array<uint8_t, 16> key{};
        std::copy_n(digest, key.size(), key.begin());
        return key;
    }

    // A stage opened by hand: its nonce at 0x10 keys RC4 over everything from 0x20.
    Bytes open_stage(Bytes stage, std::span<const uint8_t> key) {
        ExCryptRc4(key.data(), static_cast<uint32_t>(key.size()), stage.data() + 0x20,
                   static_cast<uint32_t>(stage.size() - 0x20));
        return stage;
    }

    bool test_devkit_chain_is_sealed_from_the_zero_secret() {
        const auto input = devkit_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        if (!require(built.has_value() && built->size() == 0x4200000,
                     "a small-block devkit image is 64 MB with spare")) {
            return false;
        }

        const auto header = read_logical(*built, 0, 0x80);
        const uint32_t chain_end = 0x8000 + align_16(uint32_t(input.bootloaders.cb_or_a.size())) +
                                   align_16(uint32_t(input.bootloaders.sc->size())) +
                                   align_16(uint32_t(input.bootloaders.cd.size())) +
                                   align_16(uint32_t(input.bootloaders.ce->size()));
        const uint32_t slot = (chain_end + 0x3FFF) & ~uint32_t{0x3FFF};
        const std::string_view copyright =
            header ? std::string_view(reinterpret_cast<const char*>(header->data() + 0x10), 0x37)
                   : std::string_view{};
        if (!require(header && read_be16(*header, 0x02) == 17489,
                     "the devkit header states the SE build") ||
            !require(read_be16(*header, 0x04) == 0x8000,
                     "the devkit header states 0x8000 at 0x04") ||
            !require(copyright.find("2004-2010") != std::string_view::npos,
                     "the devkit header states 2010 on a Jasper") ||
            !require(read_be32(*header, 0x0C) == slot && read_be32(*header, 0x64) == slot,
                     "the first slot follows the chain at the next erase block") ||
            !require(read_be16(*header, 0x68) == 2 && read_be32(*header, 0x70) == 0x10000,
                     "the devkit header states two slots of 0x10000") ||
            !require(read_be32(*header, 0x48) == 0 && read_be32(*header, 0x4C) == 0,
                     "a devkit image states no hack or boot flags")) {
            return false;
        }

        size_t at = 0x8000;
        const auto stored = [&](const Bytes& supplied) {
            auto bytes = read_logical(*built, at, supplied.size());
            at += align_16(static_cast<uint32_t>(supplied.size()));
            return bytes.value_or(Bytes{});
        };
        const auto sb = stored(input.bootloaders.cb_or_a);
        const auto sc = stored(*input.bootloaders.sc);
        const auto sd = stored(input.bootloaders.cd);
        const auto se = stored(*input.bootloaders.ce);
        const auto nonce = [](const Bytes& stage) {
            return std::span<const uint8_t>(stage).subspan(0x10, 0x10);
        };
        const std::array<uint8_t, 16> zero{};
        const auto k_sb = hmac_key(std::span(key_1bl), nonce(sb));
        const auto k_sc = hmac_key(zero, nonce(sc));
        const auto k_sd = hmac_key(k_sc, nonce(sd));
        const auto k_se = hmac_key(k_sd, nonce(se));
        const auto sb_plain = open_stage(sb, k_sb);
        const auto body_equal = [](const Bytes& opened, const Bytes& supplied, size_t from) {
            return opened.size() == supplied.size() &&
                   std::equal(opened.begin() + from, opened.end(), supplied.begin() + from);
        };
        return require(body_equal(sb_plain, input.bootloaders.cb_or_a, 0x40),
                       "SB opens under HMAC(1BL key, nonce)") &&
               require(std::equal(sb_plain.begin() + 0x20, sb_plain.begin() + 0x23,
                                  input.metadata.pairing_data.begin()),
                       "SB carries the console's pairing") &&
               require(!zero_between(sb_plain, 0x30, 0x40),
                       "SB binds the SMC in its per-box digest") &&
               require(body_equal(open_stage(sc, k_sc), *input.bootloaders.sc, 0x20),
                       "SC opens under HMAC(16 zero bytes, nonce)") &&
               require(body_equal(open_stage(sd, k_sd), input.bootloaders.cd, 0x20),
                       "SD opens under HMAC(SC key, nonce)") &&
               require(body_equal(open_stage(se, k_se), *input.bootloaders.ce, 0x20),
                       "SE opens under HMAC(SD key, nonce)");
    }

    bool test_devkit_image_reads_back_and_rebuilds_its_chain() {
        const auto input = devkit_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        if (!require(extracted.has_value(), "a devkit image parses and opens") ||
            !require(extracted->build_type == BuildType::Devkit &&
                         extracted->image_type == ImageType::NewSmallBlock,
                     "a devkit image reads back as a small-block devkit image") ||
            !require(extracted->bootloaders.sc && extracted->bootloaders.ce,
                     "the whole SB/SC/SD/SE chain reads back")) {
            return false;
        }
        // An opened stage runs to its 16-byte boundary; the rounding reads back zero.
        const auto tail_equal = [](const Bytes& opened, const Bytes& supplied) {
            return opened.size() == align_16(static_cast<uint32_t>(supplied.size())) &&
                   std::equal(supplied.begin() + 0x40, supplied.end(), opened.begin() + 0x40) &&
                   zero_between(opened, supplied.size(), opened.size());
        };
        if (!require(tail_equal(extracted->bootloaders.cb_or_a, input.bootloaders.cb_or_a) &&
                         tail_equal(*extracted->bootloaders.sc, *input.bootloaders.sc) &&
                         tail_equal(extracted->bootloaders.cd, input.bootloaders.cd) &&
                         tail_equal(*extracted->bootloaders.ce, *input.bootloaders.ce),
                     "every stage reads back as the plaintext it was built from") ||
            !require(extracted->metadata.pairing_data == input.metadata.pairing_data,
                     "the SB's pairing reads back")) {
            return false;
        }

        // Rebuilt over itself, every stage keeps the nonce at its position, so the sealed chain
        // comes out byte for byte.
        const auto rebuilt = run_build(*extracted);
        const auto header = read_logical(*built, 0, 0x80);
        const uint32_t slot = header ? read_be32(*header, 0x64) : 0;
        const auto chain = read_logical(*built, 0, slot);
        const auto rebuilt_chain = rebuilt ? read_logical(*rebuilt, 0, slot) : std::nullopt;
        return require(rebuilt.has_value() && rebuilt->size() == built->size(),
                       "an extracted devkit image builds again in its own shape") &&
               require(chain && rebuilt_chain && chain == rebuilt_chain,
                       "the header, SMC, keyvault and sealed chain rebuild byte for byte");
    }

    bool test_devkit_nonces_come_from_donor_positions() {
        auto input = devkit_input(ImageType::BigBlock);
        DonorNonces donor{};
        for (size_t index = 0; index < donor.stages.size(); ++index) {
            BootloaderNonce nonce{};
            nonce.fill(static_cast<uint8_t>(0xA0 + index));
            donor.stages[index] = nonce;
        }
        input.metadata.donor_nonces = donor;
        const auto built = run_build(input);
        if (!require(built.has_value() && built->size() == 0x4200000,
                     "a big-block devkit image builds")) {
            return false;
        }
        size_t at = 0x8000;
        bool ok = true;
        const std::array<const Bytes*, 4> stages{&input.bootloaders.cb_or_a, &*input.bootloaders.sc,
                                                 &input.bootloaders.cd, &*input.bootloaders.ce};
        for (size_t index = 0; index < stages.size(); ++index) {
            const auto nonce = read_logical(*built, at + 0x10, 0x10);
            ok = ok && nonce && std::all_of(nonce->begin(), nonce->end(), [index](uint8_t b) {
                     return b == 0xA0 + index;
                 });
            at += align_16(static_cast<uint32_t>(stages[index]->size()));
        }
        const auto header = read_logical(*built, 0, 0x80);
        return require(ok, "SB, SC, SD and SE take the donor's CB_A, CB_B, CD and CE nonces") &&
               require(header && read_be32(*header, 0x64) == 0x20000 &&
                           read_be32(*header, 0x70) == 0x20000,
                       "a big-block devkit slot follows the chain at the next 0x20000 block");
    }

    // A 16 MB donor gives a devkit image its nonces and console data; the image itself is the
    // 64 MB shape the console's spare layout takes.
    bool test_devkit_image_takes_its_own_shape_beside_a_16_mb_donor() {
        auto donor_input = fresh_input(ImageType::NewSmallBlock);
        // A donor's nonces are read off a chain that reaches CE.
        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 1;
        ce.data.assign(0x20, 0x45);
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + ce.data.size());
        ce.decrypted = true;
        donor_input.bootloaders.ce = ce.serialize();
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value() && donor->size() == 0x1080000, "16 MB donor builds")) {
            return false;
        }
        auto input = devkit_input(ImageType::NewSmallBlock);
        input.metadata.nand_image = *donor;
        const auto built = run_build(input);
        auto image = built ? parse_image(*built) : std::nullopt;
        const auto donor_cb = read_logical(*donor, 0x8010, 0x10);
        const auto sb_nonce = built ? read_logical(*built, 0x8010, 0x10) : std::nullopt;
        return require(built.has_value() && built->size() == 0x4200000 && image.has_value(),
                       "the devkit image is 64 MB beside a 16 MB donor") &&
               require(image->flash_driver.driver_mode() == Driver::DriverMode::NewSmall,
                       "it keeps the donor's spare layout") &&
               require(image->build_type == BuildType::Devkit, "it reads back as devkit") &&
               require(donor_cb && sb_nonce && donor_cb == sb_nonce,
                       "its SB takes the donor's first CB nonce");
    }

    bool test_raw_patches_are_written_last_and_bounded() {
        auto input = devkit_input(ImageType::NewSmallBlock);
        input.raw_patches.push_back(InputRawPatch{"reason.bin", 0x4E, Bytes{0x12}});
        input.raw_patches.push_back(InputRawPatch{"khv.bin", 0xE4000, Bytes(0x20, 0x77)});
        const auto built = run_build(input);
        const auto reason = built ? read_logical(*built, 0x4E, 1) : std::nullopt;
        const auto khv = built ? read_logical(*built, 0xE4000, 0x20) : std::nullopt;
        if (!require(reason == Bytes{0x12}, "a raw patch overwrites the header byte it names") ||
            !require(khv == Bytes(0x20, 0x77), "a raw patch lands at its clean offset")) {
            return false;
        }
        auto outside = devkit_input(ImageType::NewSmallBlock);
        outside.raw_patches.push_back(InputRawPatch{"far.bin", 0x3FFFFFF, Bytes{1, 2}});
        const auto refused = run_build(outside);
        return require(!refused && refused.error().code == BuildErrorCode::SerializationFailure,
                       "a raw patch running past the image is refused");
    }

    bool test_devgl_image_patches_and_signs_its_sd() {
        const auto input = devgl_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        if (!require(built.has_value() && built->size() == 0x1080000,
                     "a Jasper devgl image keeps the console's 16 MB shape")) {
            return false;
        }
        const auto header = read_logical(*built, 0, 0x80);
        const std::string_view copyright =
            header ? std::string_view(reinterpret_cast<const char*>(header->data() + 0x10), 0x37)
                   : std::string_view{};
        if (!require(header && read_be16(*header, 0x02) == 0x0760 && read_be16(*header, 0x04) == 0,
                     "the devgl header states 0x0760 and no 0x8000") ||
            !require(read_be32(*header, 0x48) == 1 && read_be32(*header, 0x4C) == 0x12,
                     "a devgl image states the hack flag and the eject XeLL button") ||
            !require(read_be32(*header, 0x0C) == 0xD0000 && read_be32(*header, 0x64) == 0xD0000,
                     "the first slot is stated at 0xD0000") ||
            !require(read_be16(*header, 0x68) == 2 && read_be32(*header, 0x70) == 0x10000,
                     "two slots of 0x10000") ||
            !require(copyright.find("2004-2009") != std::string_view::npos,
                     "a Jasper devgl image states the Jasper year")) {
            return false;
        }

        const uint32_t sd_size = align_16(devgl_sd_patch_address(input) + 4);
        size_t at = 0x8000;
        const auto stored = [&](size_t size) {
            auto bytes = read_logical(*built, at, size);
            at += align_16(static_cast<uint32_t>(size));
            return bytes.value_or(Bytes{});
        };
        const auto sb = stored(input.bootloaders.cb_or_a.size());
        const auto sc = stored(input.bootloaders.sc->size());
        const auto sd = stored(sd_size);
        const auto nonce = [](const Bytes& stage) {
            return std::span<const uint8_t>(stage).subspan(0x10, 0x10);
        };
        const std::array<uint8_t, 16> zero{};
        const auto k_sc = hmac_key(zero, nonce(sc));
        const auto sb_plain = open_stage(sb, hmac_key(std::span(key_1bl), nonce(sb)));
        const auto sd_plain = open_stage(sd, hmac_key(k_sc, nonce(sd)));
        const auto key = gxbuild3::utils::XeRsaPrivateKey::parse(*input.sb_private_key);
        const auto slot = read_logical(*built, 0xE0000, 0x60 + devgl_khv().size() + 4);
        auto expected_slot = Bytes(0x60, 0xF5);
        const auto khv = devgl_khv();
        expected_slot.insert(expected_slot.end(), khv.begin(), khv.end());
        append_be32(expected_slot, 0xFFFFFFFF);
        const auto image = parse_image(*built);
        return require(zero_between(sb_plain, 0x20, 0x40) &&
                           std::equal(sb_plain.begin() + 0x40, sb_plain.end(),
                                      input.bootloaders.cb_or_a.begin() + 0x40),
                       "the SB is zero-paired and carries no patch") &&
               require(read_be32(sd_plain, 0x0C) == sd_size &&
                           read_be32(sd_plain, devgl_sd_patch_address(input)) == 0x10203040,
                       "the SD carries the CD patch section and states its patched size") &&
               require(key && gxbuild3::utils::verify_sd_signature(sd_plain, key->public_key()),
                       "the patched SD is signed with the SB private key") &&
               require(slot == expected_slot,
                       "the fuses and KHV patches fill the second slot at 0xE0000") &&
               require(image && image->build_type == BuildType::Devgl,
                       "the image reads back as devgl");
    }

    bool test_big_block_devgl_slots_follow_the_big_block_step() {
        const auto built = run_build(devgl_input(ImageType::BigBlock));
        const auto header = built ? read_logical(*built, 0, 0x80) : std::nullopt;
        const auto fuses = built ? read_logical(*built, 0x100000, 0x60) : std::nullopt;
        return require(header && read_be32(*header, 0x64) == 0xE0000 &&
                           read_be32(*header, 0x70) == 0x20000,
                       "a big-block devgl image states its first slot at 0xE0000") &&
               require(fuses == Bytes(0x60, 0xF5), "its fuses go to 0x100000");
    }

    bool test_devgl_needs_a_well_formed_sb_private_key() {
        auto missing = devgl_input(ImageType::NewSmallBlock);
        missing.sb_private_key.reset();
        auto malformed = devgl_input(ImageType::NewSmallBlock);
        malformed.sb_private_key = Bytes(gxbuild3::utils::kXeRsa2048PrivateKeySize, 0);
        const auto refused_missing = run_build(missing);
        const auto refused_malformed = run_build(malformed);
        return require(!refused_missing &&
                           refused_missing.error().code == BuildErrorCode::InvalidInput &&
                           refused_missing.error().message.find("SB private key") !=
                               std::string::npos,
                       "a devgl build without the SB private key is refused") &&
               require(!refused_malformed &&
                           refused_malformed.error().code == BuildErrorCode::InvalidInput,
                       "a devgl build with a malformed key is refused");
    }

    // run_build output digests (tests/golden/run_build_digests.txt): SmallBlock, NewSmallBlock,
    // BigBlock and Emmc crossed with retail, glitch2, devkit and devgl, each built twice under a
    // pinned build time (SOURCE_DATE_EPOCH in UTC) with every donor nonce filled so no nonce is
    // drawn. The two builds must be byte-identical; the SHA-1 of the output goes to the golden.
    bool test_run_build_output_digests(const gxbuild3::test::GoldenOptions& options) {
        constexpr std::array layouts{std::pair{ImageType::SmallBlock, "small"},
                                     std::pair{ImageType::NewSmallBlock, "newsmall"},
                                     std::pair{ImageType::BigBlock, "big"},
                                     std::pair{ImageType::Emmc, "emmc"}};
        constexpr std::array builds{
            std::pair{BuildType::Retail, "retail"}, std::pair{BuildType::Glitch2, "glitch2"},
            std::pair{BuildType::Devkit, "devkit"}, std::pair{BuildType::Devgl, "devgl"}};

        const auto build_pinned = [](const Input& input) {
            const gxbuild3::test::ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105724");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        };

        std::string rendered;
        size_t total = 0;
        size_t identical = 0;
        bool ok = true;
        for (const auto& [image_type, layout_name] : layouts) {
            for (const auto& [build_type, build_name] : builds) {
                ++total;
                const std::string label = std::string{layout_name} + '.' + build_name;
                const auto input = digest_input(image_type, build_type);
                const auto first = build_pinned(input);
                const auto second = build_pinned(input);
                if (!first || !second) {
                    rendered += label + " error=" +
                                (first ? second.error().message : first.error().message) + '\n';
                    ok = require(false, label + " builds") && ok;
                    continue;
                }
                if (!require(*first == *second, label + " builds byte-identically twice")) {
                    rendered += label + " nondeterministic\n";
                    ok = false;
                    continue;
                }
                ++identical;
                char size[32];
                std::snprintf(size, sizeof(size), "0x%zx", first->size());
                rendered += label + " size=" + size + " sha1=" + sha1_hex(*first) + '\n';
            }
        }
        const bool matched = gxbuild3::test::check_golden(options, "run_build_digests", rendered);
        std::cout << "run_build digests: built twice and identical " << identical << '/' << total
                  << ", compared " << (matched ? identical : 0) << '/' << total
                  << " with tests/golden/run_build_digests.txt\n";
        return require(matched, "run_build output digests match the golden") && ok;
    }

    // Every public extract_* projection (tests/support/render/ExtractProjection.hpp) of two
    // run_build digest outputs, against tests/golden/extract_projections_synthetic.txt:
    //   small.glitch2             CB_A + CB_B, CE, CF/CG in slot 0, patch file and XeLL;
    //   newsmall.devkit           the SB/SC/SD/SE chain, where extract_all_info states the SC
    //                             decrypted while extract_some_info reads it sealed;
    //   newsmall.devkit.zero-key  the same image under the all-zero CPU key: its keyvault was
    //                             sealed under the test console's key, stays sealed, and
    //                             extract_all leaves it out (extract_metadata refuses).
    // Each image is built twice under the pinned build time and donor nonces, and each image
    // is projected twice; both must be identical. The mydata dump's projections live in
    // gxbuild3_orchestration_golden_tests (tests/golden/extract_projections_mydata.txt).
    bool test_extract_projection_snapshots(const gxbuild3::test::GoldenOptions& options) {
        const auto build_pinned = [](const Input& input) {
            const gxbuild3::test::ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105724");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        };
        const auto cpu_key = valid_cpu_key();
        const std::array<uint8_t, 16> zero_key{};
        struct Case {
            std::string_view label;
            ImageType image_type;
            BuildType build_type;
            bool zero_cpu_key;
        };
        constexpr std::array cases{
            Case{"small.glitch2", ImageType::SmallBlock, BuildType::Glitch2, false},
            Case{"newsmall.devkit", ImageType::NewSmallBlock, BuildType::Devkit, false},
            Case{"newsmall.devkit.zero-key", ImageType::NewSmallBlock, BuildType::Devkit, true},
        };

        std::string rendered;
        size_t stable = 0;
        size_t comparisons = 0;
        size_t agreements = 0;
        bool ok = true;
        for (const auto& c : cases) {
            const std::string label{c.label};
            const auto input = digest_input(c.image_type, c.build_type);
            const auto first = build_pinned(input);
            const auto second = build_pinned(input);
            if (!first || !second) {
                rendered += label + " build-error=" +
                            (first ? second.error().message : first.error().message) + '\n';
                ok = require(false, label + " builds") && ok;
                continue;
            }
            if (!require(*first == *second, label + " builds byte-identically twice")) {
                rendered += label + " nondeterministic-build\n";
                ok = false;
                continue;
            }
            const std::span<const uint8_t> key =
                c.zero_cpu_key ? std::span<const uint8_t>(zero_key) : std::span(cpu_key);
            const auto once =
                gxbuild3::test::projection::render_extract_projections(label, *first, key);
            const auto twice =
                gxbuild3::test::projection::render_extract_projections(label, *first, key);
            comparisons += once.comparisons;
            agreements += once.agreements;
            for (const auto& what : once.disagreements) {
                ok = require(false, what + " renders the same as the core's span overload") && ok;
            }
            if (require(once.text == twice.text, label + " projects identically twice")) {
                ++stable;
            } else {
                ok = false;
            }
            rendered += once.text;
        }
        const bool matched =
            gxbuild3::test::check_golden(options, "extract_projections_synthetic", rendered);
        std::cout << "extract projections: inputs stable " << stable << '/' << cases.size()
                  << ", overloads and shims agreed " << agreements << '/' << comparisons
                  << ", compared " << (matched ? stable : 0) << '/' << cases.size()
                  << " with tests/golden/extract_projections_synthetic.txt\n";
        return require(matched, "synthetic extract projections match the golden") && ok;
    }

    std::string_view build_error_code_name(BuildErrorCode code) {
        switch (code) {
            case BuildErrorCode::InvalidInput:
                return "InvalidInput";
            case BuildErrorCode::InvalidDonor:
                return "InvalidDonor";
            case BuildErrorCode::InvalidSmc:
                return "InvalidSmc";
            case BuildErrorCode::InvalidKeyvault:
                return "InvalidKeyvault";
            case BuildErrorCode::InvalidBootloader:
                return "InvalidBootloader";
            case BuildErrorCode::PatchFailure:
                return "PatchFailure";
            case BuildErrorCode::EncryptionFailure:
                return "EncryptionFailure";
            case BuildErrorCode::SerializationFailure:
                return "SerializationFailure";
            case BuildErrorCode::Internal:
                return "Internal";
        }
        return "unknown";
    }

    // run_build failure exits (tests/golden/run_build_failures.txt): one input per exit that an
    // Input can reach, in run_build's stage order (validation, signing key, donor, SMC, keyvault,
    // boot chain, patch file, SD signing, extra stages, metadata and nonces, patch slots,
    // payloads and layout, FlashFS, encryption, write). Each line pins the BuildErrorCode and the
    // whole describe() message, outermost context first, so moving code between functions cannot
    // reorder or drop a context layer unseen. The exits only a fault could reach are listed at
    // the end of the golden as not covered.
    bool test_run_build_failure_exits_keep_code_and_message(
        const gxbuild3::test::GoldenOptions& options) {
        struct Case {
            std::string_view label;
            Input (*input)();
        };
        const std::array cases{
            Case{"validate.cpu-key-length",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key.pop_back();
                     return input;
                 }},
            Case{"validate.devgl-without-sb-key",
                 [] {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key.reset();
                     return input;
                 }},
            Case{"devgl.malformed-sb-key",
                 [] {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key = Bytes(gxbuild3::utils::kXeRsa2048PrivateKeySize, 0);
                     return input;
                 }},
            Case{"donor.not-a-nand",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = Bytes(0x10, 0x5A);
                     return input;
                 }},
            Case{"donor.wrong-cpu-key",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = make_donor(input, {});
                     const auto wrong_key = different_valid_cpu_key();
                     input.metadata.cpu_key.assign(wrong_key.begin(), wrong_key.end());
                     return input;
                 }},
            Case{"smc.too-short",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.smc = Bytes(0x10, 0x11);
                     return input;
                 }},
            Case{"smc.jtag-over-a-clean-smc",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.metadata.smc = make_smc(0x11);
                     return input;
                 }},
            Case{"keyvault.wrong-length",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.keyvault = Bytes(0x10, 0x22);
                     return input;
                 }},
            Case{"chain.orphan-cg0",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg0 = valid_system_update(0x51).second;
                     return input;
                 }},
            Case{"chain.orphan-cg1",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg1 = valid_system_update(0x61).second;
                     return input;
                 }},
            Case{"bootloaders.malformed-cb",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cb_or_a = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"bootloaders.malformed-cf0",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cf0 = Bytes{0x43, 0x46, 0x00};
                     return input;
                 }},
            Case{"bootloaders.cd-without-payload",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCd cd{};
                     cd.header.header.magic = NANDBootloaderMagic::CD;
                     cd.header.header.version = 1;
                     cd.header.header.size = sizeof(cd_header);
                     input.bootloaders.cd = cd.serialize();
                     return input;
                 }},
            Case{"bootloaders.glitch3-without-cb-x",
                 [] {
                     auto input = glitch_input(BuildType::Glitch3,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"bootloaders.glitch1-with-cb-b",
                 [] {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"patch.malformed-patch-file",
                 [] {
                     Bytes patchset;
                     append_be32(patchset, 0x20);
                     append_be32(patchset, 1);
                     append_be32(patchset, 0);
                     append_be32(patchset, 0xFFFFFFFF);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.glitch2-without-cb-b",
                 [] {
                     return glitch_input(BuildType::Glitch2,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                 }},
            Case{"patch.cb-past-32-bit-space",
                 [] {
                     Bytes patchset;
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     append_patch_entry(patchset, 0x30, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.cd-past-32-bit-space",
                 [] {
                     Bytes patchset;
                     append_patch_entry(patchset, 0x20, 0);
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.chain-over-capacity",
                 [] {
                     return glitch_input(BuildType::Glitch, glitch_patchset(0x70000, 0xDEADBEEF,
                                                                            0x30, 0, Bytes{0xA0}));
                 }},
            Case{"extra.malformed-jtag-cb",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cb = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"extra.malformed-jtag-cd",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cd = Bytes{0x43, 0x44, 0x00};
                     return input;
                 }},
            Case{"metadata.cb-without-per-box",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCb cb{};
                     cb.header.header.magic = NANDBootloaderMagic::CB;
                     cb.header.header.version = 1;
                     cb.header.header.size = sizeof(generic_header);
                     input.bootloaders.cb_or_a = cb.serialize();
                     return input;
                 }},
            Case{"slots.jtag-patch-over-0x4000", [] { return jtag_input(Bytes(0x4001, 0x44)); }},
            Case{"slots.khv-over-its-slot",
                 [] {
                     return glitch_input(BuildType::Glitch,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55)));
                 }},
            Case{"payloads.malformed-xell",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     InputPayloads payloads{};
                     payloads.xell = Bytes(0x40000, 0);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"layout.xell-over-the-rebooter",
                 [] {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     InputPayloads payloads{};
                     payloads.xell = valid_xell();
                     payloads.rebooter = Bytes(0x1000, 0x71);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"flashfs.add-a-257th-file",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
                     for (size_t index = 0; index < 257; ++index) {
                         input.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
                     }
                     return input;
                 }},
            Case{"encrypt.invalid-cpu-key",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key = invalid_cpu_key();
                     return input;
                 }},
            Case{"write.mobile-over-a-block",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x800, 2)}});
                     *input.mobiles.slot(0x32) = Bytes(0x4001, 9);
                     return input;
                 }},
        };
        // The exits no Input reaches; only a fault seam could, and none is added.
        constexpr std::array<std::pair<std::string_view, std::string_view>, 19> uncovered{{
            {"donor.read", "FlashImage::read refuses only an empty dump, which run_build skips"},
            {"chain.clear-donor-records",
             "needs a parsed donor whose boot chain runs past its own image; none is built"},
            {"smc.reboot-patch",
             "apply_signature_patch fails only on a null buffer or a bad built-in pattern"},
            {"patch.missing-section",
             "the glitch patch file parser always yields the first, CD and KHV sections"},
            {"patch.cb-apply", "the chain capacity check bounds the patched CB, and an aligned "
                               "patched stage always parses again"},
            {"patch.cb-b-apply", "as patch.cb-apply, for the CB_B"},
            {"patch.cd-apply", "as patch.cb-apply, for the CD"},
            {"sd.sign", "a key that parses (n = pq, consistent exponents) signs and verifies, and "
                        "an SD is never shorter than its 0x260-byte header"},
            {"sd.reparse", "the signed SD keeps the size it parsed with"},
            {"nonces.open-cg", "a CG that parsed opens: prepare_payload repeats the parse's check"},
            {"slots.khv-missing", "the glitch patch file parser always yields a KHV section"},
            {"flashfs.data-limit", "every layout leaves 1..0xFFFF FlashFS blocks"},
            {"flashfs.first-block",
             "no layout lays its fixed payloads past the FlashFS data limit"},
            {"flashfs.format", "every layout's block count fits the FlashFS block map"},
            {"flashfs.reserve-tail", "the tail lies inside the formatted block map"},
            {"flashfs.reserve-bad-block", "a freshly formatted map holds only free or reserved "
                                          "blocks below the data limit"},
            {"flashfs.reserve-payload-blocks",
             "the fixed payload ranges lie inside the formatted block map"},
            {"flashfs.seal-secured-file",
             "sealing fails only on a CPU key that is not 16 bytes, which validation refuses"},
            {"internal.std-exception",
             "run_build's catch: only a std exception (an allocation failure) reaches it"},
        }};

        std::string rendered;
        size_t refused = 0;
        bool ok = true;
        for (const auto& test_case : cases) {
            const std::string label{test_case.label};
            const auto input = test_case.input();
            const auto first = run_build(input);
            const auto second = run_build(input);
            if (first || second) {
                rendered += label + " built\n";
                ok = require(false, label + " is refused") && ok;
                continue;
            }
            if (!require(first.error().code == second.error().code &&
                             first.error().message == second.error().message,
                         label + " is refused the same way twice")) {
                rendered += label + " nondeterministic\n";
                ok = false;
                continue;
            }
            ++refused;
            rendered += label + " code=" + std::string{build_error_code_name(first.error().code)} +
                        " message=" + first.error().message + '\n';
        }
        for (const auto& [label, reason] : uncovered) {
            rendered += "not-covered " + std::string{label} + ": " + std::string{reason} + '\n';
        }
        const bool matched = gxbuild3::test::check_golden(options, "run_build_failures", rendered);
        std::cout << "run_build failure exits: refused " << refused << '/' << cases.size()
                  << ", compared " << (matched ? refused : 0) << '/' << cases.size()
                  << " with tests/golden/run_build_failures.txt, " << uncovered.size()
                  << " exits not covered\n";
        return require(matched, "run_build failure exits match the golden") && ok;
    }
} // namespace

int main(int argc, char** argv) {
    const auto golden = gxbuild3::test::golden_options(argc, argv);
    if (!golden) {
        return 2;
    }
    bool passed = true;
    passed = test_run_build_output_digests(*golden) && passed;
    passed = test_extract_projection_snapshots(*golden) && passed;
    passed = test_run_build_failure_exits_keep_code_and_message(*golden) && passed;
    passed = test_devkit_chain_is_sealed_from_the_zero_secret() && passed;
    passed = test_devkit_image_reads_back_and_rebuilds_its_chain() && passed;
    passed = test_devkit_nonces_come_from_donor_positions() && passed;
    passed = test_devkit_image_takes_its_own_shape_beside_a_16_mb_donor() && passed;
    passed = test_raw_patches_are_written_last_and_bounded() && passed;
    passed = test_devgl_image_patches_and_signs_its_sd() && passed;
    passed = test_big_block_devgl_slots_follow_the_big_block_step() && passed;
    passed = test_devgl_needs_a_well_formed_sb_private_key() && passed;
    passed = test_system_update_slot_zero_spills_and_preserves_slot_one() && passed;
    passed = test_clear_bootloader_chain_clears_header_only_cb_and_cd_records() && passed;
    passed = test_fresh_build_seals_stages_under_random_nonces() && passed;
    passed = test_donor_nonces_seal_stages_by_position_and_every_slot_alike() && passed;
    passed = test_extraction_takes_cf_metadata_and_nonces_from_the_max_ldv_slot() && passed;
    passed = test_donor_build_leaves_unlaid_space_erased() && passed;
    passed = test_emmc_build_leaves_anchor_tails_and_unused_blocks_erased() && passed;
    passed = test_bigblock_flashfs_stamps_only_the_clusters_it_fills() && passed;
    return passed ? 0 : 1;
}
