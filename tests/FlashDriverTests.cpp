#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/XConfig.hpp"
#include "support/FlashFsAccess.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3::nand;

namespace {

    bool check(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    bool check(const gxbuild3::Result<>& result, std::string_view message) {
        if (!result) {
            std::cerr << "FAIL: " << message << ": " << result.error().describe() << '\n';
            return false;
        }
        return true;
    }

    bool test_fresh_blocks_are_not_bad() {
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        return check(!driver.is_bad_block(100),
                     "fresh unused blocks must have a good-block marker");
    }

    bool test_bad_block_mark_is_read_on_the_first_and_middle_pages() {
        bool ok = true;
        const std::array<std::pair<Driver::ImageSize, Driver::DriverMode>, 2> shapes{
            {{Driver::Smallblock, Driver::DriverMode::Small},
             {Driver::Bigordevkit, Driver::DriverMode::Big}}};
        for (const auto& [size, mode] : shapes) {
            Driver driver(size, mode);
            const size_t mark = mode == Driver::DriverMode::Big ? 0 : 5;
            const size_t pages = driver.pages_per_block();

            // A big block's filesystem pages after the first hold zero at the mark byte.
            driver.read_page_spare(3 * pages + 1)[mark] = 0;
            ok = check(!driver.is_bad_block(3), "a mark on the second page is not a bad block") &&
                 ok;

            driver.read_page_spare(4 * pages + pages / 2)[mark] = 0;
            ok = check(driver.is_bad_block(4), "a mark on the middle page is a bad block") && ok;

            driver.mark_bad_block(5);
            ok = check(driver.read_page_spare(5 * pages)[mark] == 0 &&
                           driver.read_page_spare(5 * pages + pages / 2)[mark] == 0 &&
                           driver.read_page_spare(5 * pages + 1)[mark] == 0xFF,
                       "marking a block bad marks its first and middle pages") &&
                 ok;
            ok = check(driver.is_bad_block(5) && driver.interpret_block(5).is_bad,
                       "a block marked bad reads back bad") &&
                 ok;
        }
        return ok;
    }

    bool test_big_block_sequence_layout() {
        Driver driver(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        BlockMetadata metadata{};
        metadata.logical_block_id = 2;
        metadata.sequence = 0x123456;
        driver.write_block_metadata(2, metadata);

        const auto spare = driver.read_page_spare(2 * driver.pages_per_block());
        return check(spare.size() == 16, "Big Block spare data must be readable") &&
               check(spare[3] == 0x34 && spare[4] == 0x12 && spare[5] == 0x56,
                     "Big Block sequence must use spare bytes 3, 4, and 5") &&
               check(spare[6] == 0, "Big Block sequence high byte must be zero for a 24-bit value");
    }

    bool test_block_type_masks_ecc_bits() {
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        BlockMetadata metadata{};
        metadata.logical_block_id = 0;
        metadata.block_type = 0x30;
        driver.write_block_metadata(0, metadata);

        for (size_t page = 0; page < 2; ++page) {
            auto spare = driver.read_page_spare(page);
            std::array<uint8_t, 16> updated{};
            std::copy(spare.begin(), spare.end(), updated.begin());
            updated[0xC] = 0xF0;
            driver.write_page_spare(page, updated);
        }

        return check(driver.interpret_block(0).block_type == 0x30,
                     "ECC bits must not be returned as part of the block type");
    }

    // A settings block as a console holds it: 0x400 bytes whose head is the one's complement
    // of the byte sum over [0x10, 0x10C), little-endian.
    std::vector<uint8_t> sound_smc_config_block() {
        std::vector<uint8_t> block(0x400);
        for (size_t i = 2; i < block.size(); ++i) {
            block[i] = static_cast<uint8_t>(i * 7 + 3);
        }
        uint32_t sum = 0;
        for (size_t i = 0x10; i < 0x10C; ++i) {
            sum += block[i];
        }
        const uint16_t head = static_cast<uint16_t>(~sum);
        block[0] = static_cast<uint8_t>(head);
        block[1] = static_cast<uint8_t>(head >> 8);
        return block;
    }

    struct ConfigShape {
        Driver::ImageSize size;
        Driver::DriverMode mode;
        size_t offset;
    };

    // Where the settings block sits on each shape, read off real dumps (16 MB and big block)
    // and the eMMC layout.
    constexpr ConfigShape kConfigShapes[] = {
        {Driver::Smallblock, Driver::DriverMode::Small, 0xF7C000},
        {Driver::Bigordevkit, Driver::DriverMode::Big, 0x3BE0000},
        {Driver::Emmcblock, Driver::DriverMode::Emmc, 0x2FFC000},
    };

    bool test_emmc_image_is_48_megabytes() {
        Driver emmc(Driver::Emmcblock, Driver::DriverMode::Emmc);
        return check(emmc.block_count() == 0xC00, "an eMMC image has 0xC00 blocks") &&
               check(emmc.serialize().size() == size_t{0xC00} * 0x4000,
                     "an eMMC image is 48 MB long");
    }

    bool test_flash_image_reads_cross_page_config() {
        bool ok = true;
        const auto block = sound_smc_config_block();
        for (const auto& shape : kConfigShapes) {
            Driver source(shape.size, shape.mode);
            ok =
                check(source.write_offset(shape.offset, block), "the settings block is laid") && ok;

            auto image = FlashImage::read(source.serialize());
            ok = check(image.has_value(), "FlashImage must accept a valid-sized NAND image") && ok;
            if (!image) {
                continue;
            }
            ok = check(image->parse(), "FlashImage must parse the NAND image") && ok;
            ok = check(image->smc_config == block,
                       "FlashImage must read the SMC config block where the shape keeps it") &&
                 ok;
        }
        return ok;
    }

    bool test_smc_config_with_bad_checksum_is_not_carried() {
        Driver source(Driver::Smallblock, Driver::DriverMode::Small);
        auto block = sound_smc_config_block();
        block[0x50] ^= 0xFF;
        if (!check(source.write_offset(0xF7C000, block), "the settings block is laid")) {
            return false;
        }

        auto image = FlashImage::read(source.serialize());
        return check(image && image->parse() && !image->smc_config.has_value(),
                     "a settings block whose checksum fails must not be carried");
    }

    bool test_smc_config_write_leaves_neighbouring_blocks() {
        bool ok = true;
        const auto block = sound_smc_config_block();
        for (const auto& shape : kConfigShapes) {
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            // A dump written back keeps the bytes it does not model, as here the neighbours.
            image.preserve_layout = true;
            const size_t step = image.flash_driver.block_size_clean();
            // The statistics and manufacturing blocks lie one and two erase blocks below.
            const std::vector<uint8_t> statistics(0x1000, 0xA5);
            const std::vector<uint8_t> manufacturing(0x1000, 0x5A);
            ok = check(image.flash_driver.write_offset(shape.offset - step, statistics) &&
                           image.flash_driver.write_offset(shape.offset - 2 * step, manufacturing),
                       "the neighbouring blocks are laid") &&
                 ok;
            image.smc_config = block;

            ok = check(image.write_to_driver(), "an image with a settings block writes") && ok;
            const auto& driver = std::as_const(image.flash_driver);
            // A raw NAND read lands in a scratch buffer the next read replaces, so each
            // result is copied out before the next one is taken.
            const auto copy_of = [&driver](size_t offset) {
                const auto span = driver.read_offset(offset, 0x1000);
                return std::vector<uint8_t>(span.begin(), span.end());
            };
            const auto settings = copy_of(shape.offset);
            std::vector<uint8_t> expected(0x1000, 0xFF);
            std::copy(block.begin(), block.end(), expected.begin());
            ok = check(settings == expected,
                       "the settings block is laid in 0x1000 with 0xFF after it") &&
                 ok;
            const auto stats = copy_of(shape.offset - step);
            const auto manu = copy_of(shape.offset - 2 * step);
            ok = check(stats == statistics,
                       "writing the settings block must not touch the statistics block") &&
                 ok;
            ok = check(manu == manufacturing,
                       "writing the settings block must not touch the manufacturing block") &&
                 ok;
        }
        return ok;
    }

    std::vector<uint8_t> hex_bytes(std::string_view hex) {
        std::vector<uint8_t> out;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            out.push_back(
                static_cast<uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
        }
        return out;
    }

    // Vectors from xerunner's Anchor.encoded, which was measured on images the original
    // built: only the first 0x30 bytes are non-zero.
    bool test_anchor_block_matches_reference_layout() {
        using gxbuild3::nand::CoronaConfig;
        bool ok = true;

        CoronaConfig first{};
        first.number = 1;
        first.table = 0x38E;
        first.blobs[1] = {0x38C, 0x200}; // type 0x32 is slot 1, which sits at 0x24
        first.blobs[3] = {0x38D, 0x800}; // type 0x34 is slot 3, which sits at 0x2C
        auto bytes = first.serialize();
        ok = check(bytes.size() == 0x200, "an anchor block is 0x200 bytes") && ok;
        ok = check(std::vector<uint8_t>(bytes.begin(), bytes.begin() + 0x14) ==
                       hex_bytes("af9c1da90c94a9fb5329ea470c7618833abb5d4e"),
                   "anchor digest matches the reference") &&
             ok;
        ok = check(std::vector<uint8_t>(bytes.begin() + 0x14, bytes.begin() + 0x30) ==
                       hex_bytes("0000000000000001038e000000000000038c020000000000038d0800"),
                   "anchor body matches the reference") &&
             ok;
        ok = check(std::all_of(bytes.begin() + 0x30, bytes.end(), [](uint8_t b) { return b == 0; }),
                   "an anchor block is zero past 0x30") &&
             ok;

        CoronaConfig second{};
        second.number = 2;
        second.table = 0x38E;
        second.blobs[0] = {0x38B, 0x800};
        auto second_bytes = second.serialize();
        ok = check(std::vector<uint8_t>(second_bytes.begin(), second_bytes.begin() + 0x14) ==
                       hex_bytes("f8c15d3b38d5dafe77d001984aa909b62c5eab1b"),
                   "second anchor digest matches the reference") &&
             ok;

        auto parsed = CoronaConfig::parse(bytes);
        ok = check(parsed && parsed->number == 1 && parsed->table == 0x38E &&
                       parsed->blobs[1].block == 0x38C && parsed->blobs[1].length == 0x200 &&
                       parsed->blobs[3].block == 0x38D && parsed->blobs[3].length == 0x800 &&
                       parsed->blobs[0].length == 0 && parsed->blobs[2].length == 0,
                   "an anchor block reads back what was written") &&
             ok;

        auto damaged = bytes;
        damaged[0x40] ^= 0xFF;
        ok = check(!CoronaConfig::parse(damaged).has_value(),
                   "an anchor whose hash disagrees is refused") &&
             ok;
        return ok;
    }

    // The anchor a console believes is decided by its number, not by where it sits.
    bool test_anchor_choice_follows_the_number() {
        using gxbuild3::nand::CoronaConfig;
        CoronaConfig low{};
        low.number = 1;
        low.table = 0x111;
        CoronaConfig high{};
        high.number = 2;
        high.table = 0x222;
        const auto low_bytes = low.serialize();
        const auto high_bytes = high.serialize();
        auto damaged = high_bytes;
        damaged[0x30] ^= 0xFF;
        bool ok = true;

        auto swapped = CoronaConfig::choose(
            {std::span<const uint8_t>(high_bytes), std::span<const uint8_t>(low_bytes)});
        ok =
            check(swapped && swapped->table == 0x222, "the higher number wins in the first slot") &&
            ok;
        auto normal = CoronaConfig::choose(
            {std::span<const uint8_t>(low_bytes), std::span<const uint8_t>(high_bytes)});
        ok = check(normal && normal->table == 0x222, "the higher number wins in the second slot") &&
             ok;
        auto fallback = CoronaConfig::choose(
            {std::span<const uint8_t>(damaged), std::span<const uint8_t>(low_bytes)});
        ok = check(fallback && fallback->table == 0x111,
                   "a copy whose hash disagrees is skipped for the other") &&
             ok;
        auto none = CoronaConfig::choose(
            {std::span<const uint8_t>(damaged), std::span<const uint8_t>(damaged)});
        ok = check(!none.has_value(), "no sound copy names no filesystem") && ok;
        return ok;
    }

    bool test_emmc_write_lays_both_anchors() {
        using gxbuild3::nand::CoronaConfig;
        FlashImage image{};
        image.flash_driver = Driver(Driver::Emmcblock, Driver::DriverMode::Emmc);
        gxbuild3::nand::MobileData mobile;
        mobile.x31 = std::vector<uint8_t>(0x800, 0x31);
        mobile.x32 = std::vector<uint8_t>(0x200, 0x32);
        image.mobile_data = mobile;

        bool ok = check(image.write_to_driver(), "an eMMC image with mobile data writes");
        const auto& driver = std::as_const(image.flash_driver);
        for (size_t copy = 0; copy < CoronaConfig::kOffsets.size(); ++copy) {
            auto bytes = driver.read_offset(CoronaConfig::kOffsets[copy], CoronaConfig::kSpan);
            auto parsed = CoronaConfig::parse(std::span<const uint8_t>(bytes));
            ok = check(parsed.has_value(), "each anchor copy parses") && ok;
            if (!parsed) {
                continue;
            }
            ok = check(parsed->number == copy + 1, "the copies are numbered 1 and 2") && ok;
            ok = check(parsed->blobs[0].length == 0x800 && parsed->blobs[1].length == 0x200 &&
                           parsed->blobs[2].length == 0 && parsed->blobs[3].length == 0,
                       "blob lengths are bytes and each blob sits in the slot of its type") &&
                 ok;
            ok = check(std::all_of(bytes.begin() + CoronaConfig::kSize, bytes.end(),
                                   [](uint8_t b) { return b == 0; }),
                       "the anchor's span is zero after the structure") &&
                 ok;
            const auto tail = driver.read_offset(CoronaConfig::kOffsets[copy] + CoronaConfig::kSpan,
                                                 CoronaConfig::kBlockSize - CoronaConfig::kSpan);
            ok = check(!tail.empty() && std::all_of(tail.begin(), tail.end(),
                                                    [](uint8_t b) { return b == 0xFF; }),
                       "the anchor's block is erased past its span") &&
                 ok;
        }

        auto reread = FlashImage::read(image.flash_driver.serialize());
        ok = check(reread && reread->parse() && reread->mobile_data &&
                       reread->mobile_data->x31 == mobile.x31 &&
                       reread->mobile_data->x32 == mobile.x32,
                   "mobile data is found again through the anchor") &&
             ok;
        return ok;
    }

    // Lays one blob copy as a console does: its bytes in consecutive pages and, on those pages
    // only, a spare naming its type, version, length and the free count left behind it.
    void stamp_mobile_copy(Driver& driver, size_t block, size_t first_page, uint8_t type,
                           uint32_t sequence, uint8_t free_count, size_t tagged_pages,
                           const std::vector<uint8_t>& bytes) {
        const size_t page = block * driver.pages_per_block() + first_page;
        check(driver.write_offset(page * 512, bytes), "a mobile copy is laid");
        BlockMetadata meta{};
        meta.logical_block_id = static_cast<uint16_t>(block);
        meta.sequence = sequence;
        meta.block_type = type;
        meta.page_count = free_count;
        meta.fs_size = static_cast<uint16_t>(bytes.size());
        driver.write_page_metadata(page, tagged_pages, meta);
    }

    bool test_flash_image_takes_the_latest_mobile_copy() {
        bool ok = true;
        for (const auto mode : {Driver::DriverMode::Small, Driver::DriverMode::NewSmall}) {
            Driver source(Driver::ImageSize::Smallblock, mode);
            // An older block of MobileB, then its live block holding three copies appended
            // one after another, each with four fewer pages free.
            source.erase_block(0x80);
            stamp_mobile_copy(source, 0x80, 0, 0x31, 5, 28, 4, std::vector<uint8_t>(0x800, 0x99));
            source.erase_block(0x90);
            for (uint8_t copy = 0; copy < 3; ++copy) {
                stamp_mobile_copy(source, 0x90, copy * 4, 0x31, 6,
                                  static_cast<uint8_t>(28 - copy * 4), 4,
                                  std::vector<uint8_t>(0x800, static_cast<uint8_t>(0x11 + copy)));
            }
            // MobileC: one-page copies.
            source.erase_block(0xA0);
            stamp_mobile_copy(source, 0xA0, 0, 0x32, 1, 31, 1, std::vector<uint8_t>(0x200, 0x21));
            stamp_mobile_copy(source, 0xA0, 1, 0x32, 1, 30, 1, std::vector<uint8_t>(0x200, 0x22));

            auto image = FlashImage::read(source.serialize());
            ok = check(image && image->parse() && image->mobile_data,
                       "FlashImage must parse small-block mobile copies") &&
                 ok;
            if (!image || !image->mobile_data) {
                continue;
            }
            ok = check(image->mobile_data->x31 == std::vector<uint8_t>(0x800, 0x13),
                       "the newest version's last copy of MobileB is taken") &&
                 ok;
            ok = check(image->mobile_data->x32 == std::vector<uint8_t>(0x200, 0x22),
                       "the last one-page copy of MobileC is taken") &&
                 ok;
        }

        // Big block: every type shares one erase block, each copy in its own 0x800 slot. A
        // console tags the whole slot, so a 0x200-byte copy is followed by three tagged
        // pages of 0xFF.
        Driver big(Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big);
        big.erase_block(0x1C4);
        std::vector<uint8_t> slot_32(0x200, 0x32);
        stamp_mobile_copy(big, 0x1C4, 0, 0x32, 7, 60, 4, slot_32);
        stamp_mobile_copy(big, 0x1C4, 4, 0x31, 7, 60, 4, std::vector<uint8_t>(0x800, 0x41));
        stamp_mobile_copy(big, 0x1C4, 8, 0x31, 7, 59, 4, std::vector<uint8_t>(0x800, 0x42));
        auto image = FlashImage::read(big.serialize());
        ok = check(image && image->parse() && image->mobile_data,
                   "FlashImage must parse big-block mobile copies") &&
             ok;
        if (image && image->mobile_data) {
            ok = check(image->mobile_data->x31 == std::vector<uint8_t>(0x800, 0x42),
                       "the latest big-block MobileB slot is taken") &&
                 ok;
            ok = check(image->mobile_data->x32 == slot_32,
                       "a short big-block copy is read from its slot's first page") &&
                 ok;
        }
        return ok;
    }

    struct MobilePageSurvey {
        size_t tagged_pages = 0;
        size_t first_page = 0;
        BlockMetadata meta{};
    };

    // Where a type's pages are and what their spare says; assumes a single copy.
    MobilePageSurvey survey_mobile(const Driver& driver, uint8_t type) {
        MobilePageSurvey survey{};
        const size_t pages = driver.block_count() * driver.pages_per_block();
        for (size_t page = 0; page < pages; ++page) {
            const auto meta = driver.interpret_page(page);
            if (meta.block_type != type) {
                continue;
            }
            if (survey.tagged_pages++ == 0) {
                survey.first_page = page;
                survey.meta = meta;
            }
        }
        return survey;
    }

    bool page_is_erased(const Driver& driver, size_t page) {
        const auto raw = driver.read_page_raw(page);
        return std::all_of(raw.begin(), raw.end(), [](uint8_t b) { return b == 0xFF; });
    }

    bool test_mobile_copies_are_laid_as_xebuild_lays_them() {
        bool ok = true;
        const std::vector<uint8_t> mobile_b(0x800, 0x31);
        const std::vector<uint8_t> mobile_c(0x200, 0x32);
        struct Shape {
            Driver::ImageSize size;
            Driver::DriverMode mode;
            uint8_t b_free;
            uint8_t c_free;
            size_t c_after_b; // pages from MobileB's first page to MobileC's
        };
        // Small block: a block each, free pages counted. Big block: one erase block, 0x800
        // slots counted, 63 then 62 down the block.
        constexpr Shape kShapes[] = {
            {Driver::ImageSize::Smallblock, Driver::DriverMode::Small, 28, 31, 32},
            {Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall, 28, 31, 32},
            {Driver::ImageSize::Bigordevkit, Driver::DriverMode::Big, 63, 62, 4},
        };
        for (const auto& shape : kShapes) {
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            gxbuild3::nand::MobileData mobile;
            mobile.x31 = mobile_b;
            mobile.x32 = mobile_c;
            image.mobile_data = mobile;
            const auto bytes = image.write();
            ok = check(bytes.has_value(), "an image with mobile data writes") && ok;
            if (!bytes) {
                continue;
            }
            const auto& driver = std::as_const(image.flash_driver);
            const auto b = survey_mobile(driver, 0x31);
            const auto c = survey_mobile(driver, 0x32);
            ok = check(b.tagged_pages == 4 && c.tagged_pages == 1,
                       "only the pages holding a blob carry its type") &&
                 ok;
            ok = check(b.first_page % driver.pages_per_block() == 0 &&
                           c.first_page == b.first_page + shape.c_after_b,
                       "blobs are laid in type order where xeBuild lays them") &&
                 ok;
            ok = check(b.meta.sequence == 1 && c.meta.sequence == 1,
                       "every blob is written as version 1") &&
                 ok;
            ok = check(b.meta.page_count == shape.b_free && c.meta.page_count == shape.c_free,
                       "the spare states what is left free behind each blob") &&
                 ok;
            ok = check(b.meta.fs_size == 0x800 && c.meta.fs_size == 0x200,
                       "the spare states each blob's length") &&
                 ok;
            // On big block MobileC's slot follows MobileB's directly.
            ok = check((b.first_page + 4 == c.first_page ||
                        page_is_erased(driver, b.first_page + 4)) &&
                           page_is_erased(driver, c.first_page + 1),
                       "the pages after a blob stay erased") &&
                 ok;

            auto parsed = FlashImage::read(*bytes);
            ok = check(parsed && parsed->parse() && parsed->mobile_data &&
                           parsed->mobile_data->x31 == mobile_b &&
                           parsed->mobile_data->x32 == mobile_c,
                       "laid blobs read back byte for byte") &&
                 ok;
        }
        return ok;
    }

    bool test_rewrite_erases_every_older_mobile_copy() {
        Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::NewSmall);
        // A donor copy whose version outranks the version 1 the writer gives the new one.
        source.erase_block(0x200);
        stamp_mobile_copy(source, 0x200, 0, 0x31, 900, 28, 4, std::vector<uint8_t>(0x800, 0xEE));
        auto image = FlashImage::read(source.serialize());
        if (!check(image && image->parse() && image->mobile_data,
                   "a donor with a mobile copy parses")) {
            return false;
        }
        image->mobile_data->x31 = std::vector<uint8_t>(0x800, 0x5A);
        const auto bytes = image->write();
        auto parsed = bytes ? FlashImage::read(*bytes) : std::nullopt;
        return check(parsed && parsed->parse() && parsed->mobile_data &&
                         parsed->mobile_data->x31 == std::vector<uint8_t>(0x800, 0x5A),
                     "the replacement blob is the one read back") &&
               check(page_is_erased(parsed->flash_driver, 0x200 * 32),
                     "the donor's mobile block is erased");
    }

    bool test_mobile_longer_than_one_copy_is_refused() {
        FlashImage image{};
        image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        gxbuild3::nand::MobileData mobile;
        mobile.x31 = std::vector<uint8_t>(0x4001, 0x31);
        image.mobile_data = mobile;
        return check(!image.write(), "a small-block blob longer than its block cannot be written");
    }

    bool test_settings_blocks_are_laid_at_the_head_of_erased_blocks() {
        bool ok = true;
        const auto block = sound_smc_config_block();
        std::vector<uint8_t> statistics(0x1000);
        for (size_t i = 0; i < statistics.size(); ++i) {
            statistics[i] = static_cast<uint8_t>(i * 13 + 1);
        }
        const std::vector<uint8_t> no_manufacturing(0x1000, 0xFF);
        for (const auto& shape : kConfigShapes) {
            FlashImage image{};
            image.flash_driver = Driver(shape.size, shape.mode);
            image.smc_config = block;
            image.statistics = statistics;
            image.manufacturing = no_manufacturing;
            const auto bytes = image.write();
            ok = check(bytes.has_value(), "an image with settings blocks writes") && ok;
            if (!bytes) {
                continue;
            }
            const auto& driver = std::as_const(image.flash_driver);
            const size_t step = driver.block_size_clean();
            const auto read = [&driver](size_t offset, size_t length) {
                return driver.read_clean(offset, length);
            };
            const auto all_ff = [](const std::vector<uint8_t>& bytes_read) {
                return std::all_of(bytes_read.begin(), bytes_read.end(),
                                   [](uint8_t b) { return b == 0xFF; });
            };
            std::vector<uint8_t> settings(0x1000, 0xFF);
            std::copy(block.begin(), block.end(), settings.begin());
            ok = check(read(shape.offset, 0x1000) == settings &&
                           all_ff(read(shape.offset + 0x1000, step - 0x1000)),
                       "the settings block heads an otherwise erased block") &&
                 ok;
            ok = check(read(shape.offset - step, 0x1000) == statistics &&
                           all_ff(read(shape.offset - step + 0x1000, step - 0x1000)),
                       "the statistics block heads an otherwise erased block") &&
                 ok;
            ok = check(all_ff(read(shape.offset - 2 * step, step)),
                       "a console without manufacturing data keeps that block erased") &&
                 ok;
            if (shape.mode != Driver::DriverMode::Emmc) {
                const size_t stats_page = (shape.offset - step) / 512;
                const auto stats_meta = driver.interpret_page(stats_page + 7);
                ok = check(stats_meta.block_type == 0 && stats_meta.sequence == 0 &&
                               stats_meta.logical_block_id == (shape.offset - step) / step,
                           "the statistics pages carry a type-0 spare naming their block") &&
                     ok;
                ok = check(page_is_erased(driver, stats_page + 8) &&
                               page_is_erased(driver, (shape.offset - 2 * step) / 512),
                           "pages past the 0x1000 and an erased block carry no spare") &&
                     ok;
            }
            auto parsed = FlashImage::read(*bytes);
            ok = check(parsed && parsed->parse() && parsed->smc_config == block &&
                           parsed->statistics == statistics &&
                           parsed->manufacturing == no_manufacturing,
                       "the settings blocks read back where the shape keeps them") &&
                 ok;
        }
        return ok;
    }

    bool test_flash_image_places_filesystem_root_consistently() {
        FlashImage image{};
        image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);

        FlashFileSystem filesystem{};
        if (!check(filesystem.format(image.flash_driver.block_count()),
                   "FlashFS must format before placement")) {
            return false;
        }
        const std::vector<uint8_t> file_data{0x10, 0x20, 0x30};
        if (!check(filesystem.add_file("test.bin", file_data), "FlashFS must accept a test file")) {
            return false;
        }
        image.filesystem = std::move(filesystem);

        if (!check(image.write_to_driver(), "FlashImage must write a filesystem image")) {
            return false;
        }

        const auto root_block = image.filesystem->root_block();
        if (!check(image.flash_driver.layout().fs_root_block == root_block,
                   "FlashImage layout must identify the block containing the filesystem root")) {
            return false;
        }
        if (!check(root_block != 0x3E0, "FlashImage must relocate the default filesystem root away "
                                        "from file allocations")) {
            return false;
        }

        auto parsed = FlashImage::read(image.flash_driver.serialize());
        if (!check(parsed.has_value() && parsed->parse(),
                   "FlashImage must parse the filesystem it just wrote")) {
            return false;
        }
        return check(parsed->filesystem.has_value(),
                     "FlashImage must find the filesystem root at the recorded block") &&
               check(parsed->filesystem->get_file("test.bin") == file_data,
                     "FlashImage must preserve files after root relocation");
    }

    // A copied or moved image's filesystem reads and writes its own driver: adding a file to it
    // and saving lands in that image's flash and leaves the image it came from untouched, even
    // once the source is gone.
    bool test_flash_image_copy_and_move_rebind_the_filesystem() {
        FlashImage source{};
        source.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        FlashFileSystem filesystem{};
        filesystem.set_driver(&source.flash_driver);
        const std::vector<uint8_t> source_file{0x11, 0x22, 0x33};
        if (!check(filesystem.format(source.flash_driver.block_count()),
                   "FlashFS must format for the rebinding check") ||
            !check(filesystem.add_file("source.bin", source_file),
                   "FlashFS must accept the source file") ||
            !check(filesystem.save(), "FlashFS must save into the source image")) {
            return false;
        }
        source.filesystem = std::move(filesystem);
        const std::vector<uint8_t> source_bytes = std::as_const(source.flash_driver).serialize();

        // Adds `name` to the image's filesystem, saves it and reads it back through a filesystem
        // loaded fresh from the image's own driver.
        const auto lands_in_own_driver = [](FlashImage& image, std::string_view name,
                                            const std::vector<uint8_t>& data) {
            if (!image.filesystem || !image.filesystem->add_file(name, data) ||
                !image.filesystem->save()) {
                return false;
            }
            FlashFileSystem reread{};
            return reread.load(image.flash_driver, image.filesystem->root_block()).has_value() &&
                   reread.get_file(name) == data && image.filesystem->get_file(name) == data;
        };

        bool ok = true;
        {
            FlashImage copy = source;
            ok = check(lands_in_own_driver(copy, "copy.bin", {0x01}),
                       "a copy-constructed image's filesystem must write its own driver") &&
                 ok;
        }
        {
            FlashImage assigned{};
            assigned = source;
            ok = check(lands_in_own_driver(assigned, "assigned.bin", {0x02}),
                       "a copy-assigned image's filesystem must write its own driver") &&
                 ok;
        }
        {
            std::optional<FlashImage> donor = source;
            FlashImage moved = std::move(*donor);
            donor.reset();
            ok = check(lands_in_own_driver(moved, "moved.bin", {0x03}),
                       "a move-constructed image's filesystem must write its own driver") &&
                 ok;
        }
        {
            std::optional<FlashImage> donor = source;
            FlashImage assigned{};
            assigned = std::move(*donor);
            donor.reset();
            ok = check(lands_in_own_driver(assigned, "move_assigned.bin", {0x04}),
                       "a move-assigned image's filesystem must write its own driver") &&
                 ok;
        }
        return check(std::as_const(source.flash_driver).serialize() == source_bytes,
                     "writes through a copy or a move must leave the source image's flash") &&
               check(source.filesystem->list_files() == std::vector<std::string>{"source.bin"},
                     "the source image's filesystem must keep only its own file") &&
               ok;
    }

    // Direct regression for the reported double-allocation bug: when files and mobile
    // data pack the data region so only the final block below the limit stays free, a
    // deferred-root filesystem must still place its root there and serialize. The old
    // reserve-then-relocate path pre-consumed that block in format() and then failed
    // with "Failed to place FlashFS root block after payload allocations".
    bool test_flash_image_places_deferred_root_in_last_free_block() {
        FlashImage image{};
        image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        const size_t limit = image.flash_driver.data_block_limit();

        FlashFileSystem filesystem{};
        filesystem.set_driver(&image.flash_driver);
        if (!check(filesystem.format(image.flash_driver.block_count(), FlashFileSystem::kDeferRoot),
                   "deferred-root FlashFS must format")) {
            return false;
        }
        const std::vector<uint8_t> file_data{0x10, 0x20, 0x30};
        if (!check(filesystem.add_file("test.bin", file_data), "FlashFS must accept a test file")) {
            return false;
        }
        const size_t file_block = filesystem.stat("test.bin")->block_number;
        if (!check(filesystem.reserve_blocks(file_block + 1, limit - 1 - (file_block + 1)),
                   "FlashFS reserves every data block below the final one")) {
            return false;
        }
        image.filesystem = std::move(filesystem);

        const auto output = image.write();
        if (!check(output.has_value(),
                   "FlashImage must serialize a data region with one free block")) {
            return false;
        }
        if (!check(image.filesystem->has_root(),
                   "FlashFS root must be placed after serializing a full data region")) {
            return false;
        }
        const auto root_block = image.filesystem->root_block();
        if (!check(image.flash_driver.layout().fs_root_block == root_block &&
                       root_block == limit - 1,
                   "deferred root must land on the sole free data block, not the reserved tail")) {
            return false;
        }

        auto parsed = FlashImage::read(*output);
        if (!check(parsed.has_value() && parsed->parse() && parsed->filesystem.has_value(),
                   "FlashImage must parse the packed filesystem it just wrote")) {
            return false;
        }
        return check(parsed->filesystem->get_file("test.bin") == file_data,
                     "FlashImage must preserve the file when the root takes the last free block");
    }

    bool test_flash_image_accepts_legacy_filesystem_root_type() {
        Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        FlashFileSystem filesystem{};
        if (!check(filesystem.format(source.block_count(), 0x80),
                   "FlashFS must format at a test root block")) {
            return false;
        }
        filesystem.set_driver(&source);
        if (!check(filesystem.save(), "FlashFS must serialize its test root")) {
            return false;
        }

        BlockMetadata metadata{};
        metadata.logical_block_id = 0x80;
        metadata.sequence = 3;
        metadata.block_type = 0x2C;
        source.write_block_metadata(0x80, metadata);

        auto image = FlashImage::read(source.serialize());
        if (!check(image.has_value() && image->parse(),
                   "FlashImage must parse a NAND image with a legacy filesystem root")) {
            return false;
        }
        return check(image->filesystem.has_value(),
                     "FlashImage must recognize filesystem block type 0x2C");
    }

    bool test_writes_reject_out_of_range_data() {
        Driver driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        const size_t image_size = driver.block_count() * driver.block_size_clean();
        const std::array<uint8_t, 2> bytes{0xAA, 0xBB};
        const auto before = driver.read_clean(image_size - 1, 1);
        const bool written = driver.write_offset(image_size - 1, bytes);
        const auto after = driver.read_clean(image_size - 1, 1);
        return check(!written && before.size() == 1 && after.size() == 1 && before[0] == after[0],
                     "Driver must reject offset writes that exceed clean NAND capacity");
    }

    bool test_flash_filesystem_block_count_handles_boundaries() {
        constexpr size_t block_size = gxbuild3::nand::kCleanBlockSize;
        const auto max_blocks = gxbuild3::nand::FlashFileSystemTestAccess::checked_block_count(
            std::numeric_limits<size_t>::max(), block_size);
        return check(max_blocks.has_value() && *max_blocks != 1,
                     "FlashFS SIZE_MAX allocation must not wrap into one block") &&
               check(gxbuild3::nand::FlashFileSystemTestAccess::checked_block_count(
                         0, block_size) == std::optional<size_t>{1},
                     "FlashFS zero-length allocation must use one block") &&
               check(gxbuild3::nand::FlashFileSystemTestAccess::checked_block_count(
                         block_size * 2, block_size) == std::optional<size_t>{2},
                     "FlashFS exact multiples must use the exact block count") &&
               check(gxbuild3::nand::FlashFileSystemTestAccess::checked_block_count(
                         block_size * 2 + 1, block_size) == std::optional<size_t>{3},
                     "FlashFS one-over multiples must round up one block") &&
               check(!gxbuild3::nand::FlashFileSystemTestAccess::checked_block_count(1, 0)
                          .has_value(),
                     "FlashFS must reject a zero clean block size");
    }

    bool test_flash_filesystem_size_max_allocation_is_rejected_without_mutation() {
        FlashFileSystem filesystem{};
        if (!check(filesystem.format(0x400), "FlashFS must format before allocation guard test")) {
            return false;
        }
        const auto before = filesystem.blockmap();
        std::optional<uint16_t> result;
        try {
            result = filesystem.allocate_chain(std::numeric_limits<size_t>::max());
        } catch (...) {
            return check(false, "FlashFS SIZE_MAX allocation must not throw");
        }
        return check(!result.has_value(), "FlashFS SIZE_MAX allocation must return nullopt") &&
               check(filesystem.blockmap() == before,
                     "FlashFS SIZE_MAX allocation must not mutate the blockmap");
    }

    bool test_flash_image_rejects_oversized_smc() {
        FlashImage image{};
        image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        Smc oversized_smc{};
        oversized_smc.data.resize(0x4001, 0xA5);
        image.smc = std::move(oversized_smc);

        const auto written = image.write_to_driver();
        return check(!written && written.error().code == gxbuild3::ErrorCode::OutOfRange,
                     "FlashImage must reject an SMC that cannot fit before writing it");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_fresh_blocks_are_not_bad() && passed;
    passed = test_bad_block_mark_is_read_on_the_first_and_middle_pages() && passed;
    passed = test_big_block_sequence_layout() && passed;
    passed = test_block_type_masks_ecc_bits() && passed;
    passed = test_emmc_image_is_48_megabytes() && passed;
    passed = test_flash_image_reads_cross_page_config() && passed;
    passed = test_smc_config_with_bad_checksum_is_not_carried() && passed;
    passed = test_smc_config_write_leaves_neighbouring_blocks() && passed;
    passed = test_anchor_block_matches_reference_layout() && passed;
    passed = test_anchor_choice_follows_the_number() && passed;
    passed = test_emmc_write_lays_both_anchors() && passed;
    passed = test_flash_image_takes_the_latest_mobile_copy() && passed;
    passed = test_mobile_copies_are_laid_as_xebuild_lays_them() && passed;
    passed = test_rewrite_erases_every_older_mobile_copy() && passed;
    passed = test_mobile_longer_than_one_copy_is_refused() && passed;
    passed = test_settings_blocks_are_laid_at_the_head_of_erased_blocks() && passed;
    passed = test_flash_image_places_filesystem_root_consistently() && passed;
    passed = test_flash_image_copy_and_move_rebind_the_filesystem() && passed;
    passed = test_flash_image_places_deferred_root_in_last_free_block() && passed;
    passed = test_flash_image_accepts_legacy_filesystem_root_type() && passed;
    passed = test_writes_reject_out_of_range_data() && passed;
    passed = test_flash_filesystem_block_count_handles_boundaries() && passed;
    passed = test_flash_filesystem_size_max_allocation_is_rejected_without_mutation() && passed;
    passed = test_flash_image_rejects_oversized_smc() && passed;
    return passed ? 0 : 1;
}
