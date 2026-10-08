// The eMMC anchor block (src/nand/objects/CoronaConfig.hpp): its bytes against xerunner's
// reference vectors, the choice between the two copies by number, and FlashImage laying both
// copies of an eMMC image so the mobile data is found again through them.

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/NandShapes.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "nand/objects/MobileData.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <utility>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        // The table a chosen anchor names, or nullopt when none was chosen.
        std::optional<uint16_t> table_of(const std::optional<CoronaConfig>& chosen) {
            return chosen.transform([](const CoronaConfig& config) { return config.table; });
        }

        // Vectors from xerunner's Anchor.encoded, which was measured on images the original
        // built: only the first 0x30 bytes are non-zero.
        TEST(CoronaAnchor, AnchorBlockMatchesReferenceLayout) {
            CoronaConfig first{};
            first.number = 1;
            first.table = 0x38E;
            first.blobs[1] = {0x38C, 0x200}; // type 0x32 is slot 1, which sits at 0x24
            first.blobs[3] = {0x38D, 0x800}; // type 0x34 is slot 3, which sits at 0x2C
            const auto bytes = first.serialize();
            ASSERT_EQ(bytes.size(), 0x200u) << "an anchor block is 0x200 bytes";
            EXPECT_EQ(test::hex(std::span(bytes).first(0x14)),
                      "af9c1da90c94a9fb5329ea470c7618833abb5d4e")
                << "anchor digest matches the reference";
            EXPECT_EQ(test::hex(std::span(bytes).subspan(0x14, 0x1C)),
                      "0000000000000001038e000000000000038c020000000000038d0800")
                << "anchor body matches the reference";
            EXPECT_BYTES_EQ(Bytes(0x200 - 0x30, 0x00), std::span(bytes).subspan(0x30))
                << "an anchor block is zero past 0x30";

            CoronaConfig second{};
            second.number = 2;
            second.table = 0x38E;
            second.blobs[0] = {0x38B, 0x800};
            const auto second_bytes = second.serialize();
            ASSERT_GE(second_bytes.size(), 0x14u) << "second anchor digest matches the reference";
            EXPECT_EQ(test::hex(std::span(second_bytes).first(0x14)),
                      "f8c15d3b38d5dafe77d001984aa909b62c5eab1b")
                << "second anchor digest matches the reference";

            const auto parsed = CoronaConfig::parse(bytes);
            ASSERT_OK(parsed) << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->number, 1u) << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->table, 0x38E) << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->blobs[1].block, 0x38C)
                << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->blobs[1].length, 0x200)
                << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->blobs[3].block, 0x38D)
                << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->blobs[3].length, 0x800)
                << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->blobs[0].length, 0) << "an anchor block reads back what was written";
            EXPECT_EQ(parsed->blobs[2].length, 0) << "an anchor block reads back what was written";

            auto damaged = bytes;
            damaged[0x40] ^= 0xFF;
            EXPECT_FALSE(CoronaConfig::parse(damaged).has_value())
                << "an anchor whose hash disagrees is refused";
        }

        // The anchor a console believes is decided by its number, not by where it sits.
        TEST(CoronaAnchor, AnchorChoiceFollowsTheNumber) {
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

            const auto swapped = CoronaConfig::choose(
                {std::span<const uint8_t>(high_bytes), std::span<const uint8_t>(low_bytes)});
            EXPECT_EQ(table_of(swapped), 0x222) << "the higher number wins in the first slot";
            const auto normal = CoronaConfig::choose(
                {std::span<const uint8_t>(low_bytes), std::span<const uint8_t>(high_bytes)});
            EXPECT_EQ(table_of(normal), 0x222) << "the higher number wins in the second slot";
            const auto fallback = CoronaConfig::choose(
                {std::span<const uint8_t>(damaged), std::span<const uint8_t>(low_bytes)});
            EXPECT_EQ(table_of(fallback), 0x111)
                << "a copy whose hash disagrees is skipped for the other";
            const auto none = CoronaConfig::choose(
                {std::span<const uint8_t>(damaged), std::span<const uint8_t>(damaged)});
            EXPECT_FALSE(none.has_value()) << "no sound copy names no filesystem";
        }

        TEST(CoronaAnchor, EmmcWriteLaysBothAnchors) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::Emmcblock, Driver::DriverMode::Emmc);
            nand::MobileData mobile;
            mobile.x31 = Bytes(0x800, 0x31);
            mobile.x32 = Bytes(0x200, 0x32);
            image.mobile_data = mobile;

            EXPECT_OK(image.write_to_driver()) << "an eMMC image with mobile data writes";
            const auto& driver = std::as_const(image.flash_driver);
            // The two copies of one image, walked in turn.
            for (size_t copy = 0; copy < CoronaConfig::kOffsets.size(); ++copy) {
                SCOPED_TRACE(std::format("anchor copy {} at 0x{:X}", copy + 1,
                                         CoronaConfig::kOffsets[copy]));
                const auto bytes =
                    driver.read_offset(CoronaConfig::kOffsets[copy], CoronaConfig::kSpan);
                const auto parsed = CoronaConfig::parse(std::span<const uint8_t>(bytes));
                EXPECT_OK(parsed) << "each anchor copy parses";
                if (!parsed) {
                    continue;
                }
                EXPECT_EQ(parsed->number, copy + 1) << "the copies are numbered 1 and 2";
                EXPECT_EQ(parsed->blobs[0].length, 0x800)
                    << "blob lengths are bytes and each blob sits in the slot of its type";
                EXPECT_EQ(parsed->blobs[1].length, 0x200)
                    << "blob lengths are bytes and each blob sits in the slot of its type";
                EXPECT_EQ(parsed->blobs[2].length, 0)
                    << "blob lengths are bytes and each blob sits in the slot of its type";
                EXPECT_EQ(parsed->blobs[3].length, 0)
                    << "blob lengths are bytes and each blob sits in the slot of its type";
                EXPECT_TRUE(std::all_of(bytes.begin() + CoronaConfig::kSize, bytes.end(),
                                        [](uint8_t b) { return b == 0; }))
                    << "the anchor's span is zero after the structure";
                const auto tail =
                    driver.read_offset(CoronaConfig::kOffsets[copy] + CoronaConfig::kSpan,
                                       CoronaConfig::kBlockSize - CoronaConfig::kSpan);
                EXPECT_FALSE(tail.empty()) << "the anchor's block is erased past its span";
                EXPECT_TRUE(all_erased(tail)) << "the anchor's block is erased past its span";
            }

            auto reread = FlashImage::read(image.flash_driver.serialize());
            ASSERT_TRUE(reread.has_value()) << "mobile data is found again through the anchor";
            ASSERT_OK(reread->parse()) << "mobile data is found again through the anchor";
            ASSERT_TRUE(reread->mobile_data.has_value())
                << "mobile data is found again through the anchor";
            EXPECT_BYTES_EQ(*mobile.x31, reread->mobile_data->x31.value_or(Bytes{}))
                << "mobile data is found again through the anchor";
            EXPECT_BYTES_EQ(*mobile.x32, reread->mobile_data->x32.value_or(Bytes{}))
                << "mobile data is found again through the anchor";
        }

    } // namespace
} // namespace gxbuild3::nand
