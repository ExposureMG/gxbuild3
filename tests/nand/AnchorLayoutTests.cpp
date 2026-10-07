// The runtime anchors a glitch image lays for its patched CD (src/nand/FlashImageWrite.cpp and
// FlashImageParse.cpp): the KHV record found through the header's second-slot base, the raw XeLL
// at 0x70000 on every shape and, for Glitch2m, the manufacturing fuses at the second-slot base,
// each laid and extracted again; a parsed image with a custom header layout written back keeps
// its header-derived anchor; and the raw executable XeLL those images carry is accepted.
//
// AnchorLayout is instantiated per shape (Small, Big, Emmc) over the Glitch2 and Glitch2m rows;
// its plain companion is AnchorLayoutRoundTrip (gtest forbids TEST and TEST_P in one suite).

#include "nand/AnchorFixture.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/XeLL.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <gtest/gtest.h>
#include <utility>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        struct AnchorCell {
            const char* name;
            Driver::DriverMode mode;
            BuildType type;
        };
        GX_PRINT_ROW_AS_NAME(AnchorCell)

        constexpr AnchorCell kSmallCells[] = {
            {"Glitch2", Driver::DriverMode::Small, BuildType::Glitch2},
            {"Glitch2m", Driver::DriverMode::Small, BuildType::Glitch2m},
        };
        constexpr AnchorCell kBigCells[] = {
            {"Glitch2", Driver::DriverMode::Big, BuildType::Glitch2},
            {"Glitch2m", Driver::DriverMode::Big, BuildType::Glitch2m},
        };
        constexpr AnchorCell kEmmcCells[] = {
            {"Glitch2", Driver::DriverMode::Emmc, BuildType::Glitch2},
            {"Glitch2m", Driver::DriverMode::Emmc, BuildType::Glitch2m},
        };

        class AnchorLayout : public ::testing::TestWithParam<AnchorCell> {};

        TEST_P(AnchorLayout, KhvXellAndFusesAreAnchored) {
            const BuildType type = GetParam().type;
            auto f = anchor_image(GetParam().mode, type);
            XeLL x{};
            x.data = raw_xell();
            f.payloads.xell = x;
            if (type == BuildType::Glitch2m) {
                f.payloads.fuses = Bytes(0x60, 0xA5);
            }
            ASSERT_OK(f.write_to_driver()) << "runtime-anchor image writes";

            const auto& d = std::as_const(f.flash_driver);
            const auto h = d.read_offset(0, 0x80);
            const auto s = test::be32(h, 0x64) + test::be32(h, 0x70);
            const auto k = d.read_offset(s + (type == BuildType::Glitch2m ? 0x60 : 0x10), 16);
            EXPECT_EQ(k.size(), 16u) << "CD finds KHV through header";
            EXPECT_EQ(test::be32(k, 0), 0x1000u) << "CD finds KHV through header";
            EXPECT_EQ(test::be32(k, 4), 1u) << "CD finds KHV through header";

            const size_t xell_at = 0x70000;
            EXPECT_BYTES_EQ(x.data, d.read_offset(xell_at, 0x40000))
                << "CD finds raw XeLL at 0x70000 on every shape";
            if (type == BuildType::Glitch2m) {
                EXPECT_BYTES_EQ(Bytes(0x60, 0xA5), d.read_offset(s, 0x60))
                    << "MFG fuse reader finds fuses at second-slot base";
            }

            const auto written = f.write();
            ASSERT_OK(written) << "extract raw XeLL from runtime anchor";
            auto parsed = FlashImage::read(*written);
            ASSERT_TRUE(parsed.has_value()) << "extract raw XeLL from runtime anchor";
            ASSERT_OK(parsed->parse()) << "extract raw XeLL from runtime anchor";
            EXPECT_TRUE(parsed->payloads.xell.has_value())
                << "extract raw XeLL from runtime anchor";
            EXPECT_BYTES_EQ(x.data, xell_bytes(parsed->payloads.xell))
                << "extract raw XeLL from runtime anchor";
            if (type == BuildType::Glitch2m) {
                EXPECT_TRUE(parsed->payloads.fuses.has_value()) << "extract manufacturing fuses";
                EXPECT_BYTES_EQ(*f.payloads.fuses, parsed->payloads.fuses.value_or(Bytes{}))
                    << "extract manufacturing fuses";
            }
        }

        INSTANTIATE_TEST_SUITE_P(Small, AnchorLayout, ::testing::ValuesIn(kSmallCells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Big, AnchorLayout, ::testing::ValuesIn(kBigCells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Emmc, AnchorLayout, ::testing::ValuesIn(kEmmcCells),
                                 test::RowName{});

        TEST(AnchorLayoutRoundTrip, CustomHeaderLayoutKeepsItsHeaderDerivedKhvAnchor) {
            auto f = anchor_image(Driver::Big, BuildType::Glitch2);
            f.preserve_layout = true;
            f.header.cf_offset = 0x100000;
            f.header.fs_addr = 0x30000;
            const auto written = f.write();
            ASSERT_OK(written) << "custom header layout parses";
            auto parsed = FlashImage::read(*written);
            ASSERT_TRUE(parsed.has_value()) << "custom header layout parses";
            ASSERT_OK(parsed->parse()) << "custom header layout parses";

            const auto rewritten = parsed->write();
            ASSERT_OK(rewritten) << "custom header layout rewrites";
            auto again = FlashImage::read(*rewritten);
            ASSERT_TRUE(again.has_value()) << "custom header layout rewrites";
            ASSERT_OK(again->parse()) << "custom header layout rewrites";

            const auto bytes = std::as_const(again->flash_driver).read_offset(0x130010, 16);
            EXPECT_EQ(again->header.cf_offset.get(), 0x100000u)
                << "read/write preserves header-derived runtime KHV anchor";
            EXPECT_EQ(again->header.fs_addr.get(), 0x30000u)
                << "read/write preserves header-derived runtime KHV anchor";
            EXPECT_EQ(bytes.size(), 16u)
                << "read/write preserves header-derived runtime KHV anchor";
            EXPECT_EQ(test::be32(bytes, 0), 0x1000u)
                << "read/write preserves header-derived runtime KHV anchor";
        }

        // The XeLL the anchor images carry: a raw executable, not a packaged XeLL.
        TEST(XeLL, RawExecutableIsAccepted) {
            EXPECT_OK(XeLL::parse(raw_xell())) << "raw executable XeLL is accepted";
        }

    } // namespace
} // namespace gxbuild3::nand
