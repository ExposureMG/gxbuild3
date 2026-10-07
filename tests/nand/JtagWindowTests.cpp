// The JTAG window (src/nand/FlashImageWrite.cpp and FlashImageParse.cpp): the JTAG loader reads
// its neighbours from addresses compiled into it, so its window sits at 0x90000 on every shape.
// The SMC payload lands at 0x200; the rebooter, the KHV patchset, the virtual fuses, XeLL and the
// extra CB and CD land at fixed offsets from the window; and the image reads back as JTAG with
// its XeLL and fuses. Mode/JtagWindow runs the Small and Big shapes, one bundled entry.

#include "nand/AnchorFixture.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/XeLL.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <utility>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        struct JtagWindowMode {
            const char* name;
            Driver::DriverMode mode;
        };
        GX_PRINT_ROW_AS_NAME(JtagWindowMode)

        constexpr JtagWindowMode kJtagWindowModes[] = {
            {"Small", Driver::DriverMode::Small},
            {"Big", Driver::DriverMode::Big},
        };

        class JtagWindow : public ::testing::TestWithParam<JtagWindowMode> {};

        TEST_P(JtagWindow, PayloadsLandAtTheAnchoredWindowAndReadBackAsJtag) {
            const size_t window = 0x90000;
            auto f = anchor_image(GetParam().mode, BuildType::Jtag);
            f.build_type = BuildType::Jtag;
            XeLL x{};
            x.data = raw_xell();
            f.payloads.xell = x;
            f.payloads.rebooter = Bytes(0xd40, 0xAA);
            f.payloads.fuses = Bytes(0x60, 0xBB);
            f.payloads.payload = Bytes(0x200, 0xCC);
            f.payloads.extra_cb = synthetic_cb(0x11);
            f.payloads.extra_cd = synthetic_cd(0x22);
            ASSERT_TRUE(f.payloads.patchset.has_value()) << "fixture yields a JTAG patchset";
            ASSERT_EQ(f.payloads.patchset->kind, PatchSetKind::Jtag)
                << "fixture yields a JTAG patchset";
            const auto& sections = f.payloads.patchset->sections;
            ASSERT_EQ(sections.size(), 4u)
                << "the KHV record occupies JtagSection4 as in [1bl][CB][CD][KHV]";
            ASSERT_EQ(sections.back().target, PatchSectionTarget::JtagSection4)
                << "the KHV record occupies JtagSection4 as in [1bl][CB][CD][KHV]";
            ASSERT_EQ(sections.back().raw_data.size(), 12u)
                << "the KHV record occupies JtagSection4 as in [1bl][CB][CD][KHV]";
            ASSERT_EQ(test::be32(sections.back().raw_data, 0), 0x1000u)
                << "the KHV record occupies JtagSection4 as in [1bl][CB][CD][KHV]";
            ASSERT_OK(f.write_to_driver()) << "anchored jtag image writes";

            const auto& d = std::as_const(f.flash_driver);
            EXPECT_BYTES_EQ(Bytes(0x200, 0xCC), d.read_clean(0x200, 0x200))
                << "SMC payload lands at absolute 0x200";
            EXPECT_BYTES_EQ(Bytes(0xd40, 0xAA), d.read_clean(window, 0xd40))
                << "rebooter lands at the anchored window base";
            EXPECT_BYTES_EQ(Bytes(0x60, 0xBB), d.read_clean(window + 0x5000, 0x60))
                << "virtual fuses land at window + 0x5000";
            const auto patches = serialize_patch_set(*f.payloads.patchset);
            EXPECT_BYTES_EQ(patches, d.read_clean(window + 0x1000, patches.size()))
                << "KHV patchset is pinned at window + 0x1000";
            EXPECT_BYTES_EQ(x.data, d.read_clean(window + 0x5060, 0x40000))
                << "XeLL lands at window + 0x5060";
            const auto extra_cb = f.payloads.extra_cb->serialize();
            const auto extra_cd = f.payloads.extra_cd->serialize();
            EXPECT_BYTES_EQ(extra_cb, d.read_clean(window + 0x45060, extra_cb.size()))
                << "extra CB lands immediately after XeLL at window + 0x45060";
            const size_t cd_at = window + 0x45060 + ((extra_cb.size() + 0xF) & ~size_t{0xF});
            EXPECT_BYTES_EQ(extra_cd, d.read_clean(cd_at, extra_cd.size()))
                << "extra CD follows the 16-byte-aligned extra CB";

            const auto written = f.write();
            ASSERT_OK(written) << "anchored window is recognized as JTAG on read-back";
            auto parsed = FlashImage::read(*written);
            ASSERT_TRUE(parsed.has_value()) << "anchored window is recognized as JTAG on read-back";
            EXPECT_OK(parsed->parse()) << "anchored window is recognized as JTAG on read-back";
            EXPECT_EQ(parsed->build_type, BuildType::Jtag)
                << "anchored window is recognized as JTAG on read-back";
            EXPECT_TRUE(parsed->payloads.xell.has_value())
                << "XeLL is recovered from the anchored window";
            EXPECT_BYTES_EQ(x.data, xell_bytes(parsed->payloads.xell))
                << "XeLL is recovered from the anchored window";
            EXPECT_TRUE(parsed->payloads.fuses.has_value())
                << "virtual fuses are recovered from the anchored window";
            EXPECT_BYTES_EQ(*f.payloads.fuses, parsed->payloads.fuses.value_or(Bytes{}))
                << "virtual fuses are recovered from the anchored window";
        }

        INSTANTIATE_TEST_SUITE_P(Mode, JtagWindow, ::testing::ValuesIn(kJtagWindowModes),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::nand
