// run_build's image layout and NAND header (src/BuildRunner.cpp, src/nand/FlashImage.cpp):
// FreshLayout: a fresh build takes the driver mode of the requested image type, and a two-slot
// replacement over a one-slot donor writes its own two-slot header. NandHeader: 0x74 stays zero
// (xeBuild parity), 0x04 states no pairing, the copyright notice follows the board (a donor of
// the same board keeps its own, a JTAG Jasper states 2008), and the hacked boot flags at 0x48 and
// 0x4C, the two update slots at 0x68 and the zeroed KHV tail of a glitch2/JTAG image. The value
// loops run in one case under SCOPED_TRACE. One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/NandTypes.hpp"
#include "nand/objects/SMC.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/Stages.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using nand::Driver;
        using nand::FlashImage;
        using test::Bytes;

        TEST(FreshLayout, LayoutsMatchRequestedImageTypes) {
            const std::array<std::pair<ImageType, Driver::DriverMode>, 4> layouts{{
                {ImageType::SmallBlock, Driver::DriverMode::Small},
                {ImageType::NewSmallBlock, Driver::DriverMode::NewSmall},
                {ImageType::BigBlock, Driver::DriverMode::Big},
                {ImageType::Emmc, Driver::DriverMode::Emmc},
            }};

            for (const auto& [image_type, expected_mode] : layouts) {
                SCOPED_TRACE(::testing::Message() << "image type " << static_cast<int>(image_type));
                const auto built = run_build(test::fresh_input(image_type));
                ASSERT_OK(built) << "fresh layout build succeeds";
                const auto parsed = parse_image(*built);
                ASSERT_TRUE(parsed.has_value()) << "fresh layout output parses";
                EXPECT_EQ(parsed->flash_driver.driver_mode(), expected_mode)
                    << "fresh layout uses the requested NAND driver mode";
            }
        }

        TEST(FreshLayout, ReplacementLayoutOverridesAOneSlotDonorHeader) {
            const auto donor = run_build(test::fresh_input(ImageType::SmallBlock));
            ASSERT_OK(donor) << "one-slot donor header fixture is created";
            auto donor_image = FlashImage::read(*donor);
            ASSERT_TRUE(donor_image && donor_image->parse())
                << "one-slot donor header fixture is created";
            const std::array<uint8_t, 2> one_slot{{0x00, 0x01}};
            ASSERT_TRUE(donor_image->flash_driver.write_offset(
                offsetof(nand::nand_header, patch_slots), one_slot))
                << "one-slot donor header fixture is created";
            auto patched_donor = FlashImage::read(donor_image->flash_driver.serialize());
            ASSERT_TRUE(patched_donor && patched_donor->parse())
                << "one-slot donor header fixture is created";
            ASSERT_EQ(patched_donor->header.patch_slots.get(), 1u)
                << "one-slot donor header fixture is created";

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = donor_image->flash_driver.serialize();
            const auto [cf0, cg0] = test::valid_system_update(0x51);
            const auto [cf1, cg1] = test::valid_system_update(0x61);
            input.bootloaders.cf0 = cf0;
            input.bootloaders.cg0 = cg0;
            input.bootloaders.cf1 = cf1;
            input.bootloaders.cg1 = cg1;

            const auto built = run_build(input);
            ASSERT_OK(built) << "two-slot replacement over one-slot donor builds";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image && image->parse())
                << "two-slot replacement over one-slot donor builds";
            EXPECT_EQ(image->header.patch_slots.get(), 2u)
                << "replacement layout writes two patch slots instead of preserving donor header";
            EXPECT_TRUE(image->system_update_0.cf.has_value())
                << "both replacement CF/CG slots parse from the advertised two-slot layout (CF0)";
            EXPECT_TRUE(image->system_update_0.cg.has_value())
                << "both replacement CF/CG slots parse from the advertised two-slot layout (CG0)";
            EXPECT_TRUE(image->system_update_1.cf.has_value())
                << "both replacement CF/CG slots parse from the advertised two-slot layout (CF1)";
            EXPECT_TRUE(image->system_update_1.cg.has_value())
                << "both replacement CF/CG slots parse from the advertised two-slot layout (CG1)";
        }

        // xeBuild leaves header 0x74 zero (xerunner build.py `header`), as do the console
        // dumps measured; a rewrite must not carry a donor's value forward either.
        TEST(NandHeader, Header0x74StaysZeroOnFreshAndRewrittenImages) {
            const auto zero_at_0x74 = [](const Bytes& image) {
                return image.size() >= 0x78 &&
                       std::all_of(image.begin() + 0x74, image.begin() + 0x78,
                                   [](uint8_t b) { return b == 0; });
            };
            for (const auto image_type :
                 {ImageType::SmallBlock, ImageType::BigBlock, ImageType::Emmc}) {
                SCOPED_TRACE(::testing::Message() << "image type " << static_cast<int>(image_type));
                const auto built = run_build(test::fresh_input(image_type));
                ASSERT_OK(built) << "header 0x74 fixture builds";
                EXPECT_TRUE(zero_at_0x74(*built)) << "fresh image leaves header 0x74 zero";
                auto parsed = parse_image(*built);
                ASSERT_TRUE(parsed.has_value()) << "header 0x74 fixture parses";
                parsed->header.smc_config_offset = 0xF7C000;
                EXPECT_TRUE(zero_at_0x74(parsed->write().value_or(Bytes{})))
                    << "rewrite does not carry a donor's header 0x74";
            }
        }

        // The 0x38-byte notice at header 0x10: "(c) 2004-<year> Microsoft Corporation. All rights
        // reserved.", zero padded.
        Bytes copyright(std::string_view year) {
            const std::string text =
                "\xA9 2004-" + std::string(year) + " Microsoft Corporation. All rights reserved.";
            Bytes bytes(0x38, 0);
            std::copy(text.begin(), text.end(), bytes.begin());
            return bytes;
        }

        Bytes header_copyright(const Bytes& image) {
            return Bytes(image.begin() + 0x10, image.begin() + 0x48);
        }

        TEST(NandHeader, StatesZeroPairingAndTheBoardCopyright) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.pairing_data = {0x63, 0xDB, 0x01};
            input.console = ConsoleType::Trinity;
            const auto trinity = run_build(input);
            ASSERT_OK(trinity) << "header fixture builds";
            EXPECT_EQ((*trinity)[4], 0) << "header 0x04 states no pairing";
            EXPECT_EQ((*trinity)[5], 0) << "header 0x04 states no pairing";
            EXPECT_BYTES_EQ(copyright("2010"), header_copyright(*trinity))
                << "a fresh Trinity image states 2004-2010";

            // The fixture SMC names a Xenon board, so a Xenon donor is the same board.
            const auto smc = nand::Smc::parse(*input.metadata.smc);
            input.console = ConsoleType::Xenon;
            const auto xenon = run_build(input);
            ASSERT_OK(smc) << "header fixture SMC names a Xenon board";
            EXPECT_EQ(smc->motherboard, nand::SmcMotherboard::Xenon)
                << "header fixture SMC names a Xenon board";
            ASSERT_OK(xenon) << "a fresh Xenon image states 2004-2005";
            EXPECT_BYTES_EQ(copyright("2005"), header_copyright(*xenon))
                << "a fresh Xenon image states 2004-2005";
            auto custom = parse_image(*xenon);
            ASSERT_TRUE(custom.has_value()) << "header donor parses";
            const auto donor_copyright = copyright("2006");
            std::copy(donor_copyright.begin(), donor_copyright.end(), custom->header.copyright);
            const auto donor = custom->write().value_or(Bytes{});

            auto same_board = input;
            same_board.metadata.nand_image = donor;
            const auto kept = run_build(same_board);
            auto other_board = same_board;
            other_board.console = ConsoleType::Falcon;
            const auto replaced = run_build(other_board);
            ASSERT_OK(kept) << "a donor of the same board keeps its own notice";
            EXPECT_BYTES_EQ(donor_copyright, header_copyright(*kept))
                << "a donor of the same board keeps its own notice";
            ASSERT_OK(replaced) << "a donor of another board takes the target's notice";
            EXPECT_BYTES_EQ(copyright("2007"), header_copyright(*replaced))
                << "a donor of another board takes the target's notice";

            // A JTAG Jasper states 2008 even over a Jasper donor.
            auto jasper = test::fresh_input(ImageType::SmallBlock);
            (*jasper.metadata.smc)[0x100] = 0x40;
            jasper.console = ConsoleType::Jasper;
            const auto retail_jasper = run_build(jasper);
            ASSERT_OK(retail_jasper) << "Jasper header donor builds and parses";
            auto jasper_donor = parse_image(*retail_jasper);
            ASSERT_TRUE(jasper_donor.has_value()) << "Jasper header donor builds and parses";
            std::copy(donor_copyright.begin(), donor_copyright.end(),
                      jasper_donor->header.copyright);
            jasper.metadata.nand_image = jasper_donor->write().value_or(Bytes{});
            const auto kept_jasper = run_build(jasper);
            auto jtag = jasper;
            jtag.build_type = BuildType::Jtag;
            test::mark_jtag_smc(*jtag.metadata.smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13})};
            jtag.patches = std::move(patches);
            const auto jtag_jasper = run_build(jtag);
            ASSERT_OK(kept_jasper) << "a retail Jasper keeps its Jasper donor's notice";
            EXPECT_BYTES_EQ(donor_copyright, header_copyright(*kept_jasper))
                << "a retail Jasper keeps its Jasper donor's notice";
            ASSERT_OK(jtag_jasper) << "a JTAG Jasper over a Jasper donor states 2004-2008";
            EXPECT_BYTES_EQ(copyright("2008"), header_copyright(*jtag_jasper))
                << "a JTAG Jasper over a Jasper donor states 2004-2008";
        }

        using HeaderWords = std::pair<uint32_t, uint32_t>;

        // The words at 0x48 (hacked boot flags) and 0x4C (XeLL and dualboot buttons), or
        // {~0, ~0} when the image did not build.
        HeaderWords header_words(const BuildResult& image) {
            return image ? HeaderWords{test::be32(*image, 0x48), test::be32(*image, 0x4C)}
                         : HeaderWords{~0u, ~0u};
        }

        BuildResult glitch2_build(OptionsArgs options) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch2;
            input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", test::glitch_patchset(0x20, 0, 0x30, 0, Bytes{0x92})};
            input.patches = std::move(patches);
            input.options = std::move(options);
            return run_build(input);
        }

        BuildResult jtag_build(OptionsArgs options) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            test::mark_jtag_smc(*input.metadata.smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13})};
            input.patches = std::move(patches);
            input.options = std::move(options);
            return run_build(input);
        }

        TEST(NandHeader, HackedHeaderStatesBootFlagsTwoSlotsAndAZeroedKhvTail) {
            // Glitch2 with no options: XeLL on eject, two slots, and the KHV patch slot (0x80000,
            // behind slot zero at 0x70000) zero after its terminator up to 0x84000, erased after.
            const auto plain = glitch2_build({});
            ASSERT_OK(plain) << "a glitch2 image states 0x48 = 1 and XeLL on eject at 0x4C";
            EXPECT_EQ(header_words(plain), (HeaderWords{1u, 0x12u}))
                << "a glitch2 image states 0x48 = 1 and XeLL on eject at 0x4C";
            EXPECT_EQ(test::be16(*plain, 0x68), 2u) << "a glitch2 image states two update slots";
            const auto khv = read_logical(*plain, 0x80010, 5);
            const auto tail = read_logical(*plain, 0x80015, 0x4000 - 0x15);
            const auto past = read_logical(*plain, 0x84000, 0x10);
            EXPECT_EQ(khv, std::optional<Bytes>(Bytes({0x92, 0xFF, 0xFF, 0xFF, 0xFF})))
                << "the KHV and its terminator open the patch slot";
            ASSERT_TRUE(tail.has_value())
                << "the patch slot is zero from the KHV terminator to 0x4000";
            EXPECT_TRUE(std::all_of(tail->begin(), tail->end(), [](uint8_t byte) {
                return byte == 0;
            })) << "the patch slot is zero from the KHV terminator to 0x4000";
            EXPECT_EQ(past, std::optional<Bytes>(Bytes(0x10, 0xFF)))
                << "the patch slot past 0x4000 stays erased";

            OptionsArgs buttons{};
            buttons.xellbutton = "Power";
            buttons.xellbutton2 = "eject";
            buttons.cygnos = true;
            buttons.dualboot = "kiosk";
            OptionsArgs same_button{};
            same_button.xellbutton = "power";
            same_button.xellbutton2 = "power";
            OptionsArgs nodvd{};
            nodvd.nodvd = true;
            OptionsArgs olddvd{};
            olddvd.olddvd = true;
            olddvd.demon = true;
            OptionsArgs dualboot{};
            dualboot.dualboot = "wiredx";
            OptionsArgs dualboot_on_xell{};
            dualboot_on_xell.dualboot = "eject";
            EXPECT_EQ(header_words(glitch2_build(buttons)), (HeaderWords{1u, 0x00011211u}))
                << "glitch2 takes both XeLL buttons and cygnos, and no dualboot";
            EXPECT_EQ(header_words(glitch2_build(same_button)), (HeaderWords{1u, 0x00000011u}))
                << "a second XeLL button equal to the first is dropped";
            EXPECT_EQ(header_words(glitch2_build(nodvd)), (HeaderWords{1u, 0u}))
                << "nodvd leaves a glitch2 image without a XeLL button";
            EXPECT_EQ(header_words(jtag_build({})), (HeaderWords{1u, 0x00040012u}))
                << "a JTAG image states the DVD bit and XeLL on eject";
            EXPECT_EQ(header_words(jtag_build(nodvd)), (HeaderWords{1u, 0x00020000u}))
                << "nodvd on JTAG states bit 2 and no XeLL button";
            EXPECT_EQ(header_words(jtag_build(olddvd)), (HeaderWords{1u, 0x00010000u}))
                << "olddvd on JTAG clears the DVD bits; demon states bit 1";
            EXPECT_EQ(header_words(jtag_build(dualboot)), (HeaderWords{1u, 0x5A040012u}))
                << "a JTAG dualboot button lands at 0x4C";
            EXPECT_EQ(header_words(jtag_build(dualboot_on_xell)), (HeaderWords{1u, 0x00040012u}))
                << "a dualboot button that starts XeLL is ignored";

            // Retail states neither word, whatever the options and whatever its donor held.
            const auto donor = run_build(test::fresh_input(ImageType::SmallBlock));
            ASSERT_OK(donor) << "hacked-header donor fixture is created";
            auto donor_image = FlashImage::read(*donor);
            ASSERT_TRUE(donor_image && donor_image->parse())
                << "hacked-header donor fixture is created";
            const std::array<uint8_t, 8> hacked{{0, 0, 0, 1, 0x11, 0x04, 0x00, 0x12}};
            ASSERT_TRUE(donor_image->flash_driver.write_offset(
                offsetof(nand::nand_header, hack_flags), hacked))
                << "hacked-header donor fixture is created";
            auto retail = test::fresh_input(ImageType::SmallBlock);
            retail.metadata.nand_image = donor_image->flash_driver.serialize();
            retail.options = buttons;
            const auto rebuilt = run_build(retail);
            ASSERT_OK(rebuilt) << "a retail image over a hacked donor states 0x48 and 0x4C zero";
            EXPECT_EQ(header_words(rebuilt), (HeaderWords{0u, 0u}))
                << "a retail image over a hacked donor states 0x48 and 0x4C zero";
            EXPECT_EQ(test::be16(*rebuilt, 0x68), 2u) << "a retail image states two update slots";
        }

    } // namespace
} // namespace gxbuild3::orchestration
