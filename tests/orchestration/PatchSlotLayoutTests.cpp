// run_build's patch-slot layout (src/nand/FlashImageLayout.hpp and src/BuildRunner.cpp): where
// the glitch KHV lands (the header overlay anchor, one patch stride above the first update slot,
// 0x20000 on big block), how a XeLL at 0x70000 pushes the slots to the next erase block, the
// fixed JTAG offsets (patches at 0x91000, fuses at 0x95000, XeLL at 0x95060), the collisions
// refused between XeLL, the rebooter, the virtual fuses and an oversized boot chain, and how
// extraction attributes a patch-base XeLL without inventing JTAG payloads. The layout loops run
// each shape in one case under SCOPED_TRACE. One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Patchset.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/Stages.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using nand::FlashImage;
        using test::Bytes;

        const Bytes kElfMagic{0x7F, 'E', 'L', 'F'};

        const char* shape_name(ImageType image_type) {
            switch (image_type) {
                case ImageType::SmallBlock:
                    return "SmallBlock";
                case ImageType::NewSmallBlock:
                    return "NewSmallBlock";
                case ImageType::BigBlock:
                    return "BigBlock";
                case ImageType::Emmc:
                    return "Emmc";
            }
            return "unknown";
        }

        // A small-block glitch input whose automatic patch file carries khv after empty CB and CD
        // sections.
        Input glitch_with_khv(ImageType image_type, Bytes khv) {
            auto input = test::fresh_input(image_type);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", test::glitch_patchset(0x20, 0, 0x30, 0, khv)};
            input.patches = std::move(patches);
            return input;
        }

        TEST(PatchSlotLayout, GlitchPatchRegionDoesNotOverwriteMobileData) {
            auto input = glitch_with_khv(ImageType::SmallBlock, Bytes{0xA0, 0xA1, 0xA2});

            // Every blob type, each a full block, laid from the first free block.
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                Bytes expected_mobile(0x4000);
                for (size_t index = 0; index < expected_mobile.size(); ++index) {
                    expected_mobile[index] =
                        static_cast<uint8_t>((index * 17U + block_type) & 0xFFU);
                }
                *input.mobiles.slot(block_type) = std::move(expected_mobile);
            }

            const auto built = run_build(input);
            ASSERT_OK(built) << "glitch image with mobile data extracts";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "glitch image with mobile data extracts";
            for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
                SCOPED_TRACE(::testing::Message()
                             << "mobile block type 0x" << std::hex << static_cast<int>(block_type));
                const auto& written = *extracted->mobiles.slot(block_type);
                ASSERT_TRUE(written.has_value())
                    << "glitch patch reservation prevents overwriting mobile data";
                EXPECT_BYTES_EQ(**input.mobiles.slot(block_type), *written)
                    << "glitch patch reservation prevents overwriting mobile data";
            }
        }

        TEST(PatchSlotLayout, GlitchPatchUsesHeaderOverlayAnchor) {
            auto input = glitch_with_khv(ImageType::SmallBlock, Bytes{0xA0});
            InputPayloads payloads{};
            payloads.xell = test::valid_xell();
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            ASSERT_OK(built) << "glitch patch and XeLL image builds";
            const auto khv = read_logical(*built, 0xC0010, 1);
            const auto xell_magic = read_logical(*built, 0x70000, 4);
            ASSERT_TRUE(khv.has_value() && xell_magic.has_value())
                << "glitch patch and XeLL image builds";
            EXPECT_BYTES_EQ(Bytes({0xA0}), *khv)
                << "glitch KHV starts at header update base plus stride plus 0x10";
            EXPECT_BYTES_EQ(kElfMagic, *xell_magic) << "glitch patch placement preserves XeLL";
        }

        TEST(PatchSlotLayout, BigBlockGlitchUsesBigPatchStride) {
            const auto input = glitch_with_khv(ImageType::BigBlock, Bytes(0x10000, 0xB4));

            const auto built = run_build(input);
            ASSERT_OK(built) << "big-block glitch accepts payload above small stride";
            // With no XeLL the first slot is the chain's end rounded up by 0x20000, which is
            // 0x80000, and the overlay one 0x20000 stride above it.
            const auto first = read_logical(*built, 0xA0010, 1);
            ASSERT_TRUE(first.has_value()) << "big-block KHV uses the second-slot overlay";
            EXPECT_BYTES_EQ(Bytes({0xB4}), *first) << "big-block KHV uses the second-slot overlay";
        }

        TEST(PatchSlotLayout, GlitchPatchIsDisjointFromRebooterWithoutXell) {
            auto input = glitch_with_khv(ImageType::SmallBlock, Bytes{0xA0});
            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x1000, 0x71);
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            ASSERT_OK(built) << "fixed KHV anchor is disjoint from the rebooter";
            const auto khv = read_logical(*built, 0x80010, 1);
            ASSERT_TRUE(khv.has_value()) << "KHV stays at runtime anchor";
            EXPECT_BYTES_EQ(Bytes{0xA0}, *khv) << "KHV stays at runtime anchor";
        }

        TEST(PatchSlotLayout, JtagXellWithoutRebooterPreservesPatchesAndUsesFixedOffset) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            test::mark_jtag_smc(*input.metadata.smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13, 0x14})};
            input.patches = patches;
            InputPayloads payloads{};
            payloads.xell = test::valid_xell();
            input.payloads = std::move(payloads);

            const auto merged = nand::parse_and_merge_patch_set(patches, BuildType::Jtag);
            ASSERT_OK(merged) << "JTAG patch bytes survive beside XeLL";
            const auto expected = nand::serialize_patch_set(*merged);
            const auto built = run_build(input);
            ASSERT_OK(built) << "JTAG patch plus XeLL image builds";
            const auto written_patch = read_logical(*built, 0x91000, expected.size());
            const auto xell_magic = read_logical(*built, 0x95060, 4);
            ASSERT_TRUE(written_patch.has_value()) << "JTAG patch bytes survive beside XeLL";
            EXPECT_BYTES_EQ(expected, *written_patch) << "JTAG patch bytes survive beside XeLL";
            ASSERT_TRUE(xell_magic.has_value()) << "JTAG XeLL always starts at 0x95060";
            EXPECT_BYTES_EQ(kElfMagic, *xell_magic) << "JTAG XeLL always starts at 0x95060";
        }

        TEST(PatchSlotLayout, GlitchXellShiftsPatchSlotsOnSmallAndBigLayouts) {
            for (auto image_type : {ImageType::SmallBlock, ImageType::BigBlock, ImageType::Emmc}) {
                SCOPED_TRACE(shape_name(image_type));
                auto input = test::fresh_input(image_type);
                input.build_type = BuildType::Glitch;
                InputPatches patches{};
                patches.automatic = InputPatchFile{
                    "automatic", test::glitch_patchset(0x20, 0, 0x30, 0,
                                                       Bytes{0, 0, 0x10, 0, 0, 0, 0, 1, 0x60, 0, 0,
                                                             0, 255, 255, 255, 255})};
                input.patches = patches;
                input.payloads = InputPayloads{};
                input.payloads->xell = test::valid_xell();
                auto [cf, cg] = test::valid_system_update(0x61);
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                const auto built = run_build(input);
                // XeLL sits at 0x70000 on every shape and the slots follow it, rounded up by the
                // erase block: 0xB0000, or 0xC0000 on big block, whose slot is 0x20000 long.
                const size_t base = image_type == ImageType::BigBlock ? 0xC0000 : 0xB0000;
                const size_t stride = image_type == ImageType::BigBlock ? 0x20000 : 0x10000;
                const size_t xell_at = 0x70000;
                ASSERT_OK(built) << "one update slot and runtime overlay build";
                const auto khv = read_logical(*built, base + stride + 0x10, 4);
                ASSERT_TRUE(khv.has_value()) << "KHV matches CD header anchor";
                EXPECT_BYTES_EQ(Bytes({0, 0, 0x10, 0}), *khv) << "KHV matches CD header anchor";
                const auto xell = read_logical(*built, xell_at, 0x40000);
                ASSERT_TRUE(xell.has_value()) << "XeLL sits at 0x70000";
                EXPECT_BYTES_EQ(*input.payloads->xell, *xell) << "XeLL sits at 0x70000";

                const auto extracted = extract_all(*built, input.metadata.cpu_key);
                ASSERT_OK(extracted)
                    << "extraction preserves the runtime patch stream and build type";
                EXPECT_TRUE(extracted->patches.has_value())
                    << "extraction preserves the runtime patch stream and build type";
                EXPECT_EQ(extracted->build_type, BuildType::Glitch)
                    << "extraction preserves the runtime patch stream and build type";

                const auto rebuilt = run_build(*extracted);
                ASSERT_OK(rebuilt) << "extract/rebuild preserves XeLL and the KHV anchor";
                const auto rebuilt_khv = read_logical(*rebuilt, base + stride + 0x10, 4);
                const auto rebuilt_xell = read_logical(*rebuilt, xell_at, 0x40000);
                ASSERT_TRUE(rebuilt_khv.has_value() && rebuilt_xell.has_value())
                    << "extract/rebuild preserves XeLL and the KHV anchor";
                EXPECT_BYTES_EQ(Bytes({0, 0, 0x10, 0}), *rebuilt_khv)
                    << "extract/rebuild preserves XeLL and the KHV anchor";
                EXPECT_BYTES_EQ(*input.payloads->xell, *rebuilt_xell)
                    << "extract/rebuild preserves XeLL and the KHV anchor";

                input.bootloaders.cf1 = cf;
                input.bootloaders.cg1 = cg;
                const auto conflict = run_build(input);
                ASSERT_FALSE(conflict.has_value()) << "CF1 cannot occupy the glitch overlay";
                EXPECT_TRUE(conflict.error().message.contains("second update slot"))
                    << "CF1 cannot occupy the glitch overlay";
            }
        }

        TEST(PatchSlotLayout, SmallGlitchXellRejectsFixedPayloadCollisions) {
            struct Case {
                std::string_view name;
                bool add_rebooter;
                bool add_fuses;
                std::string_view collided_payload;
            };
            const std::array cases{Case{"rebooter", true, false, "rebooter"},
                                   Case{"virtual fuses", false, true, "virtual-fuse"}};

            for (const auto& test_case : cases) {
                SCOPED_TRACE(test_case.name);
                auto input = glitch_with_khv(ImageType::SmallBlock, Bytes{0xA0});
                InputPayloads payloads{};
                payloads.xell = test::valid_xell();
                if (test_case.add_rebooter) {
                    payloads.rebooter = Bytes(0x1000, 0x71);
                }
                if (test_case.add_fuses) {
                    payloads.fuses = Bytes(0x60, 0x72);
                }
                input.payloads = std::move(payloads);

                const auto built = run_build(input);
                ASSERT_ERROR(built, BuildErrorCode::InvalidInput)
                    << "small-block Glitch rejects overlapping fixed payloads";
                EXPECT_TRUE(built.error().message.contains(test_case.collided_payload))
                    << "fixed-payload collision identifies the overwritten payload";
            }
        }

        TEST(PatchSlotLayout, DonorTransitionRejectsRetainedGlitchXellCollision) {
            auto donor_input = test::fresh_input(ImageType::SmallBlock);
            donor_input.build_type = BuildType::Jtag;
            test::mark_jtag_smc(*donor_input.metadata.smc);
            InputPatches donor_patches{};
            donor_patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0xA1})};
            donor_input.patches = std::move(donor_patches);
            InputPayloads donor_payloads{};
            donor_payloads.rebooter = Bytes(0x1000, 0x71);
            donor_payloads.fuses = Bytes(0x60, 0x72);
            donor_payloads.xell = test::valid_xell();
            donor_input.payloads = std::move(donor_payloads);
            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "adjacent JTAG donor payload layout builds";

            auto input = glitch_with_khv(ImageType::SmallBlock, Bytes{0xA2});
            input.metadata.nand_image = *donor;

            const auto built = run_build(input);
            ASSERT_ERROR(built, BuildErrorCode::InvalidInput)
                << "donor transition rejects retained payload collision";
            EXPECT_TRUE(built.error().message.contains("XeLL overlaps rebooter"))
                << "donor transition reports the retained XeLL and rebooter collision";
        }

        TEST(PatchSlotLayout, FixedPayloadsRoundTripInValidJtagLayout) {
            struct Case {
                ImageType image_type;
                BuildType build_type;
                InputPatchFile automatic;
                size_t xell_offset;
            };
            const std::array cases{
                Case{ImageType::SmallBlock, BuildType::Jtag,
                     InputPatchFile{"automatic", test::jtag_patchset(Bytes{0xA3})}, 0x95060},
            };

            for (const auto& test_case : cases) {
                const std::string layout_name =
                    test_case.build_type == BuildType::Jtag ? "JTAG" : "big-block Glitch";
                SCOPED_TRACE(layout_name);
                auto input = test::fresh_input(test_case.image_type);
                input.build_type = test_case.build_type;
                if (input.build_type == BuildType::Jtag) {
                    test::mark_jtag_smc(*input.metadata.smc);
                }
                InputPatches patches{};
                patches.automatic = test_case.automatic;
                input.patches = std::move(patches);
                InputPayloads payloads{};
                payloads.rebooter = Bytes(0x1000, 0x71);
                payloads.fuses = Bytes(0x60, 0x72);
                payloads.xell = test::valid_xell();
                input.payloads = std::move(payloads);

                const auto built = run_build(input);
                ASSERT_OK(built) << layout_name << " fixed payload layout builds";
                const auto rebooter =
                    read_logical(*built, 0x90000, input.payloads->rebooter->size());
                const auto fuses = read_logical(*built, 0x95000, input.payloads->fuses->size());
                const auto xell_magic = read_logical(*built, test_case.xell_offset, 4);
                ASSERT_TRUE(xell_magic.has_value())
                    << layout_name << " keeps XeLL at its historical offset";
                EXPECT_BYTES_EQ(kElfMagic, *xell_magic)
                    << layout_name << " keeps XeLL at its historical offset";
                ASSERT_TRUE(rebooter.has_value() && fuses.has_value())
                    << layout_name << " fixed payload layout roundtrips every payload";
                EXPECT_BYTES_EQ(*input.payloads->rebooter, *rebooter)
                    << layout_name << " fixed payload layout roundtrips every payload";
                EXPECT_BYTES_EQ(*input.payloads->fuses, *fuses)
                    << layout_name << " fixed payload layout roundtrips every payload";
            }
        }

        TEST(PatchSlotLayout, SmallGlitchPatchBaseXellOwnsOverlappingFixedPayloadOffsets) {
            auto input = glitch_with_khv(ImageType::SmallBlock, Bytes{0xA7});
            InputPayloads payloads{};
            payloads.xell = test::valid_xell();
            payloads.xell->at(0x20000) = 0x47;
            payloads.xell->at(0x25000) = 0x57;
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            const std::string retained = "small-block Glitch extract_all retains patch-base XeLL "
                                         "bytes at 0x20000 and 0x25000";
            ASSERT_OK(built) << retained;
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << retained;
            ASSERT_TRUE(extracted->payloads.has_value()) << retained;
            ASSERT_TRUE(extracted->payloads->xell.has_value()) << retained;
            EXPECT_BYTES_EQ(*input.payloads->xell, *extracted->payloads->xell) << retained;
            EXPECT_FALSE(extracted->payloads->rebooter.has_value())
                << "patch-base XeLL suppresses ambiguous rebooter and fuse inference";
            EXPECT_FALSE(extracted->payloads->fuses.has_value())
                << "patch-base XeLL suppresses ambiguous rebooter and fuse inference";
        }

        TEST(PatchSlotLayout, PatchBaseXellOwnershipNeverFallsBackToAnInternalJtagElf) {
            for (const auto image_type : {ImageType::SmallBlock, ImageType::NewSmallBlock}) {
                SCOPED_TRACE(shape_name(image_type));
                auto input = glitch_with_khv(image_type, Bytes{0xAA});
                InputPayloads payloads{};
                payloads.xell = test::valid_xell();
                input.payloads = std::move(payloads);

                const auto built = run_build(input);
                const std::string modified =
                    "shifted patch-base XeLL fixture is modified successfully";
                ASSERT_OK(built) << modified;
                auto image = FlashImage::read(*built);
                ASSERT_TRUE(image.has_value()) << modified;
                ASSERT_OK(image->parse()) << modified;
                const Bytes invalid_patch_base{0, 0, 0, 0};
                const Bytes false_jtag_elf{0x7F, 'E', 'L', 'F'};
                const Bytes false_rebooter{0xAB};
                const Bytes false_fuses{0xAC};
                ASSERT_TRUE(image->flash_driver.write_offset(0x70000, invalid_patch_base))
                    << modified;
                ASSERT_TRUE(image->flash_driver.write_offset(0x90000, false_rebooter)) << modified;
                ASSERT_TRUE(image->flash_driver.write_offset(0x95000, false_fuses)) << modified;
                ASSERT_TRUE(image->flash_driver.write_offset(0x95060, false_jtag_elf)) << modified;
                const auto extracted =
                    extract_all(image->flash_driver.serialize(), input.metadata.cpu_key);

                const std::string no_invention =
                    "patch-base XeLL ownership does not invent JTAG or overlapping fixed payloads";
                ASSERT_OK(extracted) << no_invention;
                if (extracted->payloads) {
                    EXPECT_FALSE(extracted->payloads->xell.has_value()) << no_invention;
                    EXPECT_FALSE(extracted->payloads->rebooter.has_value()) << no_invention;
                    EXPECT_FALSE(extracted->payloads->fuses.has_value()) << no_invention;
                }
            }
        }

        TEST(PatchSlotLayout, BigAndEmmcGlitchDoNotInferJtagInsideXell) {
            for (auto image_type : {ImageType::BigBlock, ImageType::Emmc}) {
                SCOPED_TRACE(shape_name(image_type));
                auto input = glitch_with_khv(image_type, Bytes{0, 0, 0x10, 0, 0, 0, 0, 1, 0x60, 0,
                                                               0, 0, 255, 255, 255, 255});
                input.payloads = InputPayloads{};
                input.payloads->xell = test::valid_xell();
                const auto built = run_build(input);
                ASSERT_OK(built) << "glitch donor with runtime KHV parses";
                auto image = FlashImage::read(*built);
                ASSERT_TRUE(image.has_value()) << "glitch donor with runtime KHV parses";
                ASSERT_OK(image->parse()) << "glitch donor with runtime KHV parses";
                ASSERT_TRUE(image->flash_driver.write_offset(0x70000, Bytes{0, 0, 0, 0}))
                    << "the stale JTAG anchors are laid";
                ASSERT_TRUE(image->flash_driver.write_offset(0x95060, test::valid_xell()))
                    << "the stale JTAG anchors are laid";
                const auto extracted =
                    extract_all(image->flash_driver.serialize(), input.metadata.cpu_key);
                ASSERT_OK(extracted)
                    << "known glitch image cannot infer JTAG XeLL inside its damaged payload";
                if (extracted->payloads) {
                    EXPECT_FALSE(extracted->payloads->xell.has_value())
                        << "known glitch image cannot infer JTAG XeLL inside its damaged payload";
                }
            }
        }

        TEST(PatchSlotLayout, BigBlockGlitchXellAnchorsAtPatchBaseAndShiftsCf) {
            for (const auto image_type : {ImageType::BigBlock, ImageType::Emmc}) {
                SCOPED_TRACE(shape_name(image_type));
                auto input = test::fresh_input(image_type);
                input.build_type = BuildType::Glitch2;
                input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                const auto [cf, cg] = test::valid_system_update(0x61);
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                InputPatches patches{};
                patches.automatic = InputPatchFile{
                    "automatic", test::glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA5})};
                input.patches = std::move(patches);
                InputPayloads payloads{};
                payloads.xell = test::valid_xell();
                input.payloads = std::move(payloads);

                const auto built = run_build(input);
                ASSERT_OK(built)
                    << "big-geometry glitch carrying a XeLL builds without a collision";
                auto image = FlashImage::read(*built);
                constexpr size_t xell_at = 0x70000;
                const bool big = image_type == ImageType::BigBlock;
                const size_t stride = big ? 0x20000 : 0x10000;
                const size_t shifted_slot = big ? 0xC0000 : 0xB0000;
                const auto xell_magic = read_logical(*built, xell_at, 4);
                const auto khv = read_logical(*built, shifted_slot + stride + 0x10, 1);
                const auto cg_bytes = read_logical(
                    *built, shifted_slot + ((cf.size() + 0x0F) & ~size_t{0x0F}), cg.size());
                const std::string parses =
                    "big-geometry glitch parses CF and CG out of the shifted patch slot";
                ASSERT_TRUE(image.has_value()) << parses;
                ASSERT_OK(image->parse()) << parses;
                ASSERT_TRUE(image->system_update_0.cf.has_value()) << parses;
                ASSERT_TRUE(image->system_update_0.cg.has_value()) << parses;
                EXPECT_EQ(image->header.cf_offset.get(), shifted_slot)
                    << "the XeLL pushes the first slot to the next erase-block boundary";
                ASSERT_TRUE(xell_magic.has_value()) << "big-geometry glitch XeLL sits at 0x70000";
                EXPECT_BYTES_EQ(kElfMagic, *xell_magic)
                    << "big-geometry glitch XeLL sits at 0x70000";
                ASSERT_TRUE(khv.has_value())
                    << "glitch KHV follows the shifted slot plus one stride plus 0x10";
                EXPECT_BYTES_EQ(Bytes({0xA5}), *khv)
                    << "glitch KHV follows the shifted slot plus one stride plus 0x10";
                ASSERT_TRUE(cg_bytes.has_value()) << "CG survives beside the anchored XeLL";
                ASSERT_OK_AND_ASSIGN(const auto supplied_cg, test::opened_cg(cf, cg));
                ASSERT_OK_AND_ASSIGN(
                    const auto placed_cg,
                    test::opened_cg(image->system_update_0.cf->serialize(), *cg_bytes));
                ASSERT_TRUE(supplied_cg.has_value() && placed_cg.has_value())
                    << "CG survives beside the anchored XeLL";
                EXPECT_BYTES_EQ(*supplied_cg, *placed_cg) << "CG survives beside the anchored XeLL";

                const auto extracted = extract_all(*built, input.metadata.cpu_key);
                ASSERT_OK(extracted) << "the shifted CF0 is recovered by extract_all";
                EXPECT_TRUE(extracted->bootloaders.cf0.has_value())
                    << "the shifted CF0 is recovered by extract_all";
                ASSERT_TRUE(extracted->payloads.has_value())
                    << "the anchored XeLL round-trips byte for byte";
                ASSERT_TRUE(extracted->payloads->xell.has_value())
                    << "the anchored XeLL round-trips byte for byte";
                EXPECT_BYTES_EQ(*input.payloads->xell, *extracted->payloads->xell)
                    << "the anchored XeLL round-trips byte for byte";
            }
        }

        TEST(PatchSlotLayout, UnambiguousJtagXellPreservesFixedPayloadExtraction) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            test::mark_jtag_smc(*input.metadata.smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0xA8})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = test::valid_xell();
            payloads.rebooter = Bytes(0x1000, 0x81);
            payloads.fuses = Bytes(0x60, 0x82);
            input.payloads = std::move(payloads);

            const std::string preserved =
                "an exact JTAG XeLL preserves adjacent fixed payload extraction";
            const auto built = run_build(input);
            ASSERT_OK(built) << preserved;
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << preserved;
            ASSERT_TRUE(extracted->payloads.has_value()) << preserved;
            const auto& out = *extracted->payloads;
            ASSERT_TRUE(out.xell.has_value() && out.rebooter.has_value() && out.fuses.has_value())
                << preserved;
            EXPECT_BYTES_EQ(*input.payloads->xell, *out.xell) << preserved;
            EXPECT_BYTES_EQ(*input.payloads->rebooter, *out.rebooter) << preserved;
            EXPECT_BYTES_EQ(*input.payloads->fuses, *out.fuses) << preserved;
        }

        TEST(PatchSlotLayout, BootChainCollisionIsRejectedForUnpatchedPayloadLayouts) {
            struct Case {
                const char* name;
                BuildType build_type;
                bool noblpatch;
                bool jtag_patchset;
                size_t xell_offset;
            };
            const std::array cases{
                Case{"Retail", BuildType::Retail, false, false, 0x70000},
                Case{"Devkit", BuildType::Devkit, false, false, 0x70000},
                Case{"Jtag", BuildType::Jtag, false, true, 0x95060},
                Case{"GlitchNoblpatch", BuildType::Glitch, true, false, 0x70000}};

            for (const auto& test_case : cases) {
                SCOPED_TRACE(test_case.name);
                auto input = test::fresh_input(ImageType::SmallBlock);
                input.build_type = test_case.build_type;
                if (input.build_type == BuildType::Jtag) {
                    test::mark_jtag_smc(*input.metadata.smc);
                }
                input.options.noblpatch = test_case.noblpatch;
                input.bootloaders.cb_or_a.resize(test_case.xell_offset - 0x8000 + 0x10, 0xA9);
                const uint32_t cb_size =
                    std::byteswap(static_cast<uint32_t>(input.bootloaders.cb_or_a.size()));
                std::memcpy(input.bootloaders.cb_or_a.data() + offsetof(nand::generic_header, size),
                            &cb_size, sizeof(cb_size));
                if (test_case.jtag_patchset || test_case.noblpatch) {
                    InputPatches patches{};
                    patches.automatic = InputPatchFile{
                        "automatic", test_case.jtag_patchset
                                         ? test::jtag_patchset(Bytes{0xAA})
                                         : test::glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xAB})};
                    input.patches = std::move(patches);
                }
                InputPayloads payloads{};
                payloads.xell = test::valid_xell();
                input.payloads = std::move(payloads);

                const auto built = run_build(input);
                ASSERT_ERROR(built, BuildErrorCode::InvalidInput)
                    << "oversized unpatched boot chain is rejected before fixed payload overwrite";
                EXPECT_TRUE(built.error().message.contains("serialized boot chain"))
                    << "boot-chain collision identifies the serialized boot-chain interval";
            }
        }

        TEST(PatchSlotLayout, BootloaderPatchEndIsBoundedByBootChainLayout) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic = InputPatchFile{
                "automatic", test::glitch_patchset(0x70000, 0xDEADBEEF, 0x30, 0, Bytes{0xA0})};
            input.patches = std::move(patches);

            EXPECT_ERROR(run_build(input), BuildErrorCode::PatchFailure)
                << "bootloader patch beyond chain capacity fails before resize";

            auto hostile = test::fresh_input(ImageType::SmallBlock);
            hostile.build_type = BuildType::Glitch;
            InputPatches hostile_patches{};
            hostile_patches.automatic = InputPatchFile{
                "hostile", test::glitch_patchset(0xFFFFFFF8, 0xDEADBEEF, 0x30, 0, Bytes{0xA0})};
            hostile.patches = std::move(hostile_patches);
            EXPECT_ERROR(run_build(hostile), BuildErrorCode::PatchFailure)
                << "near-UINT32_MAX patch end is rejected without allocation";
        }

    } // namespace
} // namespace gxbuild3::orchestration
