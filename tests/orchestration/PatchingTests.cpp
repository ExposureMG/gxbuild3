// run_build's patching (src/BuildRunner.cpp and src/patchers/): a glitch patch file grows CB (or
// CB_B for glitch2 and up) and CD to the greatest patched end and restates their sizes rounded up
// to 0x10; the glitch types take the reboot patch on a clean retail SMC; noblpatch and nopatch
// leave the named stages alone; patch regions refuse overflow; retail and devkit refuse add-ons.
// RunBuildJtag: the JTAG patch file is serialized at 0x91000, the SMC payload and a second sealed
// boot chain land in the JTAG window, the window padding is programmed as xeBuild programs it,
// and a JTAG image refuses an SMC without its hack mark. One ctest entry per case (each runs
// run_build).

#include "BuildRunner.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
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
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BootloaderCb;
        using nand::BootloaderCd;
        using nand::FlashImage;
        using test::Bytes;

        TEST(RunBuildPatching, GlitchPatchesResizeCbAndCdAndUpdateDeclaredSizes) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch;
            const uint32_t cb_patch_address =
                static_cast<uint32_t>(input.bootloaders.cb_or_a.size() + 0x10);
            const uint32_t cd_patch_address =
                static_cast<uint32_t>(input.bootloaders.cd.size() + 0x10);
            InputPatches patches{};
            patches.automatic = InputPatchFile{
                "automatic", test::glitch_patchset(cb_patch_address, 0xA1B2C3D4, cd_patch_address,
                                                   0x10203040, Bytes{0x91})};
            input.patches = std::move(patches);

            const auto built = run_build(input);
            ASSERT_OK(built) << "patched glitch image builds and extracts";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "patched glitch image builds and extracts";

            const auto& cb = extracted->bootloaders.cb_or_a;
            const auto& cd = extracted->bootloaders.cd;
            const uint32_t cb_end = align_16(cb_patch_address + 4);
            const uint32_t cd_end = align_16(cd_patch_address + 4);
            ASSERT_GE(cb.size(), cb_patch_address + 4u)
                << "CB grows to and contains the greatest patched end";
            EXPECT_EQ(test::be32(cb, cb_patch_address), 0xA1B2C3D4u)
                << "CB grows to and contains the greatest patched end";
            EXPECT_EQ(test::be32(cb, 0x0C), cb_end)
                << "CB declared size is the patched end rounded up to 0x10";
            EXPECT_TRUE(zero_between(cb, cb_patch_address + 4, cb_end))
                << "CB padding after the patched end is zero";
            ASSERT_GE(cd.size(), cd_patch_address + 4u)
                << "CD grows to and contains the greatest patched end";
            EXPECT_EQ(test::be32(cd, cd_patch_address), 0x10203040u)
                << "CD grows to and contains the greatest patched end";
            EXPECT_EQ(test::be32(cd, 0x0C), cd_end)
                << "CD declared size is the patched end rounded up to 0x10";
            EXPECT_TRUE(zero_between(cd, cd_patch_address + 4, cd_end))
                << "CD padding after the patched end is zero";
        }

        // Glitch2m CD 9452: 0x5290 bytes, patched to 0x52A8, states 0x52B0 (xeBuild 1.21).
        TEST(RunBuildPatching, Glitch2mCdPatchStatesThe16ByteAlignedSize) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch2m;
            input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            const uint32_t cd_size = static_cast<uint32_t>(input.bootloaders.cd.size());
            const uint32_t cd_patch_address = cd_size + 0x14;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", test::glitch_patchset(0x20, 0, cd_patch_address,
                                                                  0x5A5A5A5A, Bytes{0x93})};
            input.patches = std::move(patches);

            const auto built = run_build(input);
            ASSERT_OK(built) << "patched glitch2m image builds and extracts";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "patched glitch2m image builds and extracts";
            const auto& cd = extracted->bootloaders.cd;
            const uint32_t cd_end = align_16(cd_patch_address + 4);
            ASSERT_NE(cd_end, cd_patch_address + 4) << "fixture patch ends off a 0x10 boundary";
            EXPECT_EQ(test::be32(cd, 0x0C), cd_end)
                << "glitch2m CD states and carries the 16-byte-aligned patched size";
            ASSERT_EQ(cd.size(), cd_end)
                << "glitch2m CD states and carries the 16-byte-aligned patched size";
            EXPECT_EQ(test::be32(cd, cd_patch_address), 0x5A5A5A5Au)
                << "glitch2m CD carries the patched word";
            EXPECT_TRUE(zero_between(cd, cd_patch_address + 4, cd_end))
                << "glitch2m CD padding inside the stated size is zero";
        }

        TEST(RunBuildPatching, Glitch2TargetsCbB) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch2;
            input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            const uint32_t cbb_patch_address =
                static_cast<uint32_t>(input.bootloaders.cb_b->size() + 0x10);
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", test::glitch_patchset(cbb_patch_address, 0xCAFEBABE,
                                                                  0x30, 0, Bytes{0x92})};
            input.patches = std::move(patches);

            const auto built = run_build(input);
            ASSERT_OK(built) << "Glitch2 CBB image builds and extracts";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "Glitch2 CBB image builds and extracts";
            ASSERT_TRUE(extracted->bootloaders.cb_b.has_value())
                << "Glitch2 CBB image builds and extracts";
            const auto& cb_b = *extracted->bootloaders.cb_b;
            ASSERT_GE(cb_b.size(), cbb_patch_address + 4u) << "Glitch2 applies section one to CBB";
            EXPECT_EQ(test::be32(cb_b, cbb_patch_address), 0xCAFEBABEu)
                << "Glitch2 applies section one to CBB";
            EXPECT_EQ(test::be32(cb_b, 0x0C), align_16(cbb_patch_address + 4))
                << "CBB declared size is the patched end rounded up to 0x10";
        }

        // Glitch, glitch2 and glitch2m take the reboot patch on a clean retail SMC: the two bytes
        // at the site become zero and nothing else changes.
        TEST(RunBuildPatching, GlitchTypesPatchACleanRetailSmc) {
            for (const auto& [build_type, name] :
                 {std::pair{BuildType::Glitch, "glitch"}, std::pair{BuildType::Glitch2, "glitch2"},
                  std::pair{BuildType::Glitch2m, "glitch2m"}}) {
                SCOPED_TRACE(name);
                auto input = test::fresh_input(ImageType::SmallBlock);
                input.build_type = build_type;
                input.metadata.smc = test::clean_retail_smc();
                if (build_type != BuildType::Glitch) {
                    input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                }
                InputPatches patches{};
                patches.automatic = InputPatchFile{
                    "automatic", test::glitch_patchset(0x20, 0, 0x30, 0, Bytes{0x94})};
                input.patches = std::move(patches);

                const auto built = run_build(input);
                ASSERT_OK(built) << name << " image builds with an SMC";
                auto image = FlashImage::read(*built);
                ASSERT_TRUE(image.has_value()) << name << " image builds with an SMC";
                ASSERT_OK(image->parse()) << name << " image builds with an SMC";
                ASSERT_TRUE(image->smc.has_value()) << name << " image builds with an SMC";
                image->smc->decrypt();
                auto expected = test::clean_retail_smc();
                expected[test::kSmcRebootSite] = 0x00;
                expected[test::kSmcRebootSite + 1] = 0x00;
                EXPECT_BYTES_EQ(expected, image->smc->data)
                    << name << " zeroes the two reboot-site bytes and nothing else";
            }
        }

        TEST(RunBuildPatching, NoblpatchSkipsBootloaderMutationButWritesKhv) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch;
            input.options.noblpatch = true;
            const auto original_cb_size = input.bootloaders.cb_or_a.size();
            InputPatches patches{};
            patches.automatic = InputPatchFile{
                "automatic", test::glitch_patchset(static_cast<uint32_t>(original_cb_size + 0x10),
                                                   0xDEADBEEF, 0x30, 0, Bytes{0xA0, 0xA1})};
            patches.addons = {{"addon", {0xA2}}};
            input.patches = std::move(patches);

            const auto built = run_build(input);
            ASSERT_OK(built) << "noblpatch leaves CB size unchanged";
            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "noblpatch leaves CB size unchanged";
            EXPECT_EQ(extracted->bootloaders.cb_or_a.size(), original_cb_size)
                << "noblpatch leaves CB size unchanged";
            const auto khv = read_logical(*built, 0x80010, 3);
            ASSERT_TRUE(khv.has_value())
                << "noblpatch still writes merged KHV at the runtime anchor";
            EXPECT_BYTES_EQ(Bytes({0xA0, 0xA1, 0xA2}), *khv)
                << "noblpatch still writes merged KHV at the runtime anchor";
        }

        // nopatch names the stages left unpatched: cb keeps the CB, cd the CD, khv the KHV
        // payload.
        TEST(RunBuildPatching, NopatchSkipsOnlyTheNamedStages) {
            struct Case {
                const char* options;
                bool cb_patched;
                bool cd_patched;
                bool khv_written;
            };
            for (const auto& test_case :
                 {Case{"nopatch=cb", false, true, true}, Case{"nopatch=cd", true, false, true},
                  Case{"nopatch=khv", true, true, false},
                  Case{"nopatch=cb,nopatch=khv", false, true, false}}) {
                const std::string name(test_case.options);
                SCOPED_TRACE(name);
                auto input = test::fresh_input(ImageType::SmallBlock);
                input.build_type = BuildType::Glitch;
                OptionsManager options;
                ASSERT_TRUE(options.parse(test_case.options)) << "nopatch options parse";
                input.options = options.data();
                const uint32_t cb_patch_address =
                    static_cast<uint32_t>(input.bootloaders.cb_or_a.size() + 0x10);
                const uint32_t cd_patch_address =
                    static_cast<uint32_t>(input.bootloaders.cd.size() + 0x10);
                const auto original_cb_size = input.bootloaders.cb_or_a.size();
                const auto original_cd_size = input.bootloaders.cd.size();
                InputPatches patches{};
                patches.automatic =
                    InputPatchFile{"automatic", test::glitch_patchset(cb_patch_address, 0xA1B2C3D4,
                                                                      cd_patch_address, 0x10203040,
                                                                      Bytes{0xA0, 0xA1})};
                patches.addons = {{"addon", {0xA2}}};
                input.patches = std::move(patches);

                const auto built = run_build(input);
                ASSERT_OK(built) << name << " image builds and extracts";
                const auto extracted = extract_all(*built, input.metadata.cpu_key);
                ASSERT_OK(extracted) << name << " image builds and extracts";
                const auto khv = read_logical(*built, 0x80010, 3);
                EXPECT_EQ(extracted->bootloaders.cb_or_a.size() != original_cb_size,
                          test_case.cb_patched)
                    << name << " leaves exactly the named CB alone";
                EXPECT_EQ(extracted->bootloaders.cd.size() != original_cd_size,
                          test_case.cd_patched)
                    << name << " leaves exactly the named CD alone";
                EXPECT_EQ(khv == Bytes({0xA0, 0xA1, 0xA2}), test_case.khv_written)
                    << name << " writes the KHV payload only if unnamed";
            }
        }

        TEST(RunBuildPatching, PatchRegionsRejectOverflow) {
            auto jtag = test::fresh_input(ImageType::SmallBlock);
            jtag.build_type = BuildType::Jtag;
            jtag.metadata.smc = test::make_jtag_smc(0x11);
            InputPatches jtag_patches{};
            jtag_patches.automatic =
                InputPatchFile{"automatic", test::jtag_patchset(Bytes(0x4001, 0x44))};
            jtag.patches = std::move(jtag_patches);
            const auto jtag_result = run_build(jtag);

            auto glitch = test::fresh_input(ImageType::SmallBlock);
            glitch.build_type = BuildType::Glitch;
            InputPatches glitch_patches{};
            glitch_patches.automatic = InputPatchFile{
                "automatic", test::glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55))};
            glitch.patches = std::move(glitch_patches);
            const auto glitch_result = run_build(glitch);

            EXPECT_ERROR(jtag_result, BuildErrorCode::PatchFailure)
                << "JTAG patch overflow returns PatchFailure";
            EXPECT_ERROR(glitch_result, BuildErrorCode::PatchFailure)
                << "glitch patch overflow returns PatchFailure";
        }

        TEST(RunBuildPatching, RejectsRetailAndDevkitAddonPatchData) {
            for (const auto& [build_type, name] :
                 {std::pair{BuildType::Retail, "retail"}, std::pair{BuildType::Devkit, "devkit"}}) {
                SCOPED_TRACE(name);
                auto input = test::fresh_input(ImageType::SmallBlock);
                input.build_type = build_type;
                input.patches = InputPatches{.automatic = std::nullopt,
                                             .addons = {InputPatchFile{"addon", {0x01}}}};
                EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidInput)
                    << "run_build rejects retail and devkit add-on patch data";
            }
        }

        // The Patchset delimiter gate seen from run_build: parse_glitch_patch_set counts every
        // 0xFFFFFFFF word as a section delimiter, so a CB_B data word of 0xFFFFFFFF splits the
        // glitch2 file into four sections and the build is refused; the same file with an
        // ordinary data word builds. CB_B is CB_A's copy, as in Glitch2TargetsCbB.
        TEST(RunBuildPatching, FfffffffPatchWordSplitsTheGlitchPatchsetAsToday) {
            auto split = test::glitch_input(
                BuildType::Glitch2,
                test::glitch_patchset(0x20, 0xFFFFFFFF, 0x30, 0x55667788, Bytes{0xA5}));
            split.bootloaders.cb_b = split.bootloaders.cb_or_a;
            EXPECT_ERROR_MSG(run_build(split), BuildErrorCode::PatchFailure,
                             "automatic patchset automatic: Glitch patchset must have 3 sections "
                             "[CB_B][CD][KHV], found 4")
                << "a 0xFFFFFFFF data word is a fourth delimiter";
            auto ordinary = test::glitch_input(
                BuildType::Glitch2,
                test::glitch_patchset(0x20, 0x11223344, 0x30, 0x55667788, Bytes{0xA5}));
            ordinary.bootloaders.cb_b = ordinary.bootloaders.cb_or_a;
            EXPECT_OK(run_build(ordinary)) << "the same file with data word 0x11223344 builds";
        }

        TEST(RunBuildJtag, PatchsetIsSerializedAtFixedRegion) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            input.metadata.smc = test::make_jtag_smc(0x11);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13, 0x13})};
            patches.addons = {{"first", {0x20}}, {"second", {0x30}}};
            input.patches = std::move(patches);

            Bytes expected(4, 0x10);
            test::append_be32(expected, 0xFFFFFFFF);
            expected.insert(expected.end(), 4, 0x11);
            test::append_be32(expected, 0xFFFFFFFF);
            expected.insert(expected.end(), 4, 0x12);
            test::append_be32(expected, 0xFFFFFFFF);
            expected.insert(expected.end(), {0x13, 0x13, 0x20, 0x30});

            const auto built = run_build(input);
            ASSERT_OK(built) << "JTAG patchset image builds";
            const auto raw = read_logical(*built, 0x91000, expected.size());
            ASSERT_TRUE(raw.has_value()) << "merged JTAG patchset is byte-exact at 0x91000";
            EXPECT_BYTES_EQ(expected, *raw) << "merged JTAG patchset is byte-exact at 0x91000";
        }

        // A CB whose 0x260..0x380 is zero and a CD stating a CE hash with no 6BL nonce: the
        // plaintext extra stages as the release ships them.
        std::pair<Bytes, Bytes> plaintext_extra_chain() {
            BootloaderCb extra_cb{};
            extra_cb.header.header.magic = nand::NANDBootloaderMagic::CB;
            extra_cb.header.header.version = 4579;
            extra_cb.data.resize(0x380, 0);
            extra_cb.data.resize(0x400, 0x71);
            extra_cb.header.header.size =
                static_cast<uint32_t>(sizeof(nand::generic_header) + extra_cb.data.size());
            BootloaderCd extra_cd{};
            extra_cd.header.header.magic = nand::NANDBootloaderMagic::CD;
            extra_cd.header.header.version = 8453;
            extra_cd.header.ce_hash[0] = 1;
            std::ranges::copy(gxbuild3::nand::kRomSalt6bl, extra_cd.header.salt_6bl);
            extra_cd.data.resize(0x100, 0x72);
            extra_cd.header.header.size =
                static_cast<uint32_t>(sizeof(nand::cd_header) + extra_cd.data.size());
            return {extra_cb.serialize(), extra_cd.serialize()};
        }

        TEST(RunBuildJtag, FlowsPayloadAndExtraBootloaders) {
            const auto [cb_bytes, cd_bytes] = plaintext_extra_chain();

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            input.metadata.smc = test::make_jtag_smc(0x11);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13, 0x13})};
            input.patches = std::move(patches);
            input.bootloaders.extra_cb = cb_bytes;
            input.bootloaders.extra_cd = cd_bytes;
            InputPayloads payloads{};
            payloads.payload = Bytes(0x200, 0x73);
            input.payloads = std::move(payloads);

            // Small-block window base is 0x90000, so the window tail starts at 0x90000 + 0x45060.
            const size_t cb_at = 0xD5060;
            const size_t cd_at = cb_at + ((cb_bytes.size() + 0x0F) & ~size_t{0x0F});
            const auto built = run_build(input);
            ASSERT_OK(built) << "JTAG image carrying payload and extra bootloaders builds";
            const auto placed_payload = read_logical(*built, 0x200, 0x200);
            const auto placed_cb = read_logical(*built, cb_at, cb_bytes.size());
            const auto placed_cd = read_logical(*built, cd_at, cd_bytes.size());
            const auto main_cb = read_logical(*built, 0x8000, 0x20);
            ASSERT_TRUE(placed_payload.has_value() && placed_cb.has_value() &&
                        placed_cd.has_value() && main_cb.has_value())
                << "JTAG image carrying payload and extra bootloaders builds";
            // The second chain is sealed: each stage keeps its clear header and takes the main
            // chain's CB or CD nonce, and its body no longer reads as the plaintext supplied.
            const auto same = [](const Bytes& left, size_t left_at, const Bytes& right,
                                 size_t right_at, size_t length) {
                return left.size() >= left_at + length && right.size() >= right_at + length &&
                       std::equal(left.begin() + static_cast<std::ptrdiff_t>(left_at),
                                  left.begin() + static_cast<std::ptrdiff_t>(left_at + length),
                                  right.begin() + static_cast<std::ptrdiff_t>(right_at));
            };
            EXPECT_BYTES_EQ(Bytes(0x200, 0x73), *placed_payload)
                << "SMC payload is placed at 0x200";
            EXPECT_TRUE(same(*placed_cb, 0, cb_bytes, 0, 0x10))
                << "extra CB is placed in the JTAG window tail with its clear header";
            EXPECT_TRUE(same(*placed_cb, 0x10, *main_cb, 0x10, 0x10))
                << "extra CB takes the main CB's nonce";
            EXPECT_FALSE(same(*placed_cb, 0x380, cb_bytes, 0x380, 0x80))
                << "extra CB is sealed, not written as supplied";
            EXPECT_TRUE(same(*placed_cd, 0, cd_bytes, 0, 0x10))
                << "extra CD follows the 16-byte-aligned extra CB";
            EXPECT_FALSE(same(*placed_cd, 0x20, cd_bytes, 0x20, 0x100))
                << "extra CD is sealed, not written as supplied";
        }

        // xeBuild programs the bytes after each JTAG window item zero up to the next item or the
        // end of the 16 KiB block holding the item's end. The patch buffer is programmed whole,
        // so its erased tail is written as pages that carry a spare stamp.
        TEST(RunBuildJtag, WindowPaddingIsProgrammedLikeXebuild) {
            const auto [cb_bytes, cd_bytes] = plaintext_extra_chain();

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            input.metadata.smc = test::make_jtag_smc(0x11);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13, 0x13})};
            input.patches = std::move(patches);
            input.bootloaders.extra_cb = cb_bytes;
            input.bootloaders.extra_cd = cd_bytes;
            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x40, 0x74);
            payloads.payload = Bytes(0x200, 0x73);
            input.payloads = std::move(payloads);

            const size_t cd_at = 0xD5060 + ((cb_bytes.size() + 0x0F) & ~size_t{0x0F});
            const size_t chain_end = cd_at + cd_bytes.size();
            const size_t pad_end = (chain_end + 0x3FFF) & ~size_t{0x3FFF};
            const auto built = run_build(input);
            ASSERT_OK(built) << "JTAG image with a rebooter and a payload builds";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "JTAG image with a rebooter reads back";
            ASSERT_OK(image->parse()) << "JTAG image with a rebooter parses";
            const auto& driver = std::as_const(image->flash_driver);
            const auto all_equal = [&driver](size_t offset, size_t length, uint8_t value) {
                const auto bytes = driver.read_offset(offset, length);
                return bytes.size() == length &&
                       std::all_of(bytes.begin(), bytes.end(),
                                   [value](uint8_t b) { return b == value; });
            };
            const auto spare_stamped = [&driver](size_t offset) {
                const auto spare = driver.read_page_spare(offset / 0x200);
                return std::any_of(spare.begin(), spare.end(), [](uint8_t b) { return b != 0xFF; });
            };
            const auto payload_spare = driver.read_page_spare(1);
            EXPECT_TRUE(all_equal(0x90040, 0x1000 - 0x40, 0))
                << "the bytes after the rebooter are zero up to the patch list";
            EXPECT_TRUE(all_equal(0x91100, 0x94000 - 0x91100, 0))
                << "the bytes after the patch list are zero to the end of its block";
            EXPECT_TRUE(all_equal(0x94000, 0x1000, 0xFF))
                << "the patch buffer's tail stays erased data";
            EXPECT_TRUE(spare_stamped(0x94000))
                << "the patch buffer's erased tail is programmed as pages";
            EXPECT_TRUE(spare_stamped(0x94E00))
                << "the patch buffer's erased tail is programmed as pages";
            EXPECT_FALSE(spare_stamped(0x95200))
                << "pages past the patch buffer that nothing writes stay unprogrammed";
            ASSERT_LT(chain_end, pad_end)
                << "the bytes after the second chain are zero to the end of its block";
            EXPECT_TRUE(all_equal(chain_end, pad_end - chain_end, 0))
                << "the bytes after the second chain are zero to the end of its block";
            ASSERT_EQ(payload_spare.size(), 16u)
                << "the payload page's spare carries xeBuild's 0x03 0x50 at bytes 10 and 11";
            EXPECT_EQ(payload_spare[10], 0x03)
                << "the payload page's spare carries xeBuild's 0x03 0x50 at bytes 10 and 11";
            EXPECT_EQ(payload_spare[11], 0x50)
                << "the payload page's spare carries xeBuild's 0x03 0x50 at bytes 10 and 11";
        }

        // A JTAG image boots through its SMC's hack: an SMC with no JTAG mark is refused, unless
        // smcnocheck waives the check. A marked SMC, sealed or plaintext, builds.
        TEST(RunBuildJtag, RefusesACleanSmc) {
            const auto jtag_over = [](Bytes smc) {
                auto input = test::fresh_input(ImageType::SmallBlock);
                input.build_type = BuildType::Jtag;
                input.metadata.smc = std::move(smc);
                InputPatches patches{};
                patches.automatic =
                    InputPatchFile{"automatic", test::jtag_patchset(Bytes{0x13, 0x13})};
                input.patches = std::move(patches);
                return input;
            };
            const auto clean = run_build(jtag_over(test::make_smc(0x11)));
            auto waived_input = jtag_over(test::make_smc(0x11));
            waived_input.options.smcnocheck = true;
            const auto waived = run_build(waived_input);
            const auto marked = run_build(jtag_over(test::make_jtag_smc(0x11)));
            auto cygnos_smc = test::make_smc(0x11);
            const Bytes cygnos_mark{0x78, 0xBA, 0xB6};
            std::copy(cygnos_mark.begin(), cygnos_mark.end(), cygnos_smc.begin() + 0x180);
            const auto sealed = run_build(jtag_over(nand::smc_encrypt(cygnos_smc)));
            auto retail_input = test::fresh_input(ImageType::SmallBlock);
            retail_input.build_type = BuildType::Retail;
            const auto retail = run_build(retail_input);
            EXPECT_ERROR_HAS(clean, BuildErrorCode::InvalidSmc, "Clean SMC")
                << "JTAG over an SMC with no JTAG mark is refused as a clean SMC";
            EXPECT_OK(waived) << "smcnocheck builds JTAG over a clean SMC";
            EXPECT_OK(marked) << "JTAG builds over a JTAG-marked SMC";
            EXPECT_OK(sealed) << "JTAG builds over a sealed SMC carrying the Cygnos mark";
            EXPECT_OK(retail) << "the check leaves retail images alone";
        }

    } // namespace
} // namespace gxbuild3::orchestration
