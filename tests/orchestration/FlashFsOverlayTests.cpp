// run_build's FlashFS (src/BuildRunner.cpp, src/nand/objects/FlashFileSystem.cpp): a big-block
// FlashFS formats empty and round-trips a file over 16 KiB, a big-block donor keeps its FlashFS
// without an overlay, an overlay root outranks a donor root of a higher (or the saturated 24-bit)
// sequence, allocation stops before the SMC tail and stays off the fixed payloads, an empty file
// is kept, the directory holds 256 entries and refuses 257, and a built FlashFS is laid as
// xeBuild 1.21 lays it (FlashFsIsLaidAsXebuildLaysIt, build time pinned to 1791105722 in UTC0).
// One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Env.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BlockMetadata;
        using nand::FlashImage;
        using test::Bytes;

        using FlashFsFiles = std::vector<std::pair<std::string, Bytes>>;

        TEST(FlashFsOverlay, BigBlockFormatsAndRoundTripsAnEmptyOverlay) {
            auto input = test::fresh_input(ImageType::BigBlock);
            input.flashfs_sec = FlashFsFiles{};
            const auto built = run_build(input);
            ASSERT_OK(built) << "BigBlock empty FlashFS formats";
            const auto parsed = parse_image(*built);
            EXPECT_TRUE(parsed.has_value() && parsed->filesystem.has_value())
                << "BigBlock empty FlashFS parses";
        }

        TEST(FlashFsOverlay, BigBlockRoundTripsAFileLargerThan16KiB) {
            Bytes expected(0x5000);
            for (size_t index = 0; index < expected.size(); ++index) {
                expected[index] =
                    static_cast<uint8_t>((index * 37U + (index >> 8U) * 13U + 0x5BU) & 0xFFU);
            }

            auto input = test::fresh_input(ImageType::BigBlock);
            input.flashfs_sec = FlashFsFiles{{"big-file.bin", expected}};
            const auto built = run_build(input);
            ASSERT_OK(built) << "BigBlock FlashFS file image builds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->filesystem.has_value())
                << "BigBlock FlashFS file image parses";
            const auto extracted = parsed->filesystem->get_file("big-file.bin");
            ASSERT_TRUE(extracted.has_value()) << "BigBlock FlashFS file retains its exact length";
            EXPECT_EQ(extracted->size(), expected.size())
                << "BigBlock FlashFS file retains its exact length";
            EXPECT_BYTES_EQ(expected, *extracted)
                << "BigBlock FlashFS file retains its exact contents";
        }

        TEST(FlashFsOverlay, BigBlockDonorRetainsFlashFsWithoutReplacement) {
            auto input = test::fresh_input(ImageType::BigBlock);
            const Bytes expected(0x4003, 0x52);
            input.flashfs_sec = FlashFsFiles{{"data.bin", expected}};
            const auto built = run_build(input);
            ASSERT_OK(built) << "big-block filesystem donor builds";

            input.metadata.nand_image = *built;
            input.flashfs_sec.reset();
            const auto rebuilt = run_build(input);
            ASSERT_OK(rebuilt)
                << "moved donor filesystem uses the current driver geometry without an overlay";
            const auto parsed = parse_image(*rebuilt);
            ASSERT_TRUE(parsed && parsed->filesystem)
                << "moved donor filesystem uses the current driver geometry without an overlay";
            const auto data = parsed->filesystem->get_file("data.bin");
            ASSERT_TRUE(data.has_value())
                << "moved donor filesystem uses the current driver geometry without an overlay";
            EXPECT_BYTES_EQ(expected, *data)
                << "moved donor filesystem uses the current driver geometry without an overlay";
        }

        TEST(FlashFsOverlay, OverlayOutranksAHigherSequenceDonorRoot) {
            auto first = test::fresh_input(ImageType::SmallBlock);
            first.flashfs_sec = FlashFsFiles{{"first.bin", Bytes{1}}};
            const auto first_build = run_build(first);
            ASSERT_OK(first_build) << "initial FlashFS donor build succeeds";

            auto higher_sequence_donor = test::fresh_input(ImageType::SmallBlock);
            higher_sequence_donor.metadata.nand_image = *first_build;
            higher_sequence_donor.flashfs_sec = FlashFsFiles{{"donor-old.bin", Bytes{2}}};
            const auto donor_build = run_build(higher_sequence_donor);
            ASSERT_OK(donor_build) << "a rebuilt FlashFS starts at root sequence 1";
            auto donor_image = parse_image(*donor_build);
            ASSERT_TRUE(donor_image.has_value() && donor_image->filesystem.has_value())
                << "a rebuilt FlashFS starts at root sequence 1";
            ASSERT_EQ(donor_image->filesystem->version(), 1u)
                << "a rebuilt FlashFS starts at root sequence 1";
            // Raise the donor root above the sequence a new build writes.
            const uint16_t donor_root = donor_image->filesystem->root_block();
            BlockMetadata raised = donor_image->flash_driver.interpret_cluster(donor_root);
            raised.sequence = 0x125;
            donor_image->flash_driver.write_cluster_metadata(donor_root, raised);
            // The bytes as they stand: a driver with no layout of its own would stamp its low
            // blocks, the root among them, as system area.
            const auto donor_bytes = std::as_const(donor_image->flash_driver).serialize();
            const auto parsed_donor = parse_image(donor_bytes);
            ASSERT_TRUE(parsed_donor.has_value() && parsed_donor->filesystem.has_value())
                << "donor FlashFS root carries a sequence above the fresh default";
            ASSERT_EQ(parsed_donor->filesystem->version(), 0x125u)
                << "donor FlashFS root carries a sequence above the fresh default";

            auto overlay = test::fresh_input(ImageType::SmallBlock);
            overlay.metadata.nand_image = donor_bytes;
            overlay.flashfs_sec = FlashFsFiles{{"replacement.bin", Bytes{7, 8, 9}}};
            const auto built = run_build(overlay);
            ASSERT_OK(built) << "FlashFS overlay output parses";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->filesystem.has_value())
                << "FlashFS overlay output parses";
            EXPECT_EQ(parsed->filesystem->version(), 1u)
                << "the overlay root is written at sequence 1";
            EXPECT_EQ(parsed->filesystem->get_file("replacement.bin"),
                      std::optional<Bytes>(Bytes({7, 8, 9})))
                << "FlashFS overlay selects the exact replacement contents";
            EXPECT_FALSE(parsed->filesystem->get_file("donor-old.bin").has_value())
                << "stale donor FlashFS root cannot win selection";
        }

        TEST(FlashFsOverlay, AllocationReportsExhaustionBeforeTheSmcTail) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.flashfs_sec = FlashFsFiles{{"probe.bin", Bytes{1}}};
            const auto probe = run_build(input);
            ASSERT_OK(probe) << "a one-file FlashFS builds and lists its file";
            const auto probed = parse_image(*probe);
            ASSERT_TRUE(probed && probed->filesystem)
                << "a one-file FlashFS builds and lists its file";
            const auto probe_entry = probed->filesystem->stat("probe.bin");
            ASSERT_TRUE(probe_entry.has_value()) << "a one-file FlashFS builds and lists its file";
            const size_t first_flashfs_block = probe_entry->block_number;
            constexpr size_t smc_tail_start = 0x3DC;
            input.flashfs_sec =
                FlashFsFiles{{"fills-tail.bin",
                              Bytes((smc_tail_start - first_flashfs_block + 1) * 0x4000, 0xA5)}};

            EXPECT_ERROR(run_build(input), BuildErrorCode::SerializationFailure)
                << "FlashFS allocation cannot enter the SMC tail; FlashFS tail exhaustion reports "
                   "SerializationFailure";
        }

        TEST(FlashFsOverlay, SerializedFlashFsRetainsAnEmptyFile) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.flashfs_sec = FlashFsFiles{{"empty.bin", Bytes{}}};
            const auto built = run_build(input);
            ASSERT_OK(built) << "empty FlashFS file build succeeds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->filesystem.has_value())
                << "empty FlashFS file image parses";
            EXPECT_EQ(parsed->filesystem->get_file("empty.bin"), std::optional<Bytes>(Bytes{}))
                << "serialized empty FlashFS file is retained";
        }

        TEST(FlashFsOverlay, SerializedFlashFsDoesNotOverlapFixedPayloads) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x1000, 0x71);
            payloads.fuses = Bytes(0x60, 0x72);
            payloads.xell = test::valid_xell();
            input.payloads = std::move(payloads);
            input.flashfs_sec = FlashFsFiles{{"payload-safe.bin", Bytes(0x4000, 0x5A)}};

            const auto built = run_build(input);
            ASSERT_OK(built) << "FlashFS and fixed payload image builds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->filesystem.has_value())
                << "serialized FlashFS bytes are not overwritten by fixed payloads";
            const auto safe = parsed->filesystem->get_file("payload-safe.bin");
            ASSERT_TRUE(safe.has_value())
                << "serialized FlashFS bytes are not overwritten by fixed payloads";
            EXPECT_BYTES_EQ(Bytes(0x4000, 0x5A), *safe)
                << "serialized FlashFS bytes are not overwritten by fixed payloads";
            ASSERT_TRUE(parsed->payloads.rebooter.has_value())
                << "serialized rebooter bytes survive FlashFS allocation";
            EXPECT_BYTES_EQ(*input.payloads->rebooter, *parsed->payloads.rebooter)
                << "serialized rebooter bytes survive FlashFS allocation";
            ASSERT_TRUE(parsed->payloads.fuses.has_value())
                << "serialized fuse bytes survive FlashFS allocation";
            EXPECT_BYTES_EQ(*input.payloads->fuses, *parsed->payloads.fuses)
                << "serialized fuse bytes survive FlashFS allocation";
            ASSERT_TRUE(parsed->payloads.xell.has_value())
                << "serialized XeLL bytes survive FlashFS allocation";
            EXPECT_BYTES_EQ(*input.payloads->xell, parsed->payloads.xell->data)
                << "serialized XeLL bytes survive FlashFS allocation";
        }

        TEST(FlashFsOverlay, DirectoryHolds256EntriesAndRefuses257) {
            auto full = test::fresh_input(ImageType::SmallBlock);
            full.flashfs_sec = FlashFsFiles{};
            for (size_t index = 0; index < 256; ++index) {
                full.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
            }
            const auto full_build = run_build(full);
            ASSERT_OK(full_build) << "256 FlashFS entries serialize successfully";
            const auto full_image = parse_image(*full_build);
            ASSERT_TRUE(full_image.has_value() && full_image->filesystem.has_value())
                << "serialized FlashFS retains all 256 directory entries";
            EXPECT_EQ(full_image->filesystem->list_files().size(), 256u)
                << "serialized FlashFS retains all 256 directory entries";

            auto overflow = test::fresh_input(ImageType::SmallBlock);
            overflow.flashfs_sec = FlashFsFiles{};
            for (size_t index = 0; index < 257; ++index) {
                overflow.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
            }
            EXPECT_ERROR(run_build(overflow), BuildErrorCode::SerializationFailure)
                << "257 FlashFS entries are rejected; FlashFS directory overflow returns "
                   "SerializationFailure";
        }

        TEST(FlashFsOverlay, BigBlockOverlayHandlesThe24BitSequenceLimit) {
            auto first = test::fresh_input(ImageType::BigBlock);
            first.flashfs_sec = FlashFsFiles{{"donor-old.bin", Bytes{2}}};
            const auto first_build = run_build(first);
            ASSERT_OK(first_build) << "BigBlock donor FlashFS parses before sequence saturation";
            auto max_sequence_donor = FlashImage::read(*first_build);
            ASSERT_TRUE(max_sequence_donor.has_value() && max_sequence_donor->parse() &&
                        max_sequence_donor->filesystem.has_value())
                << "BigBlock donor FlashFS parses before sequence saturation";

            const uint16_t root = max_sequence_donor->filesystem->root_block();
            BlockMetadata max_sequence_root{};
            max_sequence_root.logical_block_id = root;
            max_sequence_root.sequence = 0xFFFFFF;
            max_sequence_root.block_type = 0x30;
            max_sequence_donor->flash_driver.write_block_metadata(root, max_sequence_root);
            const auto donor_bytes = max_sequence_donor->flash_driver.serialize();

            auto overlay = test::fresh_input(ImageType::BigBlock);
            overlay.metadata.nand_image = donor_bytes;
            overlay.flashfs_sec = FlashFsFiles{{"replacement.bin", Bytes{7, 8, 9}}};
            const auto built = run_build(overlay);
            ASSERT_OK(built) << "24-bit sequence overlay build succeeds";
            const auto parsed = parse_image(*built);
            ASSERT_TRUE(parsed.has_value() && parsed->filesystem.has_value())
                << "24-bit sequence overlay selects replacement content";
            EXPECT_EQ(parsed->filesystem->get_file("replacement.bin"),
                      std::optional<Bytes>(Bytes({7, 8, 9})))
                << "24-bit sequence overlay selects replacement content";
        }

        // A built FlashFS is laid as xeBuild 1.21 lays it: the CG tail first, directly past the
        // update slots, then the listed files back to back in their order, the settings blobs and
        // the root behind them, every entry stamped with the build's time plus two seconds. Its
        // table states the root as itself, the blobs free, the four settings blocks reserved and
        // the remap pool after them as nothing.
        TEST(FlashFsOverlay, FlashFsIsLaidAsXebuildLaysIt) {
            using BlockMapStatus = nand::BlockMapStatus;
            auto input = test::fresh_input(ImageType::SmallBlock);
            const auto [cf0, ignored_cg0] = test::valid_system_update(0x51);
            nand::BootloaderCg cg0{};
            cg0.header.header.magic = nand::NANDBootloaderMagic::CG;
            cg0.header.header.version = 1;
            cg0.data.assign(0x10000, 0x7A);
            cg0.header.header.size =
                static_cast<uint32_t>(sizeof(nand::cg_header) + cg0.data.size());
            input.bootloaders.cf0 = cf0;
            input.bootloaders.cg0 = cg0.serialize();
            input.flashfs_sec =
                FlashFsFiles{{"zeta.bin", Bytes(0x4001, 0x5A)}, {"alpha.bin", Bytes(0x10, 0x41)}};
            *input.mobiles.slot(0x31) = Bytes(0x800, 0x31);

            // 2026-10-04 09:22:02 UTC: in UTC the entries say 09:22:04, 0x5D444AC2.
            const auto built = [&] {
                const test::PinnedBuildTime pin{"1791105722", "UTC0"};
                return run_build(input);
            }();
            ASSERT_OK(built) << "a FlashFS build with a CG tail parses";
            const auto image = parse_image(*built);
            ASSERT_TRUE(image.has_value() && image->filesystem.has_value())
                << "a FlashFS build with a CG tail parses";
            const auto& fs = *image->filesystem;
            const auto& entries = fs.entries();
            const std::array<std::string_view, 3> names{"sysupdate.xexp1", "zeta.bin", "alpha.bin"};
            ASSERT_EQ(entries.size(), names.size())
                << "the CG tail is listed first, then the files in their order, each stamped "
                   "with the build's time";
            for (size_t i = 0; i < names.size(); ++i) {
                SCOPED_TRACE(names[i]);
                EXPECT_EQ(std::string_view(entries[i].filename), names[i])
                    << "the CG tail is listed first, then the files in their order";
                EXPECT_EQ(entries[i].timestamp, 0x5D444AC2u)
                    << "each entry is stamped with the build's time";
            }
            const size_t first = (image->header.cf_offset + 2 * 0x10000) / 0x4000;
            const auto tail = fs.get_chain(entries[0].block_number);
            const size_t root = fs.root_block();
            const auto& map = fs.blockmap();
            EXPECT_EQ(entries[0].block_number, first)
                << "the CG tail starts on the first block past the update slots";
            EXPECT_EQ(map[first - 1], BlockMapStatus::Reserved)
                << "the CG tail starts on the first block past the update slots";
            EXPECT_EQ(image->system_update_0.cg_spill_blocks, tail)
                << "the CF names the CG tail's blocks";
            EXPECT_EQ(entries[1].block_number, first + tail.size())
                << "the files follow back to back";
            EXPECT_EQ(entries[2].block_number, entries[1].block_number + 2)
                << "the files follow back to back";
            EXPECT_EQ(map[entries[2].block_number + 1], BlockMapStatus::Free)
                << "the settings blob follows the files, stated free, and the root it";
            EXPECT_EQ(root, entries[2].block_number + 2u)
                << "the settings blob follows the files, stated free, and the root it";
            EXPECT_EQ(map[root], BlockMapStatus::Table) << "the root states itself";
            EXPECT_EQ(map[0x3DB], BlockMapStatus::Free)
                << "the settings blocks are reserved and the remap pool never named";
            EXPECT_EQ(map[0x3DC], BlockMapStatus::Reserved)
                << "the settings blocks are reserved and the remap pool never named";
            EXPECT_EQ(map[0x3DF], BlockMapStatus::Reserved)
                << "the settings blocks are reserved and the remap pool never named";
            EXPECT_EQ(map[0x3E0], BlockMapStatus::Unnamed)
                << "the settings blocks are reserved and the remap pool never named";
            EXPECT_EQ(map[0x3FF], BlockMapStatus::Unnamed)
                << "the settings blocks are reserved and the remap pool never named";
        }

    } // namespace
} // namespace gxbuild3::orchestration
