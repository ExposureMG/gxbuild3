// What run_build leaves erased (src/BuildRunner.cpp, src/nand/FlashImage.cpp,
// src/nand/FlashDriver.cpp): over a donor with old data, the header block is zero up to the SMC,
// the boot chain's last block is zero past the chain, and the space up to the first update slot,
// an unused update slot 1, a stale FlashFS block and a remap-pool block are erased (0xFF data and
// spare) while a bad block keeps its mark; an eMMC image is zero past each Corona anchor structure
// and erased past its span, in an unused update slot 1 and in an unused block; a big-block FlashFS
// stamps only the cluster its file fills. One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/CoronaConfig.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <ios>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BlockMetadata;
        using nand::CoronaConfig;
        using nand::Driver;
        using nand::FlashImage;
        using test::Bytes;

        // Whether `bytes` is non-empty and every byte is `value`; names the first byte that is
        // not.
        ::testing::AssertionResult all_bytes(std::span<const uint8_t> bytes, uint8_t value) {
            if (bytes.empty()) {
                return ::testing::AssertionFailure() << "the span is empty";
            }
            const auto other = std::find_if(bytes.begin(), bytes.end(),
                                            [value](uint8_t byte) { return byte != value; });
            if (other != bytes.end()) {
                return ::testing::AssertionFailure()
                       << std::format("byte +{:#x} of {:#x} is {:#04x}, not {:#04x}",
                                      other - bytes.begin(), bytes.size(), *other, value);
            }
            return ::testing::AssertionSuccess();
        }

        // Every page in [first_page, first_page + page_count): 0xFF data and an erased spare.
        // Names the first page that is not.
        ::testing::AssertionResult pages_are_erased(const Driver& driver, size_t first_page,
                                                    size_t page_count) {
            for (size_t page = first_page; page < first_page + page_count; ++page) {
                if (!all_bytes(driver.read_page(page), 0xFF)) {
                    return ::testing::AssertionFailure()
                           << std::format("page {:#x} holds data", page);
                }
                if (!all_bytes(driver.read_page_spare(page), 0xFF)) {
                    return ::testing::AssertionFailure()
                           << std::format("page {:#x} has a programmed spare", page);
                }
            }
            return ::testing::AssertionSuccess();
        }

        TEST(ErasedSpace, DonorBuildLeavesUnlaidSpaceErased) {
            const auto initial = run_build(test::fresh_input(ImageType::SmallBlock));
            ASSERT_OK(initial) << "erased-fill donor image opens";
            auto donor = FlashImage::read(*initial);
            ASSERT_TRUE(donor.has_value()) << "erased-fill donor image opens";

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
                ASSERT_TRUE(donor->flash_driver.write_block(block, Bytes(0x4000, 0x5A)))
                    << "the donor's old data is laid";
                donor->flash_driver.write_block_metadata(block, stale);
            }
            donor->flash_driver.mark_bad_block(kBadBlock);

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = donor->flash_driver.serialize();
            const auto built = run_build(input);
            ASSERT_OK(built) << "a build over a donor with old data parses";
            const auto image = parse_image(*built);
            ASSERT_TRUE(image.has_value()) << "a build over a donor with old data parses";
            const auto& driver = image->flash_driver;
            const size_t pages = driver.pages_per_block();

            // The header block is zero from the header to the SMC; the boot chain's last 16 KiB
            // block is zero past its end; the rest up to the first update slot is erased.
            const size_t smc_at = test::be32(driver.read_clean(0x7C, 4), 0);
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

            ASSERT_GT(smc_at, 0x80u) << "the header block is zero from the header to the SMC";
            EXPECT_TRUE(all_bytes(driver.read_clean(0x80, smc_at - 0x80), 0))
                << "the header block is zero from the header to the SMC";
            ASSERT_LT(pad_end, 0x70000u) << "the boot chain's last block is zero past the chain";
            EXPECT_TRUE(all_bytes(driver.read_clean(chain_end, pad_end - chain_end), 0))
                << "the boot chain's last block is zero past the chain";
            EXPECT_TRUE(pages_are_erased(driver, pad_end / 512, (0x70000 - pad_end) / 512))
                << "the blocks between the chain and the first update slot stay erased";
            EXPECT_TRUE(pages_are_erased(driver, kSlotOneBlock * pages, 4 * pages))
                << "an unused update slot 1 is erased, not zeroed or left to the donor";
            EXPECT_TRUE(pages_are_erased(driver, kStaleBlock * pages, pages))
                << "a donor's old filesystem block is erased";
            EXPECT_TRUE(pages_are_erased(driver, kPoolBlock * pages, pages))
                << "a donor's remap-pool block is erased";
            EXPECT_TRUE(driver.is_bad_block(kBadBlock)) << "a block marked bad keeps its mark";
        }

        TEST(ErasedSpace, EmmcBuildLeavesAnchorTailsAndUnusedBlocksErased) {
            const auto built = run_build(test::fresh_input(ImageType::Emmc));
            ASSERT_OK(built) << "an eMMC image builds";
            ASSERT_EQ(built->size(), 0x3000000u) << "an eMMC image builds";
            const std::span<const uint8_t> bytes(*built);
            for (const size_t anchor : CoronaConfig::kOffsets) {
                SCOPED_TRACE(::testing::Message() << "anchor at 0x" << std::hex << anchor);
                EXPECT_TRUE(all_bytes(bytes.subspan(anchor + CoronaConfig::kSize,
                                                    CoronaConfig::kSpan - CoronaConfig::kSize),
                                      0))
                    << "an anchor's span is zero after its structure";
                EXPECT_TRUE(all_bytes(bytes.subspan(anchor + CoronaConfig::kSpan,
                                                    CoronaConfig::kBlockSize - CoronaConfig::kSpan),
                                      0xFF))
                    << "an anchor's block is erased past its span";
            }
            EXPECT_TRUE(all_bytes(bytes.subspan(0x80000, 0x10000), 0xFF))
                << "an unused eMMC update slot 1 is erased";
            EXPECT_TRUE(all_bytes(bytes.subspan(0xB00 * 0x4000, 0x4000), 0xFF))
                << "an unused eMMC block is erased";
        }

        TEST(ErasedSpace, BigBlockFlashFsStampsOnlyTheClustersItFills) {
            auto input = test::fresh_input(ImageType::BigBlock);
            input.flashfs_sec =
                std::vector<std::pair<std::string, Bytes>>{{"small.bin", Bytes(0x100, 0x6B)}};
            constexpr const char* kParses = "a big-block image with one small file parses";
            const auto built = run_build(input);
            ASSERT_OK(built) << kParses;
            const auto image = parse_image(*built);
            ASSERT_TRUE(image.has_value()) << kParses;
            ASSERT_TRUE(image->filesystem.has_value()) << kParses;
            const auto entry = image->filesystem->stat("small.bin");
            ASSERT_TRUE(entry.has_value()) << kParses;

            const auto& driver = image->flash_driver;
            const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
            const size_t file_cluster = entry->block_number;
            const size_t first_cluster = file_cluster / clusters_per_block * clusters_per_block;
            EXPECT_EQ(driver.interpret_cluster(file_cluster).block_type, 0x2A)
                << "the file's cluster carries the big-block data stamp";
            for (size_t cluster = first_cluster; cluster < first_cluster + clusters_per_block;
                 ++cluster) {
                if (cluster != file_cluster) {
                    EXPECT_TRUE(pages_are_erased(driver, cluster * 32, 32))
                        << "the rest of the file's big block stays erased (cluster 0x" << std::hex
                        << cluster << ")";
                }
            }
        }

    } // namespace
} // namespace gxbuild3::orchestration
