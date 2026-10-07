// A CG too large for its update slot (src/nand/FlashImageCrypt.cpp and FlashImageParse.cpp):
// encrypt_all lays its tail in FlashFS continuation clusters and lists them in the CF from 0x32,
// the image reassembles the complete CG on read-back, a parsed split image survives a second
// parse and a direct rewrite, a duplicate continuation cluster is refused, and shrinking the CG
// clears the block list and the obsolete continuation file. Retail allocates disjoint chains for
// both slots.
//
// The CG is sealed with random nonces (ExCryptRandom), so only structure is compared, never
// bytes against a constant. Each row rewrites a big-block image several times (about 2 s), so
// Type/SpillChain is discovered one ctest entry per row.

#include "nand/AnchorFixture.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/XeLL.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <gtest/gtest.h>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        struct SpillType {
            const char* name;
            BuildType type;
        };
        GX_PRINT_ROW_AS_NAME(SpillType)

        constexpr SpillType kSpillTypes[] = {
            {"Retail", BuildType::Retail},
            {"Glitch2", BuildType::Glitch2},
            {"Jtag", BuildType::Jtag},
        };

        class SpillChain : public ::testing::TestWithParam<SpillType> {};

        TEST_P(SpillChain, OversizedCgSpillsThroughTheCfBlockListAndReassembles) {
            const BuildType type = GetParam().type;
            auto f = anchor_image(Driver::DriverMode::Big, BuildType::Glitch2);
            if (type != BuildType::Glitch2) {
                f.payloads.patchset.reset();
            }
            if (type == BuildType::Jtag) {
                XeLL x{};
                x.data = raw_xell();
                f.payloads.xell = x;
            }
            f.build_type = type;
            BootloaderCf cf{};
            cf.header.header.magic = NANDBootloaderMagic::CF;
            cf.data.resize(0x400, 0);
            cf.header.header.size = 0x430;
            cf.decrypted = true;
            BootloaderCg cg{};
            cg.header.header.magic = NANDBootloaderMagic::CG;
            cg.data.resize(0x30000, 0xAB);
            cg.header.header.size = sizeof(cg_header) + cg.data.size();
            cg.decrypted = false;
            f.system_update_0 = {cf, cg};
            if (type == BuildType::Retail) {
                f.system_update_1 = {cf, cg};
            }
            f.filesystem = FlashFileSystem{};
            f.filesystem->set_driver(&f.flash_driver);
            ASSERT_OK(f.filesystem->format(f.flash_driver.block_count(), 0x1D0))
                << "the filesystem formats";
            const auto expected = cg.serialize();
            ASSERT_OK(f.encrypt_all({}, type))
                << "oversized CG prepares and writes within its slot";
            ASSERT_OK(f.write_to_driver()) << "oversized CG prepares and writes within its slot";

            if (type == BuildType::Retail) {
                const auto& first = f.system_update_0.cg_spill_blocks;
                const auto& second = f.system_update_1.cg_spill_blocks;
                ASSERT_FALSE(first.empty()) << "retail allocates both CG continuation chains";
                ASSERT_FALSE(second.empty()) << "retail allocates both CG continuation chains";
                for (const auto block : first) {
                    ASSERT_TRUE(std::find(second.begin(), second.end(), block) == second.end())
                        << "retail continuation chains do not overlap (cluster " << block << ")";
                }
            }

            ASSERT_TRUE(f.system_update_0.cf.has_value()) << "CF has a CG continuation block list";
            auto c = *f.system_update_0.cf;
            ASSERT_OK(c.decrypt(key_1bl));
            ASSERT_GE(c.data.size(), 2u) << "CF has a CG continuation block list";
            ASSERT_TRUE(c.data[0] != 0 || c.data[1] != 0) << "CF has a CG continuation block list";

            const auto written = f.write();
            ASSERT_OK(written) << "CF block list reconstructs the complete CG ciphertext";
            auto parsed = FlashImage::read(*written);
            ASSERT_TRUE(parsed.has_value())
                << "CF block list reconstructs the complete CG ciphertext";
            ASSERT_OK(parsed->parse()) << "CF block list reconstructs the complete CG ciphertext";
            ASSERT_TRUE(parsed->system_update_0.cg.has_value())
                << "CF block list reconstructs the complete CG ciphertext";
            ASSERT_BYTES_EQ(expected, parsed->system_update_0.cg->serialize())
                << "CF block list reconstructs the complete CG ciphertext";
            if (type == BuildType::Retail) {
                ASSERT_EQ(parsed->header.patch_slots.get(), 2u)
                    << "retail preserves slot one and reconstructs its complete CG";
                ASSERT_TRUE(parsed->system_update_1.cg.has_value())
                    << "retail preserves slot one and reconstructs its complete CG";
                ASSERT_BYTES_EQ(expected, parsed->system_update_1.cg->serialize())
                    << "retail preserves slot one and reconstructs its complete CG";
            }
            ASSERT_OK(parsed->parse()) << "split image can be parsed twice";

            const auto rewritten = parsed->write();
            ASSERT_OK(rewritten) << "parsed split CG survives direct write/reparse";
            auto roundtrip = FlashImage::read(*rewritten);
            ASSERT_TRUE(roundtrip.has_value()) << "parsed split CG survives direct write/reparse";
            ASSERT_OK(roundtrip->parse()) << "parsed split CG survives direct write/reparse";
            ASSERT_TRUE(roundtrip->system_update_0.cg.has_value())
                << "parsed split CG survives direct write/reparse";
            ASSERT_BYTES_EQ(expected, roundtrip->system_update_0.cg->serialize())
                << "parsed split CG survives direct write/reparse";

            // A duplicate continuation cluster must not silently replace part of the CG.
            auto corrupt = *f.system_update_0.cf;
            ASSERT_OK(corrupt.decrypt(key_1bl));
            ASSERT_GE(corrupt.data.size(), 6u);
            corrupt.data[4] = corrupt.data[2];
            corrupt.data[5] = corrupt.data[3];
            ASSERT_OK(corrupt.encrypt(key_1bl));
            ASSERT_TRUE(
                parsed->flash_driver.write_offset(parsed->header.cf_offset, corrupt.serialize()))
                << "the corrupt CF is laid";
            auto damaged = FlashImage::read(parsed->flash_driver.serialize());
            ASSERT_TRUE(damaged.has_value()) << "duplicate CG continuation clusters are rejected";
            ASSERT_FALSE(damaged->parse().has_value())
                << "duplicate CG continuation clusters are rejected";

            ASSERT_TRUE(f.system_update_0.cg.has_value()) << "shrunk CG prepares";
            f.system_update_0.cg->data.resize(0x20);
            f.system_update_0.cg->header.header.size = sizeof(cg_header) + 0x20;
            ASSERT_OK(f.encrypt_all({}, type)) << "shrunk CG prepares";
            auto shrunk = *f.system_update_0.cf;
            ASSERT_OK(shrunk.decrypt(key_1bl));
            ASSERT_GE(shrunk.data.size(), 2u)
                << "shrinking CG clears its block table and obsolete continuation file";
            EXPECT_EQ(shrunk.data[0], 0)
                << "shrinking CG clears its block table and obsolete continuation file";
            EXPECT_EQ(shrunk.data[1], 0)
                << "shrinking CG clears its block table and obsolete continuation file";
            EXPECT_FALSE(f.filesystem->exists("sysupdate.xexp1"))
                << "shrinking CG clears its block table and obsolete continuation file";
        }

        INSTANTIATE_TEST_SUITE_P(Type, SpillChain, ::testing::ValuesIn(kSpillTypes),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::nand
