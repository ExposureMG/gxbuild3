// FlashImage round trips as they behave today (src/nand/FlashImageParse.cpp, FlashImageWrite.cpp),
// named after the golden lines that were their only record:
//   FlashImageRoundTrip  the tracked mydata/image.bin written straight after parse, and written
//                        again after decrypt_all and encrypt_all, is not the input byte for byte
//                        (flashimage_golden.txt write.identity=0 and roundtrip.identity=0);
//   FlashImageSeal       the sealed Small Retail matrix cell (support/builders/FlashImageCells)
//                        parses back with no build type, and its parsed CG stops at the declared
//                        size while the sealed one keeps the 16-byte rounding
//                        (flashimage_matrix.txt matrix.Small.Retail.sealed.reparse.*).
// Both fixtures are tracked: a missing file is a failure, never a skip. These pin current
// behaviour; the goldens stay authoritative.

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "support/Env.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/Scratch.hpp"
#include "support/builders/FlashImageCells.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <utility>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        // FlashImage::read then parse, as the golden renderers do.
        std::optional<FlashImage> read_and_parse(const Bytes& bytes) {
            auto image = FlashImage::read(bytes);
            if (!image) {
                ADD_FAILURE() << "FlashImage::read returned no image";
                return std::nullopt;
            }
            if (auto parsed = image->parse(); !parsed) {
                ADD_FAILURE() << "parse failed: " << parsed.error().describe();
                return std::nullopt;
            }
            return image;
        }

        TEST(FlashImageRoundTrip, WriteAfterParseIsNotIdentityAsToday) {
            const test::PinnedBuildTime pinned;
            ASSERT_OK_AND_ASSIGN(const Bytes input, test::read_support_file("mydata/image.bin"));
            ASSERT_EQ(input.size(), 0x1080000u) << "input.size";

            // write.identity=0: write() straight after parse.
            {
                auto image = read_and_parse(input);
                ASSERT_TRUE(image.has_value());
                EXPECT_FALSE(image->build_type.has_value()) << "parse.build_type=none";
                const auto written = image->write();
                ASSERT_OK(written) << "write() after parse";
                EXPECT_EQ(written->size(), input.size()) << "write.size=0x1080000";
                EXPECT_FALSE(*written == input)
                    << "write.identity=0: rewriting a parsed image changes its bytes today";
            }

            // roundtrip.identity=0: decrypt_all, encrypt_all as Retail (the renderer's
            // value_or(Retail) for an image that parses with no build type), write().
            auto image = read_and_parse(input);
            ASSERT_TRUE(image.has_value());
            ASSERT_OK(image->decrypt_all(test::kBuildAllCpuKey))
                << "decrypt_all under the donor's CPU key";
            EXPECT_FALSE(image->build_type.has_value()) << "decrypt.build_type=none";
            ASSERT_OK(image->encrypt_all(test::kBuildAllCpuKey, BuildType::Retail))
                << "roundtrip.encrypt_build_type=Retail";
            const auto written = image->write();
            ASSERT_OK(written) << "write() after decrypt_all and encrypt_all";
            EXPECT_EQ(written->size(), input.size()) << "roundtrip.size=0x1080000";
            EXPECT_FALSE(*written == input)
                << "roundtrip.identity=0: a decrypt and re-seal round trip changes the bytes today";
        }

        // The Small Retail cell with CF/CG 4532, sealed under the public CPU key, written and
        // parsed back: the render_cell steps of flashimage_matrix.txt's sealed half.
        class FlashImageSeal : public ::testing::Test {
          protected:
            void SetUp() override {
                const test::PinnedBuildTime pinned;
                test::flashimage_cells::Problems problems;
                sealed_ = std::make_unique<FlashImage>();
                ASSERT_OK(test::flashimage_cells::build_cell(*sealed_, test::support_dir(),
                                                             Driver::DriverMode::Small,
                                                             BuildType::Retail, true, problems))
                    << "the Small Retail cell builds";
                for (const auto& problem : problems) {
                    ADD_FAILURE() << problem;
                }
                ASSERT_OK(sealed_->encrypt_all(test::kBuildAllCpuKey, BuildType::Retail))
                    << "matrix.Small.Retail.sealed.seal=ok";
                const auto written = sealed_->write();
                ASSERT_OK(written) << "the sealed cell writes";
                reparsed_ = read_and_parse(*written);
                ASSERT_TRUE(reparsed_.has_value()) << "matrix.Small.Retail.sealed.reparse=ok";
            }

            // Points into its own driver: built in place and never moved.
            std::unique_ptr<FlashImage> sealed_;
            std::optional<FlashImage> reparsed_;
        };

        TEST_F(FlashImageSeal, SealedRetailReparsesWithoutBuildTypeAsToday) {
            ASSERT_TRUE(sealed_->build_type.has_value());
            EXPECT_EQ(*sealed_->build_type, BuildType::Retail) << "the cell is built as Retail";
            // A retail image carries no KHV, XeLL or JTAG window, so parse infers no type.
            EXPECT_FALSE(reparsed_->build_type.has_value())
                << "matrix.Small.Retail.sealed.reparse.build_type=none";
            EXPECT_EQ(reparsed_->flash_driver.driver_mode(), Driver::DriverMode::Small)
                << "matrix.Small.Retail.sealed.reparse.driver_mode=Small";
        }

        TEST_F(FlashImageSeal, ReparsedCgStopsAtDeclaredSizeWhileSealedKeepsRounding) {
            ASSERT_TRUE(sealed_->system_update_0.cg.has_value());
            ASSERT_TRUE(reparsed_->system_update_0.cg.has_value());
            const auto sealed_cg = sealed_->system_update_0.cg->serialize();
            const auto read_back = reparsed_->system_update_0.cg->serialize();
            EXPECT_EQ(sealed_cg.size(), 0x2EF40u)
                << "matrix.Small.Retail.sealed.stage.CG0=0x2EF40: sealed keeps the rounding";
            EXPECT_EQ(read_back.size(), 0x2EF3Au)
                << "matrix.Small.Retail.sealed.reparse.cg0=0x2EF3A of 0x2EF40: parse stops at "
                   "the declared size";
            ASSERT_LE(read_back.size(), sealed_cg.size());
            EXPECT_TRUE(std::equal(read_back.begin(), read_back.end(), sealed_cg.begin()))
                << "prefix_match=1: the parsed CG is the sealed one without its rounding";
        }

    } // namespace
} // namespace gxbuild3::nand
