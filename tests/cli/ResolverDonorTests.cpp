// src/cli/BuildInputResolver.hpp: the NAND donor. The first root's nanddump.bin is discovered
// and an explicit -i (relative to the working directory, or absolute) overrides it; the donor
// sets the layout unless -t names one, and a layout override keeps every extracted component
// but drops the raw donor backing. A missing, unextractable or malformed donor fails with its
// path, a nanddump.bin that cannot be inspected stops the search instead of falling through to
// a later root, and without a donor the block layout is required.

#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/builders/ResolverTree.hpp"

#include <expected>
#include <filesystem>
#include <gtest/gtest.h>
#include <system_error>

namespace gxbuild3::cli {
    namespace {

        using test::Bytes;

        class ResolverDonor : public ResolverTest {};

        TEST_F(ResolverDonor, NandIsDiscoveredAndAnExplicitNandOverridesIt) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto small_donor,
                                 test::donor_image(ImageType::SmallBlock, key));
            write("first/nanddump.bin", small_donor);
            write("second/nanddump.bin", Bytes{0x00, 0x01});
            auto args = minimum_args();
            args.cpu_key = test::hex(key);
            args.image_type.reset();
            args.source_dirs = {path("first"), path("second")};
            const auto discovered = resolve_foundations(args);
            ASSERT_OK(discovered)
                << "the first exact nanddump.bin is discovered and determines layout";
            ASSERT_TRUE(discovered->donor.has_value())
                << "the first exact nanddump.bin is discovered and determines layout";
            ASSERT_EQ(discovered->image_type, ImageType::SmallBlock)
                << "the first exact nanddump.bin is discovered and determines layout";

            ASSERT_OK_AND_ASSIGN(const auto big_donor, test::donor_image(ImageType::BigBlock, key));
            write("explicit.bin", big_donor);
            args.input_path = "../explicit.bin";
            const auto explicit_nand = resolve_foundations(args);
            ASSERT_OK(explicit_nand)
                << "relative explicit NAND resolves from the supplied working directory";
            ASSERT_TRUE(explicit_nand->donor.has_value())
                << "relative explicit NAND resolves from the supplied working directory";
            ASSERT_EQ(explicit_nand->image_type, ImageType::BigBlock)
                << "relative explicit NAND resolves from the supplied working directory";

            args.input_path = path("explicit.bin");
            args.output_path = path("absolute-output.bin");
            args.build_ini = "build.ini";
            args.section = "falcon";
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            const auto absolute = resolve(args);
            ASSERT_OK(absolute) << "absolute explicit NAND and output paths remain absolute";
            EXPECT_EQ(absolute->input.image_type, ImageType::BigBlock)
                << "absolute explicit NAND and output paths remain absolute";
            EXPECT_EQ(absolute->output_path, path("absolute-output.bin"))
                << "absolute explicit NAND and output paths remain absolute";
        }

        TEST_F(ResolverDonor, NandErrorsArePrecise) {
            auto args = minimum_args();
            args.input_path = "missing.bin";
            const auto missing = resolve_foundations(args);
            ASSERT_ERROR(missing, ResolutionErrorCode::InputReadFailed)
                << "missing explicit NAND reports its resolved path";
            ASSERT_EQ(missing.error().path, path("working/missing.bin"))
                << "missing explicit NAND reports its resolved path";

            write("working/bad.bin", Bytes{0x00, 0x01, 0x02});
            args.input_path = "bad.bin";
            const auto invalid = resolve_foundations(args);
            ASSERT_ERROR(invalid, ResolutionErrorCode::InvalidDonor)
                << "unextractable NAND is reported as InvalidDonor";
            EXPECT_EQ(invalid.error().path, path("working/bad.bin"))
                << "unextractable NAND is reported as InvalidDonor";
        }

        TEST_F(ResolverDonor, NandLookupFailureDoesNotFallThrough) {
            std::error_code error;
            ASSERT_TRUE(std::filesystem::create_directory(path("first/nanddump.bin"), error))
                << "a directory stands in the first root's nanddump.bin: " << error.message();
            write("second/nanddump.bin", Bytes{0x00, 0x01});
            auto args = minimum_args();
            args.source_dirs = {path("first"), path("second")};

            std::expected<ResolvedFoundations, ResolutionError> result;
            ASSERT_NO_THROW(result = resolve_foundations(args))
                << "NAND filesystem failures must not escape the resolver";
            ASSERT_ERROR(result, ResolutionErrorCode::InputReadFailed)
                << "first-priority NAND inspection failure is structured and terminal";
            EXPECT_EQ(result.error().path, path("first/nanddump.bin"))
                << "first-priority NAND inspection failure is structured and terminal";
            EXPECT_EQ(result.error().item, "nanddump.bin")
                << "first-priority NAND inspection failure is structured and terminal";
        }

        TEST_F(ResolverDonor, MalformedSupportedSizeNandIsAnInvalidDonor) {
            write("working/malformed.bin", test::malformed_supported_size_nand());
            auto args = minimum_args();
            args.input_path = "malformed.bin";

            std::expected<ResolvedFoundations, ResolutionError> result;
            ASSERT_NO_THROW(result = resolve_foundations(args))
                << "donor parser exceptions must not escape resolve_foundations";
            ASSERT_ERROR(result, ResolutionErrorCode::InvalidDonor)
                << "malformed supported-size NAND maps to InvalidDonor with provenance";
            EXPECT_EQ(result.error().path, path("working/malformed.bin"))
                << "malformed supported-size NAND maps to InvalidDonor with provenance";
        }

        TEST_F(ResolverDonor, LayoutOverrideOnlyClearsTheRawBacking) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto donor, test::donor_image(ImageType::SmallBlock, key));
            write("first/nanddump.bin", donor);
            auto args = minimum_args();
            args.cpu_key = test::hex(key);
            args.image_type = ImageType::BigBlock;
            const auto result = resolve_foundations(args);
            ASSERT_OK(result) << "explicit layout overrides the donor layout";
            ASSERT_TRUE(result->donor.has_value()) << "explicit layout overrides the donor layout";
            EXPECT_EQ(result->image_type, ImageType::BigBlock)
                << "explicit layout overrides the donor layout";
            EXPECT_EQ(result->donor->image_type, ImageType::BigBlock)
                << "explicit layout overrides the donor layout";
            EXPECT_FALSE(result->donor->metadata.nand_image.has_value())
                << "layout mismatch clears only raw donor backing";
            EXPECT_TRUE(result->donor->metadata.smc.has_value())
                << "layout mismatch retains all extracted donor components";
            EXPECT_TRUE(result->donor->metadata.keyvault.has_value())
                << "layout mismatch retains all extracted donor components";
            EXPECT_FALSE(result->donor->bootloaders.cb_or_a.empty())
                << "layout mismatch retains all extracted donor components";
            EXPECT_FALSE(result->donor->bootloaders.cd.empty())
                << "layout mismatch retains all extracted donor components";
        }

        TEST_F(ResolverDonor, MatchingOrDetectedLayoutRetainsTheRawBacking) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto donor, test::donor_image(ImageType::SmallBlock, key));
            write("first/nanddump.bin", donor);
            auto args = minimum_args();
            args.cpu_key = test::hex(key);
            args.image_type = ImageType::SmallBlock;
            const auto matching = resolve_foundations(args);
            ASSERT_OK(matching) << "matching explicit layout retains raw donor backing";
            ASSERT_TRUE(matching->donor.has_value())
                << "matching explicit layout retains raw donor backing";
            ASSERT_TRUE(matching->donor->metadata.nand_image.has_value())
                << "matching explicit layout retains raw donor backing";

            args.image_type.reset();
            const auto detected = resolve_foundations(args);
            ASSERT_OK(detected) << "detected donor layout retains raw donor backing";
            ASSERT_TRUE(detected->donor.has_value())
                << "detected donor layout retains raw donor backing";
            EXPECT_TRUE(detected->donor->metadata.nand_image.has_value())
                << "detected donor layout retains raw donor backing";
        }

        TEST_F(ResolverDonor, LayoutIsRequiredWithoutADonor) {
            auto args = minimum_args();
            args.image_type.reset();
            ASSERT_ERROR(resolve_foundations(args), ResolutionErrorCode::BlockTypeRequired)
                << "block layout is required when no donor exists";

            args.image_type = ImageType::Emmc;
            const auto explicit_layout = resolve_foundations(args);
            ASSERT_OK(explicit_layout) << "explicit block layout permits donor-free foundations";
            EXPECT_FALSE(explicit_layout->donor.has_value())
                << "explicit block layout permits donor-free foundations";
            EXPECT_EQ(explicit_layout->image_type, ImageType::Emmc)
                << "explicit block layout permits donor-free foundations";
        }

    } // namespace
} // namespace gxbuild3::cli
