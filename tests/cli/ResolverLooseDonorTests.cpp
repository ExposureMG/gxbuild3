// src/cli/BuildInputResolver.hpp: the build INI and the loose donor. The build INI is required,
// read from the working directory, and only its exact [<section>bl] supplies the bootloader
// chain (an INI SC replaces a donor's, and a chain that omits SC inherits none). Without a NAND
// donor every loose component is required (the first missing one is named); kv.bin is opened
// under the CPU key, else taken in the clear as it stands (0x4000 bytes, or 0x3FF0 with a zero
// nonce prepended; any other length is refused). Under the all-zero CPU key a donor still
// resolves and kv.bin supplies its keyvault.

#include "ResolverTest.hpp"
#include "cli/BuildInputResolver.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/builders/ResolverTree.hpp"
#include "support/builders/Stages.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace gxbuild3::cli {
    namespace {

        using test::Bytes;

        class ResolverLooseDonor : public ResolverTest {};

        TEST_F(ResolverLooseDonor, BuildIniIsRequiredReadableAndTheExactSectionIsSelected) {
            ASSERT_OK_AND_ASSIGN(auto args, tree().complete_loose_args());
            args.build_ini.clear();
            ASSERT_ERROR(resolve(args), ResolutionErrorCode::BuildIniReadFailed)
                << "a build INI path is mandatory";

            args.build_ini = "missing.ini";
            const auto missing_file = resolve(args);
            ASSERT_ERROR(missing_file, ResolutionErrorCode::BuildIniReadFailed)
                << "a relative missing INI reports its working-directory path";
            ASSERT_EQ(missing_file.error().path, path("working/missing.ini"))
                << "a relative missing INI reports its working-directory path";

            write("working/build.ini", "[falcon]\ncb.bin\ncd.bin\n");
            args.build_ini = "build.ini";
            const auto wrong_section = resolve(args);
            ASSERT_ERROR(wrong_section, ResolutionErrorCode::SectionNotFound)
                << "the resolver requires exactly [<section stem>bl] without inference";
            EXPECT_EQ(wrong_section.error().path, path("working/build.ini"))
                << "the resolver requires exactly [<section stem>bl] without inference";
            EXPECT_EQ(wrong_section.error().item, "falconbl")
                << "the resolver requires exactly [<section stem>bl] without inference";
        }

        TEST_F(ResolverLooseDonor, IniScBootloaderReachesTheResolvedInput) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args());
            const auto sc = *test::valid_bootloaders().sc;
            write("first/sc_1.bin", sc);
            write("working/build.ini", "[falconbl]\ncb_1.bin\nsc_1.bin\ncd.bin\n");

            const auto result = resolve(args);
            ASSERT_OK(result) << "INI SC bootloader fixture resolves";
            ASSERT_TRUE(result->input.bootloaders.sc.has_value())
                << "INI SC bytes are retained in the resolved Input";
            ASSERT_BYTES_EQ(sc, *result->input.bootloaders.sc)
                << "INI SC bytes are retained in the resolved Input";

            ASSERT_OK_AND_ASSIGN(const auto donor_image,
                                 test::donor_image(ImageType::SmallBlock, test::valid_cpu_key()));
            write("first/nanddump.bin", donor_image);
            auto replacement_sc = sc;
            replacement_sc.back() ^= 1;
            write("first/3bl.bin", replacement_sc);
            write("working/build.ini", "[falconbl]\ncb_1.bin\n3bl.bin\ncd.bin\n");
            const auto donor = resolve(args);
            ASSERT_OK(donor) << "donor plus INI SC override resolves";
            ASSERT_TRUE(donor->input.bootloaders.sc.has_value())
                << "INI SC replaces donor SC while preserving donor backing";
            ASSERT_BYTES_EQ(replacement_sc, *donor->input.bootloaders.sc)
                << "INI SC replaces donor SC while preserving donor backing";
            ASSERT_TRUE(donor->input.metadata.nand_image.has_value())
                << "INI SC replaces donor SC while preserving donor backing";

            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            const auto without_sc = resolve(args);
            ASSERT_OK(without_sc) << "INI chain omitting SC resolves";
            EXPECT_FALSE(without_sc->input.bootloaders.sc.has_value())
                << "the selected INI chain does not inherit an omitted donor SC";
        }

        TEST_F(ResolverLooseDonor, LooseDonorRequiresAndPopulatesEveryComponent) {
            auto args = minimum_args();
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            args.build_ini = "build.ini";
            args.section = "falcon";

            const auto incomplete = resolve(args);
            ASSERT_ERROR(incomplete, ResolutionErrorCode::IncompleteLooseDonor)
                << "the first missing loose-donor component is reported precisely";
            ASSERT_EQ(incomplete.error().item, "kv.bin")
                << "the first missing loose-donor component is reported precisely";

            const auto key = test::valid_cpu_key();
            const auto expected_keyvault = test::canonical_keyvault_filled(key, 0x48);
            write("first/kv.bin", test::encrypted_keyvault(key, 0x48));
            write("first/smc.bin", test::make_smc(0x49));
            write("working/options.ini", "cbldv=0x0a\ncfldv=11\npairing_data=a1b2c3\n");
            const auto complete = resolve(args);
            ASSERT_OK(complete) << "a complete loose donor resolves";
            const auto& metadata = complete->input.metadata;
            ASSERT_TRUE(metadata.keyvault.has_value())
                << "loose encrypted kv.bin becomes canonical plaintext input";
            EXPECT_BYTES_EQ(expected_keyvault, *metadata.keyvault)
                << "loose encrypted kv.bin becomes canonical plaintext input";
            ASSERT_TRUE(metadata.smc.has_value()) << "loose smc.bin populates the input";
            EXPECT_BYTES_EQ(test::make_smc(0x49), *metadata.smc)
                << "loose smc.bin populates the input";
            EXPECT_EQ(metadata.cb_ldv, 10) << "loose donor metadata is fully parsed";
            EXPECT_EQ(metadata.cf_ldv, std::optional<uint8_t>{11})
                << "loose donor metadata is fully parsed";
            EXPECT_EQ(metadata.pairing_data, (std::array<uint8_t, 3>{0xA1, 0xB2, 0xC3}))
                << "loose donor metadata is fully parsed";
            EXPECT_BYTES_EQ(Bytes{0xCB}, complete->input.bootloaders.cb_or_a)
                << "the exact INI section supplies the bootloader chain";
            EXPECT_BYTES_EQ(Bytes{0xCD}, complete->input.bootloaders.cd)
                << "the exact INI section supplies the bootloader chain";
        }

        // A kv.bin that does not open under the CPU key is the console's keyvault in the clear,
        // as J-Runner supplies it for a console whose key is unknown; one of 0x3FF0 bytes lacks
        // its nonce. Any other length is refused. The four forms run in the old order.
        TEST_F(ResolverLooseDonor, KeyvaultInTheClearIsTakenAsItStands) {
            ASSERT_OK_AND_ASSIGN(const auto args, tree().complete_loose_args());
            const auto key = test::valid_cpu_key();
            const auto clear = test::canonical_keyvault_filled(key, 0x5A);
            write("first/kv.bin", clear);
            const auto whole = resolve(args);
            ASSERT_OK(whole) << "a kv.bin in the clear resolves";
            ASSERT_TRUE(whole->input.metadata.keyvault.has_value())
                << "a kv.bin in the clear is the build's keyvault as it stands";
            ASSERT_BYTES_EQ(clear, *whole->input.metadata.keyvault)
                << "a kv.bin in the clear is the build's keyvault as it stands";

            write("first/kv.bin", Bytes(clear.begin() + 0x10, clear.end()));
            const auto bare = resolve(args);
            Bytes zero_nonce = clear;
            std::fill(zero_nonce.begin(), zero_nonce.begin() + 0x10, 0);
            ASSERT_OK(bare) << "a kv.bin without its nonce resolves";
            ASSERT_TRUE(bare->input.metadata.keyvault.has_value())
                << "a kv.bin without its nonce gets sixteen zero bytes in front";
            ASSERT_BYTES_EQ(zero_nonce, *bare->input.metadata.keyvault)
                << "a kv.bin without its nonce gets sixteen zero bytes in front";

            // Sealed for another console, it opens under no key: xeBuild 1.21 reports it and
            // still takes it as the keyvault in the clear, and so does this.
            const auto foreign = test::encrypted_keyvault(test::different_valid_cpu_key(), 0x5A);
            write("first/kv.bin", foreign);
            const auto other = resolve(args);
            ASSERT_OK(other) << "a kv.bin sealed under another key resolves";
            ASSERT_TRUE(other->input.metadata.keyvault.has_value())
                << "a kv.bin sealed under another key is taken as it stands";
            ASSERT_BYTES_EQ(foreign, *other->input.metadata.keyvault)
                << "a kv.bin sealed under another key is taken as it stands";

            write("first/kv.bin", Bytes(0x100, 0x5A));
            const auto wrong_length = resolve(args);
            ASSERT_ERROR(wrong_length, ResolutionErrorCode::InvalidInput)
                << "a kv.bin of another length is refused";
            EXPECT_EQ(wrong_length.error().item, "kv.bin")
                << "a kv.bin of another length is refused";
        }

        // Under the all-zero CPU key the donor's keyvault does not open; the donor still
        // resolves, and the console's kv.bin supplies the keyvault. Without one the build is
        // refused.
        TEST_F(ResolverLooseDonor, ZeroCpuKeyDonorTakesTheKeyvaultFromKvBin) {
            const auto key = test::valid_cpu_key();
            ASSERT_OK_AND_ASSIGN(const auto donor, test::donor_image(ImageType::SmallBlock, key));
            write("first/nanddump.bin", donor);
            write("first/cb_1.bin", Bytes{0xCB});
            write("first/cd.bin", Bytes{0xCD});
            write("working/build.ini", "[falconbl]\ncb_1.bin\ncd.bin\n");
            auto args = minimum_args();
            args.build_ini = "build.ini";
            args.section = "falcon";
            args.image_type.reset();
            args.cpu_key = std::string(32, '0');

            const auto without = resolve(args);
            ASSERT_ERROR(without, ResolutionErrorCode::InvalidInput)
                << "a zero-key donor without kv.bin is refused for want of a keyvault";
            ASSERT_EQ(without.error().item, "kv.bin")
                << "a zero-key donor without kv.bin is refused for want of a keyvault";

            const auto clear = test::canonical_keyvault_filled(key, 0x72);
            write("first/kv.bin", clear);
            const auto with = resolve(args);
            ASSERT_OK(with) << "a zero-key donor with kv.bin resolves";
            ASSERT_TRUE(with->input.metadata.keyvault.has_value())
                << "the zero-key build carries the donor and the kv.bin's keyvault";
            EXPECT_BYTES_EQ(clear, *with->input.metadata.keyvault)
                << "the zero-key build carries the donor and the kv.bin's keyvault";
            EXPECT_BYTES_EQ(Bytes(16, 0), with->input.metadata.cpu_key)
                << "the zero-key build carries the donor and the kv.bin's keyvault";
            EXPECT_TRUE(with->input.metadata.nand_image.has_value())
                << "the zero-key build carries the donor and the kv.bin's keyvault";
        }

    } // namespace
} // namespace gxbuild3::cli
