// run_build's boot-chain metadata (src/BuildRunner.cpp): extract_all hands back the serialized
// CB/A, CD, SC and fixed payloads, and a rebuild of what it returns keeps them; the winning CB LDV
// and pairing go to CB_B when one is supplied (CB_A stays as given) and the CF LDV and pairing to
// every supplied CF, keeping the CF's extended header fields; pairing-only metadata keeps each
// CF's own LDV; a JTAG image's first update pair stays unbound; a CB or CF whose per-box block
// cannot be written is a structured InvalidBootloader. ZeroCpuKey: under the all-zero CPU key a
// CB_B chain is bound to no console (xeBuild 1.21 "zeropairing CB_B"), and a console's donor
// keyvault stays sealed while the supplied one is sealed under the zero key. One ctest entry per
// case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Patchsets.hpp"
#include "support/builders/Stages.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BootloaderCb;
        using nand::BootloaderCd;
        using nand::BootloaderCf;
        using nand::FlashImage;
        using nand::NANDBootloaderMagic;
        using test::Bytes;

        // A small-block glitch patch file with one KHV byte 0x91, as the metadata cases use.
        InputPatches glitch_patches() {
            InputPatches patches{};
            patches.automatic = InputPatchFile{
                "automatic", test::glitch_patchset(0x100, 0x11223344, 0x30, 0, Bytes{0x91})};
            return patches;
        }

        TEST(BootChainMetadata, ExtractionRoundTripsSerializedBootloadersAndPayloads) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(const auto bootloader_donor, test::make_donor(source, {}));
            auto bootloaders = extract_all(bootloader_donor, source.metadata.cpu_key);
            ASSERT_OK(bootloaders) << "serialized bootloader donor extracts";
            EXPECT_BYTES_EQ(source.bootloaders.cb_or_a, bootloaders->bootloaders.cb_or_a)
                << "extraction preserves exact CB/A bytes";
            ASSERT_OK_AND_ASSIGN(const auto extracted_cd,
                                 BootloaderCd::parse(bootloaders->bootloaders.cd));
            EXPECT_EQ(extracted_cd.header.header.magic.get(),
                      std::to_underlying(NANDBootloaderMagic::CD))
                << "extraction preserves decrypted CD header and payload data";
            EXPECT_EQ(extracted_cd.header.header.version.get(), 1u)
                << "extraction preserves decrypted CD header and payload data";
            EXPECT_BYTES_EQ(Bytes(0x20, 0x42), extracted_cd.data)
                << "extraction preserves decrypted CD header and payload data";
            ASSERT_TRUE(source.bootloaders.sc.has_value()) << "extraction preserves exact SC bytes";
            ASSERT_TRUE(bootloaders->bootloaders.sc.has_value())
                << "extraction preserves exact SC bytes";
            EXPECT_BYTES_EQ(*source.bootloaders.sc, *bootloaders->bootloaders.sc)
                << "extraction preserves exact SC bytes";

            bootloaders->metadata.nand_image.reset();
            const auto bootloader_rebuilt = run_build(*bootloaders);
            ASSERT_OK(bootloader_rebuilt)
                << "rebuilt CB/A remains serialized-identical outside its nonce";
            const auto bootloader_roundtrip =
                extract_all(*bootloader_rebuilt, bootloaders->metadata.cpu_key);
            ASSERT_OK(bootloader_roundtrip)
                << "rebuilt CB/A remains serialized-identical outside its nonce";
            // The donor chain stops before CE, so the rebuild seals CB/A under a fresh nonce.
            const std::span<const uint8_t> rebuilt_cb = bootloader_roundtrip->bootloaders.cb_or_a;
            const std::span<const uint8_t> source_cb = source.bootloaders.cb_or_a;
            ASSERT_EQ(rebuilt_cb.size(), source_cb.size())
                << "rebuilt CB/A remains serialized-identical outside its nonce";
            ASSERT_GE(rebuilt_cb.size(), 0x20u)
                << "rebuilt CB/A remains serialized-identical outside its nonce";
            EXPECT_BYTES_EQ(source_cb.first(0x10), rebuilt_cb.first(0x10))
                << "rebuilt CB/A remains serialized-identical outside its nonce";
            EXPECT_BYTES_EQ(source_cb.subspan(0x20), rebuilt_cb.subspan(0x20))
                << "rebuilt CB/A remains serialized-identical outside its nonce";
            ASSERT_OK_AND_ASSIGN(const auto roundtrip_cd,
                                 BootloaderCd::parse(bootloader_roundtrip->bootloaders.cd));
            EXPECT_EQ(roundtrip_cd.header.header.magic.get(),
                      std::to_underlying(NANDBootloaderMagic::CD))
                << "rebuilt CD retains decrypted header and payload data";
            EXPECT_EQ(roundtrip_cd.header.header.version.get(), 1u)
                << "rebuilt CD retains decrypted header and payload data";
            EXPECT_BYTES_EQ(Bytes(0x20, 0x42), roundtrip_cd.data)
                << "rebuilt CD retains decrypted header and payload data";
            ASSERT_TRUE(bootloader_roundtrip->bootloaders.sc.has_value())
                << "rebuilt SC remains serialized-identical";
            EXPECT_BYTES_EQ(*source.bootloaders.sc, *bootloader_roundtrip->bootloaders.sc)
                << "rebuilt SC remains serialized-identical";

            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x1000, 0x71);
            payloads.fuses = Bytes(0x60, 0x72);
            payloads.xell = test::valid_xell();
            source.payloads = std::move(payloads);
            const auto donor_bytes = run_build(source);
            ASSERT_OK(donor_bytes) << "serialized payload donor extracts";
            auto payload_extracted = extract_all(*donor_bytes, source.metadata.cpu_key);
            ASSERT_OK(payload_extracted) << "serialized payload donor extracts";
            ASSERT_TRUE(payload_extracted->payloads.has_value())
                << "extraction preserves parsed rebooter bytes";
            const auto& extracted_payloads = *payload_extracted->payloads;
            ASSERT_TRUE(extracted_payloads.rebooter.has_value())
                << "extraction preserves parsed rebooter bytes";
            EXPECT_BYTES_EQ(*source.payloads->rebooter, *extracted_payloads.rebooter)
                << "extraction preserves parsed rebooter bytes";
            ASSERT_TRUE(extracted_payloads.fuses.has_value())
                << "extraction preserves parsed virtual-fuse bytes";
            EXPECT_BYTES_EQ(*source.payloads->fuses, *extracted_payloads.fuses)
                << "extraction preserves parsed virtual-fuse bytes";
            ASSERT_TRUE(extracted_payloads.xell.has_value())
                << "an exact JTAG XeLL makes adjacent payload extraction unambiguous";
            EXPECT_BYTES_EQ(*source.payloads->xell, *extracted_payloads.xell)
                << "an exact JTAG XeLL makes adjacent payload extraction unambiguous";

            payload_extracted->metadata.nand_image.reset();
            const auto rebuilt = run_build(*payload_extracted);
            ASSERT_OK(rebuilt) << "rebuilt rebooter remains serialized-identical";
            const auto roundtrip = extract_all(*rebuilt, payload_extracted->metadata.cpu_key);
            ASSERT_OK(roundtrip) << "rebuilt rebooter remains serialized-identical";
            ASSERT_TRUE(roundtrip->payloads.has_value())
                << "rebuilt rebooter remains serialized-identical";
            ASSERT_TRUE(roundtrip->payloads->rebooter.has_value())
                << "rebuilt rebooter remains serialized-identical";
            EXPECT_BYTES_EQ(*source.payloads->rebooter, *roundtrip->payloads->rebooter)
                << "rebuilt rebooter remains serialized-identical";
            ASSERT_TRUE(roundtrip->payloads->fuses.has_value())
                << "rebuilt virtual fuses remain serialized-identical";
            EXPECT_BYTES_EQ(*source.payloads->fuses, *roundtrip->payloads->fuses)
                << "rebuilt virtual fuses remain serialized-identical";
        }

        TEST(BootChainMetadata, OverridesReachFinalPatchedCbBAndCf0) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch2;
            ASSERT_OK_AND_ASSIGN(auto cb_a, BootloaderCb::parse(input.bootloaders.cb_or_a));
            ASSERT_OK(cb_a.parse_perbox()) << "the CB_A fixture exposes its per-box block";
            cb_a.perbox->lockdown_value = 0x11;
            cb_a.perbox->pairing_data[0] = 0x12;
            cb_a.perbox->pairing_data[1] = 0x13;
            cb_a.perbox->pairing_data[2] = 0x14;
            ASSERT_OK(cb_a.serialize_perbox()) << "the CB_A fixture takes its per-box block";
            input.bootloaders.cb_or_a = cb_a.serialize();

            ASSERT_OK_AND_ASSIGN(auto cb_b, BootloaderCb::parse(input.bootloaders.cb_or_a));
            ASSERT_OK(cb_b.parse_perbox()) << "the CB_B fixture exposes its per-box block";
            cb_b.perbox->lockdown_value = 0x21;
            cb_b.perbox->pairing_data[0] = 0x22;
            cb_b.perbox->pairing_data[1] = 0x23;
            cb_b.perbox->pairing_data[2] = 0x24;
            ASSERT_OK(cb_b.serialize_perbox()) << "the CB_B fixture takes its per-box block";
            input.bootloaders.cb_b = cb_b.serialize();
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf0,
                                 test::decrypted_cf(0x31, {0x32, 0x33, 0x34}));
            input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            input.metadata.cb_ldv = 9;
            input.metadata.cf_ldv = 10;
            input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};
            input.patches = glitch_patches();

            const auto built = run_build(input);
            ASSERT_OK(built) << "metadata override fixture builds";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "metadata override output parses";
            ASSERT_OK(image->parse()) << "metadata override output parses";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key))
                << "metadata override output decrypts";
            ASSERT_OK(image->cb_section.cb_or_A.parse_perbox())
                << "metadata override output CB per-box metadata parses";
            ASSERT_TRUE(image->cb_section.cb_B.has_value())
                << "metadata override output CB per-box metadata parses";
            ASSERT_OK(image->cb_section.cb_B->parse_perbox())
                << "metadata override output CB per-box metadata parses";
            ASSERT_TRUE(image->system_update_0.cf.has_value())
                << "metadata override output contains all replacement bootloaders";
            EXPECT_FALSE(image->system_update_1.cf.has_value())
                << "metadata override output contains all replacement bootloaders";

            const auto& cb_a_perbox = *image->cb_section.cb_or_A.perbox;
            EXPECT_EQ(cb_a_perbox.lockdown_value, 0x11u)
                << "CB_A remains non-authoritative when CB_B is supplied";
            EXPECT_EQ(std::to_array(cb_a_perbox.pairing_data),
                      (std::array<uint8_t, 3>{0x12, 0x13, 0x14}))
                << "CB_A remains non-authoritative when CB_B is supplied";
            const auto& cb_b_perbox = *image->cb_section.cb_B->perbox;
            EXPECT_EQ(cb_b_perbox.lockdown_value, 9u)
                << "patched CB_B receives the winning LDV and all pairing bytes";
            EXPECT_EQ(std::to_array(cb_b_perbox.pairing_data), input.metadata.pairing_data)
                << "patched CB_B receives the winning LDV and all pairing bytes";
            ASSERT_TRUE(image->system_update_0.cf->perbox.has_value())
                << "every supplied CF receives the winning LDV and pairing bytes";
            const auto& cf_perbox = *image->system_update_0.cf->perbox;
            EXPECT_EQ(cf_perbox.lockdown_value, 10u)
                << "every supplied CF receives the winning LDV and pairing bytes";
            EXPECT_EQ(std::to_array(cf_perbox.pairing_data), input.metadata.pairing_data)
                << "every supplied CF receives the winning LDV and pairing bytes";
        }

        TEST(BootChainMetadata, OverrideRequiresWritableCbPerbox) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.bootloaders.cb_or_a = Bytes(sizeof(nand::generic_header), 0);
            EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidBootloader)
                << "unwritable selected CB perbox is a structured bootloader error";
        }

        TEST(BootChainMetadata, PresentUnwritableCbBRemainsMetadataAuthoritative) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(auto cb_a, BootloaderCb::parse(input.bootloaders.cb_or_a));
            ASSERT_GT(cb_a.data.size(), 0x260u) << "the CB_A fixture reaches 0x260";
            cb_a.data[0x260] = 0x01;
            cb_a.decrypted = false;
            input.bootloaders.cb_or_a = cb_a.serialize();

            BootloaderCb cb_b{};
            cb_b.header.header.magic = NANDBootloaderMagic::CB;
            cb_b.header.header.version = 1;
            cb_b.header.header.size = sizeof(nand::generic_header);
            input.bootloaders.cb_b = cb_b.serialize();

            EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidBootloader)
                << "a present header-only CB_B is authoritative and fails metadata structurally";
        }

        TEST(BootChainMetadata, CfRoundTripPreservesExtendedHeaderFields) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf0,
                                 test::decrypted_cf(0x31, {0x32, 0x33, 0x34}, 0x1234, 0x5678,
                                                    0x9ABC, 0xDEF0, 0x10203040, 0x50607080));
            input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            input.metadata.cf_ldv = 10;
            input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

            const auto built = run_build(input);
            ASSERT_OK(built) << "extended CF metadata fixture builds";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "extended CF metadata output parses and decrypts";
            ASSERT_OK(image->parse()) << "extended CF metadata output parses and decrypts";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key))
                << "extended CF metadata output parses and decrypts";
            ASSERT_TRUE(image->system_update_0.cf.has_value())
                << "extended CF metadata output parses and decrypts";
            const auto& header = image->system_update_0.cf->header;
            EXPECT_EQ(header.source_version.get(), 0x1234u)
                << "modified CF preserves source version through encryption";
            EXPECT_EQ(header.source_qfe.get(), 0x5678u)
                << "modified CF preserves source QFE through encryption";
            EXPECT_EQ(header.target_version.get(), 0x9ABCu)
                << "modified CF preserves target version through encryption";
            EXPECT_EQ(header.target_qfe.get(), 0xDEF0u)
                << "modified CF preserves target QFE through encryption";
            EXPECT_EQ(header.reserved.get(), 0x10203040u)
                << "modified CF preserves reserved value through encryption";
            EXPECT_EQ(header.cg_size.get(), 0x50607080u)
                << "modified CF preserves CG size through encryption";
        }

        TEST(BootChainMetadata, PairingOnlyUpdatesEveryCfWithoutChangingLdv) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf0,
                                 test::decrypted_cf(0x31, {0x32, 0x33, 0x34}));
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf1,
                                 test::decrypted_cf(0x41, {0x42, 0x43, 0x44}));
            input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            input.bootloaders.cg1 = test::valid_system_update(0x61).second;
            input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

            const auto built = run_build(input);
            ASSERT_OK(built) << "pairing-only CF metadata fixture builds";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "pairing-only CF metadata output parses and decrypts";
            ASSERT_OK(image->parse()) << "pairing-only CF metadata output parses and decrypts";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key))
                << "pairing-only CF metadata output parses and decrypts";
            ASSERT_TRUE(image->system_update_0.cf.has_value())
                << "pairing-only CF metadata output parses and decrypts";
            ASSERT_TRUE(image->system_update_1.cf.has_value())
                << "pairing-only CF metadata output parses and decrypts";
            ASSERT_TRUE(image->system_update_0.cf->perbox.has_value())
                << "pairing-only CF metadata output exposes both per-boxes";
            ASSERT_TRUE(image->system_update_1.cf->perbox.has_value())
                << "pairing-only CF metadata output exposes both per-boxes";

            const auto& cf0 = *image->system_update_0.cf->perbox;
            const auto& cf1 = *image->system_update_1.cf->perbox;
            EXPECT_EQ(cf0.lockdown_value, 0x31u)
                << "pairing-only metadata leaves CF lockdown values unchanged";
            EXPECT_EQ(cf1.lockdown_value, 0x41u)
                << "pairing-only metadata leaves CF lockdown values unchanged";
            EXPECT_EQ(std::to_array(cf0.pairing_data), input.metadata.pairing_data)
                << "pairing-only metadata writes all three bytes to every CF";
            EXPECT_EQ(std::to_array(cf1.pairing_data), input.metadata.pairing_data)
                << "pairing-only metadata writes all three bytes to every CF";
        }

        // A JTAG image's first update pair carries nothing of the console: its CF keeps the
        // per-box block it was supplied with (slot 0, no pairing, no LDV, no binding). The second
        // pair states slot 1, the console's pairing and LDV, and the CPU-key binding at 0x220.
        TEST(BootChainMetadata, JtagFirstUpdatePairStaysUnbound) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            test::mark_jtag_smc(*input.metadata.smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", test::jtag_patchset(Bytes{0xA1})};
            input.patches = std::move(patches);
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf0, test::decrypted_cf(0, {0, 0, 0}));
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf1,
                                 test::decrypted_cf(0x41, {0x42, 0x43, 0x44}));
            input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            input.bootloaders.cg1 = test::valid_system_update(0x61).second;
            input.metadata.cf_ldv = 9;
            input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

            const auto built = run_build(input);
            ASSERT_OK(built) << "two-pair JTAG fixture builds";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value())
                << "two-pair JTAG output parses and decrypts both CF per-boxes";
            ASSERT_OK(image->parse())
                << "two-pair JTAG output parses and decrypts both CF per-boxes";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key))
                << "two-pair JTAG output parses and decrypts both CF per-boxes";
            ASSERT_TRUE(image->system_update_0.cf && image->system_update_1.cf &&
                        image->system_update_0.cf->perbox && image->system_update_1.cf->perbox)
                << "two-pair JTAG output parses and decrypts both CF per-boxes";

            const auto& first = *image->system_update_0.cf->perbox;
            const auto& second = *image->system_update_1.cf->perbox;
            const std::array<uint8_t, 3> no_pairing{};
            const std::array<uint8_t, 16> no_binding{};
            EXPECT_EQ(first.update_slot, 0u)
                << "first JTAG CF states slot 0, no pairing and no LDV";
            EXPECT_EQ(first.lockdown_value, 0u)
                << "first JTAG CF states slot 0, no pairing and no LDV";
            EXPECT_EQ(std::to_array(first.pairing_data), no_pairing)
                << "first JTAG CF states slot 0, no pairing and no LDV";
            EXPECT_BYTES_EQ(no_binding, first.per_box_digest)
                << "first JTAG CF carries no CPU-key binding";
            EXPECT_EQ(second.update_slot, 1u)
                << "second JTAG CF states slot 1, the console pairing and its LDV";
            EXPECT_EQ(second.lockdown_value, 9u)
                << "second JTAG CF states slot 1, the console pairing and its LDV";
            EXPECT_EQ(std::to_array(second.pairing_data), input.metadata.pairing_data)
                << "second JTAG CF states slot 1, the console pairing and its LDV";

            BootloaderCf bound = *image->system_update_1.cf;
            ASSERT_OK(bound.calc_mac(nand::key_1bl, input.metadata.cpu_key.data()))
                << "second JTAG CF is bound to the CPU key";
            ASSERT_TRUE(bound.perbox.has_value()) << "second JTAG CF is bound to the CPU key";
            EXPECT_BYTES_EQ(bound.perbox->per_box_digest, second.per_box_digest)
                << "second JTAG CF is bound to the CPU key";
        }

        TEST(BootChainMetadata, PairingOnlyRejectsUnwritableCfPerbox) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            BootloaderCf cf{};
            cf.header.header.magic = NANDBootloaderMagic::CF;
            cf.header.header.version = 1;
            cf.data.assign(0x1EF, 0x5A);
            cf.header.header.size = static_cast<uint32_t>(sizeof(nand::cf_header) + cf.data.size());
            input.bootloaders.cf0 = cf.serialize();

            EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidBootloader)
                << "pairing-only metadata reports an unwritable CF perbox structurally";
        }

        // Under the all-zero CPU key a chain with a CB_B is bound to no console (xeBuild 1.21
        // "zeropairing CB_B"): the CB_B per-box block is zero, the CFs state no pairing and LDV 0,
        // and the secured files state LDV 0, whatever the console's metadata says.
        TEST(ZeroCpuKey, ZeroPairsACbBChain) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch2;
            input.metadata.cpu_key.assign(16, 0);
            input.metadata.keyvault = test::canonical_keyvault(input.metadata.cpu_key,
                                                               Bytes(nand::Keyvault::kSize, 0x22));
            input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            ASSERT_OK_AND_ASSIGN(input.bootloaders.cf0,
                                 test::decrypted_cf(0x31, {0x32, 0x33, 0x34}));
            input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            input.metadata.cb_ldv = 9;
            input.metadata.cf_ldv = 10;
            input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};
            input.metadata.cf_pairing_data = std::array<uint8_t, 3>{0xA4, 0xB5, 0xC6};
            input.flashfs_sec =
                std::vector<std::pair<std::string, Bytes>>{{"secdata.bin", Bytes{}}};
            input.patches = glitch_patches();

            const auto built = run_build(input);
            ASSERT_OK(built) << "a zero-key CB_B chain builds and opens under the zero key";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value())
                << "a zero-key CB_B chain builds and opens under the zero key";
            ASSERT_OK(image->parse())
                << "a zero-key CB_B chain builds and opens under the zero key";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key))
                << "a zero-key CB_B chain builds and opens under the zero key";
            ASSERT_TRUE(image->cb_section.cb_B.has_value())
                << "a zero-key CB_B chain builds and opens under the zero key";
            ASSERT_OK(image->cb_section.cb_B->parse_perbox())
                << "a zero-key CB_B chain builds and opens under the zero key";
            ASSERT_TRUE(image->cb_section.cb_B->perbox.has_value())
                << "a zero-key CB_B chain builds and opens under the zero key";

            const auto& perbox = *image->cb_section.cb_B->perbox;
            const std::span<const uint8_t> perbox_bytes(reinterpret_cast<const uint8_t*>(&perbox),
                                                        sizeof(nand::cb_perbox));
            EXPECT_BYTES_EQ(Bytes(sizeof(nand::cb_perbox), 0), perbox_bytes)
                << "the zero-key CB_B states no pairing, no LDV and no digest";
            ASSERT_TRUE(image->system_update_0.cf.has_value())
                << "the zero-key CF states no pairing and LDV 0";
            ASSERT_TRUE(image->system_update_0.cf->perbox.has_value())
                << "the zero-key CF states no pairing and LDV 0";
            EXPECT_EQ(image->system_update_0.cf->perbox->lockdown_value, 0u)
                << "the zero-key CF states no pairing and LDV 0";
            EXPECT_EQ(std::to_array(image->system_update_0.cf->perbox->pairing_data),
                      (std::array<uint8_t, 3>{}))
                << "the zero-key CF states no pairing and LDV 0";

            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            ASSERT_OK(extracted) << "the keyvault is sealed under the zero key";
            ASSERT_TRUE(extracted->metadata.keyvault.has_value())
                << "the keyvault is sealed under the zero key";
            EXPECT_BYTES_EQ(*input.metadata.keyvault, *extracted->metadata.keyvault)
                << "the keyvault is sealed under the zero key";

            const Bytes* secdata = nullptr;
            if (extracted->flashfs_sec) {
                for (const auto& [name, data] : *extracted->flashfs_sec) {
                    if (name == "secdata.bin") {
                        secdata = &data;
                    }
                }
            }
            ASSERT_NE(secdata, nullptr) << "the made-up secdata.bin states LDV 0";
            ASSERT_EQ(secdata->size(), nand::kSecdataSize)
                << "the made-up secdata.bin states LDV 0";
            EXPECT_TRUE(nand::secdata_opened(*secdata, input.metadata.cpu_key))
                << "the made-up secdata.bin states LDV 0";
            EXPECT_EQ((*secdata)[0x19], 0u) << "the made-up secdata.bin states LDV 0";
        }

        // A console's keyvault does not open under the all-zero CPU key: its donor still extracts
        // and builds, with no keyvault of its own, and the keyvault the build is given is sealed
        // under the zero key.
        TEST(ZeroCpuKey, LeavesTheDonorKeyvaultSealed) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(const auto donor, test::make_donor(source, {}));
            const Bytes zero_key(16, 0);
            const auto extracted = extract_all(donor, zero_key);
            ASSERT_OK(extracted) << "a donor extracts under the zero key without a keyvault";
            EXPECT_FALSE(extracted->metadata.keyvault.has_value())
                << "a donor extracts under the zero key without a keyvault";
            EXPECT_FALSE(extract_metadata(donor, zero_key).has_value())
                << "metadata extraction needs a keyvault that opens";

            auto input = source;
            input.metadata.cpu_key = zero_key;
            input.metadata.nand_image = donor;
            const auto built = run_build(input);
            ASSERT_OK(built) << "a zero-key build over a console's donor succeeds";
            auto image = parse_image(*built);
            ASSERT_TRUE(image.has_value()) << "the supplied keyvault is sealed under the zero key";
            ASSERT_OK(image->decrypt_all(zero_key))
                << "the supplied keyvault is sealed under the zero key";
            ASSERT_TRUE(image->keyvault.has_value())
                << "the supplied keyvault is sealed under the zero key";
            ASSERT_FALSE(image->keyvault->encrypted)
                << "the supplied keyvault is sealed under the zero key";
            const auto sealed_body = image->keyvault->serialize();
            ASSERT_EQ(sealed_body.size(), nand::Keyvault::kSize)
                << "the supplied keyvault is sealed under the zero key";
            ASSERT_GE(input.metadata.keyvault->size(), nand::Keyvault::kSize)
                << "the supplied keyvault is sealed under the zero key";
            EXPECT_BYTES_EQ(std::span<const uint8_t>(*input.metadata.keyvault)
                                .subspan(0x10, sealed_body.size() - 0x10),
                            std::span<const uint8_t>(sealed_body).subspan(0x10))
                << "the supplied keyvault is sealed under the zero key";
        }

    } // namespace
} // namespace gxbuild3::orchestration
