// run_build's boot-chain records (src/BuildRunner.cpp, src/nand/bootloaders/, src/nand/
// FlashImageLayout.cpp): the Input's chain replaces a donor's by presence (an omitted stage clears
// the donor's, a CF without CG does not rediscover the donor's CG, a header-only donor CE does not
// reappear), a rebuilt donor names the CF slot it actually lays for each build type, every stage
// keeps its generic and stage-specific numeric headers host-order after parse and big-endian on
// the wire (through CF and CG encryption too), the CB console allowance serializes and encrypts
// without touching the separately stored per-box bytes, and header-only required records and
// orphan CGs are refused before anything is serialized. The build-type loop runs in one case
// under SCOPED_TRACE. One ctest entry per case.

#include "BuildRunner.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/Common.hpp"
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
#include <span>
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using nand::BootloaderCb;
        using nand::BootloaderCd;
        using nand::BootloaderCe;
        using nand::BootloaderCf;
        using nand::BootloaderCg;
        using nand::BootloaderSc;
        using nand::FlashImage;
        using nand::NANDBootloaderMagic;
        using test::Bytes;

        const Bytes kElfMagic{0x7F, 'E', 'L', 'F'};

        // Offset of the generic header's pairing word, which every stage carries.
        constexpr size_t kPairingOffset = offsetof(nand::generic_header, pairing);

        uint64_t be64(std::span<const uint8_t> bytes, size_t offset) {
            return (uint64_t{test::be32(bytes, offset)} << 32) | test::be32(bytes, offset + 4);
        }

        TEST(BootChainRecords, DonorBootloaderChainIsReplacedByInputPresence) {
            auto donor_input = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(auto donor_cb,
                                 BootloaderCb::parse(donor_input.bootloaders.cb_or_a));
            ASSERT_GT(donor_cb.data.size(), 0x260u) << "the donor CB fixture reaches 0x260";
            donor_cb.data[0x260] = 0x01;
            donor_cb.decrypted = false;
            donor_input.bootloaders.cb_or_a = donor_cb.serialize();
            donor_input.bootloaders.cb_x = donor_cb.serialize();
            donor_input.bootloaders.cb_b = donor_cb.serialize();

            BootloaderCe ce{};
            ce.header.header.magic = NANDBootloaderMagic::CE;
            ce.header.header.version = 1;
            ce.header.header.size = static_cast<uint32_t>(sizeof(nand::ce_header) + 0x20);
            ce.data.assign(0x20, 0xCE);
            ce.decrypted = true;
            donor_input.bootloaders.ce = ce.serialize();
            ASSERT_OK_AND_ASSIGN(donor_input.bootloaders.cf0,
                                 test::decrypted_cf(0x31, {0x32, 0x33, 0x34}));
            donor_input.bootloaders.cg0 = test::valid_system_update(0x51).second;
            ASSERT_OK_AND_ASSIGN(donor_input.bootloaders.cf1,
                                 test::decrypted_cf(0x41, {0x42, 0x43, 0x44}));
            donor_input.bootloaders.cg1 = test::valid_system_update(0x61).second;
            *donor_input.mobiles.slot(0x31) = Bytes{0xD1, 0x31};

            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "all-optional donor fixture builds";

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            input.metadata.cb_ldv = 7;
            input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};
            input.bootloaders.cb_x.reset();
            input.bootloaders.cb_b.reset();
            input.bootloaders.sc.reset();
            input.bootloaders.ce.reset();
            input.bootloaders.cf0.reset();
            input.bootloaders.cg0.reset();
            input.bootloaders.cf1.reset();
            input.bootloaders.cg1.reset();

            const auto built = run_build(input);
            ASSERT_OK(built)
                << "replacement-chain output parses, decrypts, and exposes CB/A metadata";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value())
                << "replacement-chain output parses, decrypts, and exposes CB/A metadata";
            ASSERT_OK(image->parse())
                << "replacement-chain output parses, decrypts, and exposes CB/A metadata";
            ASSERT_OK(image->decrypt_all(input.metadata.cpu_key))
                << "replacement-chain output parses, decrypts, and exposes CB/A metadata";
            ASSERT_OK(image->cb_section.cb_or_A.parse_perbox())
                << "replacement-chain output parses, decrypts, and exposes CB/A metadata";

            constexpr const char* kCleared = "omitted Input bootloaders clear every donor optional "
                                             "stage";
            EXPECT_FALSE(image->cb_section.cb_x.has_value()) << kCleared << " (CB_X)";
            EXPECT_FALSE(image->cb_section.cb_B.has_value()) << kCleared << " (CB_B)";
            EXPECT_FALSE(image->cb_section.sc.has_value()) << kCleared << " (SC)";
            EXPECT_FALSE(image->kernel_section.ce.has_value()) << kCleared << " (CE)";
            EXPECT_FALSE(image->system_update_0.cf.has_value()) << kCleared << " (CF0)";
            EXPECT_FALSE(image->system_update_0.cg.has_value()) << kCleared << " (CG0)";
            EXPECT_FALSE(image->system_update_1.cf.has_value()) << kCleared << " (CF1)";
            EXPECT_FALSE(image->system_update_1.cg.has_value()) << kCleared << " (CG1)";
            ASSERT_TRUE(image->cb_section.cb_or_A.perbox.has_value())
                << "without donor CB_B, replacement CB/A is metadata-authoritative";
            EXPECT_EQ(image->cb_section.cb_or_A.perbox->lockdown_value, 7u)
                << "without donor CB_B, replacement CB/A is metadata-authoritative";

            ASSERT_TRUE(image->mobile_data.has_value())
                << "non-bootloader donor mobile data survives replacement";
            const auto* donor_mobile = image->mobile_data->get_slot(0x31);
            ASSERT_NE(donor_mobile, nullptr)
                << "non-bootloader donor mobile data survives replacement";
            ASSERT_TRUE(donor_mobile->has_value())
                << "non-bootloader donor mobile data survives replacement";
            EXPECT_BYTES_EQ(Bytes({0xD1, 0x31}), **donor_mobile)
                << "non-bootloader donor mobile data survives replacement";
        }

        TEST(BootChainRecords, DonorCfSpanIsClearedWhenReplacementOmitsCg) {
            auto donor_input = test::fresh_input(ImageType::SmallBlock);
            const auto [donor_cf, donor_cg] = test::valid_system_update(0x51);
            donor_input.bootloaders.cf0 = donor_cf;
            donor_input.bootloaders.cg0 = donor_cg;
            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "donor CF/CG fixture builds";

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            input.bootloaders.cf0 = donor_cf; // Same size as the donor CF.
            input.bootloaders.cg0.reset();
            const auto built = run_build(input);
            ASSERT_OK(built) << "replacement CF without CG output parses";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "replacement CF without CG output parses";
            ASSERT_OK(image->parse()) << "replacement CF without CG output parses";
            ASSERT_TRUE(image->system_update_0.cf.has_value())
                << "replacement CF without CG output parses";
            EXPECT_FALSE(image->system_update_0.cg.has_value())
                << "replacement CF does not rediscover the donor CG tail";
        }

        TEST(BootChainRecords, HeaderOnlyDonorCeIsClearedWhenInputOmitsIt) {
            auto donor_input = test::fresh_input(ImageType::SmallBlock);
            BootloaderCe ce{};
            ce.header.header.magic = NANDBootloaderMagic::CE;
            ce.header.header.version = 1;
            ce.header.header.size = sizeof(nand::ce_header);
            ce.decrypted = true;
            donor_input.bootloaders.ce = ce.serialize();
            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "header-only CE donor fixture builds";

            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            input.bootloaders.ce.reset();
            const auto built = run_build(input);
            ASSERT_OK(built) << "header-only CE replacement output parses";
            auto image = FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "header-only CE replacement output parses";
            ASSERT_OK(image->parse()) << "header-only CE replacement output parses";
            EXPECT_FALSE(image->kernel_section.ce.has_value())
                << "omitted header-only donor CE does not reappear";
        }

        TEST(BootChainRecords, RebuiltDonorUsesActualCfSlotBaseForEachBuildType) {
            auto donor_input = test::fresh_input(ImageType::SmallBlock);
            donor_input.build_type = BuildType::Glitch;
            InputPatches donor_patches{};
            donor_patches.automatic =
                InputPatchFile{"automatic", test::glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
            donor_input.patches = donor_patches;
            InputPayloads donor_payloads{};
            donor_payloads.xell = test::valid_xell();
            donor_input.payloads = donor_payloads;
            const auto [donor_cf, donor_cg] = test::valid_system_update(0x51);
            donor_input.bootloaders.cf0 = donor_cf;
            donor_input.bootloaders.cg0 = donor_cg;
            const auto donor = run_build(donor_input);
            ASSERT_OK(donor) << "shifted donor fixture builds";

            struct Case {
                const char* name;
                BuildType type;
                size_t expected_slot;
                size_t expected_xell;
            };
            // A devkit image is 64 MB, so it is laid fresh beside this 16 MB donor (see
            // test_devkit_image_takes_its_own_shape_beside_a_16_mb_donor).
            const std::array cases{Case{"Retail", BuildType::Retail, 0xB0000, 0x70000},
                                   Case{"Jtag", BuildType::Jtag, 0x70000, 0x95060}};
            for (const auto& test_case : cases) {
                SCOPED_TRACE(test_case.name);
                auto input = test::fresh_input(ImageType::SmallBlock);
                input.metadata.nand_image = *donor;
                input.build_type = test_case.type;
                if (input.build_type == BuildType::Jtag) {
                    test::mark_jtag_smc(*input.metadata.smc);
                }
                const auto [cf, cg] = test::valid_system_update(
                    static_cast<uint8_t>(0x60 + test_case.expected_slot / 0x10000));
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                if (test_case.type == BuildType::Jtag) {
                    InputPatches patches{};
                    patches.automatic =
                        InputPatchFile{"automatic", test::jtag_patchset(Bytes{0xA1})};
                    input.patches = std::move(patches);
                }

                const auto built = run_build(input);
                ASSERT_OK(built) << "rebuilt donor parses requested CF and CG";
                auto image = FlashImage::read(*built);
                ASSERT_TRUE(image.has_value()) << "rebuilt donor parses requested CF and CG";
                ASSERT_OK(image->parse()) << "rebuilt donor parses requested CF and CG";
                ASSERT_TRUE(image->system_update_0.cf.has_value())
                    << "rebuilt donor parses requested CF and CG";
                ASSERT_TRUE(image->system_update_0.cg.has_value())
                    << "rebuilt donor parses requested CF and CG";
                EXPECT_EQ(image->header.cf_offset.get(), test_case.expected_slot)
                    << "serialized header names the actual replacement CF slot";

                const auto cg_bytes = read_logical(
                    *built, test_case.expected_slot + ((cf.size() + 0x0F) & ~size_t{0x0F}),
                    cg.size());
                ASSERT_TRUE(cg_bytes.has_value())
                    << "replacement CG remains intact beside fixed payloads";
                ASSERT_OK_AND_ASSIGN(const auto supplied_cg, test::opened_cg(cf, cg));
                ASSERT_OK_AND_ASSIGN(
                    const auto placed_cg,
                    test::opened_cg(image->system_update_0.cf->serialize(), *cg_bytes));
                ASSERT_TRUE(supplied_cg.has_value() && placed_cg.has_value())
                    << "replacement CG remains intact beside fixed payloads";
                EXPECT_BYTES_EQ(*supplied_cg, *placed_cg)
                    << "replacement CG remains intact beside fixed payloads";

                const auto xell_magic = read_logical(*built, test_case.expected_xell, 4);
                ASSERT_TRUE(xell_magic.has_value())
                    << "retained XeLL remains intact without CF collision";
                EXPECT_BYTES_EQ(kElfMagic, *xell_magic)
                    << "retained XeLL remains intact without CF collision";
            }
        }

        TEST(BootChainRecords, GenericHeaderPairingRoundTripsForEveryBootloader) {
            constexpr uint16_t pairing = 0x1234;

            BootloaderCb cb{};
            cb.header.header.magic = NANDBootloaderMagic::CB;
            cb.header.header.pairing = pairing;
            cb.header.header.size = sizeof(nand::generic_header);
            const auto cb_wire = cb.serialize();
            EXPECT_EQ(test::be16(cb_wire, kPairingOffset), pairing)
                << "CB generic pairing is big-endian on wire and host-order after parse";
            ASSERT_OK_AND_ASSIGN(const auto parsed_cb, BootloaderCb::parse(cb_wire));
            EXPECT_EQ(parsed_cb.header.header.pairing.get(), pairing)
                << "CB generic pairing is big-endian on wire and host-order after parse";

            BootloaderSc sc{};
            sc.header.header.magic = NANDBootloaderMagic::SC;
            sc.header.header.pairing = pairing;
            sc.header.header.size = sizeof(nand::sc_header);
            const auto sc_wire = sc.serialize();
            EXPECT_EQ(test::be16(sc_wire, kPairingOffset), pairing)
                << "SC generic pairing is big-endian on wire and host-order after parse";
            ASSERT_OK_AND_ASSIGN(const auto parsed_sc, BootloaderSc::parse(sc_wire));
            EXPECT_EQ(parsed_sc.header.header.pairing.get(), pairing)
                << "SC generic pairing is big-endian on wire and host-order after parse";

            BootloaderCd cd{};
            cd.header.header.magic = NANDBootloaderMagic::CD;
            cd.header.header.pairing = pairing;
            cd.header.header.size = sizeof(nand::cd_header);
            const auto cd_wire = cd.serialize();
            EXPECT_EQ(test::be16(cd_wire, kPairingOffset), pairing)
                << "CD generic pairing is big-endian on wire and host-order after parse";
            ASSERT_OK_AND_ASSIGN(const auto parsed_cd, BootloaderCd::parse(cd_wire));
            EXPECT_EQ(parsed_cd.header.header.pairing.get(), pairing)
                << "CD generic pairing is big-endian on wire and host-order after parse";

            BootloaderCe ce{};
            ce.header.header.magic = NANDBootloaderMagic::CE;
            ce.header.header.pairing = pairing;
            ce.header.header.size = sizeof(nand::ce_header);
            const auto ce_wire = ce.serialize();
            EXPECT_EQ(test::be16(ce_wire, kPairingOffset), pairing)
                << "CE generic pairing is big-endian on wire and host-order after parse";
            ASSERT_OK_AND_ASSIGN(const auto parsed_ce, BootloaderCe::parse(ce_wire));
            EXPECT_EQ(parsed_ce.header.header.pairing.get(), pairing)
                << "CE generic pairing is big-endian on wire and host-order after parse";

            BootloaderCf cf{};
            cf.header.header.magic = NANDBootloaderMagic::CF;
            cf.header.header.pairing = pairing;
            cf.data.assign(0x200, 0);
            cf.header.header.size = static_cast<uint32_t>(sizeof(nand::cf_header) + cf.data.size());
            cf.decrypted = true;
            const auto cf_wire = cf.serialize();
            EXPECT_EQ(test::be16(cf_wire, kPairingOffset), pairing)
                << "CF generic pairing is big-endian on wire and host-order after parse";
            ASSERT_OK_AND_ASSIGN(const auto parsed_cf, BootloaderCf::parse(cf_wire));
            EXPECT_EQ(parsed_cf.header.header.pairing.get(), pairing)
                << "CF generic pairing is big-endian on wire and host-order after parse";

            BootloaderCg cg{};
            cg.header.header.magic = NANDBootloaderMagic::CG;
            cg.header.header.pairing = pairing;
            cg.header.header.size = sizeof(nand::cg_header);
            const auto cg_wire = cg.serialize();
            EXPECT_EQ(test::be16(cg_wire, kPairingOffset), pairing)
                << "CG generic pairing is big-endian on wire and host-order after parse";
            ASSERT_OK_AND_ASSIGN(const auto parsed_cg, BootloaderCg::parse(cg_wire));
            EXPECT_EQ(parsed_cg.header.header.pairing.get(), pairing)
                << "CG generic pairing is big-endian on wire and host-order after parse";

            ASSERT_OK(cf.encrypt(nand::key_1bl))
                << "CF encrypt/decrypt preserves the generic pairing endian invariant";
            const auto encrypted_cf_wire = cf.serialize();
            ASSERT_OK_AND_ASSIGN(auto opened_cf, BootloaderCf::parse(encrypted_cf_wire));
            ASSERT_OK(opened_cf.decrypt(nand::key_1bl))
                << "CF encrypt/decrypt preserves the generic pairing endian invariant";
            EXPECT_EQ(test::be16(encrypted_cf_wire, kPairingOffset), pairing)
                << "CF encrypt/decrypt preserves the generic pairing endian invariant";
            EXPECT_EQ(opened_cf.header.header.pairing.get(), pairing)
                << "CF encrypt/decrypt preserves the generic pairing endian invariant";
        }

        TEST(BootChainRecords, StageSpecificNumericHeadersAreHostOrderAndWireBigEndian) {
            BootloaderCb cb{};
            cb.header.header.magic = NANDBootloaderMagic::CB;
            cb.header.header.size = sizeof(nand::cb_header);
            cb.data.assign(sizeof(nand::cb_header) - sizeof(nand::generic_header), 0);
            constexpr size_t console_allow_offset =
                offsetof(nand::cb_header, console_seq_allow) +
                offsetof(nand::ConsoleTypeSeqAllow, console_sequence_allow) -
                sizeof(nand::generic_header);
            cb.data[console_allow_offset] = 0x12;
            cb.data[console_allow_offset + 1] = 0x34;
            ASSERT_OK_AND_ASSIGN(const auto parsed_cb, BootloaderCb::parse(cb.serialize()));
            EXPECT_EQ(parsed_cb.header.console_seq_allow.console_sequence_allow.get(), 0x1234u)
                << "CB console sequence allowance is normalized after parse";

            BootloaderCd cd{};
            cd.header.header.magic = NANDBootloaderMagic::CD;
            cd.header.header.size = sizeof(nand::cd_header);
            cd.header.padding = 0x1234;
            const auto cd_wire = cd.serialize();
            EXPECT_EQ(test::be16(cd_wire, offsetof(nand::cd_header, padding)), 0x1234u)
                << "CD padding is host-order after parse and big-endian on wire";
            ASSERT_OK_AND_ASSIGN(const auto parsed_cd, BootloaderCd::parse(cd_wire));
            EXPECT_EQ(parsed_cd.header.padding.get(), 0x1234u)
                << "CD padding is host-order after parse and big-endian on wire";

            BootloaderCe ce{};
            ce.header.header.magic = NANDBootloaderMagic::CE;
            ce.header.header.size = sizeof(nand::ce_header);
            ce.header.address = 0x0102030405060708ULL;
            ce.header.size = 0x11223344;
            ce.header.padding = 0x55667788;
            const auto ce_wire = ce.serialize();
            ASSERT_OK_AND_ASSIGN(const auto parsed_ce, BootloaderCe::parse(ce_wire));
            constexpr const char* kCeInvariant =
                "CE address, size, and padding retain host/wire endian invariants";
            EXPECT_EQ(be64(ce_wire, offsetof(nand::ce_header, address)), 0x0102030405060708ULL)
                << kCeInvariant;
            EXPECT_EQ(test::be32(ce_wire, offsetof(nand::ce_header, size)), 0x11223344u)
                << kCeInvariant;
            EXPECT_EQ(test::be32(ce_wire, offsetof(nand::ce_header, padding)), 0x55667788u)
                << kCeInvariant;
            EXPECT_EQ(parsed_ce.header.address.get(), 0x0102030405060708ULL) << kCeInvariant;
            EXPECT_EQ(parsed_ce.header.size.get(), 0x11223344u) << kCeInvariant;
            EXPECT_EQ(parsed_ce.header.padding.get(), 0x55667788u) << kCeInvariant;

            BootloaderCg cg{};
            cg.header.header.magic = NANDBootloaderMagic::CG;
            cg.header.header.size = sizeof(nand::cg_header) + 0x40;
            cg.header.source_size = 0x10203040;
            cg.header.target_size = 0x50607080;
            cg.data.assign(0x40, 0x33);
            const auto cg_wire = cg.serialize();
            ASSERT_OK_AND_ASSIGN(auto parsed_cg, BootloaderCg::parse(cg_wire));
            constexpr const char* kCgSizes =
                "CG source and target sizes are host-order after parse and big-endian on wire";
            EXPECT_EQ(test::be32(cg_wire, offsetof(nand::cg_header, source_size)), 0x10203040u)
                << kCgSizes;
            EXPECT_EQ(test::be32(cg_wire, offsetof(nand::cg_header, target_size)), 0x50607080u)
                << kCgSizes;
            EXPECT_EQ(parsed_cg.header.source_size.get(), 0x10203040u) << kCgSizes;
            EXPECT_EQ(parsed_cg.header.target_size.get(), 0x50607080u) << kCgSizes;

            parsed_cg.decrypted = true;
            ASSERT_OK(parsed_cg.encrypt(nand::key_1bl))
                << "CG encrypt/decrypt preserves normalized source and target sizes";
            ASSERT_OK_AND_ASSIGN(auto crypt_roundtrip_cg,
                                 BootloaderCg::parse(parsed_cg.serialize()));
            ASSERT_OK(crypt_roundtrip_cg.decrypt(nand::key_1bl))
                << "CG encrypt/decrypt preserves normalized source and target sizes";
            EXPECT_EQ(crypt_roundtrip_cg.header.source_size.get(), 0x10203040u)
                << "CG encrypt/decrypt preserves normalized source and target sizes";
            EXPECT_EQ(crypt_roundtrip_cg.header.target_size.get(), 0x50607080u)
                << "CG encrypt/decrypt preserves normalized source and target sizes";
        }

        // A plaintext CB of 0x380 payload bytes whose console allowance is stated on the wire as
        // wire_console_allow and whose per-box bytes are 0x80, 0x81, ..., parsed back.
        Result<BootloaderCb> asymmetric_decrypted_cb(uint16_t wire_console_allow) {
            BootloaderCb cb{};
            cb.header.header.magic = NANDBootloaderMagic::CB;
            cb.header.header.version = 1;
            cb.data.assign(
                std::max<size_t>(0x380, sizeof(nand::cb_header) - sizeof(nand::generic_header)), 0);
            cb.header.header.size =
                static_cast<uint32_t>(sizeof(nand::generic_header) + cb.data.size());
            constexpr size_t console_allow_offset =
                offsetof(nand::cb_header, console_seq_allow) +
                offsetof(nand::ConsoleTypeSeqAllow, console_sequence_allow) -
                sizeof(nand::generic_header);
            cb.data[console_allow_offset] = static_cast<uint8_t>(wire_console_allow >> 8);
            cb.data[console_allow_offset + 1] = static_cast<uint8_t>(wire_console_allow);
            for (size_t index = 0; index < sizeof(nand::cb_perbox); ++index) {
                cb.data[0x10 + index] = static_cast<uint8_t>(0x80 + index);
            }
            cb.decrypted = true;
            return BootloaderCb::parse(cb.serialize());
        }

        TEST(BootChainRecords, CbConsoleAllowHostValueSerializesWithoutOverwritingPerbox) {
            constexpr size_t console_allow_wire_offset =
                offsetof(nand::cb_header, console_seq_allow) +
                offsetof(nand::ConsoleTypeSeqAllow, console_sequence_allow);
            constexpr size_t perbox_wire_offset = sizeof(nand::generic_header) + 0x10;
            ASSERT_OK_AND_ASSIGN(auto cb, asymmetric_decrypted_cb(0x1357));
            ASSERT_GE(cb.data.size(), 0x10 + sizeof(nand::cb_perbox))
                << "the CB fixture holds its per-box bytes";
            const Bytes original_perbox(cb.data.begin() + 0x10,
                                        cb.data.begin() + 0x10 + sizeof(nand::cb_perbox));
            cb.header.console_seq_allow.console_sequence_allow = 0xBEEF;
            const auto wire = cb.serialize();
            EXPECT_EQ(cb.header.console_seq_allow.console_sequence_allow.get(), 0xBEEFu)
                << "decrypted CB exposes the asymmetric console allowance in host order";
            EXPECT_EQ(test::be16(wire, console_allow_wire_offset), 0xBEEFu)
                << "decrypted CB serialization writes the host-order console allowance to wire";
            ASSERT_GE(wire.size(), perbox_wire_offset + sizeof(nand::cb_perbox))
                << "serializing the CB numeric field preserves separately stored per-box bytes";
            EXPECT_BYTES_EQ(original_perbox, std::span<const uint8_t>(wire).subspan(
                                                 perbox_wire_offset, sizeof(nand::cb_perbox)))
                << "serializing the CB numeric field preserves separately stored per-box bytes";
        }

        TEST(BootChainRecords, CbConsoleAllowHostValueEncryptsAndRoundTripsAsymmetrically) {
            ASSERT_OK_AND_ASSIGN(auto cb, asymmetric_decrypted_cb(0x1357));
            ASSERT_GE(cb.data.size(), 0x10 + sizeof(nand::cb_perbox))
                << "the CB fixture holds its per-box bytes";
            const Bytes original_perbox(cb.data.begin() + 0x10,
                                        cb.data.begin() + 0x10 + sizeof(nand::cb_perbox));
            cb.header.console_seq_allow.console_sequence_allow = 0xBEEF;
            ASSERT_OK(cb.encrypt(nand::key_1bl));
            ASSERT_OK_AND_ASSIGN(auto parsed_encrypted, BootloaderCb::parse(cb.serialize()));
            ASSERT_OK(parsed_encrypted.decrypt(nand::key_1bl));
            EXPECT_EQ(parsed_encrypted.header.console_seq_allow.console_sequence_allow.get(),
                      0xBEEFu)
                << "encrypted CB roundtrip retains the host-order asymmetric console allowance";
            ASSERT_GE(parsed_encrypted.data.size(), 0x10 + sizeof(nand::cb_perbox))
                << "CB encryption only synchronizes its numeric console field, not per-box bytes";
            EXPECT_BYTES_EQ(original_perbox, std::span<const uint8_t>(parsed_encrypted.data)
                                                 .subspan(0x10, sizeof(nand::cb_perbox)))
                << "CB encryption only synchronizes its numeric console field, not per-box bytes";
        }

        TEST(BootChainRecords, DirectPayloadLayoutRejectsHeaderOnlyRequiredRecords) {
            FlashImage header_only_cb{};
            header_only_cb.cb_section.cb_or_A.header.header.magic = NANDBootloaderMagic::CB;
            header_only_cb.cb_section.cb_or_A.header.header.size = sizeof(nand::generic_header);

            FlashImage header_only_cd{};
            const auto bootloaders = test::valid_bootloaders();
            ASSERT_OK_AND_ASSIGN(header_only_cd.cb_section.cb_or_A,
                                 BootloaderCb::parse(bootloaders.cb_or_a));
            header_only_cd.kernel_section.cd.header.header.magic = NANDBootloaderMagic::CD;
            header_only_cd.kernel_section.cd.header.header.size = sizeof(nand::cd_header);

            EXPECT_ERROR_HAS(header_only_cb.payload_layout(), ErrorCode::InvalidArgument, "CB/A")
                << "direct layout validation rejects a header-only required CB/A";
            EXPECT_ERROR_HAS(header_only_cd.payload_layout(), ErrorCode::InvalidArgument, "CD")
                << "direct layout validation rejects a header-only required CD";
        }

        TEST(BootChainRecords, RequiredChainRelationshipsRejectBeforeSerialization) {
            auto header_only_cd = test::fresh_input(ImageType::SmallBlock);
            BootloaderCd cd{};
            cd.header.header.magic = NANDBootloaderMagic::CD;
            cd.header.header.version = 1;
            cd.header.header.size = sizeof(nand::cd_header);
            header_only_cd.bootloaders.cd = cd.serialize();
            EXPECT_ERROR(run_build(header_only_cd), BuildErrorCode::InvalidBootloader)
                << "a header-only required CD is rejected before output";

            auto cg0_without_cf0 = test::fresh_input(ImageType::SmallBlock);
            cg0_without_cf0.bootloaders.cg0 = test::valid_system_update(0x51).second;
            EXPECT_ERROR(run_build(cg0_without_cf0), BuildErrorCode::InvalidInput)
                << "CG0 without CF0 is rejected structurally";

            auto cg1_without_cf1 = test::fresh_input(ImageType::SmallBlock);
            cg1_without_cf1.bootloaders.cg1 = test::valid_system_update(0x61).second;
            EXPECT_ERROR(run_build(cg1_without_cf1), BuildErrorCode::InvalidInput)
                << "CG1 without CF1 is rejected structurally";
        }

    } // namespace
} // namespace gxbuild3::orchestration
