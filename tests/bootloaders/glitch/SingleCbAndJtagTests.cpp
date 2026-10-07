// Single-CB chains. Glitch (RGH1) seals one zero-paired CB and retail keeps it paired
// (SingleCbPairing); JTAG seals two chains, the second paired and bound to the sealed SMC
// (JtagChain). Every stage is opened with the oracle in GlitchOracle.hpp.

#include "BuildRunner.hpp"
#include "bootloaders/glitch/GlitchFixture.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <utility>

namespace gxbuild3::bootloaders::glitch {
    namespace {

        struct SingleCbRow {
            const char* name;
            BuildType type;
            const char* label;
        };
        GX_PRINT_ROW_AS_NAME(SingleCbRow)
        constexpr SingleCbRow kSingleCbRows[] = {
            {"Glitch1", BuildType::Glitch, "glitch1"},
            {"Retail", BuildType::Retail, "retail"},
        };

        class SingleCbPairing : public ::testing::TestWithParam<SingleCbRow> {};

        // Glitch (RGH1) seals one zero-paired CB: whatever pairing and LDV the console has, the
        // CB per-box block (+0x20..+0x3F) is zero, CD is keyed HMAC(K_cb, nonce) alone, and
        // every CF states no pairing but keeps its LDV and a valid MAC. A retail single CB with
        // the same metadata stays paired and keys CD with the CPU-key second pass.
        TEST_P(SingleCbPairing, SealsCbCdCeAndCfForTheBuildTypesPairing) {
            const auto& row = GetParam();
            const std::string name = row.label;
            auto input = fixture(row.type);
            input.bootloaders.cb_or_a = cb(6750, 0, 0x11);
            input.bootloaders.cb_b.reset();
            input.metadata.pairing_data = {1, 2, 3};
            input.metadata.cb_ldv = 4;
            input.metadata.cf_ldv = 9;
            input.metadata.cf_pairing_data = std::array<uint8_t, 3>{5, 6, 7};
            // A per-box block left in the CB template; zero-pairing clears all of it.
            std::fill(input.bootloaders.cb_or_a.begin() + 0x20,
                      input.bootloaders.cb_or_a.begin() + 0x40, 0xCC);
            nand::BootloaderCf cf{};
            cf.header.header = stage_header(nand::NANDBootloaderMagic::CF, 17559, 0, 0, 0,
                                            sizeof(nand::cf_header) + 0x340);
            cf.data.assign(0x340, 0);
            cf.decrypted = true;
            input.bootloaders.cf0 = cf.serialize();

            const auto built = run_build(input);
            ASSERT_OK(built) << name << " single-CB image builds";
            auto image = nand::FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << name << " single-CB image parses";
            ASSERT_OK(image->parse()) << name << " single-CB image parses";
            ASSERT_TRUE(image->kernel_section.ce.has_value()) << name << " single-CB image parses";
            ASSERT_TRUE(image->system_update_0.cf.has_value()) << name << " single-CB image parses";

            const bool zero_paired = row.type == BuildType::Glitch;
            auto sealed_cb = image->cb_section.cb_or_A.serialize();
            const Key cb_key =
                hmac(kOneBlKey, Bytes(sealed_cb.begin() + 0x10, sealed_cb.begin() + 0x20));
            ExCryptRc4(cb_key.data(), cb_key.size(), sealed_cb.data() + 0x20,
                       sealed_cb.size() - 0x20);
            const Bytes perbox(sealed_cb.begin() + 0x20, sealed_cb.begin() + 0x40);
            if (zero_paired) {
                EXPECT_BYTES_EQ(Bytes(0x20, 0), perbox) << name << " CB per-box block is zero";
            } else {
                EXPECT_BYTES_EQ((Bytes{1, 2, 3, 4}), Bytes(perbox.begin(), perbox.begin() + 4))
                    << name << " CB states the console pairing and LDV";
            }

            const auto cd = image->kernel_section.cd.serialize();
            Key cd_key = hmac(cb_key, Bytes(cd.begin() + 0x10, cd.begin() + 0x20));
            if (!zero_paired) {
                Key cpu{};
                std::copy_n(input.metadata.cpu_key.begin(), cpu.size(), cpu.begin());
                cd_key = hmac(cpu, Bytes(cd_key.begin(), cd_key.end()));
            }
            EXPECT_TRUE(opens_to(cd, cd_key, input.bootloaders.cd))
                << name
                << (zero_paired ? " CD opens under HMAC(K_cb, nonce) alone"
                                : " CD opens under the CPU-key second pass");
            ASSERT_TRUE(input.bootloaders.ce.has_value()) << "the fixture has a CE";
            const auto ce = image->kernel_section.ce->serialize();
            EXPECT_TRUE(opens_to(ce, hmac(cd_key, Bytes(ce.begin() + 0x10, ce.begin() + 0x20)),
                                 *input.bootloaders.ce))
                << name << " CE opens under CD's key";

            ASSERT_OK_AND_ASSIGN(auto sealed_cf,
                                 nand::BootloaderCf::parse(image->system_update_0.cf->serialize()));
            ASSERT_OK(sealed_cf.decrypt(kOneBlKey.data()));
            ASSERT_OK(sealed_cf.parse_perbox()) << name << " CF per-box parses";
            ASSERT_TRUE(sealed_cf.perbox.has_value()) << name << " CF per-box parses";
            const auto& cf_perbox = *sealed_cf.perbox;
            const std::array<uint8_t, 3> expected_pairing =
                zero_paired ? std::array<uint8_t, 3>{} : std::array<uint8_t, 3>{5, 6, 7};
            EXPECT_BYTES_EQ(expected_pairing, cf_perbox.pairing_data)
                << name << (zero_paired ? " CF states no pairing" : " CF states the pairing");
            EXPECT_EQ(unsigned{cf_perbox.lockdown_value}, 9u)
                << name << " CF keeps the console's LDV";
            auto remac = sealed_cf;
            ASSERT_OK(remac.calc_mac(kOneBlKey.data(), input.metadata.cpu_key.data()))
                << name << " CF MAC recomputes";
            EXPECT_BYTES_EQ(sealed_cf.data, remac.data) << name << " CF MAC covers what it states";
        }

        INSTANTIATE_TEST_SUITE_P(Type, SingleCbPairing, ::testing::ValuesIn(kSingleCbRows),
                                 test::RowName{});

        // JTAG seals two chains (xeBuild 1.21). The main chain's single CB is zero-paired, so
        // its CD is keyed HMAC(K_cb, nonce) alone. The second chain's CB carries the console's
        // pairing and CB LDV, bound to the sealed SMC, under HMAC(1BL key, nonce), and its CD
        // is keyed HMAC(K_cb2, nonce) without the CPU key. Both chains take the donor's first
        // CB and CD nonces.
        TEST(JtagChain, SealsAZeroPairedMainChainAndAPairedSecondChainBoundToTheSmc) {
            auto input = fixture(BuildType::Jtag);
            input.bootloaders.cb_or_a = cb(6723, 0, 0x11);
            input.bootloaders.cb_b.reset();
            input.metadata.pairing_data = {1, 2, 3};
            input.metadata.cb_ldv = 4;
            Bytes smc(0x300, 0);
            const Bytes jtag_mark{0xD0, 0x00, 0x00, 0x1B};
            std::copy(jtag_mark.begin(), jtag_mark.end(), smc.begin() + 0x200);
            input.metadata.smc = smc;
            Bytes patch(4, 0x10);
            for (const uint8_t fill : {0x11, 0x12}) {
                patch.insert(patch.end(), 4, 0xFF);
                patch.insert(patch.end(), 4, fill);
            }
            patch.insert(patch.end(), 4, 0xFF);
            patch.push_back(0x13);
            input.patches = InputPatches{.automatic = InputPatchFile{"automatic", patch}};

            const Bytes extra_cb = cb(6750, 0, 0x66);
            nand::BootloaderCd cd{};
            cd.header.header = stage_header(nand::NANDBootloaderMagic::CD, 8453, 0, 0, 0,
                                            sizeof(nand::cd_header) + 0x20);
            std::fill_n(cd.header.key, 16, 0x88);
            cd.header.ce_hash[0] = 1;
            cd.data.assign(0x20, 0xDC);
            cd.decrypted = true;
            const Bytes extra_cd = cd.serialize();
            input.bootloaders.extra_cb = extra_cb;
            input.bootloaders.extra_cd = extra_cd;

            const auto built = run_build(input);
            ASSERT_OK(built) << "JTAG image builds";
            auto image = nand::FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "JTAG image parses with a sealed SMC";
            ASSERT_OK(image->parse()) << "JTAG image parses with a sealed SMC";
            ASSERT_TRUE(image->smc.has_value()) << "JTAG image parses with a sealed SMC";
            ASSERT_TRUE(image->smc->encrypted) << "JTAG image parses with a sealed SMC";

            auto main_cb = image->cb_section.cb_or_A.serialize();
            const Key cb_key =
                hmac(kOneBlKey, Bytes(main_cb.begin() + 0x10, main_cb.begin() + 0x20));
            ExCryptRc4(cb_key.data(), cb_key.size(), main_cb.data() + 0x20, main_cb.size() - 0x20);
            EXPECT_BYTES_EQ(Bytes(0x20, 0), Bytes(main_cb.begin() + 0x20, main_cb.begin() + 0x40))
                << "JTAG main CB per-box block is zero";
            const auto main_cd = image->kernel_section.cd.serialize();
            const Key cd_key = hmac(cb_key, Bytes(main_cd.begin() + 0x10, main_cd.begin() + 0x20));
            EXPECT_TRUE(opens_to(main_cd, cd_key, input.bootloaders.cd))
                << "JTAG main CD opens under HMAC(K_cb, nonce) alone";

            const auto read = [&image](size_t offset, size_t length) {
                const auto bytes = std::as_const(image->flash_driver).read_offset(offset, length);
                return Bytes(bytes.begin(), bytes.end());
            };
            constexpr size_t kSecondChain = 0xD5060;
            const Bytes second_cb = read(kSecondChain, extra_cb.size());
            const Bytes second_cd =
                read(kSecondChain + ((extra_cb.size() + 0x0F) & ~size_t{0x0F}), extra_cd.size());

            // The donor's first CB nonce (0x11) and CD nonce (0x44) replace the templates'.
            Bytes expected_cb = extra_cb;
            std::fill_n(expected_cb.begin() + 0x10, 0x10, 0x11);
            const Key second_cb_key =
                hmac(kOneBlKey, Bytes(expected_cb.begin() + 0x10, expected_cb.begin() + 0x20));
            const Bytes head{1, 2, 3, 4};
            std::copy(head.begin(), head.end(), expected_cb.begin() + 0x20);
            expected_cb =
                authenticate(expected_cb, second_cb_key, input.metadata.cpu_key, image->smc->data);
            EXPECT_TRUE(opens_to(second_cb, second_cb_key, expected_cb))
                << "JTAG second CB opens under HMAC(1BL, nonce), paired and bound to the SMC";
            EXPECT_TRUE(std::any_of(expected_cb.begin() + 0x30, expected_cb.begin() + 0x40,
                                    [](uint8_t b) { return b != 0; }))
                << "JTAG second CB digest is not zero";
            Bytes expected_cd = extra_cd;
            std::fill_n(expected_cd.begin() + 0x10, 0x10, 0x44);
            const Key second_cd_key =
                hmac(second_cb_key, Bytes(expected_cd.begin() + 0x10, expected_cd.begin() + 0x20));
            EXPECT_TRUE(opens_to(second_cd, second_cd_key, expected_cd))
                << "JTAG second CD opens under HMAC(K_cb2, nonce) without the CPU key";
        }

    } // namespace
} // namespace gxbuild3::bootloaders::glitch
