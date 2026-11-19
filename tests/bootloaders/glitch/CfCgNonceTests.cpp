// The CG RC4 key is HMAC-SHA1(CF_dec[0x330:0x340], CG[0x10:0x20]): the 7BL nonce inside the
// decrypted CF payload, not the CF header fixpoint at +0x20. A gxbuild3-only round-trip cannot
// catch a wrong key source because encrypt and decrypt would share it, so this rebuilds a
// synthetic CF/CG pair whose payload nonce differs from the header fixpoint and decrypts the
// result with the oracle in GlitchOracle.hpp.

#include "BuildRunner.hpp"
#include "bootloaders/glitch/GlitchFixture.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/bootloaders/Common.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

namespace gxbuild3::bootloaders::glitch {
    namespace {

        TEST(CfCgNonce, CgDecryptsWithTheCfPayloadNonce) {
            auto input = fixture(BuildType::Retail);

            // Decrypted CF whose 7BL nonce (payload +0x300 == serialized +0x330) is
            // 0xA0..0xAF, deliberately different from the zeroed header fixpoint at +0x20.
            nand::BootloaderCf cf{};
            cf.header.header = stage_header(nand::NANDBootloaderMagic::CF, 17559, 0, 0, 0,
                                            sizeof(nand::cf_header) + 0x340);
            cf.data.assign(0x340, 0);
            for (size_t i = 0; i < 16; ++i) {
                cf.data[0x300 + i] = static_cast<uint8_t>(0xA0 + i);
            }
            cf.decrypted = true;
            input.bootloaders.cf0 = cf.serialize();

            // Decrypted CG: a non-zero header key survives encryption unchanged, and a
            // 0x1000-aligned source_size makes the CG plaintext heuristic recognise it.
            nand::BootloaderCg cg{};
            cg.header.header = stage_header(nand::NANDBootloaderMagic::CG, 17559, 0, 0, 0,
                                            sizeof(nand::cg_header) + 0x40);
            std::fill_n(cg.header.key, 16, 0x77);
            cg.header.source_size = 0x1000;
            cg.data.assign(0x40, 0xEE);
            cg.decrypted = true;
            const Bytes cg_input = cg.serialize();
            input.bootloaders.cg0 = cg_input;

            const auto built = run_build(input);
            ASSERT_OK(built) << "cf/cg retail image builds";
            auto image = nand::FlashImage::read(*built);
            ASSERT_TRUE(image.has_value()) << "cf/cg image parses";
            ASSERT_OK(image->parse()) << "cf/cg image parses";
            ASSERT_TRUE(image->system_update_0.cf.has_value()) << "parse populates CF0 and CG0";
            ASSERT_TRUE(image->system_update_0.cg.has_value()) << "parse populates CF0 and CG0";

            // Independent oracle: CF is RC4'd from 0x30 under HMAC(1BL, CF[0x20:0x30]); the
            // recovered payload nonce at 0x330 then keys the CG (RC4 from 0x20).
            Bytes cf_bytes = image->system_update_0.cf->serialize();
            ASSERT_GE(cf_bytes.size(), 0x340u) << "on-NAND CF reaches the 7BL nonce";
            const Key cf_key =
                hmac(kOneBlKey, Bytes(cf_bytes.begin() + 0x20, cf_bytes.begin() + 0x30));
            ExCryptRc4(cf_key.data(), cf_key.size(), cf_bytes.data() + 0x30,
                       cf_bytes.size() - 0x30);
            Bytes expected_nonce(16);
            for (size_t i = 0; i < 16; ++i) {
                expected_nonce[i] = static_cast<uint8_t>(0xA0 + i);
            }
            const Bytes planted(cf_bytes.begin() + 0x330, cf_bytes.begin() + 0x340);
            ASSERT_BYTES_EQ(expected_nonce, planted) << "CF payload 7BL nonce survives the build";

            Bytes cg_bytes = image->system_update_0.cg->serialize();
            ASSERT_GE(cg_bytes.size(), 0x20u) << "on-NAND CG has a header key";
            Key cg_parent{};
            std::copy_n(planted.begin(), 16, cg_parent.begin());
            const Key cg_key =
                hmac(cg_parent, Bytes(cg_bytes.begin() + 0x10, cg_bytes.begin() + 0x20));
            ExCryptRc4(cg_key.data(), cg_key.size(), cg_bytes.data() + 0x20,
                       cg_bytes.size() - 0x20);
            // Without a donor the CG is sealed under a fresh random nonce, stored in clear.
            Bytes expected_cg = cg_input;
            std::copy_n(cg_bytes.begin() + 0x10, 0x10, expected_cg.begin() + 0x10);
            EXPECT_FALSE(std::equal(cg_bytes.begin() + 0x10, cg_bytes.begin() + 0x20,
                                    cg_input.begin() + 0x10))
                << "CG without a donor takes a fresh nonce";
            EXPECT_BYTES_EQ(expected_cg, cg_bytes)
                << "CG decrypts with the CF payload nonce at +0x330";
        }

    } // namespace
} // namespace gxbuild3::bootloaders::glitch
