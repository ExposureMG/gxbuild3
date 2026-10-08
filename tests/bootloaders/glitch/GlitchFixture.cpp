#include "bootloaders/glitch/GlitchFixture.hpp"

#include "bootloaders/glitch/GlitchOracle.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Keys.hpp"

#include <algorithm>
#include <array>

namespace gxbuild3::bootloaders::glitch {

    nand::generic_header stage_header(uint16_t magic, uint16_t version, uint16_t pairing,
                                      uint16_t flags, uint32_t entrypoint, size_t size) {
        nand::generic_header header{};
        header.magic = magic;
        header.version = version;
        header.pairing = pairing;
        header.flags = flags;
        header.entrypoint = entrypoint;
        header.size = static_cast<uint32_t>(size);
        return header;
    }

    Bytes cb(uint16_t version, uint16_t flags, uint8_t nonce) {
        nand::BootloaderCb loader{};
        loader.header.header =
            stage_header(nand::NANDBootloaderMagic::CB, version, 0, flags, 0x400, 0x600);
        loader.data.assign(0x600 - sizeof(nand::generic_header), 0);
        std::fill_n(loader.data.begin(), 16, nonce);
        loader.data[0x400] = 0x42;
        loader.decrypted = true;
        return loader.serialize();
    }

    Input fixture(BuildType type, uint16_t flags) {
        Input input{};
        input.build_type = type;
        input.image_type = ImageType::SmallBlock;
        // Bits 0..52 set, then ECC-encoded (test::valid_cpu_key(), the same bytes).
        const Key cpu = test::ecc_encoded_bit_range(0, 53);
        input.metadata.cpu_key.assign(cpu.begin(), cpu.end());
        input.metadata.smc = Bytes(0x300, 0);
        input.metadata.keyvault =
            nand::keyvault_decrypt(
                cpu, nand::keyvault_encrypt(cpu, Bytes(nand::Keyvault::kSize, 0)).value())
                .value();
        const bool split = type != BuildType::Glitch;
        input.bootloaders.cb_or_a = cb(split ? 9188 : 6750, split ? flags : 0, 0x11);
        if (split) {
            input.bootloaders.cb_b = cb(9188, 0, 0x33);
        }
        if (type == BuildType::Glitch3) {
            input.bootloaders.cb_x = cb(15432, 0x800, 0x22);
            // CB_X is executable payload, not a retail CB: these instructions from
            // RGH2to3's legacy payload patch occupy the usual zero signature region.
            const Bytes instruction{0x64, 0x69, 0x00, 0x02};
            std::copy(instruction.begin(), instruction.end(),
                      input.bootloaders.cb_x->begin() + 0x354);
        }

        nand::BootloaderCd cd{};
        cd.header.header = stage_header(nand::NANDBootloaderMagic::CD, 9452, 0, 0, 0,
                                        sizeof(nand::cd_header) + 0x20);
        std::fill_n(cd.header.key, 16, 0x44);
        cd.header.ce_hash[0] = 1;
        std::ranges::copy(gxbuild3::nand::kRomSalt6bl, cd.header.salt_6bl);
        cd.data.assign(0x20, 0xCD);
        cd.decrypted = true;
        input.bootloaders.cd = cd.serialize();

        nand::BootloaderCe ce{};
        ce.header.header = stage_header(nand::NANDBootloaderMagic::CE, 1888, 0, 0, 0,
                                        sizeof(nand::ce_header) + 0x20);
        std::fill_n(ce.header.key, 16, 0x55);
        ce.data.assign(0x20, 0xCE);
        ce.decrypted = true;
        input.bootloaders.ce = ce.serialize();

        // A donor whose nonces equal the templates' keeps every stage's nonce, so the
        // reference encryption below can read it from the input bytes.
        DonorNonces nonces{};
        const auto nonce = [](uint8_t value) {
            BootloaderNonce bytes{};
            bytes.fill(value);
            return bytes;
        };
        nonces.stages = {nonce(0x11), nonce(0x33), nonce(0x44), nonce(0x55)};
        input.metadata.donor_nonces = nonces;

        if (type != BuildType::Retail) {
            // Empty CB and CD patch sections followed by a KHV payload. This isolates
            // the crypto policy while still exercising the normal hacked-image build.
            const Bytes patch{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xA5};
            input.patches = InputPatches{.automatic = InputPatchFile{"automatic", patch}};
        }
        return input;
    }

    void expect_chain(const Input& input, const Bytes& bytes, const std::string& label) {
        auto image = nand::FlashImage::read(bytes);
        ASSERT_TRUE(image.has_value()) << label << " parses";
        ASSERT_OK(image->parse()) << label << " parses";
        const auto [cba, cba_key] = encrypt(input.bootloaders.cb_or_a, kOneBlKey);
        EXPECT_BYTES_EQ(cba, image->cb_section.cb_or_A.serialize())
            << label << " CB_A is encrypted with the 1BL key";
        Key cd_parent = cba_key;
        Bytes suffix = input.metadata.cpu_key;
        if (input.build_type == BuildType::Glitch3) {
            suffix.assign(16, 0);
        }
        if ((input.bootloaders.cb_or_a[6] & 0x10) != 0) {
            auto header =
                Bytes(input.bootloaders.cb_or_a.begin(), input.bootloaders.cb_or_a.begin() + 16);
            header[6] = header[7] = 0;
            suffix.insert(suffix.end(), header.begin(), header.end());
        }
        if (input.build_type == BuildType::Glitch3) {
            ASSERT_TRUE(input.bootloaders.cb_b.has_value()) << label << " input has a CB_B";
            ASSERT_TRUE(input.bootloaders.cb_x.has_value()) << label << " input has a CB_X";
            // RGH2to3 stores the real CB_B's handoff key at +0x10 when it emits
            // CB_B plaintext. CD still uses that key, not CB_X's derived key.
            std::copy_n(input.bootloaders.cb_b->begin() + 0x10, 16, cd_parent.begin());
            const auto cbx = encrypt(*input.bootloaders.cb_x, cba_key, suffix).first;
            EXPECT_OPTIONAL_BYTES_EQ(std::optional<Bytes>(cbx), serialized(image->cb_section.cb_x))
                << label << " CB_X is encrypted with CB_A and a zero CPU key";
            EXPECT_OPTIONAL_BYTES_EQ(input.bootloaders.cb_b, serialized(image->cb_section.cb_B))
                << label << " CB_B is plaintext";
        } else if (input.bootloaders.cb_b) {
            auto plain = *input.bootloaders.cb_b;
            auto cb_b_suffix = suffix;
            if ((input.bootloaders.cb_or_a[7] & 0x01) != 0) {
                // Manufacturing CB_A (xerunner sealing.message_for / build.py): CB_B is
                // keyed over its nonce and sixteen zeros, with no CB_A head, and its SMC
                // digest slot is zero.
                cb_b_suffix.assign(16, 0);
                std::fill_n(plain.begin() + 0x30, 16, 0);
            } else {
                // Every other split chain binds the final encrypted SMC (xerunner
                // build.py `chain`), glitch2 included.
                ASSERT_TRUE(image->smc.has_value()) << label << " parses an SMC";
                plain = authenticate(plain, encrypt(plain, cba_key, suffix).second,
                                     input.metadata.cpu_key, image->smc->data);
            }
            const auto [cbb, key] = encrypt(plain, cba_key, cb_b_suffix);
            cd_parent = key;
            EXPECT_OPTIONAL_BYTES_EQ(std::optional<Bytes>(cbb), serialized(image->cb_section.cb_B))
                << label << " CB_B remains encrypted";
        }
        // The xeBuild CB_B patches leave CD's RC4 decryption enabled. The
        // plaintext-CD rule belongs to the separate XeLL-only ECC builders.
        const auto [cd, cd_key] = encrypt(input.bootloaders.cd, cd_parent);
        EXPECT_BYTES_EQ(cd, image->kernel_section.cd.serialize())
            << label << " CD remains encrypted";
        ASSERT_TRUE(input.bootloaders.ce.has_value()) << label << " input has a CE";
        EXPECT_OPTIONAL_BYTES_EQ(std::optional<Bytes>(encrypt(*input.bootloaders.ce, cd_key).first),
                                 serialized(image->kernel_section.ce))
            << label << " CE is encrypted with CD's derived key, not its nonce";
    }

    ::testing::AssertionResult optional_bytes_equal(const char* expected_expression,
                                                    const char* actual_expression,
                                                    const std::optional<Bytes>& expected,
                                                    const std::optional<Bytes>& actual) {
        if (expected.has_value() != actual.has_value()) {
            return ::testing::AssertionFailure()
                   << expected_expression << (expected ? " is present" : " is absent") << " but "
                   << actual_expression << (actual ? " is present" : " is absent");
        }
        if (!expected) {
            return ::testing::AssertionSuccess();
        }
        return test::detail::bytes_equal(expected_expression, actual_expression, *expected,
                                         *actual);
    }

} // namespace gxbuild3::bootloaders::glitch
