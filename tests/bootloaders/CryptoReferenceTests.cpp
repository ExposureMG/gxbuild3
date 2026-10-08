// Seals checked against bytes produced by the xerunner reference builder
// (src/xebuild/chain/sealing.py `keys` + crypto/formats.py `encrypt_bootloader`),
// run over the release files in tests/gxBuild-support-files/common, plus the SMC encryption
// test that decides by the decrypted tail. A missing tracked fixture fails the case.

#include "Error.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/SMC.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace gxbuild3::bootloaders {
    namespace {

        using test::Bytes;
        using Key = std::array<uint8_t, 16>;

        Key key_from_hex(const char* hex) {
            Key key{};
            for (size_t i = 0; i < key.size(); ++i) {
                key[i] = static_cast<uint8_t>(std::stoul(std::string(hex + i * 2, 2), nullptr, 16));
            }
            return key;
        }

        // SHA-1 of each stage after xerunner seals the chain SB_10375, SC_17489, SD_17489.
        // The SC opens under HMAC(16 zero bytes, nonce at 0x10) and is RC4'd from 0x20.
        constexpr const char* kSealedSb = "0c509a0249d7a234ccdf7bd641156b76a572e123";
        constexpr const char* kSealedSc = "c4bb96712e75a96d8f0fabc0896adbb7b6cfc93b";
        constexpr const char* kSealedSd = "908a11b90a27f0c285c9e27a154cb1a81e06b380";

        TEST(XerunnerSeal, ScSealedUnderTheZeroSecretMatchesXerunnerAndOpensBack) {
            ASSERT_OK_AND_ASSIGN(const Bytes plain, test::read_support_file("common/SC_17489.bin"));
            ASSERT_EQ(plain.size(), 0x6540u) << "SC_17489.bin fixture is present";

            const uint8_t zero_secret[16] = {};
            ASSERT_OK_AND_ASSIGN(auto sc, nand::BootloaderSc::parse(plain));
            sc.decrypted = true;
            ASSERT_OK(sc.encrypt(zero_secret));
            const Bytes sealed = sc.serialize();
            ASSERT_EQ(test::sha1_hex(sealed), kSealedSc)
                << "SC sealed under the zero secret matches xerunner";

            ASSERT_OK_AND_ASSIGN(auto reopened, nand::BootloaderSc::parse(sealed));
            ASSERT_OK(reopened.decrypt(zero_secret));
            EXPECT_BYTES_EQ(plain, reopened.serialize())
                << "sealed SC opens back to the release file";
        }

        TEST(XerunnerSeal, PackerSealsTheDevkitChainLikeXerunner) {
            std::vector<nand::BootloaderBlock> chain;
            for (const char* name : {"SB_10375.bin", "SC_17489.bin", "SD_17489.bin"}) {
                nand::BootloaderBlock block{};
                ASSERT_OK_AND_ASSIGN(block.data,
                                     test::read_support_file(std::string("common/") + name));
                ASSERT_GE(block.data.size(), 0x20u) << name << " fixture is present";
                block.magic = static_cast<uint16_t>(block.data[0] << 8 | block.data[1]);
                block.build = static_cast<uint16_t>(block.data[2] << 8 | block.data[3]);
                block.flags = static_cast<uint16_t>(block.data[6] << 8 | block.data[7]);
                block.size = static_cast<uint32_t>(block.data.size());
                chain.push_back(std::move(block));
            }
            ASSERT_OK(nand::crypt_bootloaders(chain, {})) << "packer seals chain";
            EXPECT_EQ(test::sha1_hex(chain[0].data), kSealedSb) << "packer SB matches xerunner";
            EXPECT_EQ(test::sha1_hex(chain[1].data), kSealedSc) << "packer SC matches xerunner";
            EXPECT_EQ(test::sha1_hex(chain[2].data), kSealedSd) << "packer SD matches xerunner";
        }

        // An encrypted SMC whose ciphertext byte 0x100 has a high nibble of 1..7 looks like a
        // plaintext motherboard nibble. Plaintext SMCs end in four zero bytes (xerunner
        // smc.py `handed_in`), so the decrypted tail decides.
        TEST(SmcDetection, EncryptionIsDetectedByTheZeroTailNotTheMotherboardNibble) {
            Bytes plain(0x3000, 0);
            for (size_t i = 0; i < 0x2F00; ++i) {
                plain[i] = static_cast<uint8_t>(i * 7 + 3);
            }
            plain[0x100] = 0x41; // Jasper
            Bytes sealed;
            for (unsigned seed = 0; seed < 0x100; ++seed) {
                plain[0] = static_cast<uint8_t>(seed);
                sealed = nand::smc_encrypt(plain);
                const uint8_t nibble = sealed[0x100] >> 4;
                if (nibble >= 1 && nibble <= 7) {
                    break;
                }
            }
            ASSERT_TRUE((sealed[0x100] >> 4) >= 1 && (sealed[0x100] >> 4) <= 7)
                << "constructed SMC ciphertext has a motherboard-like nibble at 0x100";

            EXPECT_FALSE(nand::smc_is_encrypted(plain)) << "zero-tail plaintext SMC is plaintext";
            EXPECT_TRUE(nand::smc_is_encrypted(sealed))
                << "SMC ciphertext is detected as encrypted";

            auto parsed = nand::Smc::parse(sealed);
            ASSERT_OK(parsed) << "Smc::parse marks the ciphertext encrypted";
            EXPECT_TRUE(parsed->encrypted) << "Smc::parse marks the ciphertext encrypted";
            EXPECT_EQ(parsed->motherboard, nand::SmcMotherboard::Jasper)
                << "Smc::parse reads metadata from the plaintext";
            parsed->encrypt();
            EXPECT_BYTES_EQ(sealed, parsed->data)
                << "encrypt() does not seal an encrypted SMC twice";
        }

        // xerunner `sealing.keys` over cba_9188_mfg.bin + cbb_6752.bin with the CB_A flag word
        // set as listed, for CPU keys 00..0f and a5 * 16. Bit 0 makes CB_B independent of the
        // CPU key and of bit 0x1000.
        struct CbBVector {
            const char* name;
            uint16_t flags;
            const char* cb_b_key_cpu_0f;
            const char* cb_b_key_cpu_a5;
        };
        GX_PRINT_ROW_AS_NAME(CbBVector)
        constexpr const char* kCbAKey = "0773a05f2c7b9d2e3e3703e678c0dc27";
        constexpr CbBVector kCbBVectors[] = {
            {"Flags0x0801", 0x0801, "04cdc9871e6f58c01bff03fbe58e91d9",
             "04cdc9871e6f58c01bff03fbe58e91d9"},
            {"Flags0x1801", 0x1801, "04cdc9871e6f58c01bff03fbe58e91d9",
             "04cdc9871e6f58c01bff03fbe58e91d9"},
            {"Flags0x0800", 0x0800, "65c72ed08c4318d2580f341403467ad1",
             "9c343766fde280530a9d19ac130ec964"},
            {"Flags0x1800", 0x1800, "0159fbe5ff63094f537d8d5120aa9975",
             "52962fa0a51519e7e0af98fa64e56799"},
        };

        // SHA-1 of CB_B (cbb_6752.bin) sealed by xerunner `Build.chain` under cba_9188.bin with
        // the flag word listed: Fields.write(pairing 123456, CPU key 00..0f, CB_B key,
        // fingerprint(smc)) at the start of the body, smc being bytes (i * 13 + 7) & 0xFF over
        // 0x3000 taken as the sealed image. The digest is bound on every regime but bit 0.
        struct BoundCbB {
            const char* name;
            uint16_t flags;
            const char* digest;
        };
        GX_PRINT_ROW_AS_NAME(BoundCbB)
        constexpr BoundCbB kBoundCbB[] = {
            {"Flags0x0800", 0x0800, "05a75da213f6d05cf70c0e08bf1956f88df780b7"},
            {"Flags0x1800", 0x1800, "1f6094da88850d62f1eb8fa044236091185873de"},
            {"Flags0x0801", 0x0801, "883bb208466f1988a9a34a8700ec910d623d9da2"},
        };

        Key counting_cpu_key() {
            Key cpu{};
            for (size_t i = 0; i < cpu.size(); ++i) {
                cpu[i] = static_cast<uint8_t>(i);
            }
            return cpu;
        }

        // A CB_A from common/ sealed under the 1BL key, so its derived_key is CB_A's key, and
        // the clear CB_B bytes of cbb_6752.bin. Each suite below names its CB_A.
        class CbBChainTest : public ::testing::Test {
          protected:
            void load_chain(const char* cb_a_name) {
                ASSERT_OK_AND_ASSIGN(const Bytes cb_a_bytes,
                                     test::read_support_file(std::string("common/") + cb_a_name));
                ASSERT_OK_AND_ASSIGN(cb_b_bytes_, test::read_support_file("common/cbb_6752.bin"));
                ASSERT_GT(cb_a_bytes.size(), 0x400u)
                    << cb_a_name << " and cbb_6752.bin fixtures are present";
                ASSERT_GT(cb_b_bytes_.size(), 0x400u)
                    << cb_a_name << " and cbb_6752.bin fixtures are present";
                ASSERT_OK_AND_ASSIGN(cb_a_, nand::BootloaderCb::parse(cb_a_bytes));
                cb_a_.decrypted = true;
                ASSERT_OK(cb_a_.encrypt(nand::key_1bl));
                ASSERT_TRUE(cb_a_.derived_key.has_value()) << "sealing CB_A derives its key";
            }

            nand::BootloaderCb cb_a_{};
            Bytes cb_b_bytes_;
        };

        class CbBRegime : public CbBChainTest, public ::testing::WithParamInterface<CbBVector> {
          protected:
            void SetUp() override { ASSERT_NO_FATAL_FAILURE(load_chain("cba_9188_mfg.bin")); }
        };

        TEST_P(CbBRegime, CbBKeyMatchesXerunnerAndOpensBack) {
            const auto& vector = GetParam();
            ASSERT_BYTES_EQ(key_from_hex(kCbAKey), *cb_a_.derived_key)
                << "CB_A key matches xerunner";

            const Key cpu_0f = counting_cpu_key();
            Key cpu_a5{};
            cpu_a5.fill(0xA5);

            auto header = cb_a_.header;
            header.header.flags = vector.flags;
            for (const auto& [cpu_name, cpu, expected] :
                 {std::tuple{"CPU key 00..0f", cpu_0f, vector.cb_b_key_cpu_0f},
                  std::tuple{"CPU key a5 * 16", cpu_a5, vector.cb_b_key_cpu_a5}}) {
                SCOPED_TRACE(cpu_name);
                ASSERT_OK_AND_ASSIGN(auto cbb, nand::BootloaderCb::parse(cb_b_bytes_));
                cbb.decrypted = true;
                cbb.populate_metadata();
                ASSERT_OK(cbb.encrypt_cb_b(header, cb_a_.derived_key->data(), cpu.data()));
                const std::string label = "CB_B key under CB_A flags " +
                                          std::to_string(vector.flags) + " matches xerunner";
                ASSERT_TRUE(cbb.derived_key.has_value()) << label;
                EXPECT_BYTES_EQ(key_from_hex(expected), *cbb.derived_key) << label;

                ASSERT_OK_AND_ASSIGN(auto sealed, nand::BootloaderCb::parse(cbb.serialize()));
                ASSERT_OK(sealed.decrypt_cb_b(header, cb_a_.derived_key->data(), cpu.data()));
                EXPECT_BYTES_EQ(cb_b_bytes_, sealed.serialize()) << "CB_B opens back: " << label;
            }
        }

        INSTANTIATE_TEST_SUITE_P(Flags, CbBRegime, ::testing::ValuesIn(kCbBVectors),
                                 test::RowName{});

        // xerunner build.py writes sixteen zeros where the SMC digest goes for a manufacturing
        // chain or a zero CPU key, and seals CB_B with the regime's key.
        class UnboundCbB : public CbBChainTest {
          protected:
            void SetUp() override { ASSERT_NO_FATAL_FAILURE(load_chain("cba_9188_mfg.bin")); }
        };

        TEST_F(UnboundCbB, HasAZeroDigestSlotAndIsSealedWithTheRegimesKey) {
            const Bytes smc(0x3000, 0x5A);
            const Key cpu_0f = counting_cpu_key();
            const Key zero_cpu{};
            const auto digest_slot_is_zero = [](const nand::BootloaderCb& cbb) {
                return std::all_of(cbb.data.begin() + 0x20, cbb.data.begin() + 0x30,
                                   [](uint8_t b) { return b == 0; });
            };

            for (const auto& [flags, cpu, expected] :
                 {std::tuple{uint16_t{0x0801}, cpu_0f, kCbBVectors[0].cb_b_key_cpu_0f},
                  std::tuple{uint16_t{0x1801}, cpu_0f, kCbBVectors[1].cb_b_key_cpu_0f}}) {
                SCOPED_TRACE(std::format("manufacturing CB_A flags 0x{:04X}", flags));
                auto header = cb_a_.header;
                header.header.flags = flags;
                ASSERT_OK_AND_ASSIGN(auto cbb, nand::BootloaderCb::parse(cb_b_bytes_));
                cbb.decrypted = true;
                cbb.populate_metadata();
                ASSERT_OK(cbb.encrypt_retail(cb_a_.derived_key->data(), cpu, smc, &header));
                ASSERT_TRUE(cbb.derived_key.has_value())
                    << "retail seal of a manufacturing CB_B uses xerunner's key";
                EXPECT_BYTES_EQ(key_from_hex(expected), *cbb.derived_key)
                    << "retail seal of a manufacturing CB_B uses xerunner's key";
                ASSERT_OK(cbb.decrypt_cb_b(header, cb_a_.derived_key->data(), cpu.data()));
                EXPECT_TRUE(digest_slot_is_zero(cbb)) << "manufacturing CB_B digest slot is zero";
            }

            auto header = cb_a_.header;
            header.header.flags = 0x0800;
            ASSERT_OK_AND_ASSIGN(auto cbb, nand::BootloaderCb::parse(cb_b_bytes_));
            cbb.decrypted = true;
            cbb.populate_metadata();
            ASSERT_OK(cbb.encrypt_retail(cb_a_.derived_key->data(), zero_cpu, smc, &header));
            ASSERT_OK(cbb.decrypt_cb_b(header, cb_a_.derived_key->data(), zero_cpu.data()));
            EXPECT_TRUE(digest_slot_is_zero(cbb)) << "zero-CPU-key CB_B digest slot is zero";
        }

        class CbBBinding : public CbBChainTest, public ::testing::WithParamInterface<BoundCbB> {
          protected:
            void SetUp() override { ASSERT_NO_FATAL_FAILURE(load_chain("cba_9188.bin")); }
        };

        TEST_P(CbBBinding, BoundCbBMatchesXerunner) {
            const auto& row = GetParam();
            Bytes smc(0x3000);
            for (size_t i = 0; i < smc.size(); ++i) {
                smc[i] = static_cast<uint8_t>(i * 13 + 7);
            }
            const Key cpu = counting_cpu_key();

            auto header = cb_a_.header;
            header.header.flags = row.flags;
            ASSERT_OK_AND_ASSIGN(auto cbb, nand::BootloaderCb::parse(cb_b_bytes_));
            cbb.decrypted = true;
            cbb.populate_metadata();
            // xerunner's console block: pairing, LDV 0, twelve zero bytes.
            ASSERT_TRUE(cbb.perbox.has_value()) << "CB_B carries a per-box block";
            *cbb.perbox = nand::cb_perbox{};
            cbb.perbox->pairing_data[0] = 0x12;
            cbb.perbox->pairing_data[1] = 0x34;
            cbb.perbox->pairing_data[2] = 0x56;
            ASSERT_OK(cbb.serialize_perbox()) << "CB_B per-box serializes";
            ASSERT_OK(cbb.encrypt_retail(cb_a_.derived_key->data(), cpu, smc, &header));
            EXPECT_EQ(test::sha1_hex(cbb.serialize()), row.digest)
                << "bound CB_B under CB_A flags " << std::to_string(row.flags)
                << " matches xerunner";
        }

        INSTANTIATE_TEST_SUITE_P(Flags, CbBBinding, ::testing::ValuesIn(kBoundCbB),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::bootloaders
