// Seals checked against bytes produced by the xerunner reference builder
// (src/xebuild/chain/sealing.py `keys` + crypto/formats.py `encrypt_bootloader`),
// run over the release files in tests/gxBuild-support-files/common.

#include "excrypt.h"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/objects/SMC.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {
    using Bytes = std::vector<uint8_t>;
    using Digest = std::array<uint8_t, 20>;

    bool require(bool condition, const std::string& message) {
        if (!condition)
            std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    Bytes read_common(const char* name) {
        const auto path = std::filesystem::path(GXBUILD3_SUPPORT_DIR) / "common" / name;
        std::ifstream in(path, std::ios::binary);
        return Bytes(std::istreambuf_iterator<char>(in), {});
    }

    Digest sha1(const Bytes& bytes) {
        Digest digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        return digest;
    }

    Digest digest_from_hex(const char* hex) {
        Digest digest{};
        for (size_t i = 0; i < digest.size(); ++i)
            digest[i] = static_cast<uint8_t>(std::stoul(std::string(hex + i * 2, 2), nullptr, 16));
        return digest;
    }

    // SHA-1 of each stage after xerunner seals the chain SB_10375, SC_17489, SD_17489.
    // The SC opens under HMAC(16 zero bytes, nonce at 0x10) and is RC4'd from 0x20.
    constexpr const char* kSealedSb = "0c509a0249d7a234ccdf7bd641156b76a572e123";
    constexpr const char* kSealedSc = "c4bb96712e75a96d8f0fabc0896adbb7b6cfc93b";
    constexpr const char* kSealedSd = "908a11b90a27f0c285c9e27a154cb1a81e06b380";

    bool test_sc_seals_like_xerunner() {
        const Bytes plain = read_common("SC_17489.bin");
        if (!require(plain.size() == 0x6540, "SC_17489.bin fixture is present"))
            return false;

        const uint8_t zero_secret[16] = {};
        auto sc = BootloaderSc::parse(plain);
        sc.decrypted = true;
        sc.encrypt(zero_secret);
        const Bytes sealed = sc.serialize();
        if (!require(sha1(sealed) == digest_from_hex(kSealedSc),
                     "SC sealed under the zero secret matches xerunner"))
            return false;

        auto reopened = BootloaderSc::parse(sealed);
        reopened.decrypt(zero_secret);
        return require(reopened.serialize() == plain, "sealed SC opens back to the release file");
    }

    bool test_packer_seals_devkit_chain_like_xerunner() {
        using gxbuild3::bootloaders::BootloaderBlock;
        std::vector<BootloaderBlock> chain;
        for (const char* name : {"SB_10375.bin", "SC_17489.bin", "SD_17489.bin"}) {
            BootloaderBlock block{};
            block.data = read_common(name);
            if (!require(block.data.size() >= 0x20, std::string(name) + " fixture is present"))
                return false;
            block.magic = static_cast<uint16_t>(block.data[0] << 8 | block.data[1]);
            block.build = static_cast<uint16_t>(block.data[2] << 8 | block.data[3]);
            block.flags = static_cast<uint16_t>(block.data[6] << 8 | block.data[7]);
            block.size = static_cast<uint32_t>(block.data.size());
            chain.push_back(std::move(block));
        }
        if (!require(gxbuild3::bootloaders::crypt_bootloaders(chain, {}), "packer seals chain"))
            return false;
        bool ok = require(sha1(chain[0].data) == digest_from_hex(kSealedSb),
                          "packer SB matches xerunner");
        ok = require(sha1(chain[1].data) == digest_from_hex(kSealedSc),
                     "packer SC matches xerunner") &&
             ok;
        ok = require(sha1(chain[2].data) == digest_from_hex(kSealedSd),
                     "packer SD matches xerunner") &&
             ok;
        return ok;
    }

    // An encrypted SMC whose ciphertext byte 0x100 has a high nibble of 1..7 looks like a
    // plaintext motherboard nibble. Plaintext SMCs end in four zero bytes (xerunner
    // smc.py `handed_in`), so the decrypted tail decides.
    bool test_smc_encryption_is_detected_by_zero_tail() {
        using namespace gxbuild3::NAND;
        Bytes plain(0x3000, 0);
        for (size_t i = 0; i < 0x2F00; ++i)
            plain[i] = static_cast<uint8_t>(i * 7 + 3);
        plain[0x100] = 0x41; // Jasper
        Bytes sealed;
        for (unsigned seed = 0; seed < 0x100; ++seed) {
            plain[0] = static_cast<uint8_t>(seed);
            sealed = smc_encrypt(plain);
            const uint8_t nibble = sealed[0x100] >> 4;
            if (nibble >= 1 && nibble <= 7)
                break;
        }
        if (!require((sealed[0x100] >> 4) >= 1 && (sealed[0x100] >> 4) <= 7,
                     "constructed SMC ciphertext has a motherboard-like nibble at 0x100"))
            return false;

        bool ok = require(!smc_is_encrypted(plain), "zero-tail plaintext SMC is plaintext");
        ok = require(smc_is_encrypted(sealed), "SMC ciphertext is detected as encrypted") && ok;

        auto parsed = Smc::parse(sealed);
        ok =
            require(parsed && parsed->encrypted, "Smc::parse marks the ciphertext encrypted") && ok;
        if (!parsed)
            return false;
        ok = require(parsed->motherboard == SmcMotherboard::Jasper,
                     "Smc::parse reads metadata from the plaintext") &&
             ok;
        parsed->encrypt();
        ok =
            require(parsed->data == sealed, "encrypt() does not seal an encrypted SMC twice") && ok;
        return ok;
    }

    using Key = std::array<uint8_t, 16>;

    Key key_from_hex(const char* hex) {
        Key key{};
        for (size_t i = 0; i < key.size(); ++i)
            key[i] = static_cast<uint8_t>(std::stoul(std::string(hex + i * 2, 2), nullptr, 16));
        return key;
    }

    // xerunner `sealing.keys` over cba_9188_mfg.bin + cbb_6752.bin with the CB_A flag word
    // set as listed, for CPU keys 00..0f and a5 * 16. Bit 0 makes CB_B independent of the
    // CPU key and of bit 0x1000.
    struct CbBVector {
        uint16_t flags;
        const char* cb_b_key_cpu_0f;
        const char* cb_b_key_cpu_a5;
    };
    constexpr const char* kCbAKey = "0773a05f2c7b9d2e3e3703e678c0dc27";
    constexpr CbBVector kCbBVectors[] = {
        {0x0801, "04cdc9871e6f58c01bff03fbe58e91d9", "04cdc9871e6f58c01bff03fbe58e91d9"},
        {0x1801, "04cdc9871e6f58c01bff03fbe58e91d9", "04cdc9871e6f58c01bff03fbe58e91d9"},
        {0x0800, "65c72ed08c4318d2580f341403467ad1", "9c343766fde280530a9d19ac130ec964"},
        {0x1800, "0159fbe5ff63094f537d8d5120aa9975", "52962fa0a51519e7e0af98fa64e56799"},
    };

    bool test_cb_b_regime_matches_xerunner() {
        const Bytes cba_bytes = read_common("cba_9188_mfg.bin");
        const Bytes cbb_bytes = read_common("cbb_6752.bin");
        if (!require(cba_bytes.size() > 0x400 && cbb_bytes.size() > 0x400,
                     "cba_9188_mfg.bin and cbb_6752.bin fixtures are present"))
            return false;
        auto cba = BootloaderCb::parse(cba_bytes);
        cba.decrypted = true;
        cba.encrypt(key_1bl);
        if (!require(cba.derived_key && *cba.derived_key == key_from_hex(kCbAKey),
                     "CB_A key matches xerunner"))
            return false;

        Key cpu_0f{};
        for (size_t i = 0; i < cpu_0f.size(); ++i)
            cpu_0f[i] = static_cast<uint8_t>(i);
        Key cpu_a5{};
        cpu_a5.fill(0xA5);

        bool ok = true;
        for (const auto& vector : kCbBVectors) {
            auto header = cba.header;
            header.header.flags = vector.flags;
            for (const auto& [cpu, expected] : {std::pair{cpu_0f, vector.cb_b_key_cpu_0f},
                                                std::pair{cpu_a5, vector.cb_b_key_cpu_a5}}) {
                auto cbb = BootloaderCb::parse(cbb_bytes);
                cbb.decrypted = true;
                cbb.populate_metadata();
                cbb.encrypt_cb_b(header, cba.derived_key->data(), cpu.data());
                const std::string label = "CB_B key under CB_A flags " +
                                          std::to_string(vector.flags) + " matches xerunner";
                ok =
                    require(cbb.derived_key && *cbb.derived_key == key_from_hex(expected), label) &&
                    ok;
                auto sealed = BootloaderCb::parse(cbb.serialize());
                sealed.decrypt_cb_b(header, cba.derived_key->data(), cpu.data());
                ok = require(sealed.serialize() == cbb_bytes, "CB_B opens back: " + label) && ok;
            }
        }
        return ok;
    }

    // xerunner build.py writes sixteen zeros where the SMC digest goes for a manufacturing
    // chain or a zero CPU key, and seals CB_B with the regime's key.
    bool test_unbound_cb_b_has_zero_digest() {
        const Bytes cba_bytes = read_common("cba_9188_mfg.bin");
        const Bytes cbb_bytes = read_common("cbb_6752.bin");
        auto cba = BootloaderCb::parse(cba_bytes);
        cba.decrypted = true;
        cba.encrypt(key_1bl);
        const Bytes smc(0x3000, 0x5A);

        Key cpu_0f{};
        for (size_t i = 0; i < cpu_0f.size(); ++i)
            cpu_0f[i] = static_cast<uint8_t>(i);
        const Key zero_cpu{};

        bool ok = true;
        for (const auto& [flags, cpu, expected] :
             {std::tuple{uint16_t{0x0801}, cpu_0f, kCbBVectors[0].cb_b_key_cpu_0f},
              std::tuple{uint16_t{0x1801}, cpu_0f, kCbBVectors[1].cb_b_key_cpu_0f}}) {
            auto header = cba.header;
            header.header.flags = flags;
            auto cbb = BootloaderCb::parse(cbb_bytes);
            cbb.decrypted = true;
            cbb.populate_metadata();
            cbb.encrypt_retail(cba.derived_key->data(), cpu, smc, &header);
            ok = require(cbb.derived_key && *cbb.derived_key == key_from_hex(expected),
                         "retail seal of a manufacturing CB_B uses xerunner's key") &&
                 ok;
            cbb.decrypt_cb_b(header, cba.derived_key->data(), cpu.data());
            ok = require(std::all_of(cbb.data.begin() + 0x20, cbb.data.begin() + 0x30,
                                     [](uint8_t b) { return b == 0; }),
                         "manufacturing CB_B digest slot is zero") &&
                 ok;
        }

        auto header = cba.header;
        header.header.flags = 0x0800;
        auto cbb = BootloaderCb::parse(cbb_bytes);
        cbb.decrypted = true;
        cbb.populate_metadata();
        cbb.encrypt_retail(cba.derived_key->data(), zero_cpu, smc, &header);
        cbb.decrypt_cb_b(header, cba.derived_key->data(), zero_cpu.data());
        ok = require(std::all_of(cbb.data.begin() + 0x20, cbb.data.begin() + 0x30,
                                 [](uint8_t b) { return b == 0; }),
                     "zero-CPU-key CB_B digest slot is zero") &&
             ok;
        return ok;
    }

    // SHA-1 of CB_B (cbb_6752.bin) sealed by xerunner `Build.chain` under cba_9188.bin with
    // the flag word listed: Fields.write(pairing 123456, CPU key 00..0f, CB_B key,
    // fingerprint(smc)) at the start of the body, smc being bytes (i * 13 + 7) & 0xFF over
    // 0x3000 taken as the sealed image. The digest is bound on every regime but bit 0.
    constexpr std::pair<uint16_t, const char*> kBoundCbB[] = {
        {0x0800, "05a75da213f6d05cf70c0e08bf1956f88df780b7"},
        {0x1800, "1f6094da88850d62f1eb8fa044236091185873de"},
        {0x0801, "883bb208466f1988a9a34a8700ec910d623d9da2"},
    };

    bool test_cb_b_binding_matches_xerunner() {
        const Bytes cba_bytes = read_common("cba_9188.bin");
        const Bytes cbb_bytes = read_common("cbb_6752.bin");
        if (!require(cba_bytes.size() > 0x400 && cbb_bytes.size() > 0x400,
                     "cba_9188.bin and cbb_6752.bin fixtures are present"))
            return false;
        auto cba = BootloaderCb::parse(cba_bytes);
        cba.decrypted = true;
        cba.encrypt(key_1bl);

        Bytes smc(0x3000);
        for (size_t i = 0; i < smc.size(); ++i)
            smc[i] = static_cast<uint8_t>(i * 13 + 7);
        Key cpu{};
        for (size_t i = 0; i < cpu.size(); ++i)
            cpu[i] = static_cast<uint8_t>(i);

        bool ok = true;
        for (const auto& [flags, expected] : kBoundCbB) {
            auto header = cba.header;
            header.header.flags = flags;
            auto cbb = BootloaderCb::parse(cbb_bytes);
            cbb.decrypted = true;
            cbb.populate_metadata();
            // xerunner's console block: pairing, LDV 0, twelve zero bytes.
            *cbb.perbox = cb_perbox{};
            cbb.perbox->pairing_data[0] = 0x12;
            cbb.perbox->pairing_data[1] = 0x34;
            cbb.perbox->pairing_data[2] = 0x56;
            cbb.serialize_perbox();
            cbb.encrypt_retail(cba.derived_key->data(), cpu, smc, &header);
            ok = require(sha1(cbb.serialize()) == digest_from_hex(expected),
                         "bound CB_B under CB_A flags " + std::to_string(flags) +
                             " matches xerunner") &&
                 ok;
        }
        return ok;
    }
} // namespace

int main() {
    bool ok = test_sc_seals_like_xerunner();
    ok = test_packer_seals_devkit_chain_like_xerunner() && ok;
    ok = test_smc_encryption_is_detected_by_zero_tail() && ok;
    ok = test_cb_b_regime_matches_xerunner() && ok;
    ok = test_unbound_cb_b_has_zero_digest() && ok;
    ok = test_cb_b_binding_matches_xerunner() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
