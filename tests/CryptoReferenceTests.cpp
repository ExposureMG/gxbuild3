// Seals checked against bytes produced by the xerunner reference builder
// (src/xebuild/chain/sealing.py `keys` + crypto/formats.py `encrypt_bootloader`),
// run over the release files in tests/gxBuild-support-files/common.

#include "TestResult.hpp"
#include "excrypt.h"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
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

using namespace gxbuild3::nand;

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
        auto sc = gxbuild3::test::must(BootloaderSc::parse(plain));
        sc.decrypted = true;
        gxbuild3::test::must(sc.encrypt(zero_secret));
        const Bytes sealed = sc.serialize();
        if (!require(sha1(sealed) == digest_from_hex(kSealedSc),
                     "SC sealed under the zero secret matches xerunner"))
            return false;

        auto reopened = gxbuild3::test::must(BootloaderSc::parse(sealed));
        gxbuild3::test::must(reopened.decrypt(zero_secret));
        return require(reopened.serialize() == plain, "sealed SC opens back to the release file");
    }

    bool test_packer_seals_devkit_chain_like_xerunner() {
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
        if (!require(crypt_bootloaders(chain, {}).has_value(), "packer seals chain"))
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
        using namespace gxbuild3::nand;
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
        auto cba = gxbuild3::test::must(BootloaderCb::parse(cba_bytes));
        cba.decrypted = true;
        gxbuild3::test::must(cba.encrypt(key_1bl));
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
                auto cbb = gxbuild3::test::must(BootloaderCb::parse(cbb_bytes));
                cbb.decrypted = true;
                cbb.populate_metadata();
                gxbuild3::test::must(cbb.encrypt_cb_b(header, cba.derived_key->data(), cpu.data()));
                const std::string label = "CB_B key under CB_A flags " +
                                          std::to_string(vector.flags) + " matches xerunner";
                ok =
                    require(cbb.derived_key && *cbb.derived_key == key_from_hex(expected), label) &&
                    ok;
                auto sealed = gxbuild3::test::must(BootloaderCb::parse(cbb.serialize()));
                gxbuild3::test::must(
                    sealed.decrypt_cb_b(header, cba.derived_key->data(), cpu.data()));
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
        auto cba = gxbuild3::test::must(BootloaderCb::parse(cba_bytes));
        cba.decrypted = true;
        gxbuild3::test::must(cba.encrypt(key_1bl));
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
            auto cbb = gxbuild3::test::must(BootloaderCb::parse(cbb_bytes));
            cbb.decrypted = true;
            cbb.populate_metadata();
            gxbuild3::test::must(cbb.encrypt_retail(cba.derived_key->data(), cpu, smc, &header));
            ok = require(cbb.derived_key && *cbb.derived_key == key_from_hex(expected),
                         "retail seal of a manufacturing CB_B uses xerunner's key") &&
                 ok;
            gxbuild3::test::must(cbb.decrypt_cb_b(header, cba.derived_key->data(), cpu.data()));
            ok = require(std::all_of(cbb.data.begin() + 0x20, cbb.data.begin() + 0x30,
                                     [](uint8_t b) { return b == 0; }),
                         "manufacturing CB_B digest slot is zero") &&
                 ok;
        }

        auto header = cba.header;
        header.header.flags = 0x0800;
        auto cbb = gxbuild3::test::must(BootloaderCb::parse(cbb_bytes));
        cbb.decrypted = true;
        cbb.populate_metadata();
        gxbuild3::test::must(cbb.encrypt_retail(cba.derived_key->data(), zero_cpu, smc, &header));
        gxbuild3::test::must(cbb.decrypt_cb_b(header, cba.derived_key->data(), zero_cpu.data()));
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
        auto cba = gxbuild3::test::must(BootloaderCb::parse(cba_bytes));
        cba.decrypted = true;
        gxbuild3::test::must(cba.encrypt(key_1bl));

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
            auto cbb = gxbuild3::test::must(BootloaderCb::parse(cbb_bytes));
            cbb.decrypted = true;
            cbb.populate_metadata();
            // xerunner's console block: pairing, LDV 0, twelve zero bytes.
            *cbb.perbox = cb_perbox{};
            cbb.perbox->pairing_data[0] = 0x12;
            cbb.perbox->pairing_data[1] = 0x34;
            cbb.perbox->pairing_data[2] = 0x56;
            if (!require(cbb.serialize_perbox().has_value(), "CB_B per-box serializes"))
                return false;
            gxbuild3::test::must(cbb.encrypt_retail(cba.derived_key->data(), cpu, smc, &header));
            ok = require(sha1(cbb.serialize()) == digest_from_hex(expected),
                         "bound CB_B under CB_A flags " + std::to_string(flags) +
                             " matches xerunner") &&
                 ok;
        }
        return ok;
    }

    // A stage image of `total` zero bytes whose generic header carries `magic` and the
    // declared size `declared` (big-endian at +0xC).
    Bytes stage_bytes(uint16_t magic, size_t total, uint32_t declared) {
        Bytes bytes(total, 0);
        bytes[0] = static_cast<uint8_t>(magic >> 8);
        bytes[1] = static_cast<uint8_t>(magic);
        for (size_t i = 0; i < 4; ++i)
            bytes[0xC + i] = static_cast<uint8_t>(declared >> (24 - 8 * i));
        return bytes;
    }

    template <class R> bool fails_with(const R& result, gxbuild3::ErrorCode code) {
        return !result.has_value() && result.error().code == code;
    }

    // Behaviour change (E8a): parse refuses a declared size that cannot hold the stage's own
    // header, where decrypt and encrypt used to underflow the payload length.
    bool test_parse_refuses_undersized_declared_size() {
        using gxbuild3::ErrorCode;
        bool ok = require(fails_with(BootloaderCb::parse(Bytes(8, 0)), ErrorCode::Truncated),
                          "CB shorter than its generic header is truncated");
        ok =
            require(fails_with(BootloaderCb::parse(stage_bytes(CB, 0x40, 0)), ErrorCode::Malformed),
                    "CB declaring less than its generic header is refused") &&
            ok;
        ok = require(BootloaderCb::parse(stage_bytes(CB, 0x40, 0x40)).has_value(),
                     "CB declaring its own length parses") &&
             ok;
        ok =
            require(fails_with(BootloaderSc::parse(stage_bytes(SC, sizeof(sc_header) + 0x20, 0x20)),
                               ErrorCode::Malformed),
                    "SC declaring less than its header is refused") &&
            ok;
        ok =
            require(fails_with(BootloaderCd::parse(stage_bytes(CD, sizeof(cd_header) + 0x20, 0x20)),
                               ErrorCode::Malformed),
                    "CD declaring less than its header is refused") &&
            ok;
        ok = require(fails_with(
                         BootloaderCd::parse(stage_bytes(CD, sizeof(cd_header) + 0x20, 0xFFFFFFF8)),
                         ErrorCode::Malformed),
                     "CD declaring a size that overflows when aligned is refused") &&
             ok;
        ok =
            require(fails_with(BootloaderCe::parse(stage_bytes(CE, sizeof(ce_header) + 0x20, 0x10)),
                               ErrorCode::Malformed),
                    "CE declaring less than its header is refused") &&
            ok;
        ok = require(fails_with(BootloaderCf::parse(stage_bytes(CF, 0x430, 0x10)),
                                ErrorCode::Malformed),
                     "CF declaring less than its header is refused") &&
             ok;
        ok =
            require(fails_with(BootloaderCg::parse(stage_bytes(CG, sizeof(cg_header) + 0x20, 0x10)),
                               ErrorCode::Malformed),
                    "CG declaring less than its header is refused") &&
            ok;
        return ok;
    }

    // Behaviour change (E8a): a crypt that cannot run leaves the stage as it was instead of
    // flipping `decrypted` over an untouched or underflowing payload.
    bool test_crypt_failure_leaves_stage_unchanged() {
        using gxbuild3::ErrorCode;
        const uint8_t key[16] = {};

        auto cd = gxbuild3::test::must(BootloaderCd::parse(
            stage_bytes(CD, sizeof(cd_header) + 0x20, sizeof(cd_header) + 0x20)));
        cd.header.header.size = 0x10;
        const Bytes cd_data = cd.data;
        const bool cd_was_decrypted = cd.decrypted;
        bool ok = require(
            fails_with(cd_was_decrypted ? cd.encrypt(key) : cd.decrypt(key), ErrorCode::Malformed),
            "CD crypt with an undersized declared size fails");
        ok = require(cd.decrypted == cd_was_decrypted && cd.data == cd_data &&
                         !cd.derived_key.has_value(),
                     "failed CD crypt leaves the stage unchanged") &&
             ok;

        auto cb = gxbuild3::test::must(BootloaderCb::parse(stage_bytes(CB, 0x40, 0x40)));
        cb.header.header.size = 0x10;
        const Bytes cb_data = cb.data;
        ok = require(fails_with(cb.decrypt(key), ErrorCode::Malformed) && !cb.decrypted &&
                         cb.data == cb_data && !cb.derived_key.has_value(),
                     "CB decrypt of a header-only CB fails and leaves the stage") &&
             ok;

        auto cg = gxbuild3::test::must(BootloaderCg::parse(
            stage_bytes(CG, sizeof(cg_header) + 0x20, sizeof(cg_header) + 0x20)));
        cg.decrypted = false;
        cg.header.header.size = 0x10;
        const Bytes cg_data = cg.data;
        ok = require(fails_with(cg.decrypt(key), ErrorCode::Malformed) && !cg.decrypted &&
                         cg.data == cg_data,
                     "CG decrypt with an undersized declared size fails and leaves the stage") &&
             ok;
        return ok;
    }

    // Behaviour change (E8a): crypt_single_bl reports short data instead of returning a bool
    // every stage ignored, and it touches neither the data nor the key when it fails.
    bool test_crypt_single_bl_refuses_short_data() {
        using gxbuild3::ErrorCode;
        Bytes data(0x1F, 0xA5);
        const Bytes original = data;
        uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        uint8_t original_key[16];
        std::memcpy(original_key, key, sizeof(key));

        bool ok =
            require(fails_with(crypt_single_bl(data, HmacType::Default, key), ErrorCode::Truncated),
                    "crypt_single_bl refuses data shorter than its crypt start");
        ok = require(data == original && std::memcmp(key, original_key, sizeof(key)) == 0,
                     "refused crypt_single_bl leaves data and key untouched") &&
             ok;

        Bytes cf_sized(0x2F, 0);
        ok = require(fails_with(
                         crypt_single_bl(cf_sized, HmacType::Default, key, nullptr, nullptr, 0x30),
                         ErrorCode::Truncated),
                     "crypt_single_bl refuses data shorter than a 0x30 crypt start") &&
             ok;

        Bytes full(0x40, 0);
        ok = require(fails_with(crypt_single_bl(full, HmacType::Hmac1920, key),
                                ErrorCode::InvalidArgument),
                     "crypt_single_bl refuses a CPU-keyed HMAC without a CPU key") &&
             ok;
        ok = require(crypt_single_bl(full, HmacType::Default, key).has_value(),
                     "crypt_single_bl crypts data that holds its crypt start") &&
             ok;

        std::vector<BootloaderBlock> chain(1);
        chain[0].magic = 0x4342;
        chain[0].data.assign(0x10, 0);
        ok = require(fails_with(crypt_bootloaders(chain, {}), ErrorCode::Truncated),
                     "crypt_bootloaders reports a block too short to crypt") &&
             ok;
        return ok;
    }

    // Behaviour change (E8a): calc_mac reports what stops it instead of silently skipping.
    bool test_cf_calc_mac_reports_failure() {
        using gxbuild3::ErrorCode;
        const uint8_t onebl[16] = {};
        const uint8_t cpu[16] = {1};

        BootloaderCf cf{};
        cf.header.header.magic = CF;
        cf.data.assign(0x1F0, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = true;
        const Bytes original = cf.data;
        bool ok = require(fails_with(cf.calc_mac(onebl, cpu), ErrorCode::Truncated) &&
                              cf.data == original,
                          "calc_mac refuses a CF too short for its per-box block");
        ok = require(fails_with(cf.calc_mac(onebl, nullptr), ErrorCode::InvalidArgument),
                     "calc_mac refuses a missing CPU key") &&
             ok;

        cf.data.assign(0x340, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        ok = require(cf.parse_perbox().has_value() && cf.calc_mac(onebl, cpu).has_value(),
                     "calc_mac binds a CF that holds its per-box block") &&
             ok;
        ok = require(std::equal(std::begin(cf.perbox->per_box_digest),
                                std::end(cf.perbox->per_box_digest), cf.data.begin() + 0x1F0),
                     "calc_mac writes the digest to both the payload and the per-box copy") &&
             ok;
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
    ok = test_parse_refuses_undersized_declared_size() && ok;
    ok = test_crypt_failure_leaves_stage_unchanged() && ok;
    ok = test_crypt_single_bl_refuses_short_data() && ok;
    ok = test_cf_calc_mac_reports_failure() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
