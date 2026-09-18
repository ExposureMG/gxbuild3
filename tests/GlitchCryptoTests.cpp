#include "BuildRunner.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>

using gxbuild3::NAND::FlashImage;
using gxbuild3::NAND::Keyvault;

namespace {
    using Bytes = std::vector<uint8_t>;
    using Key = std::array<uint8_t, 16>;

    bool require(bool condition, const std::string& message) {
        if (!condition)
            std::cerr << "FAIL: " << message << '\n';
        return condition;
    }

    // Independent wire-format oracle: the HMAC/RC4 operations used by the reference
    // Python builders, without calling gxbuild3's bootloader crypto helpers.
    Key hmac(const Key& parent, const Bytes& message) {
        Key key{};
        ExCryptHmacSha(parent.data(), parent.size(), message.data(), message.size(), nullptr, 0,
                       nullptr, 0, key.data(), key.size());
        return key;
    }

    std::pair<Bytes, Key> encrypt(Bytes bytes, const Key& parent, const Bytes& suffix = {}) {
        Bytes message(bytes.begin() + 0x10, bytes.begin() + 0x20);
        message.insert(message.end(), suffix.begin(), suffix.end());
        auto key = hmac(parent, message);
        ExCryptRc4(key.data(), key.size(), bytes.data() + 0x20, bytes.size() - 0x20);
        return {bytes, key};
    }

    Bytes cb(uint16_t version, uint16_t flags, uint8_t nonce) {
        BootloaderCb loader{};
        loader.header.header = {NANDBootloaderMagic::CB, version, 0, flags, 0x400, 0x600};
        loader.data.assign(0x600 - sizeof(generic_header), 0);
        std::fill_n(loader.data.begin(), 16, nonce);
        loader.data[0x400] = 0x42;
        loader.decrypted = true;
        return loader.serialize();
    }

    Input fixture(BuildType type, uint16_t flags = 0x800) {
        Input input{};
        input.build_type = type;
        input.image_type = ImageType::SmallBlock;
        Key cpu{};
        for (size_t bit = 0; bit < 53; ++bit)
            cpu[bit / 8] |= 1U << (bit % 8);
        XeCryptUidEccEncode(cpu.data());
        input.metadata.cpu_key.assign(cpu.begin(), cpu.end());
        input.metadata.smc = Bytes(0x300, 0);
        input.metadata.keyvault =
            keyvault_decrypt(cpu, keyvault_encrypt(cpu, Bytes(Keyvault::kSize, 0)));
        const bool split = type != BuildType::Glitch;
        input.bootloaders.cb_or_a = cb(split ? 9188 : 6750, split ? flags : 0, 0x11);
        if (split)
            input.bootloaders.cb_b = cb(9188, 0, 0x33);
        if (type == BuildType::Glitch3) {
            input.bootloaders.cb_x = cb(15432, 0x800, 0x22);
            // CB_X is executable payload, not a retail CB: these instructions from
            // RGH2to3's legacy payload patch occupy the usual zero signature region.
            const Bytes instruction{0x64, 0x69, 0x00, 0x02};
            std::copy(instruction.begin(), instruction.end(),
                      input.bootloaders.cb_x->begin() + 0x354);
        }

        BootloaderCd cd{};
        cd.header.header = {NANDBootloaderMagic::CD, 9452, 0, 0, 0, sizeof(cd_header) + 0x20};
        std::fill_n(cd.header.key, 16, 0x44);
        cd.header.ce_hash[0] = 1;
        cd.data.assign(0x20, 0xCD);
        cd.decrypted = true;
        input.bootloaders.cd = cd.serialize();

        BootloaderCe ce{};
        ce.header.header = {NANDBootloaderMagic::CE, 1888, 0, 0, 0, sizeof(ce_header) + 0x20};
        std::fill_n(ce.header.key, 16, 0x55);
        ce.data.assign(0x20, 0xCE);
        ce.decrypted = true;
        input.bootloaders.ce = ce.serialize();

        if (type != BuildType::Retail) {
            // Empty CB and CD patch sections followed by a KHV payload. This isolates
            // the crypto policy while still exercising the normal hacked-image build.
            Bytes patch(8, 0xFF);
            patch.push_back(0xA5);
            input.patches = InputPatches{.automatic = InputPatchFile{"automatic", patch}};
        }
        return input;
    }

    // Reference wire-format calculation, independent of BootloaderCb helpers.
    Bytes authenticate(Bytes cb, const Key& rc4_key, const Bytes& cpu, const Bytes& smc) {
        uint64_t sums[2]{};
        for (size_t i = 0; i + 4 <= smc.size(); i += 4) {
            uint32_t word = 0;
            for (size_t j = 0; j < 4; ++j) word = (word << 8) | smc[i + j];
            sums[0] += word;
            sums[1] -= word;
            sums[0] = (sums[0] << 29) | (sums[0] >> 35);
            sums[1] = (sums[1] << 31) | (sums[1] >> 33);
        }
        Bytes message(rc4_key.begin(), rc4_key.end());
        message.insert(message.end(), cb.begin() + 0x20, cb.begin() + 0x30);
        for (auto sum : sums)
            for (int shift = 56; shift >= 0; shift -= 8) message.push_back(sum >> shift);
        Key cpu_key{};
        std::copy_n(cpu.begin(), 16, cpu_key.begin());
        const auto digest = hmac(cpu_key, message);
        std::copy(digest.begin(), digest.end(), cb.begin() + 0x30);
        return cb;
    }

    bool test_retail_digest_vectors() {
        // Fixed vectors generated separately with Python hashlib/hmac and struct.pack
        // from the J-Runner FixPerBoxDigest algorithm. SMC input is ciphertext 00..3f,
        // CPU key 00..0f, and the 16 authenticated metadata bytes are 10..1f.
        const std::array<Key, 3> expected{{
            {0xab,0xe7,0x10,0x53,0x08,0x26,0xc0,0x7d,0x59,0xd4,0x80,0x91,0x36,0x2a,0x0c,0xa0},
            {0x91,0x1a,0x8b,0xa4,0x93,0x53,0x59,0x36,0x9f,0xee,0xd9,0xf7,0x93,0x1d,0x11,0x6a},
            {0xbb,0x31,0x7e,0xfb,0x41,0xe0,0x42,0xdd,0xe5,0x7c,0xca,0xcd,0xce,0xfa,0xc2,0x3d}
        }};
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        Key cpu{};
        Bytes smc(64);
        for (size_t i = 0; i < cpu.size(); ++i) cpu[i] = i;
        for (size_t i = 0; i < smc.size(); ++i) smc[i] = i;
        bool ok = true;
        for (size_t variant = 0; variant < 3; ++variant) {
            auto cba = BootloaderCb::parse(cb(9188, variant == 2 ? 0x1800 : 0x800, 0x11));
            auto target = BootloaderCb::parse(cb(6750, 0, variant == 0 ? 0x11 : 0x33));
            for (size_t i = 0; i < 16; ++i) target.data[0x10 + i] = 0x10 + i;
            const auto parent = variant == 0 ? onebl : hmac(onebl, Bytes(16, 0x11));
            target.encrypt_retail(parent.data(), cpu, smc, variant == 0 ? nullptr : &cba.header);
            auto wire = target.serialize();
            ExCryptRc4(target.derived_key->data(), 16, wire.data() + 0x20, wire.size() - 0x20);
            ok = require(std::equal(expected[variant].begin(), expected[variant].end(), wire.begin() + 0x30),
                         "retail digest matches independent Python vector") && ok;
        }
        return ok;
    }

    bool test_retail_digest(bool split, uint16_t flags, int change) {
        auto input = fixture(BuildType::Retail, flags);
        input.image_type = change == 0 ? ImageType::BigBlock : ImageType::SmallBlock;
        if (!split) {
            input.bootloaders.cb_or_a = cb(6750, 0, 0x11);
            input.bootloaders.cb_b.reset();
        }
        input.metadata.pairing_data = {1, 2, 3};
        input.metadata.cb_ldv = 4;
        if (change == 1) input.metadata.pairing_data[1] ^= 0x80;
        if (change == 2) input.metadata.cb_ldv = 5;
        if (change == 3) {
            // Move one set bit within the CPU key's data region, then repair ECC.
            input.metadata.cpu_key[0] ^= 1;
            input.metadata.cpu_key[8] ^= 1;
            XeCryptUidEccEncode(input.metadata.cpu_key.data());
            input.metadata.keyvault = keyvault_decrypt(input.metadata.cpu_key,
                keyvault_encrypt(input.metadata.cpu_key, Bytes(Keyvault::kSize, 0)));
        }
        if (change == 4) (*input.metadata.smc)[7] = 0xAB;
        auto& target = split ? *input.bootloaders.cb_b : input.bootloaders.cb_or_a;
        target[0x24] = 0xA7; // Reserved bytes also participate in authentication.
        std::fill(target.begin() + 0x30, target.begin() + 0x40, 0xCC);
        const auto built = RunBuild(input);
        if (!require(bool(built), "retail BB digest fixture builds")) return false;
        auto image = FlashImage::read(*built);
        if (!require(image && image->parse() && image->smc, "retail BB parses")) return false;
        // parse() retains the on-NAND bytes; do not apply the SMC plaintext heuristic
        // to ciphertext when checking the authentication input.
        const auto& smc = image->smc->data;
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        auto key = encrypt(input.bootloaders.cb_or_a, onebl).second;
        if (split) {
            Bytes suffix = input.metadata.cpu_key;
            if (flags & 0x1000) {
                Bytes header(input.bootloaders.cb_or_a.begin(), input.bootloaders.cb_or_a.begin() + 16);
                header[6] = header[7] = 0;
                suffix.insert(suffix.end(), header.begin(), header.end());
            }
            key = encrypt(target, key, suffix).second;
        }
        Bytes decoded = split ? image->cb_section.cb_B->serialize() : image->cb_section.cb_or_A.serialize();
        ExCryptRc4(key.data(), 16, decoded.data() + 0x20, decoded.size() - 0x20);
        const auto expected = authenticate(decoded, key, input.metadata.cpu_key, smc);
        bool ok = require(decoded == expected, "retail digest: split=" + std::to_string(split) + " flags=" + std::to_string(flags) + " change=" + std::to_string(change));
        auto extracted = ExtractAll(*built, input.metadata.cpu_key);
        if (!require(bool(extracted), "retail BB extracts")) return false;
        if (change != 0) return ok;
        input.bootloaders = extracted->bootloaders;
        const auto rebuilt = RunBuild(input);
        if (!require(bool(rebuilt), "retail BB rebuilds")) return false;
        auto again = FlashImage::read(*rebuilt);
        if (!require(again && again->parse(), "rebuilt retail BB parses")) return false;
        return require((split ? again->cb_section.cb_B->serialize() : again->cb_section.cb_or_A.serialize()) ==
                       (split ? image->cb_section.cb_B->serialize() : image->cb_section.cb_or_A.serialize()),
                       "unchanged retail inputs preserve authenticated CB bytes") && ok;
    }

    bool check_chain(const Input& input, const Bytes& bytes, const std::string& label) {
        auto image = FlashImage::read(bytes);
        if (!require(image && image->parse(), label + " parses"))
            return false;
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        const auto [cba, cba_key] = encrypt(input.bootloaders.cb_or_a, onebl);
        bool ok = require(image->cb_section.cb_or_A.serialize() == cba,
                          label + " CB_A is encrypted with the 1BL key");
        Key cd_parent = cba_key;
        Bytes suffix = input.metadata.cpu_key;
        if (input.build_type == BuildType::Glitch3)
            suffix.assign(16, 0);
        if ((input.bootloaders.cb_or_a[6] & 0x10) != 0) {
            auto header =
                Bytes(input.bootloaders.cb_or_a.begin(), input.bootloaders.cb_or_a.begin() + 16);
            header[6] = header[7] = 0;
            suffix.insert(suffix.end(), header.begin(), header.end());
        }
        if (input.build_type == BuildType::Glitch3) {
            // RGH2to3 stores the real CB_B's handoff key at +0x10 when it emits
            // CB_B plaintext. CD still uses that key, not CB_X's derived key.
            std::copy_n(input.bootloaders.cb_b->begin() + 0x10, 16, cd_parent.begin());
            const auto cbx = encrypt(*input.bootloaders.cb_x, cba_key, suffix).first;
            ok = require(image->cb_section.cb_x && image->cb_section.cb_x->serialize() == cbx,
                         label + " CB_X is encrypted with CB_A and a zero CPU key") &&
                 ok;
            ok = require(image->cb_section.cb_B &&
                             image->cb_section.cb_B->serialize() == *input.bootloaders.cb_b,
                         label + " CB_B is plaintext") &&
                 ok;
        } else if (input.bootloaders.cb_b) {
            auto plain = *input.bootloaders.cb_b;
            if (input.build_type == BuildType::Retail)
                plain = authenticate(plain, encrypt(plain, cba_key, suffix).second,
                                     input.metadata.cpu_key, image->smc->data);
            const auto [cbb, key] = encrypt(plain, cba_key, suffix);
            cd_parent = key;
            ok = require(image->cb_section.cb_B && image->cb_section.cb_B->serialize() == cbb,
                         label + " CB_B remains encrypted") &&
                 ok;
        }
        // The xeBuild CB_B patches leave CD's RC4 decryption enabled. The
        // plaintext-CD rule belongs to the separate XeLL-only ECC builders.
        const auto [cd, cd_key] = encrypt(input.bootloaders.cd, cd_parent);
        ok = require(image->kernel_section.cd.serialize() == cd, label + " CD remains encrypted") &&
             ok;
        ok = require(image->kernel_section.ce && image->kernel_section.ce->serialize() ==
                                                     encrypt(*input.bootloaders.ce, cd_key).first,
                     label + " CE is encrypted with CD's derived key, not its nonce") &&
             ok;
        return ok;
    }

    bool test_build_policy(BuildType type, const std::string& name, uint16_t flags = 0x800,
                           ImageType image_type = ImageType::SmallBlock) {
        auto input = fixture(type, flags);
        input.image_type = image_type;
        const auto built = RunBuild(input);
        if (!require(built.has_value(), name + " builds"))
            return false;
        bool ok = check_chain(input, *built, name);
        auto extracted = ExtractAll(*built, input.metadata.cpu_key);
        if (!require(extracted.has_value(), name + " extracts"))
            return false;
        ok = require(extracted->bootloaders.cb_x == input.bootloaders.cb_x,
                     name + " extracts plaintext CB_X") &&
             ok;
        if (type == BuildType::Retail) {
            auto expected = *input.bootloaders.cb_b;
            std::copy_n(extracted->bootloaders.cb_b->begin() + 0x30, 16, expected.begin() + 0x30);
            input.bootloaders.cb_b = expected;
        }
        ok = require(extracted->bootloaders.cb_b == input.bootloaders.cb_b &&
                         extracted->bootloaders.cd == input.bootloaders.cd &&
                         extracted->bootloaders.ce == input.bootloaders.ce,
                     name + " extracts original CB_B, CD and CE") &&
             ok;
        input.bootloaders = extracted->bootloaders;
        const auto rebuilt = RunBuild(input);
        return require(rebuilt.has_value(), name + " rebuilds") &&
               check_chain(input, *rebuilt, name + " rebuild") && ok;
    }

    bool test_cb_b_extraction_preserves_perbox_ldv(uint8_t perbox_ldv) {
        auto input = fixture(BuildType::Retail);
        input.metadata.cb_ldv = perbox_ldv;
        input.metadata.pairing_data = {1, 2, 3};
        (*input.bootloaders.cb_b)[0x3B1] = 12;
        const auto donor = RunBuild(input);
        if (!require(bool(donor), "distinct per-box/display LDV donor builds")) return false;

        const auto metadata = ExtractMetadata(*donor, input.metadata.cpu_key);
        const auto extracted = ExtractAll(*donor, input.metadata.cpu_key);
        const auto info = ExtractAllInfo(*donor, input.metadata.cpu_key);
        if (!require(metadata && extracted && info && info->bootloaders.cb_b,
                     "distinct LDV donor extracts through all APIs")) return false;
        bool ok = require(metadata->cb_ldv == perbox_ldv,
                          "ExtractMetadata preserves CB_B +0x23 instead of display +0x3B1");
        ok = require(extracted->metadata.cb_ldv == perbox_ldv,
                     "ExtractAll preserves CB_B +0x23 instead of display +0x3B1") && ok;
        ok = require(info->bootloaders.cb_b->ldv == 12 && info->bootloaders.cb_ldv == 12,
                     "inspection still reports the independent display LDV") && ok;

        // Exercise both donor-metadata builds and full extract/rebuild workflows.
        for (bool full_extract : {false, true}) {
            auto rebuild_input = full_extract ? *extracted : input;
            if (!full_extract) {
                rebuild_input.metadata = *metadata;
                // ExtractMetadata supplies donor metadata; the resolver supplies SMC separately.
                rebuild_input.metadata.smc = input.metadata.smc;
            }
            const auto rebuilt = RunBuild(rebuild_input);
            if (!require(bool(rebuilt), "extracted LDV donor rebuilds")) return false;
            const auto decoded = ExtractAll(*rebuilt, input.metadata.cpu_key);
            if (!require(decoded && decoded->bootloaders.cb_b, "rebuilt CB_B decrypts")) return false;
            ok = require((*decoded->bootloaders.cb_b)[0x23] == perbox_ldv &&
                             (*decoded->bootloaders.cb_b)[0x3B1] == 12,
                         "rebuild preserves per-box and display LDV independently") && ok;
            ok = require(decoded->bootloaders.cb_b == extracted->bootloaders.cb_b,
                         "unchanged CB_B rebuild preserves its authenticated plaintext") && ok;
        }
        return ok;
    }

    bool test_glitch3_requires_cb_x_and_cb_b() {
        bool ok = true;
        for (bool missing_x : {true, false}) {
            auto input = fixture(BuildType::Glitch3);
            input.options.noblpatch = true;
            if (missing_x)
                input.bootloaders.cb_x.reset();
            else
                input.bootloaders.cb_b.reset();
            const auto result = RunBuild(input);
            ok =
                require(!result && result.error().code == BuildErrorCode::InvalidBootloader,
                        "glitch3 rejects an incomplete CB_A/CB_X/CB_B chain even with noblpatch") &&
                ok;
        }
        return ok;
    }

    bool test_patched_stages_are_encrypted_for_their_parent(BuildType type) {
        auto input = fixture(type);
        Bytes patch;
        const auto word = [&patch](uint32_t value) {
            for (int shift : {24, 16, 8, 0})
                patch.push_back(value >> shift);
        };
        word(0x400);
        word(1);
        word(0xDEADBEEF);
        word(0xFFFFFFFF);
        word(sizeof(cd_header));
        word(1);
        word(0x11223344);
        word(0xFFFFFFFF);
        patch.push_back(0xA5);
        input.patches->automatic->data = patch;
        const auto built = RunBuild(input);
        if (!require(built.has_value(), "patched glitch image builds"))
            return false;
        const Bytes cb_patch{0xDE, 0xAD, 0xBE, 0xEF};
        const Bytes cd_patch{0x11, 0x22, 0x33, 0x44};
        std::copy(cb_patch.begin(), cb_patch.end(), input.bootloaders.cb_b->begin() + 0x400);
        std::copy(cd_patch.begin(), cd_patch.end(),
                  input.bootloaders.cd.begin() + sizeof(cd_header));
        return check_chain(input, *built, "patched bootloader stages");
    }

    bool test_glitch3_encrypted_replacement_preserves_handoff_key() {
        auto expected = fixture(BuildType::Glitch3);
        auto input = expected;
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        const auto [cba, cba_key] = encrypt(input.bootloaders.cb_or_a, onebl);
        const auto [cbb, cbb_key] =
            encrypt(*input.bootloaders.cb_b, cba_key, input.metadata.cpu_key);
        input.bootloaders.cb_or_a = cba;
        input.bootloaders.cb_b = cbb;
        std::copy(cbb_key.begin(), cbb_key.end(), expected.bootloaders.cb_b->begin() + 0x10);
        const auto built = RunBuild(input);
        return require(built.has_value(), "encrypted glitch3 replacements build") &&
               check_chain(expected, *built, "encrypted replacement handoff");
    }
} // namespace

int main() {
    bool ok = test_cb_b_extraction_preserves_perbox_ldv(0);
    ok = test_cb_b_extraction_preserves_perbox_ldv(7) && ok;
    ok = test_retail_digest_vectors() && ok;
    ok = test_build_policy(BuildType::Retail, "retail") && ok;
    ok = test_build_policy(BuildType::Glitch, "glitch1") && ok;
    ok = test_build_policy(BuildType::Glitch2, "glitch2") && ok;
    ok = test_build_policy(BuildType::Glitch2, "big-block glitch2", 0x800, ImageType::BigBlock) &&
         ok;
    ok = test_build_policy(BuildType::Glitch2m, "glitch2m") && ok;
    ok = test_build_policy(BuildType::Glitch3, "glitch3") && ok;
    ok = test_build_policy(BuildType::Glitch3, "glitch3 v2", 0x1800) && ok;
    ok = test_glitch3_requires_cb_x_and_cb_b() && ok;
    ok = test_patched_stages_are_encrypted_for_their_parent(BuildType::Glitch2) && ok;
    ok = test_patched_stages_are_encrypted_for_their_parent(BuildType::Glitch3) && ok;
    ok = test_glitch3_encrypted_replacement_preserves_handoff_key() && ok;
    for (int change = 0; change < 5; ++change) {
        ok = test_retail_digest(false, 0, change) && ok;
        ok = test_retail_digest(true, 0x800, change) && ok;
        ok = test_retail_digest(true, 0x1800, change) && ok;
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
