#include "BuildRunner.hpp"
#include "excrypt.h"
#include "nand/FlashImage.hpp"
#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>

using GxBuild::BootloaderNonce;
using GxBuild::BuildErrorCode;
using GxBuild::BuildType;
using GxBuild::DonorNonces;
using GxBuild::ImageType;
using GxBuild::Input;
using GxBuild::InputPatches;
using GxBuild::InputPatchFile;

using gxbuild3::extract_all;
using gxbuild3::extract_all_info;
using gxbuild3::extract_metadata;
using gxbuild3::run_build;
using namespace gxbuild3::nand;

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
            for (size_t j = 0; j < 4; ++j)
                word = (word << 8) | smc[i + j];
            sums[0] += word;
            sums[1] -= word;
            sums[0] = (sums[0] << 29) | (sums[0] >> 35);
            sums[1] = (sums[1] << 31) | (sums[1] >> 33);
        }
        Bytes message(rc4_key.begin(), rc4_key.end());
        message.insert(message.end(), cb.begin() + 0x20, cb.begin() + 0x30);
        for (auto sum : sums)
            for (int shift = 56; shift >= 0; shift -= 8)
                message.push_back(sum >> shift);
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
        const std::array<Key, 3> expected{{{0xab, 0xe7, 0x10, 0x53, 0x08, 0x26, 0xc0, 0x7d, 0x59,
                                            0xd4, 0x80, 0x91, 0x36, 0x2a, 0x0c, 0xa0},
                                           {0x91, 0x1a, 0x8b, 0xa4, 0x93, 0x53, 0x59, 0x36, 0x9f,
                                            0xee, 0xd9, 0xf7, 0x93, 0x1d, 0x11, 0x6a},
                                           {0xbb, 0x31, 0x7e, 0xfb, 0x41, 0xe0, 0x42, 0xdd, 0xe5,
                                            0x7c, 0xca, 0xcd, 0xce, 0xfa, 0xc2, 0x3d}}};
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        Key cpu{};
        Bytes smc(64);
        for (size_t i = 0; i < cpu.size(); ++i)
            cpu[i] = i;
        for (size_t i = 0; i < smc.size(); ++i)
            smc[i] = i;
        bool ok = true;
        for (size_t variant = 0; variant < 3; ++variant) {
            auto cba = BootloaderCb::parse(cb(9188, variant == 2 ? 0x1800 : 0x800, 0x11));
            auto target = BootloaderCb::parse(cb(6750, 0, variant == 0 ? 0x11 : 0x33));
            for (size_t i = 0; i < 16; ++i)
                target.data[0x10 + i] = 0x10 + i;
            const auto parent = variant == 0 ? onebl : hmac(onebl, Bytes(16, 0x11));
            target.encrypt_retail(parent.data(), cpu, smc, variant == 0 ? nullptr : &cba.header);
            auto wire = target.serialize();
            ExCryptRc4(target.derived_key->data(), 16, wire.data() + 0x20, wire.size() - 0x20);
            ok = require(std::equal(expected[variant].begin(), expected[variant].end(),
                                    wire.begin() + 0x30),
                         "retail digest matches independent Python vector") &&
                 ok;
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
        if (change == 1)
            input.metadata.pairing_data[1] ^= 0x80;
        if (change == 2)
            input.metadata.cb_ldv = 5;
        if (change == 3) {
            // Move one set bit within the CPU key's data region, then repair ECC.
            input.metadata.cpu_key[0] ^= 1;
            input.metadata.cpu_key[8] ^= 1;
            XeCryptUidEccEncode(input.metadata.cpu_key.data());
            input.metadata.keyvault = keyvault_decrypt(
                input.metadata.cpu_key,
                keyvault_encrypt(input.metadata.cpu_key, Bytes(Keyvault::kSize, 0)));
        }
        if (change == 4)
            (*input.metadata.smc)[7] = 0xAB;
        auto& target = split ? *input.bootloaders.cb_b : input.bootloaders.cb_or_a;
        target[0x24] = 0xA7; // Reserved bytes also participate in authentication.
        std::fill(target.begin() + 0x30, target.begin() + 0x40, 0xCC);
        const auto built = run_build(input);
        if (!require(bool(built), "retail BB digest fixture builds"))
            return false;
        auto image = FlashImage::read(*built);
        if (!require(image && image->parse() && image->smc, "retail BB parses"))
            return false;
        // parse() retains the on-NAND bytes; do not apply the SMC plaintext heuristic
        // to ciphertext when checking the authentication input.
        const auto& smc = image->smc->data;
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        auto key = encrypt(input.bootloaders.cb_or_a, onebl).second;
        if (split) {
            Bytes suffix = input.metadata.cpu_key;
            if (flags & 0x1000) {
                Bytes header(input.bootloaders.cb_or_a.begin(),
                             input.bootloaders.cb_or_a.begin() + 16);
                header[6] = header[7] = 0;
                suffix.insert(suffix.end(), header.begin(), header.end());
            }
            key = encrypt(target, key, suffix).second;
        }
        Bytes decoded =
            split ? image->cb_section.cb_B->serialize() : image->cb_section.cb_or_A.serialize();
        ExCryptRc4(key.data(), 16, decoded.data() + 0x20, decoded.size() - 0x20);
        const auto expected = authenticate(decoded, key, input.metadata.cpu_key, smc);
        bool ok = require(decoded == expected, "retail digest: split=" + std::to_string(split) +
                                                   " flags=" + std::to_string(flags) +
                                                   " change=" + std::to_string(change));
        auto extracted = extract_all(*built, input.metadata.cpu_key);
        if (!require(bool(extracted), "retail BB extracts"))
            return false;
        if (change != 0)
            return ok;
        input.bootloaders = extracted->bootloaders;
        const auto rebuilt = run_build(input);
        if (!require(bool(rebuilt), "retail BB rebuilds"))
            return false;
        auto again = FlashImage::read(*rebuilt);
        if (!require(again && again->parse(), "rebuilt retail BB parses"))
            return false;
        return require((split ? again->cb_section.cb_B->serialize()
                              : again->cb_section.cb_or_A.serialize()) ==
                           (split ? image->cb_section.cb_B->serialize()
                                  : image->cb_section.cb_or_A.serialize()),
                       "unchanged retail inputs preserve authenticated CB bytes") &&
               ok;
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
                plain = authenticate(plain, encrypt(plain, cba_key, suffix).second,
                                     input.metadata.cpu_key, image->smc->data);
            }
            const auto [cbb, key] = encrypt(plain, cba_key, cb_b_suffix);
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
        const bool manufacturing = (flags & 0x01) != 0;
        // A stale digest in the input CB_B, which a manufacturing seal must clear.
        if (manufacturing)
            std::fill_n(input.bootloaders.cb_b->begin() + 0x30, 16, 0xCC);
        const auto built = run_build(input);
        if (!require(built.has_value(), name + " builds"))
            return false;
        bool ok = check_chain(input, *built, name);
        auto extracted = extract_all(*built, input.metadata.cpu_key);
        if (!require(extracted.has_value(), name + " extracts"))
            return false;
        ok = require(extracted->bootloaders.cb_x == input.bootloaders.cb_x,
                     name + " extracts plaintext CB_X") &&
             ok;
        if (input.bootloaders.cb_b && type != BuildType::Glitch3) {
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
        const auto rebuilt = run_build(input);
        return require(rebuilt.has_value(), name + " rebuilds") &&
               check_chain(input, *rebuilt, name + " rebuild") && ok;
    }

    bool test_cb_b_extraction_preserves_perbox_ldv(uint8_t perbox_ldv) {
        auto input = fixture(BuildType::Retail);
        input.metadata.cb_ldv = perbox_ldv;
        input.metadata.pairing_data = {1, 2, 3};
        (*input.bootloaders.cb_b)[0x3B1] = 12;
        const auto donor = run_build(input);
        if (!require(bool(donor), "distinct per-box/display LDV donor builds"))
            return false;

        const auto metadata = extract_metadata(*donor, input.metadata.cpu_key);
        const auto extracted = extract_all(*donor, input.metadata.cpu_key);
        const auto info = extract_all_info(*donor, input.metadata.cpu_key);
        if (!require(metadata && extracted && info && info->bootloaders.cb_b,
                     "distinct LDV donor extracts through all APIs"))
            return false;
        bool ok = require(metadata->cb_ldv == perbox_ldv,
                          "extract_metadata preserves CB_B +0x23 instead of display +0x3B1");
        ok = require(extracted->metadata.cb_ldv == perbox_ldv,
                     "extract_all preserves CB_B +0x23 instead of display +0x3B1") &&
             ok;
        ok = require(info->bootloaders.cb_b->ldv == 12 && info->bootloaders.cb_ldv == 12,
                     "inspection still reports the independent display LDV") &&
             ok;

        // Exercise both donor-metadata builds and full extract/rebuild workflows.
        for (bool full_extract : {false, true}) {
            auto rebuild_input = full_extract ? *extracted : input;
            if (!full_extract) {
                rebuild_input.metadata = *metadata;
                // extract_metadata supplies donor metadata; the resolver supplies SMC separately.
                rebuild_input.metadata.smc = input.metadata.smc;
            }
            const auto rebuilt = run_build(rebuild_input);
            if (!require(bool(rebuilt), "extracted LDV donor rebuilds"))
                return false;
            const auto decoded = extract_all(*rebuilt, input.metadata.cpu_key);
            if (!require(decoded && decoded->bootloaders.cb_b, "rebuilt CB_B decrypts"))
                return false;
            ok = require((*decoded->bootloaders.cb_b)[0x23] == perbox_ldv &&
                             (*decoded->bootloaders.cb_b)[0x3B1] == 12,
                         "rebuild preserves per-box and display LDV independently") &&
                 ok;
            ok = require(decoded->bootloaders.cb_b == extracted->bootloaders.cb_b,
                         "unchanged CB_B rebuild preserves its authenticated plaintext") &&
                 ok;
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
            const auto result = run_build(input);
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
        const auto built = run_build(input);
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
        const auto built = run_build(input);
        return require(built.has_value(), "encrypted glitch3 replacements build") &&
               check_chain(expected, *built, "encrypted replacement handoff");
    }

    void put_word(Bytes& bytes, size_t offset, uint32_t value) {
        for (size_t i = 0; i < 4; ++i)
            bytes[offset + i] = static_cast<uint8_t>(value >> (24 - 8 * i));
    }

    // RGH2to3 (2to3.py) rewrites four words of a plaintext v1 RGH3 CB_X, the one with
    // 0x646A0002 at +0x354, and leaves every other CB_X as it is.
    bool test_rgh3_v1_cb_x_fix_rewrites_exactly_four_words() {
        auto v1 = cb(15432, 0x800, 0);
        put_word(v1, 0x354, 0x646A0002);
        put_word(v1, 0x368, 0x7D8C502A);
        put_word(v1, 0x370, 0x646A0006);
        put_word(v1, 0x37C, 0xF84A1010);
        auto expected = v1;
        put_word(expected, 0x354, 0x64690002);
        put_word(expected, 0x368, 0x7D8C482A);
        put_word(expected, 0x370, 0x64690006);
        put_word(expected, 0x37C, 0xF8491010);

        auto loader = BootloaderCb::parse(v1);
        loader.decrypted = true;
        bool ok = require(loader.patch_rgh3_v1_cb_x(), "a v1 CB_X is patched") &&
                  require(loader.serialize() == expected, "the v1 fix rewrites exactly four words");
        ok = require(!loader.patch_rgh3_v1_cb_x() && loader.serialize() == expected,
                     "a patched CB_X is not patched again") &&
             ok;

        auto v2 = cb(15432, 0x800, 0);
        put_word(v2, 0x368, 0x7D8C502A);
        auto v2_loader = BootloaderCb::parse(v2);
        v2_loader.decrypted = true;
        ok = require(!v2_loader.patch_rgh3_v1_cb_x() && v2_loader.serialize() == v2,
                     "a v2 CB_X (zero at +0x354) is left unchanged") &&
             ok;

        auto sealed = BootloaderCb::parse(v1);
        sealed.decrypted = false;
        ok = require(!sealed.patch_rgh3_v1_cb_x() && sealed.serialize() == v1,
                     "a sealed CB_X is never patched") &&
             ok;

        auto short_loader = BootloaderCb::parse(Bytes(v1.begin(), v1.begin() + 0x37C));
        short_loader.decrypted = true;
        return require(!short_loader.patch_rgh3_v1_cb_x(),
                       "a CB_X too short for the fix is left unchanged") &&
               ok;
    }

    // A glitch3 build seals the fixed v1 CB_X, or a v2 CB_X unchanged, under
    // HMAC(K_cba, its own nonce || 16 zero bytes), keeping the nonce as supplied.
    bool test_glitch3_seals_cb_x_with_the_v1_fix(bool v1) {
        auto input = fixture(BuildType::Glitch3);
        auto& cb_x = *input.bootloaders.cb_x;
        if (v1) {
            // The v1 templates RGH2to3 handles carry an all-zero nonce.
            std::fill_n(cb_x.begin() + 0x10, 16, 0);
            put_word(cb_x, 0x354, 0x646A0002);
            put_word(cb_x, 0x368, 0x7D8C502A);
            put_word(cb_x, 0x370, 0x646A0006);
            put_word(cb_x, 0x37C, 0xF84A1010);
        } else {
            put_word(cb_x, 0x354, 0);
        }
        auto expected = cb_x;
        if (v1) {
            put_word(expected, 0x354, 0x64690002);
            put_word(expected, 0x368, 0x7D8C482A);
            put_word(expected, 0x370, 0x64690006);
            put_word(expected, 0x37C, 0xF8491010);
        }
        const std::string label = v1 ? "glitch3 v1 CB_X" : "glitch3 v2 CB_X";

        const auto built = run_build(input);
        if (!require(built.has_value(), label + " builds"))
            return false;
        auto image = FlashImage::read(*built);
        if (!require(image && image->parse() && image->cb_section.cb_x, label + " parses"))
            return false;
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        const auto cba_key = encrypt(input.bootloaders.cb_or_a, onebl).second;
        const auto sealed = image->cb_section.cb_x->serialize();
        bool ok = require(sealed == encrypt(expected, cba_key, Bytes(16, 0)).first,
                          label + " is sealed under CB_A's key, its nonce and a zero CPU key");
        ok = require(std::equal(sealed.begin() + 0x10, sealed.begin() + 0x20, cb_x.begin() + 0x10),
                     label + " keeps its nonce as supplied") &&
             ok;
        const auto extracted = extract_all(*built, input.metadata.cpu_key);
        return require(extracted && extracted->bootloaders.cb_x == expected,
                       label + " extracts as the sealed plaintext") &&
               ok;
    }

    // Opens a stage sealed under `key` (RC4 from +0x20) and compares it with its plaintext.
    bool opens_to(Bytes sealed, const Key& key, const Bytes& plain) {
        ExCryptRc4(key.data(), key.size(), sealed.data() + 0x20, sealed.size() - 0x20);
        return sealed == plain;
    }

    // Glitch (RGH1) seals one zero-paired CB: whatever pairing and LDV the console has, the CB
    // per-box block (+0x20..+0x3F) is zero, CD is keyed HMAC(K_cb, nonce) alone, and every CF
    // states no pairing but keeps its LDV and a valid MAC. A retail single CB with the same
    // metadata stays paired and keys CD with the CPU-key second pass.
    bool test_single_cb_pairing(BuildType type, const std::string& name) {
        auto input = fixture(type);
        input.bootloaders.cb_or_a = cb(6750, 0, 0x11);
        input.bootloaders.cb_b.reset();
        input.metadata.pairing_data = {1, 2, 3};
        input.metadata.cb_ldv = 4;
        input.metadata.cf_ldv = 9;
        input.metadata.cf_pairing_data = std::array<uint8_t, 3>{5, 6, 7};
        // A per-box block left in the CB template; zero-pairing clears all of it.
        std::fill(input.bootloaders.cb_or_a.begin() + 0x20,
                  input.bootloaders.cb_or_a.begin() + 0x40, 0xCC);
        BootloaderCf cf{};
        cf.header.header = {NANDBootloaderMagic::CF, 17559, 0, 0, 0, sizeof(cf_header) + 0x340};
        cf.data.assign(0x340, 0);
        cf.decrypted = true;
        input.bootloaders.cf0 = cf.serialize();

        const auto built = run_build(input);
        if (!require(built.has_value(), name + " single-CB image builds"))
            return false;
        auto image = FlashImage::read(*built);
        if (!require(image && image->parse() && image->kernel_section.ce &&
                         image->system_update_0.cf,
                     name + " single-CB image parses"))
            return false;

        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        const bool zero_paired = type == BuildType::Glitch;
        auto cb = image->cb_section.cb_or_A.serialize();
        const Key cb_key = hmac(onebl, Bytes(cb.begin() + 0x10, cb.begin() + 0x20));
        ExCryptRc4(cb_key.data(), cb_key.size(), cb.data() + 0x20, cb.size() - 0x20);
        const Bytes perbox(cb.begin() + 0x20, cb.begin() + 0x40);
        bool ok = true;
        if (zero_paired) {
            ok =
                require(std::all_of(perbox.begin(), perbox.end(), [](uint8_t b) { return b == 0; }),
                        name + " CB per-box block is zero") &&
                ok;
        } else {
            ok = require(perbox[0] == 1 && perbox[1] == 2 && perbox[2] == 3 && perbox[3] == 4,
                         name + " CB states the console pairing and LDV") &&
                 ok;
        }

        const auto cd = image->kernel_section.cd.serialize();
        Key cd_key = hmac(cb_key, Bytes(cd.begin() + 0x10, cd.begin() + 0x20));
        if (!zero_paired) {
            Key cpu{};
            std::copy_n(input.metadata.cpu_key.begin(), cpu.size(), cpu.begin());
            cd_key = hmac(cpu, Bytes(cd_key.begin(), cd_key.end()));
        }
        ok = require(opens_to(cd, cd_key, input.bootloaders.cd),
                     name + (zero_paired ? " CD opens under HMAC(K_cb, nonce) alone"
                                         : " CD opens under the CPU-key second pass")) &&
             ok;
        const auto ce = image->kernel_section.ce->serialize();
        ok = require(opens_to(ce, hmac(cd_key, Bytes(ce.begin() + 0x10, ce.begin() + 0x20)),
                              *input.bootloaders.ce),
                     name + " CE opens under CD's key") &&
             ok;

        auto sealed_cf = BootloaderCf::parse(image->system_update_0.cf->serialize());
        sealed_cf.decrypt(onebl.data());
        if (!require(sealed_cf.parse_perbox(), name + " CF per-box parses"))
            return false;
        const auto& cf_perbox = *sealed_cf.perbox;
        const std::array<uint8_t, 3> expected_pairing =
            zero_paired ? std::array<uint8_t, 3>{} : std::array<uint8_t, 3>{5, 6, 7};
        ok = require(std::equal(expected_pairing.begin(), expected_pairing.end(),
                                std::begin(cf_perbox.pairing_data)),
                     name + (zero_paired ? " CF states no pairing" : " CF states the pairing")) &&
             ok;
        ok = require(cf_perbox.lockdown_value == 9, name + " CF keeps the console's LDV") && ok;
        auto remac = sealed_cf;
        remac.calc_mac(onebl.data(), input.metadata.cpu_key.data());
        return require(remac.data == sealed_cf.data, name + " CF MAC covers what it states") && ok;
    }

    // JTAG seals two chains (xeBuild 1.21). The main chain's single CB is zero-paired, so
    // its CD is keyed HMAC(K_cb, nonce) alone. The second chain's CB carries the console's
    // pairing and CB LDV, bound to the sealed SMC, under HMAC(1BL key, nonce), and its CD is
    // keyed HMAC(K_cb2, nonce) without the CPU key. Both chains take the donor's first CB and
    // CD nonces.
    bool test_jtag_chains() {
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
        BootloaderCd cd{};
        cd.header.header = {NANDBootloaderMagic::CD, 8453, 0, 0, 0, sizeof(cd_header) + 0x20};
        std::fill_n(cd.header.key, 16, 0x88);
        cd.header.ce_hash[0] = 1;
        cd.data.assign(0x20, 0xDC);
        cd.decrypted = true;
        const Bytes extra_cd = cd.serialize();
        input.bootloaders.extra_cb = extra_cb;
        input.bootloaders.extra_cd = extra_cd;

        const auto built = run_build(input);
        if (!require(built.has_value(), "JTAG image builds"))
            return false;
        auto image = FlashImage::read(*built);
        if (!require(image && image->parse() && image->smc && image->smc->encrypted,
                     "JTAG image parses with a sealed SMC"))
            return false;

        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        auto main_cb = image->cb_section.cb_or_A.serialize();
        const Key cb_key = hmac(onebl, Bytes(main_cb.begin() + 0x10, main_cb.begin() + 0x20));
        ExCryptRc4(cb_key.data(), cb_key.size(), main_cb.data() + 0x20, main_cb.size() - 0x20);
        bool ok = require(std::all_of(main_cb.begin() + 0x20, main_cb.begin() + 0x40,
                                      [](uint8_t b) { return b == 0; }),
                          "JTAG main CB per-box block is zero");
        const auto main_cd = image->kernel_section.cd.serialize();
        const Key cd_key = hmac(cb_key, Bytes(main_cd.begin() + 0x10, main_cd.begin() + 0x20));
        ok = require(opens_to(main_cd, cd_key, input.bootloaders.cd),
                     "JTAG main CD opens under HMAC(K_cb, nonce) alone") &&
             ok;

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
            hmac(onebl, Bytes(expected_cb.begin() + 0x10, expected_cb.begin() + 0x20));
        const Bytes head{1, 2, 3, 4};
        std::copy(head.begin(), head.end(), expected_cb.begin() + 0x20);
        expected_cb =
            authenticate(expected_cb, second_cb_key, input.metadata.cpu_key, image->smc->data);
        ok = require(opens_to(second_cb, second_cb_key, expected_cb),
                     "JTAG second CB opens under HMAC(1BL, nonce), paired and bound to the SMC") &&
             ok;
        ok = require(std::any_of(expected_cb.begin() + 0x30, expected_cb.begin() + 0x40,
                                 [](uint8_t b) { return b != 0; }),
                     "JTAG second CB digest is not zero") &&
             ok;
        Bytes expected_cd = extra_cd;
        std::fill_n(expected_cd.begin() + 0x10, 0x10, 0x44);
        const Key second_cd_key =
            hmac(second_cb_key, Bytes(expected_cd.begin() + 0x10, expected_cd.begin() + 0x20));
        return require(opens_to(second_cd, second_cd_key, expected_cd),
                       "JTAG second CD opens under HMAC(K_cb2, nonce) without the CPU key") &&
               ok;
    }

    // The CG RC4 key is HMAC-SHA1(CF_dec[0x330:0x340], CG[0x10:0x20]): the 7BL nonce
    // inside the decrypted CF payload, not the CF header fixpoint at +0x20. A
    // gxbuild3-only round-trip cannot catch a wrong key source because encrypt and
    // decrypt would share it, so this rebuilds a synthetic CF/CG pair whose payload
    // nonce differs from the header fixpoint and decrypts the result independently.
    bool test_cg_decrypts_with_cf_payload_nonce() {
        auto input = fixture(BuildType::Retail);

        // Decrypted CF whose 7BL nonce (payload +0x300 == serialized +0x330) is
        // 0xA0..0xAF, deliberately different from the zeroed header fixpoint at +0x20.
        BootloaderCf cf{};
        cf.header.header = {NANDBootloaderMagic::CF, 17559, 0, 0, 0, sizeof(cf_header) + 0x340};
        cf.data.assign(0x340, 0);
        for (size_t i = 0; i < 16; ++i)
            cf.data[0x300 + i] = static_cast<uint8_t>(0xA0 + i);
        cf.decrypted = true;
        input.bootloaders.cf0 = cf.serialize();

        // Decrypted CG: a non-zero header key survives encryption unchanged, and a
        // 0x1000-aligned source_size makes the CG plaintext heuristic recognise it.
        BootloaderCg cg{};
        cg.header.header = {NANDBootloaderMagic::CG, 17559, 0, 0, 0, sizeof(cg_header) + 0x40};
        std::fill_n(cg.header.key, 16, 0x77);
        cg.header.source_size = 0x1000;
        cg.data.assign(0x40, 0xEE);
        cg.decrypted = true;
        const Bytes cg_input = cg.serialize();
        input.bootloaders.cg0 = cg_input;

        const auto built = run_build(input);
        if (!require(bool(built), "cf/cg retail image builds"))
            return false;
        auto image = FlashImage::read(*built);
        if (!require(image && image->parse(), "cf/cg image parses"))
            return false;
        if (!require(bool(image->system_update_0.cf && image->system_update_0.cg),
                     "parse populates CF0 and CG0"))
            return false;

        // Independent oracle: CF is RC4'd from 0x30 under HMAC(1BL, CF[0x20:0x30]); the
        // recovered payload nonce at 0x330 then keys the CG (RC4 from 0x20).
        const Key onebl{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                        0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
        Bytes cf_bytes = image->system_update_0.cf->serialize();
        if (!require(cf_bytes.size() >= 0x340, "on-NAND CF reaches the 7BL nonce"))
            return false;
        const Key cf_key = hmac(onebl, Bytes(cf_bytes.begin() + 0x20, cf_bytes.begin() + 0x30));
        ExCryptRc4(cf_key.data(), cf_key.size(), cf_bytes.data() + 0x30, cf_bytes.size() - 0x30);
        Bytes expected_nonce(16);
        for (size_t i = 0; i < 16; ++i)
            expected_nonce[i] = static_cast<uint8_t>(0xA0 + i);
        const Bytes planted(cf_bytes.begin() + 0x330, cf_bytes.begin() + 0x340);
        if (!require(planted == expected_nonce, "CF payload 7BL nonce survives the build"))
            return false;

        Bytes cg_bytes = image->system_update_0.cg->serialize();
        if (!require(cg_bytes.size() >= 0x20, "on-NAND CG has a header key"))
            return false;
        Key cg_parent{};
        std::copy_n(planted.begin(), 16, cg_parent.begin());
        const Key cg_key = hmac(cg_parent, Bytes(cg_bytes.begin() + 0x10, cg_bytes.begin() + 0x20));
        ExCryptRc4(cg_key.data(), cg_key.size(), cg_bytes.data() + 0x20, cg_bytes.size() - 0x20);
        // Without a donor the CG is sealed under a fresh random nonce, stored in clear.
        Bytes expected_cg = cg_input;
        std::copy_n(cg_bytes.begin() + 0x10, 0x10, expected_cg.begin() + 0x10);
        return require(!std::equal(cg_bytes.begin() + 0x10, cg_bytes.begin() + 0x20,
                                   cg_input.begin() + 0x10),
                       "CG without a donor takes a fresh nonce") &&
               require(cg_bytes == expected_cg, "CG decrypts with the CF payload nonce at +0x330");
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
    ok = test_build_policy(BuildType::Glitch2m, "glitch2m manufacturing", 0x0801) && ok;
    ok = test_build_policy(BuildType::Glitch2m, "glitch2m manufacturing v2", 0x1801) && ok;
    ok = test_build_policy(BuildType::Retail, "retail manufacturing", 0x0801) && ok;
    ok = test_build_policy(BuildType::Glitch3, "glitch3") && ok;
    ok = test_build_policy(BuildType::Glitch3, "glitch3 v2", 0x1800) && ok;
    ok = test_single_cb_pairing(BuildType::Glitch, "glitch1") && ok;
    ok = test_single_cb_pairing(BuildType::Retail, "retail") && ok;
    ok = test_jtag_chains() && ok;
    ok = test_glitch3_requires_cb_x_and_cb_b() && ok;
    ok = test_patched_stages_are_encrypted_for_their_parent(BuildType::Glitch2) && ok;
    ok = test_patched_stages_are_encrypted_for_their_parent(BuildType::Glitch3) && ok;
    ok = test_glitch3_encrypted_replacement_preserves_handoff_key() && ok;
    ok = test_rgh3_v1_cb_x_fix_rewrites_exactly_four_words() && ok;
    ok = test_glitch3_seals_cb_x_with_the_v1_fix(true) && ok;
    ok = test_glitch3_seals_cb_x_with_the_v1_fix(false) && ok;
    ok = test_cg_decrypts_with_cf_payload_nonce() && ok;
    for (int change = 0; change < 5; ++change) {
        ok = test_retail_digest(false, 0, change) && ok;
        ok = test_retail_digest(true, 0x800, change) && ok;
        ok = test_retail_digest(true, 0x1800, change) && ok;
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
