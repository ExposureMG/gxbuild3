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
            const auto cbx = encrypt(*input.bootloaders.cb_x, cba_key, suffix).first;
            ok = require(image->cb_section.cb_x && image->cb_section.cb_x->serialize() == cbx,
                         label + " CB_X is encrypted with CB_A and a zero CPU key") &&
                 ok;
            ok = require(image->cb_section.cb_B &&
                             image->cb_section.cb_B->serialize() == *input.bootloaders.cb_b,
                         label + " CB_B is plaintext") &&
                 ok;
        } else if (input.bootloaders.cb_b) {
            const auto [cbb, key] = encrypt(*input.bootloaders.cb_b, cba_key, suffix);
            cd_parent = key;
            ok = require(image->cb_section.cb_B && image->cb_section.cb_B->serialize() == cbb,
                         label + " CB_B remains encrypted") &&
                 ok;
        }
        const bool plaintext_cd = input.build_type == BuildType::Glitch2 ||
                                  input.build_type == BuildType::Glitch2m ||
                                  input.build_type == BuildType::Glitch3;
        const auto cd =
            plaintext_cd ? input.bootloaders.cd : encrypt(input.bootloaders.cd, cd_parent).first;
        ok = require(image->kernel_section.cd.serialize() == cd,
                     label + (plaintext_cd ? " CD is plaintext" : " CD remains encrypted")) &&
             ok;
        Key cd_nonce{};
        std::copy_n(input.bootloaders.cd.begin() + 0x10, 16, cd_nonce.begin());
        ok = require(image->kernel_section.ce && image->kernel_section.ce->serialize() ==
                                                     encrypt(*input.bootloaders.ce, cd_nonce).first,
                     label + " CE remains encrypted") &&
             ok;
        return ok;
    }

    bool test_build_policy(BuildType type, const std::string& name, uint16_t flags = 0x800) {
        auto input = fixture(type, flags);
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

    bool test_patched_plaintext_stages(BuildType type) {
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
        return check_chain(input, *built, "patched plaintext stages");
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
    bool ok = test_build_policy(BuildType::Retail, "retail");
    ok = test_build_policy(BuildType::Glitch, "glitch1") && ok;
    ok = test_build_policy(BuildType::Glitch2, "glitch2") && ok;
    ok = test_build_policy(BuildType::Glitch2m, "glitch2m") && ok;
    ok = test_build_policy(BuildType::Glitch3, "glitch3") && ok;
    ok = test_build_policy(BuildType::Glitch3, "glitch3 v2", 0x1800) && ok;
    ok = test_glitch3_requires_cb_x_and_cb_b() && ok;
    ok = test_patched_plaintext_stages(BuildType::Glitch2) && ok;
    ok = test_patched_plaintext_stages(BuildType::Glitch3) && ok;
    ok = test_glitch3_encrypted_replacement_preserves_handoff_key() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
