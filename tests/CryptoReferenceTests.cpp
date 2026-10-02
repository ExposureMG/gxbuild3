// Seals checked against bytes produced by the xerunner reference builder
// (src/xebuild/chain/sealing.py `keys` + crypto/formats.py `encrypt_bootloader`),
// run over the release files in tests/gxBuild-support-files/common.

#include "excrypt.h"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
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
} // namespace

int main() {
    bool ok = test_sc_seals_like_xerunner();
    ok = test_packer_seals_devkit_chain_like_xerunner() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
