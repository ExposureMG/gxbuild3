#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

    // Public synthetic CPU key already used by CliFixtureGenerator.cpp.
    constexpr std::array<uint8_t, 16> cpu_key{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0xe5, 0x8d,
    };

    // Independent Python hashlib/hmac + RC4 vectors for payload bytes 00..0f.
    // Nonce = HMAC-SHA1(cpu_key, payload || version_be)[:16].
    // RC4 key = HMAC-SHA1(cpu_key, nonce)[:16]. No private console data.
    struct Vector {
        uint16_t version;
        std::array<uint8_t, 32> encrypted;
    };
    constexpr Vector vectors[]{
        {0x0712, {
            0x78, 0x79, 0xd3, 0xd4, 0xd4, 0xe3, 0xa9, 0x1f,
            0xa8, 0x5d, 0x1c, 0x88, 0x62, 0x33, 0x61, 0x1b,
            0xf2, 0x58, 0xb6, 0x8d, 0xf1, 0xff, 0xef, 0x2e,
            0x4e, 0xb8, 0xde, 0x6f, 0xc8, 0xbc, 0x44, 0xd2,
        }},
        {0x1234, {
            0xff, 0xda, 0xb6, 0x58, 0xd2, 0xb5, 0xf5, 0x1f,
            0xbf, 0x3b, 0xc1, 0xaf, 0xa2, 0x5e, 0xdb, 0xe6,
            0x17, 0x90, 0x39, 0x2a, 0x46, 0x2c, 0x67, 0x95,
            0xb4, 0xf9, 0x7c, 0x3a, 0xe5, 0x46, 0x1d, 0xf2,
        }},
    };

} // namespace

int main() {
    bool passed = true;
    for (const auto& vector : vectors) {
        std::vector<uint8_t> plaintext(vector.encrypted.begin(), vector.encrypted.begin() + 16);
        for (uint8_t byte = 0; byte < 16; ++byte) {
            plaintext.push_back(byte);
        }
        try {
            const auto encrypted = keyvault_encrypt(cpu_key, plaintext, vector.version);
            if (!std::equal(encrypted.begin(), encrypted.end(),
                            vector.encrypted.begin(), vector.encrypted.end())) {
                std::cerr << "FAIL: encryption must include the big-endian version\n";
                passed = false;
            }
            if (keyvault_decrypt(cpu_key, vector.encrypted, vector.version) != plaintext) {
                std::cerr << "FAIL: decryption differs from independent plaintext\n";
                passed = false;
            }
            try {
                (void)keyvault_decrypt(cpu_key, vector.encrypted, vector.version ^ 1);
                std::cerr << "FAIL: wrong version must fail authentication\n";
                passed = false;
            } catch (const std::runtime_error& error) {
                if (std::string_view(error.what()) != "Keyvault authentication failed") {
                    throw;
                }
            }
        } catch (const std::exception& error) {
            std::cerr << "FAIL: version vector: " << error.what() << '\n';
            passed = false;
        }
    }
    return passed ? 0 : 1;
}
