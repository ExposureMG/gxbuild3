#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string_view>
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

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
        }
        return condition;
    }

    // The all-zero CPU key is accepted as a key: an image bound to no console is built under it.
    bool test_the_all_zero_cpu_key_is_accepted() {
        const std::array<uint8_t, 16> zero{};
        const auto parsed = validate_cpu_key_hex("00000000000000000000000000000000");
        return require(
                   parsed.status == CpuKeyStatus::Valid &&
                       std::equal(parsed.key.begin(), parsed.key.end(), zero.begin(), zero.end()),
                   "the all-zero CPU key validates") &&
               require(gxbuild3::NAND::cpukey_valid(zero) && is_zero_cpu_key(zero) &&
                           !is_zero_cpu_key(cpu_key),
                       "the all-zero CPU key is usable and recognised") &&
               require(validate_cpu_key_hex("00000000000000000000000000000001").status ==
                           CpuKeyStatus::Invalid,
                       "a key that is neither zero nor ECC-valid is still refused");
    }

    // A kv.bin sealed under the CPU key is opened; one in the clear (0x4000 with a stale nonce,
    // or 0x3FF0 without one) is taken as it stands; any other length is refused.
    bool test_a_loose_keyvault_is_opened_or_taken_in_the_clear() {
        std::vector<uint8_t> plain(Keyvault::kSize);
        for (size_t index = 0; index < plain.size(); ++index) {
            plain[index] = static_cast<uint8_t>(index * 7);
        }
        const auto sealed = keyvault_encrypt(cpu_key, plain);
        const auto canonical = keyvault_decrypt(cpu_key, sealed);
        const auto opened = open_loose_keyvault(cpu_key, sealed);
        const auto clear = open_loose_keyvault(cpu_key, plain);
        const std::vector<uint8_t> body(plain.begin() + 0x10, plain.end());
        const auto bare = open_loose_keyvault(cpu_key, body);
        const std::array<uint8_t, 16> zero{};
        const auto under_zero = open_loose_keyvault(zero, keyvault_encrypt(zero, plain));
        std::vector<uint8_t> zero_nonce = plain;
        std::fill(zero_nonce.begin(), zero_nonce.begin() + 0x10, 0);
        return require(opened && opened->was_sealed && opened->plain == canonical,
                       "a sealed kv.bin is opened") &&
               require(clear && !clear->was_sealed && clear->plain == plain,
                       "a kv.bin in the clear is taken as it stands") &&
               require(bare && !bare->was_sealed && bare->plain == zero_nonce,
                       "a 0x3FF0 kv.bin gets sixteen zero bytes in front") &&
               require(under_zero && under_zero->was_sealed,
                       "a kv.bin sealed under the all-zero CPU key opens under it") &&
               require(!open_loose_keyvault(cpu_key, std::vector<uint8_t>(0x100)),
                       "a kv.bin of another length is refused");
    }

} // namespace

int main() {
    bool passed = test_the_all_zero_cpu_key_is_accepted();
    passed = test_a_loose_keyvault_is_opened_or_taken_in_the_clear() && passed;
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
