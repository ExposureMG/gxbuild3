#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

    std::vector<uint8_t> read_file(const char* path, size_t maximum_size,
                                   std::string_view label) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Cannot open " + std::string(label));
        }
        const auto size = file.tellg();
        if (size < 0 || size > static_cast<std::streamoff>(maximum_size)) {
            throw std::runtime_error("Invalid file size for " + std::string(label));
        }
        std::vector<uint8_t> bytes(static_cast<size_t>(size));
        file.seekg(0);
        if (!file.read(reinterpret_cast<char*>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()))) {
            throw std::runtime_error("Cannot read " + std::string(label));
        }
        return bytes;
    }

    bool compare(std::span<const uint8_t> actual, std::span<const uint8_t> expected,
                 std::string_view label) {
        if (actual.size() != expected.size()) {
            std::cerr << "FAIL: " << label << " returned an incorrect size\n";
            return false;
        }
        const auto mismatch = std::mismatch(actual.begin(), actual.end(), expected.begin());
        if (mismatch.first != actual.end()) {
            // Report the location, never console-specific keyvault bytes.
            std::cerr << "FAIL: " << label << " differs from reference at offset 0x"
                      << std::hex << (mismatch.first - actual.begin()) << std::dec << '\n';
            return false;
        }
        return true;
    }

} // namespace

int main(int argc, char** argv) {
    if ((argc != 4 && argc != 5) ||
        (argc == 5 && std::string_view(argv[4]) != "--skip-if-missing")) {
        std::cerr << "Usage: gxbuild3_keyvault_crypto_tests <cpu-key.txt> "
                     "<encrypted-kv.bin> <decrypted-kv.bin> [--skip-if-missing]\n";
        return 1;
    }

    try {
        if (argc == 5 && !std::filesystem::exists(argv[1]) &&
            !std::filesystem::exists(argv[2]) && !std::filesystem::exists(argv[3])) {
            std::cout << "SKIP: private keyvault fixtures are not installed\n";
            return 77;
        }

        const auto key_file = read_file(argv[1], 1024, "CPU key fixture");
        std::string hex(key_file.begin(), key_file.end());
        const auto first = hex.find_first_not_of(" \t\r\n");
        const auto last = hex.find_last_not_of(" \t\r\n");
        hex = first == std::string::npos ? "" : hex.substr(first, last - first + 1);
        const auto cpu_key = validate_cpu_key_hex(hex);
        if (cpu_key.status != CpuKeyStatus::Valid) {
            // Validation messages can contain corrected CPU keys; do not print them.
            throw std::runtime_error("CPU key fixture must contain a valid, uncorrected "
                                     "32-character hexadecimal CPU key");
        }

        const auto encrypted = read_file(argv[2], Keyvault::kSize, "encrypted keyvault");
        const auto expected = read_file(argv[3], Keyvault::kSize, "decrypted keyvault");
        if (encrypted.size() != Keyvault::kSize || expected.size() != Keyvault::kSize) {
            throw std::runtime_error("Both keyvault fixtures must be exactly 16384 bytes");
        }

        // The expected bytes come exclusively from the independent reference file,
        // never from keyvault_encrypt: matching bugs must not cancel each other out.
        bool passed = true;
        try {
            passed = compare(keyvault_decrypt(cpu_key.key, encrypted), expected,
                             "keyvault_decrypt");
        } catch (const std::exception& error) {
            std::cerr << "FAIL: keyvault_decrypt: " << error.what() << '\n';
            passed = false;
        }

        auto keyvault = Keyvault::parse(encrypted);
        if (!keyvault || !keyvault->decrypt(cpu_key.key)) {
            std::cerr << "FAIL: Keyvault::decrypt rejected the encrypted fixture\n";
            passed = false;
        } else {
            passed = compare(keyvault->serialize(), expected, "Keyvault::decrypt") && passed;
            if (keyvault->encrypted) {
                std::cerr << "FAIL: Keyvault::decrypt did not clear the encrypted flag\n";
                passed = false;
            }
        }
        if (passed) {
            std::cout << "PASS: both decryption APIs match all 16384 reference bytes\n";
        }
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
