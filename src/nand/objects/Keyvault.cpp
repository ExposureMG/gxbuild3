#include "nand/objects/Keyvault.hpp"
#include "utils/Log.hpp"

#include "excrypt.h"

#include <bit>
#include <cstring>
#include <random>
#include <stdexcept>

namespace gxbuild3::NAND {

namespace {

    std::string bytes_to_hex(std::span<const uint8_t> bytes) {
        static constexpr char hex_chars[] = "0123456789ABCDEF";
        std::string hex;
        hex.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            hex.push_back(hex_chars[(b >> 4) & 0x0F]);
            hex.push_back(hex_chars[b & 0x0F]);
        }
        return hex;
    }

    uint32_t cpu_key_hamming_weight(const uint8_t cpu_key[16]) {
        static constexpr uint8_t wght_mask[16] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x00
        };
        uint32_t count = 0;
        for (size_t i = 0; i < 16; ++i) {
            uint8_t val = cpu_key[i] & wght_mask[i];
            count += std::popcount(val);
        }
        return count;
    }

} // namespace

CpuKeyResult validate_cpu_key(std::span<const uint8_t> cpu_key) {
    CpuKeyResult result{};
    if (cpu_key.size() != 16) {
        result.status = CpuKeyStatus::Invalid;
        result.message = "Invalid CPU key length: expected 16 bytes";
        return result;
    }

    uint8_t key_copy[16];
    std::memcpy(key_copy, cpu_key.data(), 16);

    int res = XeCryptUidEccDecode(key_copy);
    result.key.assign(key_copy, key_copy + 16);

    if (res < 0 || cpu_key_hamming_weight(key_copy) != 0x35) {
        result.status = CpuKeyStatus::Invalid;
        result.message = "Invalid CPU key: uncorrectable ECC checksum errors";
        return result;
    }

    if (res == 0) {
        result.status = CpuKeyStatus::Valid;
        result.message = "CPU key is valid";
    } else {
        result.status = CpuKeyStatus::Corrected;
        result.message = "Invalid CPU key (" + std::to_string(res) +
                         " bit error(s) corrected). Corrected CPU key: " + bytes_to_hex(result.key);
    }

    return result;
}

CpuKeyResult validate_cpu_key_hex(std::string_view hex) {
    CpuKeyResult result{};
    if (hex.size() != 32) {
        result.status = CpuKeyStatus::Invalid;
        result.message = "Invalid CPU key length: expected 32 hex characters";
        return result;
    }

    std::vector<uint8_t> raw(16);
    for (size_t i = 0; i < 16; ++i) {
        auto from_hex = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        int h = from_hex(hex[i * 2]);
        int l = from_hex(hex[i * 2 + 1]);
        if (h < 0 || l < 0) {
            result.status = CpuKeyStatus::Invalid;
            result.message = "Invalid CPU key: contains non-hexadecimal characters";
            return result;
        }
        raw[i] = static_cast<uint8_t>((h << 4) | l);
    }

    return validate_cpu_key(raw);
}

bool cpukey_valid(std::span<const uint8_t> cpu_key) {
    if (cpu_key.size() != 0x10) {
        return false;
    }
    uint8_t key_copy[16];
    std::memcpy(key_copy, cpu_key.data(), 16);
    if (XeCryptUidEccDecode(key_copy) < 0) {
        return false;
    }
    return cpu_key_hamming_weight(key_copy) == 0x35;
}

} // namespace gxbuild3::NAND

void ExCryptRandom(uint8_t* dest, size_t size) {
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<uint32_t> distribution(0, 255);
    for (size_t i = 0; i < size; ++i) {
        dest[i] = static_cast<uint8_t>(distribution(generator));
    }
}

namespace gxbuild3::NAND {

std::vector<uint8_t> keyvault_decrypt(std::span<const uint8_t> cpu_key,
                                      std::span<const uint8_t> data, uint16_t) {
    if (!cpukey_valid(cpu_key)) {
        throw std::runtime_error("Invalid CPU key");
    }
    if (data.size() < 0x10) {
        throw std::runtime_error("Invalid data size");
    }

    std::vector<uint8_t> out_data(data.begin(), data.end());

    uint8_t kv_hash[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data(), 0x10,
                   nullptr, 0, nullptr, 0, kv_hash, 20);

    if (out_data.size() > 0x10) {
        ExCryptRc4(kv_hash, 16, out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10));
    }

    uint8_t kv_digest[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10), nullptr, 0, nullptr, 0,
                   kv_digest, 20);

    return out_data;
}

std::vector<uint8_t> keyvault_encrypt(std::span<const uint8_t> cpu_key,
                                      std::span<const uint8_t> data, uint16_t) {
    if (!cpukey_valid(cpu_key)) {
        throw std::runtime_error("Invalid CPU key");
    }
    if (data.size() < 0x10) {
        throw std::runtime_error("Invalid data size");
    }

    std::vector<uint8_t> out_data(data.begin(), data.end());

    uint8_t kv_digest[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10), nullptr, 0, nullptr, 0,
                   kv_digest, 20);

    std::memcpy(out_data.data(), kv_digest, 0x10);

    uint8_t kv_hash[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data(), 0x10,
                   nullptr, 0, nullptr, 0, kv_hash, 20);

    if (out_data.size() > 0x10) {
        ExCryptRc4(kv_hash, 16, out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10));
    }

    return out_data;
}

bool crypt_secfile(std::span<const uint8_t> cpu_key, std::span<uint8_t> data) {
    if (cpu_key.size() != 16 || data.size() < 0x10) {
        return false;
    }
    uint8_t key[20] = {0};
    ExCryptHmacSha(cpu_key.data(), 16, data.data(), 0x10, nullptr, 0, nullptr, 0, key, 20);
    ExCryptRc4(key, 16, data.data() + 0x10, static_cast<uint32_t>(data.size() - 0x10));
    return true;
}

bool keyvault_verify(std::span<const uint8_t> cpu_key, std::span<const uint8_t> data,
                     std::span<const uint8_t> pub_key) {
    if (!cpukey_valid(cpu_key)) {
        return false;
    }
    if (data.size() < 0x18 + 0x3FE8) {
        return false;
    }

    const uint8_t* kv_data = data.data() + 0x18;

    uint8_t kv_hash[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), kv_data + 4, 0xD4,
                   kv_data + 0xE8, 0x1CF8, kv_data + 0x1EE0, 0x2108, kv_hash, 20);

    return ExKeysPkcs1Verify(
               kv_hash, kv_data + 0x1DE0,
               reinterpret_cast<EXCRYPT_RSA*>(
                   const_cast<void*>(static_cast<const void*>(pub_key.data())))) != 0;
}

std::optional<Keyvault> Keyvault::parse(std::span<const uint8_t> bytes) {
    if (bytes.size() != kSize) {
        Log::Error("Invalid Keyvault size: expected {} bytes, got {}", kSize, bytes.size());
        return std::nullopt;
    }

    Keyvault kv;
    kv.raw_data.assign(bytes.begin(), bytes.end());
    std::memcpy(&kv.data, bytes.data(), sizeof(XE_KEYVAULT_DATA));
    kv.encrypted = true;
    Log::Debug("Parsed Keyvault (0x{:X} bytes)", bytes.size());
    return kv;
}

std::optional<Keyvault> Keyvault::parse(const std::vector<uint8_t>& bytes) {
    return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
}

bool Keyvault::is_encrypted(std::span<const uint8_t> cpu_key) const {
    if (!cpukey_valid(cpu_key)) {
        return false;
    }
    return encrypted;
}

bool Keyvault::decrypt(std::span<const uint8_t> cpu_key) {
    if (!encrypted) {
        return true;
    }
    if (!cpukey_valid(cpu_key)) {
        Log::Error("Cannot decrypt Keyvault: invalid CPU key");
        return false;
    }
    try {
        raw_data = keyvault_decrypt(cpu_key, raw_data);
        std::memcpy(&data, raw_data.data(), sizeof(XE_KEYVAULT_DATA));
        encrypted = false;
        Log::Debug("Keyvault decrypted successfully");
        return true;
    } catch (const std::exception& e) {
        Log::Error("Keyvault decryption failed: {}", e.what());
        return false;
    }
}

bool Keyvault::encrypt(std::span<const uint8_t> cpu_key) {
    if (encrypted) {
        return true;
    }
    if (!cpukey_valid(cpu_key)) {
        Log::Error("Cannot encrypt Keyvault: invalid CPU key");
        return false;
    }
    try {
        raw_data = keyvault_encrypt(cpu_key, raw_data);
        std::memcpy(&data, raw_data.data(), sizeof(XE_KEYVAULT_DATA));
        encrypted = true;
        Log::Debug("Keyvault encrypted successfully");
        return true;
    } catch (const std::exception& e) {
        Log::Error("Keyvault encryption failed: {}", e.what());
        return false;
    }
}

bool Keyvault::verify(std::span<const uint8_t> cpu_key, std::span<const uint8_t> pub_key) const {
    bool ok = keyvault_verify(cpu_key, raw_data, pub_key);
    if (!ok) {
        Log::Warn("Keyvault RSA PKCS#1 signature verification failed");
    } else {
        Log::Debug("Keyvault RSA PKCS#1 signature verified successfully");
    }
    return ok;
}

std::vector<uint8_t> Keyvault::serialize() const {
    if (raw_data.size() == kSize) {
        return raw_data;
    }
    std::vector<uint8_t> out(kSize, 0x00);
    std::memcpy(out.data(), &data, sizeof(XE_KEYVAULT_DATA));
    return out;
}

} // namespace gxbuild3::NAND