#include "bootloaders/Keyvault.hpp"

#include "excrypt.h"

#include <cstring>
#include <random>
#include <stdexcept>

uint32_t hamming_weight(const uint8_t* data, size_t size) {
    uint32_t wght = 0;
    for (size_t i = 0; i < size; ++i) {
        uint8_t val = data[i];
        for (int j = 0; j < 8; ++j) {
            wght += val & 1;
            val >>= 1;
        }
    }
    return wght;
}

std::vector<uint8_t> uid_ecc_encode(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out_data = data;
    if (out_data.size() < 0x10) {
        out_data.resize(0x10, 0);
    }
    uint32_t acc1 = 0;
    uint32_t acc2 = 0;
    for (int cnt = 0; cnt < 0x80; ++cnt) {
        acc1 >>= 1;
        uint8_t b_tmp = out_data[cnt >> 3];
        uint32_t dw_tmp = (b_tmp >> (cnt & 7)) & 1;
        if (cnt < 0x6A) {
            acc1 ^= dw_tmp;
            if (acc1 & 1) {
                acc1 ^= 0x360325;
            }
            acc2 ^= dw_tmp;
        } else if (cnt < 0x7F) {
            if (dw_tmp != (acc1 & 1)) {
                out_data[cnt >> 3] = (1 << (cnt & 7)) ^ b_tmp;
            }
            acc2 ^= (acc1 & 1);
        } else if (dw_tmp != acc2) {
            out_data[0xF] = (0x80 ^ b_tmp) & 0xFF;
        }
    }
    return out_data;
}

bool cpukey_valid(const std::vector<uint8_t>& cpu_key) {
    if (cpu_key.size() != 0x10) {
        return false;
    }

    const uint8_t wght_mask[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x00};

    std::vector<uint8_t> key_tmp(0x10);
    for (int i = 0; i < 0x10; ++i) {
        key_tmp[i] = cpu_key[i] & wght_mask[i];
    }

    uint32_t wght = hamming_weight(key_tmp.data(), key_tmp.size());
    std::vector<uint8_t> ecc_key = uid_ecc_encode(key_tmp);

    bool ecc_good = (cpu_key == ecc_key);
    bool wght_good = (wght == 0x35);

    return ecc_good && wght_good;
}

void ExCryptRandom(uint8_t* dest, size_t size) {
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<uint32_t> distribution(0, 255);
    for (size_t i = 0; i < size; ++i) {
        dest[i] = static_cast<uint8_t>(distribution(generator));
    }
}

std::vector<uint8_t> keyvault_decrypt(const std::vector<uint8_t>& cpu_key,
                                      const std::vector<uint8_t>& data,
                                      uint16_t kv_version) {
    if (!cpukey_valid(cpu_key)) {
        throw std::runtime_error("Invalid CPU key");
    }
    if (data.size() < 0x10) {
        throw std::runtime_error("Invalid data size");
    }

    std::vector<uint8_t> out_data = data;

    uint8_t kv_hash[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data(), 0x10,
                   nullptr, 0, nullptr, 0, kv_hash, 20);

    if (out_data.size() > 0x10) {
        ExCryptRc4(kv_hash, 16, out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10));
    }

    const uint8_t version[2] = {static_cast<uint8_t>((kv_version >> 8) & 0xFF),
                                static_cast<uint8_t>(kv_version & 0xFF)};
    uint8_t kv_hash2[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10), version, 2, nullptr, 0, kv_hash2,
                   20);

    if (std::memcmp(out_data.data(), kv_hash2, 0x10) != 0) {
        throw std::runtime_error("Invalid KV digest");
    }

    return out_data;
}

std::vector<uint8_t> keyvault_encrypt(const std::vector<uint8_t>& cpu_key,
                                      const std::vector<uint8_t>& data,
                                      uint16_t kv_version) {
    if (!cpukey_valid(cpu_key)) {
        throw std::runtime_error("Invalid CPU key");
    }
    if (data.size() < 0x18) {
        throw std::runtime_error("Invalid data size");
    }

    std::vector<uint8_t> out_data = data;

    const uint8_t version[2] = {static_cast<uint8_t>((kv_version >> 8) & 0xFF),
                                static_cast<uint8_t>(kv_version & 0xFF)};
    uint8_t kv_hash[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data() + 0x10,
                   static_cast<uint32_t>(out_data.size() - 0x10), version, 2, nullptr, 0, kv_hash,
                   20);
    std::memcpy(out_data.data(), kv_hash, 16);

    uint8_t rc4_key[20];
    ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()), out_data.data(), 0x10,
                   nullptr, 0, nullptr, 0, rc4_key, 20);

    if (out_data.size() > 0x10) {
        ExCryptRc4(rc4_key, 16, out_data.data() + 0x10,
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

bool keyvault_is_encrypted(const std::vector<uint8_t>& cpu_key, const std::vector<uint8_t>& data,
                           uint16_t kv_version) {
    if (!cpukey_valid(cpu_key) || data.size() < 0x18) {
        return false;
    }
    try {
        keyvault_decrypt(cpu_key, data, kv_version);
        return true;
    } catch (...) {
        return false;
    }
}

bool keyvault_verify(const std::vector<uint8_t>& cpu_key, const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& pub_key) {
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

    return ExKeysPkcs1Verify(kv_hash, kv_data + 0x1DE0,
                             reinterpret_cast<EXCRYPT_RSA*>(const_cast<void*>(static_cast<const void*>(pub_key.data())))) != 0;
}