#include "nand/objects/Keyvault.hpp"

#include "excrypt.h"
#include "utils/Log.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <random>
#include <stdexcept>

namespace gxbuild3::nand {

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
            static constexpr uint8_t wght_mask[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                                      0xFF, 0x03, 0x00, 0x00};
            uint32_t count = 0;
            for (size_t i = 0; i < 16; ++i) {
                uint8_t val = cpu_key[i] & wght_mask[i];
                count += std::popcount(val);
            }
            return count;
        }

    } // namespace

    bool is_zero_cpu_key(std::span<const uint8_t> cpu_key) {
        return cpu_key.size() == 16 &&
               std::all_of(cpu_key.begin(), cpu_key.end(), [](uint8_t byte) { return byte == 0; });
    }

    CpuKeyResult validate_cpu_key(std::span<const uint8_t> cpu_key) {
        CpuKeyResult result{};
        if (cpu_key.size() != 16) {
            result.status = CpuKeyStatus::Invalid;
            result.message = "Invalid CPU key length: expected 16 bytes";
            return result;
        }

        // Sixteen zero bytes are no console's key, but an image bound to no console is built under
        // them (a manufacturing console whose key is unknown), as xeBuild 1.21 builds one.
        if (is_zero_cpu_key(cpu_key)) {
            result.status = CpuKeyStatus::Valid;
            result.key.assign(cpu_key.begin(), cpu_key.end());
            result.message = "The all-zero CPU key binds the image to no console";
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
            result.message =
                "Invalid CPU key (" + std::to_string(res) +
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
        if (is_zero_cpu_key(cpu_key)) {
            return true;
        }
        uint8_t key_copy[16];
        std::memcpy(key_copy, cpu_key.data(), 16);
        if (XeCryptUidEccDecode(key_copy) < 0) {
            return false;
        }
        return cpu_key_hamming_weight(key_copy) == 0x35;
    }

    // Every byte comes from the system's cryptographic source (getrandom, /dev/urandom,
    // RtlGenRandom or RDRAND, as the standard library selects), not from a seeded generator.
    void ExCryptRandom(uint8_t* dest, size_t size) {
        std::random_device source;
        for (size_t i = 0; i < size; i += sizeof(uint32_t)) {
            const auto word = static_cast<uint32_t>(source());
            std::memcpy(dest + i, &word, std::min(sizeof(word), size - i));
        }
    }

    std::vector<uint8_t> keyvault_decrypt(std::span<const uint8_t> cpu_key,
                                          std::span<const uint8_t> data, uint16_t kv_version) {
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

        const uint8_t version_be[2] = {static_cast<uint8_t>(kv_version >> 8),
                                       static_cast<uint8_t>(kv_version)};
        uint8_t kv_digest[20];
        ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()),
                       out_data.data() + 0x10, static_cast<uint32_t>(out_data.size() - 0x10),
                       version_be, sizeof(version_be), nullptr, 0, kv_digest, 20);

        uint8_t difference = 0;
        for (size_t i = 0; i < 0x10; ++i) {
            difference |= static_cast<uint8_t>(out_data[i] ^ kv_digest[i]);
        }
        if (difference != 0) {
            throw std::runtime_error("Keyvault authentication failed");
        }

        return out_data;
    }

    std::vector<uint8_t> keyvault_encrypt(std::span<const uint8_t> cpu_key,
                                          std::span<const uint8_t> data, uint16_t kv_version) {
        if (!cpukey_valid(cpu_key)) {
            throw std::runtime_error("Invalid CPU key");
        }
        if (data.size() < 0x10) {
            throw std::runtime_error("Invalid data size");
        }

        std::vector<uint8_t> out_data(data.begin(), data.end());

        const uint8_t version_be[2] = {static_cast<uint8_t>(kv_version >> 8),
                                       static_cast<uint8_t>(kv_version)};
        uint8_t kv_digest[20];
        ExCryptHmacSha(cpu_key.data(), static_cast<uint32_t>(cpu_key.size()),
                       out_data.data() + 0x10, static_cast<uint32_t>(out_data.size() - 0x10),
                       version_be, sizeof(version_be), nullptr, 0, kv_digest, 20);

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

    std::optional<LooseKeyvault> open_loose_keyvault(std::span<const uint8_t> cpu_key,
                                                     std::span<const uint8_t> data) {
        std::vector<uint8_t> whole(data.begin(), data.end());
        if (whole.size() == Keyvault::kSize - 0x10) {
            whole.insert(whole.begin(), 0x10, 0);
        }
        if (whole.size() != Keyvault::kSize || !cpukey_valid(cpu_key)) {
            return std::nullopt;
        }
        try {
            return LooseKeyvault{keyvault_decrypt(cpu_key, whole), LooseKeyvault::Form::Sealed};
        } catch (const std::exception&) {
        }
        const auto zero = [&whole](size_t from, size_t to) {
            return std::all_of(whole.begin() + static_cast<std::ptrdiff_t>(from),
                               whole.begin() + static_cast<std::ptrdiff_t>(to),
                               [](uint8_t byte) { return byte == 0; });
        };
        // xeBuild's tests, in its order. A zero nonce is in the clear unless 0x58-0x5F say it is
        // not; a nonce is the plaintext's own when sealing derives it again.
        const auto derived = keyvault_encrypt(cpu_key, whole);
        auto form = LooseKeyvault::Form::Unopened;
        if (zero(0, 0x10)) {
            form = zero(0x58, 0x60) ? LooseKeyvault::Form::Clear : LooseKeyvault::Form::Unopened;
        } else if (std::equal(whole.begin(), whole.begin() + 0x10, derived.begin())) {
            form = LooseKeyvault::Form::Clear;
        } else if (zero(0x38, 0x90)) {
            form = LooseKeyvault::Form::StaleNonce;
        }
        return LooseKeyvault{std::move(whole), form};
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

    std::vector<uint8_t> Keyvault::serialize() const {
        if (raw_data.size() == kSize) {
            return raw_data;
        }
        std::vector<uint8_t> out(kSize, 0x00);
        std::memcpy(out.data(), &data, sizeof(XE_KEYVAULT_DATA));
        return out;
    }

} // namespace gxbuild3::nand
