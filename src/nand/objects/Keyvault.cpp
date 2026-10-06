#include "nand/objects/Keyvault.hpp"

#include "excrypt.h"
#include "utils/Log.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <random>

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

    Result<std::vector<uint8_t>> keyvault_decrypt(std::span<const uint8_t> cpu_key,
                                                  std::span<const uint8_t> data,
                                                  uint16_t kv_version) {
        if (!cpukey_valid(cpu_key)) {
            return fail(ErrorCode::InvalidArgument, "Invalid CPU key");
        }
        if (data.size() < 0x10) {
            return fail(ErrorCode::InvalidArgument, "Invalid keyvault data size 0x{:X}",
                        data.size());
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
            return fail(ErrorCode::AuthFailed, "Keyvault authentication failed");
        }

        return out_data;
    }

    Result<std::vector<uint8_t>> keyvault_encrypt(std::span<const uint8_t> cpu_key,
                                                  std::span<const uint8_t> data,
                                                  uint16_t kv_version) {
        if (!cpukey_valid(cpu_key)) {
            return fail(ErrorCode::InvalidArgument, "Invalid CPU key");
        }
        if (data.size() < 0x10) {
            return fail(ErrorCode::InvalidArgument, "Invalid keyvault data size 0x{:X}",
                        data.size());
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

    Result<LooseKeyvault> open_loose_keyvault(std::span<const uint8_t> cpu_key,
                                              std::span<const uint8_t> data) {
        std::vector<uint8_t> whole(data.begin(), data.end());
        if (whole.size() == Keyvault::kSize - 0x10) {
            whole.insert(whole.begin(), 0x10, 0);
        }
        if (whole.size() != Keyvault::kSize) {
            return fail(ErrorCode::Malformed,
                        "kv.bin is 0x{:X} bytes, not 0x4000 nor 0x3FF0 without its nonce",
                        data.size());
        }
        if (!cpukey_valid(cpu_key)) {
            return fail(ErrorCode::InvalidArgument, "Invalid CPU key");
        }
        // Only an authentication failure means the copy is not sealed under this key.
        auto opened = keyvault_decrypt(cpu_key, whole);
        if (opened) {
            return LooseKeyvault{std::move(*opened), LooseKeyvault::Form::Sealed};
        }
        if (opened.error().code != ErrorCode::AuthFailed) {
            return std::unexpected(std::move(opened.error()));
        }
        const auto zero = [&whole](size_t from, size_t to) {
            return std::all_of(whole.begin() + static_cast<std::ptrdiff_t>(from),
                               whole.begin() + static_cast<std::ptrdiff_t>(to),
                               [](uint8_t byte) { return byte == 0; });
        };
        // xeBuild's tests, in its order. A zero nonce is in the clear unless 0x58-0x5F say it is
        // not; a nonce is the plaintext's own when sealing derives it again.
        const auto derived = keyvault_encrypt(cpu_key, whole);
        if (!derived) {
            return std::unexpected(derived.error());
        }
        auto form = LooseKeyvault::Form::Unopened;
        if (zero(0, 0x10)) {
            form = zero(0x58, 0x60) ? LooseKeyvault::Form::Clear : LooseKeyvault::Form::Unopened;
        } else if (std::equal(whole.begin(), whole.begin() + 0x10, derived->begin())) {
            form = LooseKeyvault::Form::Clear;
        } else if (zero(0x38, 0x90)) {
            form = LooseKeyvault::Form::StaleNonce;
        }
        return LooseKeyvault{std::move(whole), form};
    }

    Result<> crypt_secfile(std::span<const uint8_t> cpu_key, std::span<uint8_t> data) {
        if (cpu_key.size() != 16) {
            return fail(ErrorCode::InvalidArgument, "CPU key is {} bytes, not 16", cpu_key.size());
        }
        if (data.size() < 0x10) {
            return fail(ErrorCode::InvalidArgument,
                        "Secured file is 0x{:X} bytes, shorter than its nonce", data.size());
        }
        uint8_t key[20] = {0};
        ExCryptHmacSha(cpu_key.data(), 16, data.data(), 0x10, nullptr, 0, nullptr, 0, key, 20);
        ExCryptRc4(key, 16, data.data() + 0x10, static_cast<uint32_t>(data.size() - 0x10));
        return {};
    }

    Result<Keyvault> Keyvault::parse(std::span<const uint8_t> bytes) {
        if (bytes.size() != kSize) {
            return fail(bytes.size() < kSize ? ErrorCode::Truncated : ErrorCode::Malformed,
                        "Invalid Keyvault size: expected 0x{:X} bytes, got 0x{:X}", kSize,
                        bytes.size());
        }

        auto record = wire::read<XE_KEYVAULT_DATA>(bytes, 0, "keyvault");
        if (!record) {
            return std::unexpected(std::move(record.error()));
        }
        Keyvault kv;
        kv.raw_data.assign(bytes.begin(), bytes.end());
        kv.data = *record;
        kv.encrypted = true;
        Log::Debug("Parsed Keyvault (0x{:X} bytes)", bytes.size());
        return kv;
    }

    Result<Keyvault> Keyvault::parse(const std::vector<uint8_t>& bytes) {
        return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    Result<> Keyvault::decrypt(std::span<const uint8_t> cpu_key) {
        if (!encrypted) {
            return {};
        }
        auto crypted = keyvault_decrypt(cpu_key, raw_data);
        if (!crypted) {
            return std::unexpected(
                std::move(crypted.error()).add_context("decrypting the keyvault"));
        }
        if (crypted->size() < sizeof(XE_KEYVAULT_DATA)) {
            return fail(ErrorCode::Truncated, "Keyvault is 0x{:X} bytes, not 0x{:X}",
                        crypted->size(), sizeof(XE_KEYVAULT_DATA));
        }
        auto record = wire::read<XE_KEYVAULT_DATA>(*crypted, 0, "keyvault");
        if (!record) {
            return std::unexpected(std::move(record.error()));
        }
        raw_data = std::move(*crypted);
        data = *record;
        encrypted = false;
        Log::Debug("Keyvault decrypted successfully");
        return {};
    }

    Result<> Keyvault::encrypt(std::span<const uint8_t> cpu_key) {
        if (encrypted) {
            return {};
        }
        auto crypted = keyvault_encrypt(cpu_key, raw_data);
        if (!crypted) {
            return std::unexpected(
                std::move(crypted.error()).add_context("encrypting the keyvault"));
        }
        if (crypted->size() < sizeof(XE_KEYVAULT_DATA)) {
            return fail(ErrorCode::Truncated, "Keyvault is 0x{:X} bytes, not 0x{:X}",
                        crypted->size(), sizeof(XE_KEYVAULT_DATA));
        }
        auto record = wire::read<XE_KEYVAULT_DATA>(*crypted, 0, "keyvault");
        if (!record) {
            return std::unexpected(std::move(record.error()));
        }
        raw_data = std::move(*crypted);
        data = *record;
        encrypted = true;
        Log::Debug("Keyvault encrypted successfully");
        return {};
    }

    std::vector<uint8_t> Keyvault::serialize() const {
        if (raw_data.size() == kSize) {
            return raw_data;
        }
        const auto image = wire::encode(data);
        return std::vector<uint8_t>(image.begin(), image.end());
    }

} // namespace gxbuild3::nand
