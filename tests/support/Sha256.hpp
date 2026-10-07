#pragma once

// Test-only SHA-256 (FIPS 180-4). GxCrypt's ExCryptSha256 does not link (its excrypt_sha2.c
// calls an undeclared min()), and extern/ is not ours to fix, so goldens that want SHA-256
// digests use this. sha256_hex("abc") must equal the FIPS 180-4 example digest; tests that use
// this header check that before trusting it.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace gxbuild3::test {

    [[nodiscard]] inline std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) {
        static constexpr std::array<uint32_t, 64> k = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2};
        std::array<uint32_t, 8> h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        const auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
        const auto block = [&](const uint8_t* p) {
            std::array<uint32_t, 64> w{};
            for (size_t i = 0; i < 16; ++i) {
                w[i] = uint32_t(p[4 * i]) << 24 | uint32_t(p[4 * i + 1]) << 16 |
                       uint32_t(p[4 * i + 2]) << 8 | uint32_t(p[4 * i + 3]);
            }
            for (size_t i = 16; i < 64; ++i) {
                const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            auto v = h;
            for (size_t i = 0; i < 64; ++i) {
                const uint32_t s1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25);
                const uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
                const uint32_t t1 = v[7] + s1 + ch + k[i] + w[i];
                const uint32_t s0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22);
                const uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                const uint32_t t2 = s0 + maj;
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3] + t1;
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1 + t2;
            }
            for (size_t i = 0; i < 8; ++i) {
                h[i] += v[i];
            }
        };

        const size_t full = data.size() / 64;
        for (size_t i = 0; i < full; ++i) {
            block(data.data() + 64 * i);
        }
        std::array<uint8_t, 128> tail{};
        const size_t rest = data.size() - 64 * full;
        for (size_t i = 0; i < rest; ++i) {
            tail[i] = data[64 * full + i];
        }
        tail[rest] = 0x80;
        const size_t tail_size = rest + 9 <= 64 ? 64 : 128;
        const uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
        for (size_t i = 0; i < 8; ++i) {
            tail[tail_size - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
        }
        block(tail.data());
        if (tail_size == 128) {
            block(tail.data() + 64);
        }

        std::array<uint8_t, 32> out{};
        for (size_t i = 0; i < 8; ++i) {
            out[4 * i] = static_cast<uint8_t>(h[i] >> 24);
            out[4 * i + 1] = static_cast<uint8_t>(h[i] >> 16);
            out[4 * i + 2] = static_cast<uint8_t>(h[i] >> 8);
            out[4 * i + 3] = static_cast<uint8_t>(h[i]);
        }
        return out;
    }

    [[nodiscard]] inline std::string sha256_hex(std::span<const uint8_t> data) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const uint8_t b : sha256(data)) {
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 0xF]);
        }
        return out;
    }

} // namespace gxbuild3::test
