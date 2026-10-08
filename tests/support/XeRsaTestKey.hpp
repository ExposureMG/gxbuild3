#pragma once

// A throwaway XeCrypt RSA-2048 private key, generated for tests from a fixed seed. No real
// console or Microsoft key is ever embedded in a test.

#include "utils/BigUint.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <vector>

namespace gxbuild3::test::xe_rsa {

    using utils::BigUint;

    inline BigUint random_odd_prime_candidate(std::mt19937_64& random, size_t bits) {
        std::vector<uint8_t> bytes(bits / 8);
        for (auto& byte : bytes) {
            byte = static_cast<uint8_t>(random());
        }
        // The top two bits set, so the product of two such primes is twice as long.
        bytes.front() |= 0xC0;
        bytes.back() |= 0x01;
        return BigUint::from_be_bytes(bytes);
    }

    inline bool probably_prime(const BigUint& candidate, std::mt19937_64& random) {
        static constexpr std::array<uint32_t, 24> kSmallPrimes{3,  5,  7,  11, 13, 17, 19, 23,
                                                               29, 31, 37, 41, 43, 47, 53, 59,
                                                               61, 67, 71, 73, 79, 83, 89, 97};
        for (const uint32_t prime : kSmallPrimes) {
            if (candidate.mod_small(prime) == 0) {
                return false;
            }
        }
        for (uint32_t prime = 101; prime < 2000; prime += 2) {
            bool is_prime = true;
            for (uint32_t divisor = 3; divisor * divisor <= prime; divisor += 2) {
                if (prime % divisor == 0) {
                    is_prime = false;
                    break;
                }
            }
            if (is_prime && candidate.mod_small(prime) == 0) {
                return false;
            }
        }
        // Miller-Rabin.
        const BigUint one{1};
        const BigUint minus_one = candidate - one;
        BigUint odd = minus_one;
        size_t twos = 0;
        while (!odd.is_odd()) {
            odd = odd / BigUint{2};
            ++twos;
        }
        for (int round = 0; round < 8; ++round) {
            const BigUint witness = BigUint{2 + random() % 0xFFFFFFF0ULL};
            BigUint x = BigUint::pow_mod(witness, odd, candidate);
            if (x == one || x == minus_one) {
                continue;
            }
            bool composite = true;
            for (size_t step = 1; step < twos; ++step) {
                x = (x * x) % candidate;
                if (x == minus_one) {
                    composite = false;
                    break;
                }
            }
            if (composite) {
                return false;
            }
        }
        return true;
    }

    // A 1024-bit prime p with gcd(3, p - 1) = 1, so e = 3 has an inverse mod p - 1.
    inline BigUint generate_prime(std::mt19937_64& random) {
        while (true) {
            const auto candidate = random_odd_prime_candidate(random, 1024);
            if (candidate.mod_small(3) == 2 && probably_prime(candidate, random)) {
                return candidate;
            }
        }
    }

    // 3^-1 mod m, for m not divisible by 3: (k m + 1) / 3 for whichever k of 1, 2 divides.
    inline BigUint inverse_of_three(const BigUint& modulus) {
        const BigUint one{1};
        for (uint64_t multiple = 1; multiple <= 2; ++multiple) {
            const BigUint value = BigUint{multiple} * modulus + one;
            if (value.mod_small(3) == 0) {
                return value / BigUint{3};
            }
        }
        return {};
    }

    inline void append_digits(std::vector<uint8_t>& out, const BigUint& value, size_t size) {
        const auto digits = value.to_xe_digits(size);
        out.insert(out.end(), digits->begin(), digits->end());
    }

    // The key in XeCrypt's layout, e = 3 as Microsoft's own keys state it.
    inline std::vector<uint8_t> generate_private_key(uint64_t seed) {
        std::mt19937_64 random(seed);
        BigUint p = generate_prime(random);
        BigUint q = generate_prime(random);
        while (q == p) {
            q = generate_prime(random);
        }
        if (p < q) {
            std::swap(p, q);
        }
        const BigUint one{1};
        const BigUint n = p * q;
        const BigUint dp = inverse_of_three(p - one);
        const BigUint dq = inverse_of_three(q - one);
        // q^-1 mod p by Fermat, p being prime.
        const BigUint u = BigUint::pow_mod(q, p - BigUint{2}, p);

        std::vector<uint8_t> key{0, 0, 0, 0x20, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0};
        append_digits(key, n, 0x100);
        append_digits(key, p, 0x80);
        append_digits(key, q, 0x80);
        append_digits(key, dp, 0x80);
        append_digits(key, dq, 0x80);
        append_digits(key, u, 0x80);
        return key;
    }

    // The key with bytes 0x08..0x0B (the unused high half of XeCrypt's reserved word) chosen so
    // the file's CRC-32 is `target`: a throwaway key that passes a CRC check made for another
    // key file. CRC-32 is affine over GF(2), so the four bytes solve a 32x32 linear system.
    inline std::vector<uint8_t> with_crc32(std::vector<uint8_t> key, uint32_t target) {
        constexpr size_t kAt = 0x08;
        // A key too short to hold the four bytes has no solution (an empty key, as
        // generate_private_key never makes).
        if (key.size() < kAt + 4) {
            return {};
        }
        std::fill(key.begin() + kAt, key.begin() + kAt + 4, uint8_t{0});
        const uint32_t base = gxbuild3::utils::crc32(key);
        // Column b: how flipping bit b of the four bytes changes the CRC.
        std::array<uint32_t, 32> columns{};
        for (size_t bit = 0; bit < 32; ++bit) {
            auto flipped = key;
            flipped[kAt + bit / 8] ^= static_cast<uint8_t>(1U << (bit % 8));
            columns[bit] = gxbuild3::utils::crc32(flipped) ^ base;
        }
        // Gaussian elimination on rows (one per CRC bit) of [columns | wanted].
        std::array<uint64_t, 32> rows{};
        const uint32_t wanted = base ^ target;
        for (size_t row = 0; row < 32; ++row) {
            uint64_t value = 0;
            for (size_t bit = 0; bit < 32; ++bit) {
                value |= uint64_t{(columns[bit] >> row) & 1U} << bit;
            }
            rows[row] = value | (uint64_t{(wanted >> row) & 1U} << 32);
        }
        for (size_t pivot = 0; pivot < 32; ++pivot) {
            size_t found = pivot;
            while (found < 32 && ((rows[found] >> pivot) & 1U) == 0) {
                ++found;
            }
            if (found == 32) {
                return {};
            }
            std::swap(rows[pivot], rows[found]);
            for (size_t row = 0; row < 32; ++row) {
                if (row != pivot && ((rows[row] >> pivot) & 1U) != 0) {
                    rows[row] ^= rows[pivot];
                }
            }
        }
        for (size_t bit = 0; bit < 32; ++bit) {
            if (((rows[bit] >> 32) & 1U) != 0) {
                key[kAt + bit / 8] ^= static_cast<uint8_t>(1U << (bit % 8));
            }
        }
        return key;
    }

    // One key per test binary: generating it costs a few seconds.
    inline const std::vector<uint8_t>& shared_private_key() {
        static const auto key = generate_private_key(0x58426F78524F4D34ULL);
        return key;
    }

} // namespace gxbuild3::test::xe_rsa
