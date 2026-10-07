#pragma once

// The independent oracle the glitch-chain tests check the bootloader sealing against: the
// HMAC/RC4 operations the reference Python builders use, straight from GxCrypt's XeCrypt
// primitives and never through gxbuild3's bootloader crypto helpers (nand/bootloaders/Common.hpp
// is not included, and nand::key_1bl is not used: kOneBlKey is its own literal). hmac, encrypt,
// authenticate and opens_to are copied byte for byte from the old tests/GlitchCryptoTests.cpp,
// whose eight copies of the 1BL key literal are the one kOneBlKey.

#include "excrypt.h"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace gxbuild3::bootloaders::glitch {

    using Bytes = test::Bytes;
    using Key = std::array<uint8_t, 16>;

    // The 1BL key every CB_A, single CB and CF is sealed under.
    inline constexpr Key kOneBlKey{0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                                   0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};

    // Independent wire-format oracle: the HMAC/RC4 operations used by the reference
    // Python builders, without calling gxbuild3's bootloader crypto helpers.
    inline Key hmac(const Key& parent, const Bytes& message) {
        Key key{};
        ExCryptHmacSha(parent.data(), parent.size(), message.data(), message.size(), nullptr, 0,
                       nullptr, 0, key.data(), key.size());
        return key;
    }

    inline std::pair<Bytes, Key> encrypt(Bytes bytes, const Key& parent, const Bytes& suffix = {}) {
        Bytes message(bytes.begin() + 0x10, bytes.begin() + 0x20);
        message.insert(message.end(), suffix.begin(), suffix.end());
        auto key = hmac(parent, message);
        ExCryptRc4(key.data(), key.size(), bytes.data() + 0x20, bytes.size() - 0x20);
        return {bytes, key};
    }

    // Reference wire-format calculation, independent of BootloaderCb helpers.
    inline Bytes authenticate(Bytes cb, const Key& rc4_key, const Bytes& cpu, const Bytes& smc) {
        uint64_t sums[2]{};
        for (size_t i = 0; i + 4 <= smc.size(); i += 4) {
            uint32_t word = 0;
            for (size_t j = 0; j < 4; ++j) {
                word = (word << 8) | smc[i + j];
            }
            sums[0] += word;
            sums[1] -= word;
            sums[0] = (sums[0] << 29) | (sums[0] >> 35);
            sums[1] = (sums[1] << 31) | (sums[1] >> 33);
        }
        Bytes message(rc4_key.begin(), rc4_key.end());
        message.insert(message.end(), cb.begin() + 0x20, cb.begin() + 0x30);
        for (auto sum : sums) {
            for (int shift = 56; shift >= 0; shift -= 8) {
                message.push_back(sum >> shift);
            }
        }
        Key cpu_key{};
        std::copy_n(cpu.begin(), 16, cpu_key.begin());
        const auto digest = hmac(cpu_key, message);
        std::copy(digest.begin(), digest.end(), cb.begin() + 0x30);
        return cb;
    }

    // Opens a stage sealed under `key` (RC4 from +0x20) and compares it with its plaintext.
    inline bool opens_to(Bytes sealed, const Key& key, const Bytes& plain) {
        ExCryptRc4(key.data(), key.size(), sealed.data() + 0x20, sealed.size() - 0x20);
        return sealed == plain;
    }

} // namespace gxbuild3::bootloaders::glitch
