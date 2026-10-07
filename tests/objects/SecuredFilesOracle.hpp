#pragma once

// The independent oracle the secured-file tests check src/nand/objects/SecuredFiles.cpp against:
// HMAC-SHA and AES-CBC straight from GxCrypt's XeCrypt primitives (never through a src/ helper),
// the signed-record and dae.bin builders, the fixed sealings and the synthetic keys, copied byte
// for byte from the old tests/SecuredFilesTests.cpp.

#include "excrypt.h"
#include "nand/objects/SecuredFiles.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace gxbuild3::objects::secured_oracle {

    using Bytes = test::Bytes;
    using Key = std::array<uint8_t, 16>;

    // Synthetic keys: no console's.
    inline constexpr Key kCpuKey{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    inline constexpr Key kOtherKey{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                   0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    // The retail XEX key, which the 1BL key derives; an update package's copies open under it.
    inline constexpr Key kRetailXexKey{0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3,
                                       0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91};
    inline constexpr nand::SecuredFileBuild kBuild{0x5A123457, 14};

    inline Key hmac(std::span<const uint8_t> key, std::span<const uint8_t> first,
                    std::span<const uint8_t> second = {}) {
        uint8_t digest[20]{};
        ExCryptHmacSha(key.data(), static_cast<uint32_t>(key.size()), first.data(),
                       static_cast<uint32_t>(first.size()), second.data(),
                       static_cast<uint32_t>(second.size()), nullptr, 0, digest, sizeof(digest));
        Key out{};
        std::copy_n(digest, out.size(), out.begin());
        return out;
    }

    inline Bytes aes_cbc_decrypt(std::span<const uint8_t> key, std::span<const uint8_t> iv,
                                 std::span<const uint8_t> data) {
        alignas(16) EXCRYPT_AES_STATE state{};
        ExCryptAesKey(&state, key.data());
        Key feed{};
        std::copy_n(iv.begin(), feed.size(), feed.begin());
        Bytes out(data.size());
        ExCryptAesCbc(&state, data.data(), static_cast<uint32_t>(data.size()), out.data(),
                      feed.data(), 0);
        return out;
    }

    // A signed record in the clear: magic, length and the SHA-1 of everything from 0x150 on.
    inline Bytes a_record(std::string_view magic, size_t length, uint8_t fill) {
        Bytes out(length);
        std::copy(magic.begin(), magic.end(), out.begin());
        out[4] = static_cast<uint8_t>(length >> 8);
        out[5] = static_cast<uint8_t>(length);
        for (size_t at = 0x150; at < length; ++at) {
            out[at] = static_cast<uint8_t>(at * 7 + fill);
        }
        ExCryptSha(out.data() + 0x150, static_cast<uint32_t>(length - 0x150), nullptr, 0, nullptr,
                   0, out.data() + 0x0C, 20);
        return out;
    }

    inline Bytes clear_dae() {
        auto out = a_record("DAEP", 0x400, 2);
        const auto second = a_record("DAEP", 0x300, 3);
        out.insert(out.end(), second.begin(), second.end());
        return out;
    }

    inline constexpr nand::CrlSealing kCrlSealing{{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                                   0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF},
                                                  {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                                   0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12}};
    inline constexpr nand::DaeSealing kDaeSealing{{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77},
                                                  {0xD0, 0xD2, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
                                                   0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}};

} // namespace gxbuild3::objects::secured_oracle
