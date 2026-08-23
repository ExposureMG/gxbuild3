#include "nand/bootloaders/BootloaderPacker.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>

namespace gxbuild3::bootloaders {

namespace {

    constexpr uint8_t k1BlKey[16] = {0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
                                     0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA};
    constexpr uint8_t kSbKey[16] = {0};

    void hmac_sha1_16(const uint8_t key[16], const uint8_t* d1, size_t l1,
                      const uint8_t* d2, size_t l2,
                      const uint8_t* d3, size_t l3,
                      uint8_t out[16]) {
        uint8_t digest[20];
        ExCryptHmacSha(key, 16, d1, l1, d2, l2, d3, l3, digest, 20);
        std::memcpy(out, digest, 16);
    }

} // namespace

bool crypt_single_bl(std::span<uint8_t> data, HmacType hmac_type, uint8_t cur_key[16],
                     const uint8_t cpu_key[16], uint8_t cba_hdr[16], size_t crypt_start) {
    if (data.size() < crypt_start) {
        return false;
    }

    const size_t nonce_offset = (crypt_start >= 0x20) ? (crypt_start - 0x10) : 0x10;

    switch (hmac_type) {
        case HmacType::Default:
            hmac_sha1_16(cur_key, data.data() + nonce_offset, 16, nullptr, 0, nullptr, 0, cur_key);
            break;
        case HmacType::Hmac1920:
            hmac_sha1_16(cur_key, data.data() + nonce_offset, 16, nullptr, 0, nullptr, 0, cur_key);
            hmac_sha1_16(cpu_key, cur_key, 16, nullptr, 0, nullptr, 0, cur_key);
            break;
        case HmacType::Split:
            hmac_sha1_16(cur_key, data.data() + nonce_offset, 16, cpu_key, 16, nullptr, 0, cur_key);
            break;
        case HmacType::Split15574:
            hmac_sha1_16(cur_key, data.data() + nonce_offset, 16, cpu_key, 16, cba_hdr, 16, cur_key);
            break;
    }

    if (cba_hdr && data.size() >= 16) {
        std::memcpy(cba_hdr, data.data(), 16);
        cba_hdr[6] = 0;
        cba_hdr[7] = 0;
    }

    ExCryptRc4(cur_key, 16, data.data() + crypt_start,
               static_cast<uint32_t>(data.size() - crypt_start));
    return true;
}

bool crypt_bootloaders(std::vector<BootloaderBlock>& bls, std::span<const uint8_t> cpu_key) {
    Log::Debug("Crypting {} bootloader blocks", bls.size());
    std::map<uint16_t, int> bl_count;
    for (const auto& bl : bls) {
        bl_count[bl.magic]++;
    }

    HmacType hmac_type = HmacType::Default;
    uint8_t cur_key[16] = {};
    uint8_t use_cpu_key[16] = {};
    uint8_t cba_hdr[16] = {};

    std::memcpy(cur_key, k1BlKey, 16);
    if (cpu_key.size() >= 16) {
        std::memcpy(use_cpu_key, cpu_key.data(), 16);
    }

    bool plaintext = false;

    for (auto& bl : bls) {
        size_t crypt_start = 0x20;
        if (bl.magic == 0x5343) {
            crypt_start = 0x120;
        }

        if (plaintext) {
            if (bl.data.size() >= 0x20) {
                std::memcpy(cur_key, bl.data.data() + 0x10, 16);
            }
            plaintext = false;
        } else {
            if (!crypt_single_bl(bl.data, hmac_type, cur_key, use_cpu_key, cba_hdr, crypt_start)) {
                Log::Error("Failed to crypt bootloader block (magic=0x{:04X}, size=0x{:X})",
                           bl.magic, bl.data.size());
                return false;
            }
        }

        switch (bl.magic) {
            case 0x4342:
                if (bl.build == 15432) {
                    plaintext = true;
                    hmac_type = HmacType::Default;
                    continue;
                }

                if ((bl.flags & 0x800) == 0x800) {
                    if ((bl.flags & 1) == 1) {
                        std::memset(use_cpu_key, 0, 16);
                    }
                    if ((bl.flags & 0x1000) == 0x1000) {
                        hmac_type = HmacType::Split15574;
                    } else {
                        hmac_type = HmacType::Split;
                    }
                } else {
                    if (bl_count[0x4342] > 1) {
                        if (bl_count[0x5343] > 0 && bl_count[0x5344] > 0) {
                            bl.magic = 0x5342;
                            bl.data[0] = 'S';
                            bl.data[1] = 'B';
                            hmac_type = HmacType::Default;
                            std::memcpy(cur_key, kSbKey, 16);
                            continue;
                        }
                        hmac_type = HmacType::Default;
                    } else {
                        if (bl.build >= 1920 && bl.data.size() >= 0x40 &&
                            !std::all_of(bl.data.begin() + 0x20, bl.data.begin() + 0x40,
                                         [](uint8_t b) { return b == 0; })) {
                            hmac_type = HmacType::Hmac1920;
                        } else {
                            hmac_type = HmacType::Default;
                        }
                    }
                }
                break;

            case 0x4344:
                hmac_type = HmacType::Default;
                break;

            case 0x5342:
                hmac_type = HmacType::Default;
                std::memcpy(cur_key, kSbKey, 16);
                if (bl_count[0x4342] > 0 && bl_count[0x5343] > 0 && bl_count[0x5344] > 0) {
                    bl.magic = 0x4342;
                    bl.data[0] = 'C';
                    bl.data[1] = 'B';
                }
                break;

            default:
                break;
        }
    }

    return true;
}

} // namespace gxbuild3::bootloaders
