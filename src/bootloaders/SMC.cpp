#include "bootloaders/SMC.hpp"

#include <algorithm>

const uint8_t XECRYPT_SMC_KEY[4] = {0x42, 0x75, 0x4E, 0x79};

std::vector<uint8_t> smc_decrypt(const std::vector<uint8_t>& data) {
    uint32_t key[4] = {XECRYPT_SMC_KEY[0], XECRYPT_SMC_KEY[1], XECRYPT_SMC_KEY[2],
                       XECRYPT_SMC_KEY[3]};
    std::vector<uint8_t> decrypted;
    decrypted.reserve(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t j = data[i];
        uint32_t mod = j * 0xFB;
        decrypted.push_back(j ^ (key[i & 3] & 0xFF));
        key[(i + 1) & 3] += mod;
        key[(i + 2) & 3] += mod >> 8;
    }

    return decrypted;
}

std::vector<uint8_t> smc_encrypt(const std::vector<uint8_t>& data) {
    uint32_t key[4] = {XECRYPT_SMC_KEY[0], XECRYPT_SMC_KEY[1], XECRYPT_SMC_KEY[2],
                       XECRYPT_SMC_KEY[3]};
    std::vector<uint8_t> encrypted;
    encrypted.reserve(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t j = data[i] ^ (key[i & 3] & 0xFF);
        uint32_t mod = j * 0xFB;
        encrypted.push_back(j);
        key[(i + 1) & 3] += mod;
        key[(i + 2) & 3] += mod >> 8;
    }

    return encrypted;
}

bool smc_is_encrypted(const std::vector<uint8_t>& data) {
    if (data.size() <= 0x100) {
        return false;  // too small to be a valid SMC
    }
    const uint8_t raw_nibble = (data[0x100] >> 4) & 0xF;
    if (raw_nibble >= 1 && raw_nibble <= 7) {
        return false;  // Already plaintext
    }
    const auto decrypted = smc_decrypt(data);
    const uint8_t dec_nibble = (decrypted[0x100] >> 4) & 0xF;
    return dec_nibble >= 1 && dec_nibble <= 7;
}

std::string_view smc_type_name(SmcType type) {
    switch (type) {
        case SmcType::Retail:       return "Retail";
        case SmcType::Glitch:       return "Glitch";
        case SmcType::Jtag:         return "JTAG";
        case SmcType::Cygnos:       return "Cygnos";
        case SmcType::RJtag:        return "R-JTAG";
        case SmcType::RJtagCygnos:  return "R-JTAG+Cygnos";
        case SmcType::CR4:          return "CR4";
        case SmcType::SmcPlus:      return "SMC+";
        case SmcType::Rgh3V1:       return "RGH3 v1";
        case SmcType::Rgh3V2:       return "RGH3 v2";
        case SmcType::Rgh13:        return "RGH1.3";
        default:                    return "Unknown";
    }
}

SmcType smc_get_type(const std::vector<uint8_t>& data) {
    if (data.size() < 6) {
        return SmcType::Unknown;
    }

    // Decrypt data if encrypted to scan plaintext bytes
    std::vector<uint8_t> decrypted_data;
    const std::vector<uint8_t>* working_data = &data;
    if (smc_is_encrypted(data)) {
        decrypted_data = smc_decrypt(data);
        working_data = &decrypted_data;
    }
    const auto& sdata = *working_data;

    // 1. Check RGH3 v1 signatures first (highest priority / most specific)
    bool has_rgh3_v1_obfuscation = false;
    const std::vector<uint8_t> rgh3_v1_sig = {
        0xE5, 0x02, 0x65, 0x03, 0xF6, 0xE5, 0x06, 0x24, 0x49, 0xC0, 0xE0, 0x54, 0x32, 0x24, 0xF5, 0xC0, 0xE0, 0x22
    };
    if (sdata.size() >= rgh3_v1_sig.size()) {
        for (size_t i = 0; i <= sdata.size() - rgh3_v1_sig.size(); ++i) {
            if (std::equal(rgh3_v1_sig.begin(), rgh3_v1_sig.end(), sdata.begin() + i)) {
                has_rgh3_v1_obfuscation = true;
                break;
            }
        }
    }
    bool has_rgh3_v1_reset = (sdata.size() >= 3 && sdata[0] == 0x02 && sdata[1] == 0x2E && sdata[2] == 0x21);

    if (has_rgh3_v1_obfuscation || has_rgh3_v1_reset) {
        return SmcType::Rgh3V1;
    }

    // 2. Check CR4 / SMC+ signatures (contains 43 08 80 03)
    bool has_cr4_sig = false;
    const std::vector<uint8_t> cr4_sig = {0x43, 0x08, 0x80, 0x03};
    if (sdata.size() >= cr4_sig.size()) {
        for (size_t i = 0; i <= sdata.size() - cr4_sig.size(); ++i) {
            if (std::equal(cr4_sig.begin(), cr4_sig.end(), sdata.begin() + i)) {
                has_cr4_sig = true;
                break;
            }
        }
    }

    if (has_cr4_sig) {
        // Distinguish between CR4 and SMC+ by checking modified timeouts
        bool is_smc_plus = false;
        if (sdata.size() > 0x1284 && (sdata[0x1276] == 0x8A || sdata[0x1284] == 0x8A)) {
            is_smc_plus = true;
        } else if (sdata.size() > 0x1292 && (sdata[0x127B] == 0x50 || sdata[0x1292] == 0x50)) {
            is_smc_plus = true;
        } else if (sdata.size() > 0x1396 && (sdata[0x1380] == 0x41 || sdata[0x1396] == 0x41)) {
            is_smc_plus = true;
        } else if (sdata.size() > 0x1397 && (sdata[0x1381] == 0x41 || sdata[0x1397] == 0x41)) {
            is_smc_plus = true;
        }

        if (!is_smc_plus) {
            // General scan for SMC+ unique timeout instructions (75 3B/3C/3D 8A/41)
            for (size_t i = 0; i + 2 < sdata.size(); ++i) {
                if (sdata[i] == 0x75 && (sdata[i+1] == 0x3B || sdata[i+1] == 0x3C || sdata[i+1] == 0x3D)) {
                    if (sdata[i+2] == 0x8A || sdata[i+2] == 0x41) {
                        is_smc_plus = true;
                        break;
                    }
                }
            }
        }

        return is_smc_plus ? SmcType::SmcPlus : SmcType::CR4;
    }

    // 3. Scan the binary for other types
    auto ret = SmcType::Unknown;
    bool glitch_patched = false;
    bool retail = false;
    bool has_d4_write = false;

    const size_t scan_end = sdata.size() - 6;
    for (size_t i = 0; i < scan_end; ++i) {
        switch (sdata[i]) {
            case 0x05:
                // Retail: 05 ?? E5 ?? B4 05
                if (sdata[i+2] == 0xE5 && sdata[i+4] == 0xB4 && sdata[i+5] == 0x05) {
                    retail = true;
                    glitch_patched = false;  // not properly glitch-patched
                }
                break;
            case 0x00:
                // Glitch: 00 00 E5 ?? B4 05  (retail bytes zeroed out)
                if (sdata[i+1] == 0x00 && sdata[i+2] == 0xE5 && sdata[i+4] == 0xB4 && sdata[i+5] == 0x05) {
                    glitch_patched = true;
                }
                break;
            case 0x78:
                // Cygnos: 78 BA B6
                if (sdata[i+1] == 0xBA && sdata[i+2] == 0xB6) {
                    ret = SmcType::Cygnos;
                }
                break;
            case 0xD0:
                // JTAG: D0 00 00 1B
                if (sdata[i+1] == 0x00 && sdata[i+2] == 0x00 && sdata[i+3] == 0x1B) {
                    ret = SmcType::Jtag;
                }
                break;
            default:
                break;
        }

        // Check if there is a reference to the HANA 0xD4 register write (unique to RGH3 v2 overclocking)
        // Usually, writes are done using: MOV direct, #0xD4 (75 direct D4) or MOV A, #0xD4 (74 D4)
        if (sdata[i] == 0x75 && sdata[i+2] == 0xD4) {
            has_d4_write = true;
        } else if (sdata[i] == 0x74 && sdata[i+1] == 0xD4) {
            has_d4_write = true;
        }
    }

    if (glitch_patched && !retail) {
        if (has_d4_write) {
            return SmcType::Rgh3V2;
        }
        // Check for custom code in high code space as a generic fallback for RGH3 v2 / RGH1.3
        bool has_high_code = false;
        const size_t check_start = std::min(sdata.size(), static_cast<size_t>(0x2D73));
        for (size_t i = check_start; i < sdata.size(); ++i) {
            if (sdata[i] != 0x00 && sdata[i] != 0xFF) {
                has_high_code = true;
                break;
            }
        }
        if (has_high_code) {
            // It has custom code at the end but isn't RGH3 v1 or JTAG/Cygnos
            if (ret == SmcType::Unknown) {
                return SmcType::Rgh3V2;
            }
        }

        switch (ret) {
            case SmcType::Jtag:   return SmcType::RJtag;
            case SmcType::Cygnos: return SmcType::RJtagCygnos;
            default:              return SmcType::Glitch;
        }
    }

    return (ret == SmcType::Unknown && retail) ? SmcType::Retail : ret;
}