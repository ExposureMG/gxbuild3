#include "nand/objects/SMC.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <cstring>

namespace gxbuild3::NAND {

namespace {

    constexpr uint8_t kSmcKey[4] = {0x42, 0x75, 0x4E, 0x79};

    SmcMotherboard parse_motherboard(uint8_t b) {
        uint8_t nibble = (b >> 4) & 0xF;
        switch (nibble) {
            case 1: return SmcMotherboard::Xenon;
            case 2: return SmcMotherboard::Zephyr;
            case 3: return SmcMotherboard::Falcon;
            case 4: return SmcMotherboard::Jasper;
            case 5: return SmcMotherboard::Trinity;
            case 6: return SmcMotherboard::Corona;
            case 7: return SmcMotherboard::Winchester;
            default: return SmcMotherboard::Unknown;
        }
    }

    std::string parse_version(uint8_t b0, uint8_t b1) {
        uint8_t major = (b0 >> 4) & 0xF;
        uint8_t minor = b0 & 0xF;
        std::string ver = std::to_string(major) + "." + std::to_string(minor);
        if (b1 != 0) {
            ver += "." + std::to_string(b1);
        }
        return ver;
    }

} // namespace

std::string_view smc_motherboard_name(SmcMotherboard mb) {
    switch (mb) {
        case SmcMotherboard::Xenon: return "Xenon";
        case SmcMotherboard::Zephyr: return "Zephyr";
        case SmcMotherboard::Falcon: return "Falcon";
        case SmcMotherboard::Jasper: return "Jasper";
        case SmcMotherboard::Trinity: return "Trinity";
        case SmcMotherboard::Corona: return "Corona";
        case SmcMotherboard::Winchester: return "Winchester";
        default: return "Unknown";
    }
}

std::string_view smc_type_name(SmcType type) {
    switch (type) {
        case SmcType::Retail: return "Retail";
        case SmcType::Glitch: return "Glitch";
        case SmcType::Jtag: return "JTAG";
        case SmcType::Cygnos: return "Cygnos";
        case SmcType::RJtag: return "R-JTAG";
        case SmcType::RJtagCygnos: return "R-JTAG+Cygnos";
        case SmcType::CR4: return "CR4";
        case SmcType::SmcPlus: return "SMC+";
        case SmcType::Rgh3V1: return "RGH3 v1";
        case SmcType::Rgh3V2: return "RGH3 v2";
        case SmcType::Rgh13: return "RGH1.3";
        default: return "Unknown";
    }
}

std::vector<uint8_t> smc_decrypt(std::span<const uint8_t> data) {
    uint32_t key[4] = {kSmcKey[0], kSmcKey[1], kSmcKey[2], kSmcKey[3]};
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

std::vector<uint8_t> smc_encrypt(std::span<const uint8_t> data) {
    uint32_t key[4] = {kSmcKey[0], kSmcKey[1], kSmcKey[2], kSmcKey[3]};
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

bool smc_is_encrypted(std::span<const uint8_t> data) {
    if (data.size() <= 0x100) {
        return false;
    }
    const uint8_t raw_nibble = (data[0x100] >> 4) & 0xF;
    if (raw_nibble >= 1 && raw_nibble <= 7) {
        return false;
    }
    const auto decrypted = smc_decrypt(data);
    const uint8_t dec_nibble = (decrypted[0x100] >> 4) & 0xF;
    return dec_nibble >= 1 && dec_nibble <= 7;
}

SmcType smc_get_type(std::span<const uint8_t> data) {
    if (data.size() < 6) {
        return SmcType::Unknown;
    }

    std::vector<uint8_t> decrypted_data;
    std::span<const uint8_t> sdata = data;
    if (smc_is_encrypted(data)) {
        decrypted_data = smc_decrypt(data);
        sdata = decrypted_data;
    }

    bool has_rgh3_v1_obfuscation = false;
    static constexpr uint8_t rgh3_v1_sig[18] = {
        0xE5, 0x02, 0x65, 0x03, 0xF6, 0xE5, 0x06, 0x24, 0x49,
        0xC0, 0xE0, 0x54, 0x32, 0x24, 0xF5, 0xC0, 0xE0, 0x22
    };
    if (sdata.size() >= sizeof(rgh3_v1_sig)) {
        for (size_t i = 0; i <= sdata.size() - sizeof(rgh3_v1_sig); ++i) {
            if (std::memcmp(sdata.data() + i, rgh3_v1_sig, sizeof(rgh3_v1_sig)) == 0) {
                has_rgh3_v1_obfuscation = true;
                break;
            }
        }
    }
    bool has_rgh3_v1_reset =
        (sdata.size() >= 3 && sdata[0] == 0x02 && sdata[1] == 0x2E && sdata[2] == 0x21);

    if (has_rgh3_v1_obfuscation || has_rgh3_v1_reset) {
        return SmcType::Rgh3V1;
    }

    bool has_cr4_sig = false;
    static constexpr uint8_t cr4_sig[4] = {0x43, 0x08, 0x80, 0x03};
    if (sdata.size() >= sizeof(cr4_sig)) {
        for (size_t i = 0; i <= sdata.size() - sizeof(cr4_sig); ++i) {
            if (std::memcmp(sdata.data() + i, cr4_sig, sizeof(cr4_sig)) == 0) {
                has_cr4_sig = true;
                break;
            }
        }
    }

    if (has_cr4_sig) {
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
            for (size_t i = 0; i + 2 < sdata.size(); ++i) {
                if (sdata[i] == 0x75 &&
                    (sdata[i + 1] == 0x3B || sdata[i + 1] == 0x3C || sdata[i + 1] == 0x3D)) {
                    if (sdata[i + 2] == 0x8A || sdata[i + 2] == 0x41) {
                        is_smc_plus = true;
                        break;
                    }
                }
            }
        }

        return is_smc_plus ? SmcType::SmcPlus : SmcType::CR4;
    }

    auto ret = SmcType::Unknown;
    bool glitch_patched = false;
    bool retail = false;
    bool has_d4_write = false;

    const size_t scan_end = sdata.size() - 6;
    for (size_t i = 0; i < scan_end; ++i) {
        switch (sdata[i]) {
            case 0x05:
                if (sdata[i + 2] == 0xE5 && sdata[i + 4] == 0xB4 && sdata[i + 5] == 0x05) {
                    retail = true;
                    glitch_patched = false;
                }
                break;
            case 0x00:
                if (sdata[i + 1] == 0x00 && sdata[i + 2] == 0xE5 && sdata[i + 4] == 0xB4 &&
                    sdata[i + 5] == 0x05) {
                    glitch_patched = true;
                }
                break;
            case 0x78:
                if (sdata[i + 1] == 0xBA && sdata[i + 2] == 0xB6) {
                    ret = SmcType::Cygnos;
                }
                break;
            case 0xD0:
                if (sdata[i + 1] == 0x00 && sdata[i + 2] == 0x00 && sdata[i + 3] == 0x1B) {
                    ret = SmcType::Jtag;
                }
                break;
            default:
                break;
        }

        if (sdata[i] == 0x75 && sdata[i + 2] == 0xD4) {
            has_d4_write = true;
        } else if (sdata[i] == 0x74 && sdata[i + 1] == 0xD4) {
            has_d4_write = true;
        }
    }

    if (glitch_patched && !retail) {
        if (has_d4_write) {
            return SmcType::Rgh3V2;
        }
        bool has_high_code = false;
        const size_t check_start = std::min(sdata.size(), static_cast<size_t>(0x2D73));
        for (size_t i = check_start; i < sdata.size(); ++i) {
            if (sdata[i] != 0x00 && sdata[i] != 0xFF) {
                has_high_code = true;
                break;
            }
        }
        if (has_high_code) {
            if (ret == SmcType::Unknown) {
                return SmcType::Rgh3V2;
            }
        }

        switch (ret) {
            case SmcType::Jtag: return SmcType::RJtag;
            case SmcType::Cygnos: return SmcType::RJtagCygnos;
            default: return SmcType::Glitch;
        }
    }

    return (ret == SmcType::Unknown && retail) ? SmcType::Retail : ret;
}

std::optional<Smc> Smc::parse(std::span<const uint8_t> bytes) {
    if (bytes.size() < 0x108 || bytes.size() > 0x4000) {
        return std::nullopt;
    }

    Smc smc;
    smc.data.assign(bytes.begin(), bytes.end());
    smc.encrypted = smc_is_encrypted(bytes);

    std::vector<uint8_t> dec_copy;
    std::span<const uint8_t> inspect = bytes;
    if (smc.encrypted) {
        dec_copy = smc_decrypt(bytes);
        inspect = dec_copy;
    }

    smc.motherboard = parse_motherboard(inspect[0x100]);
    smc.version = parse_version(inspect[0x100], inspect[0x101]);
    smc.variant = smc_get_type(inspect);

    Log::Debug("Parsed SMC: version={}, motherboard={}, type={}, encrypted={}",
               smc.version, smc_motherboard_name(smc.motherboard), smc_type_name(smc.variant), smc.encrypted);

    return smc;
}

std::optional<Smc> Smc::parse(const std::vector<uint8_t>& bytes) {
    return parse(std::span<const uint8_t>(bytes.data(), bytes.size()));
}

void Smc::decrypt() {
    if (!encrypted) {
        return;
    }
    data = smc_decrypt(data);
    encrypted = false;
}

void Smc::encrypt() {
    if (encrypted) {
        return;
    }
    data = smc_encrypt(data);
    encrypted = true;
}

} // namespace gxbuild3::NAND