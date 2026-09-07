#include "nand/bootloaders/4bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCd BootloaderCd::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCd cd;
    if (bytes.size() < sizeof(cd_header))
        throw std::runtime_error("CD/4BL data too short");

    std::memcpy(&cd.header, bytes.data(), sizeof(cd_header));

    byteswap_generic_header(cd.header.header);
    byteswap_cd_header_numeric_fields(cd.header);

    cd.data = std::vector<uint8_t>(bytes.begin() + sizeof(cd_header), bytes.end());
    cd.decrypted = cd.is_decrypted();
    Log::Debug("Parsed 4BL/CD: version={}, size=0x{:X}, entrypoint=0x{:08X}",
               cd.header.header.version, cd.header.header.size, cd.header.header.entrypoint);
    return cd;
}

void BootloaderCd::decrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16]) {
    if (decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(cd_header);

    if (data.size() + sizeof(cd_header) < header.header.size)
        throw std::runtime_error("CD/4BL payload too short");

    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }

    uint8_t cur_key[16];
    std::memcpy(cur_key, parent_key, 16);

    std::vector<uint8_t> buffer(sizeof(cd_header) + data.size());
    cd_header temp_hdr = header;
    byteswap_generic_header(temp_hdr.header);
    byteswap_cd_header_numeric_fields(temp_hdr);
    std::memcpy(buffer.data(), &temp_hdr, sizeof(cd_header));
    std::memcpy(buffer.data() + sizeof(cd_header), data.data(), data.size());

    const auto hmac_type = cpu_key ? gxbuild3::bootloaders::HmacType::Hmac1920
                                   : gxbuild3::bootloaders::HmacType::Default;
    gxbuild3::bootloaders::crypt_single_bl(buffer, hmac_type, cur_key, cpu_key, nullptr, 0x20);

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                sizeof(cd_header) - 0x20);
    byteswap_cd_header_numeric_fields(header);
    std::memcpy(data.data(), buffer.data() + sizeof(cd_header), data.size());

    decrypted = true;
}

void BootloaderCd::encrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16]) {
    if (!decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(cd_header);
    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }

    bool is_zero = true;
    for (size_t i = 0; i < 16; ++i) {
        if (header.key[i] != 0) {
            is_zero = false;
            break;
        }
    }
    if (is_zero) {
        ExCryptRandom(header.key, 16);
    }

    uint8_t cur_key[16];
    std::memcpy(cur_key, parent_key, 16);

    std::vector<uint8_t> buffer(sizeof(cd_header) + data.size());
    cd_header temp_hdr = header;
    byteswap_generic_header(temp_hdr.header);
    byteswap_cd_header_numeric_fields(temp_hdr);
    std::memcpy(buffer.data(), &temp_hdr, sizeof(cd_header));
    std::memcpy(buffer.data() + sizeof(cd_header), data.data(), data.size());

    const auto hmac_type = cpu_key ? gxbuild3::bootloaders::HmacType::Hmac1920
                                   : gxbuild3::bootloaders::HmacType::Default;
    gxbuild3::bootloaders::crypt_single_bl(buffer, hmac_type, cur_key, cpu_key, nullptr, 0x20);

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                sizeof(cd_header) - 0x20);
    byteswap_cd_header_numeric_fields(header);
    std::memcpy(data.data(), buffer.data() + sizeof(cd_header), data.size());

    decrypted = false;
}

bool BootloaderCd::is_decrypted() const {
    return decrypted || (header.nonce_6bl[0] == 0x00 && header.ce_hash[0] != 0x00);
}

std::vector<uint8_t> BootloaderCd::serialize() const {
    std::vector<uint8_t> out(sizeof(cd_header));
    cd_header temp_hdr = header;
    byteswap_generic_header(temp_hdr.header);
    byteswap_cd_header_numeric_fields(temp_hdr);

    std::memcpy(out.data(), &temp_hdr, sizeof(cd_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}
