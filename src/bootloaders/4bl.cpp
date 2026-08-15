#include "bootloaders/4bl.hpp"
#include "bootloaders/Keyvault.hpp"
#include "Utils.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCd BootloaderCd::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCd cd;
    if (bytes.size() < sizeof(bl4_header))
        throw std::runtime_error("CD/4BL data too short");
    
    std::memcpy(&cd.header, bytes.data(), sizeof(bl4_header));
    
    cd.header.header.magic = bswap16(cd.header.header.magic);
    cd.header.header.version = bswap16(cd.header.header.version);
    cd.header.header.flags = bswap16(cd.header.header.flags);
    cd.header.header.size = bswap32(cd.header.header.size);
    cd.header.header.entrypoint = bswap32(cd.header.header.entrypoint);
    
    cd.data = std::vector<uint8_t>(bytes.begin() + sizeof(bl4_header), bytes.end());
    cd.decrypted = cd.is_decrypted();
    return cd;
}

void BootloaderCd::decrypt(const uint8_t cb_b_key[16]) {
    if (decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(bl4_header);
    
    if (data.size() + sizeof(bl4_header) < header.header.size)
        throw std::runtime_error("CD/4BL payload too short");

    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }
    
    uint8_t derived_key[16];
    std::memcpy(derived_key, header.rsa_pub_key, 16);
    
    // HMAC with CB_B/CBB key
    ExCryptHmacSha(cb_b_key, 16, derived_key, 16, nullptr, 0, nullptr, 0, derived_key, 16);
    
    // Decrypt everything after the first 0x20 bytes (bl_header + rsa_pub_key)
    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&header) + 0x20, reinterpret_cast<uint8_t*>(&header) + sizeof(bl4_header));
    temp.insert(temp.end(), data.begin(), data.end());
    
    ExCryptRc4(derived_key, 16, temp.data(), temp.size());
    
    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, temp.data(), sizeof(bl4_header) - 0x20);
    std::copy(temp.begin() + (sizeof(bl4_header) - 0x20), temp.begin() + (sizeof(bl4_header) - 0x20) + data.size(), data.begin());
    
    decrypted = true;
}

void BootloaderCd::encrypt(const uint8_t cb_b_key[16]) {
    if (!decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(bl4_header);
    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }

    bool is_zero = true;
    for (size_t i = 0; i < 16; ++i) {
        if (header.rsa_pub_key[i] != 0) { is_zero = false; break; }
    }
    if (is_zero) {
        ExCryptRandom(header.rsa_pub_key, 16);
    }

    uint8_t derived_key[16];
    std::memcpy(derived_key, header.rsa_pub_key, 16);

    ExCryptHmacSha(cb_b_key, 16, derived_key, 16, nullptr, 0, nullptr, 0, derived_key, 16);

    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&header) + 0x20, reinterpret_cast<uint8_t*>(&header) + sizeof(bl4_header));
    temp.insert(temp.end(), data.begin(), data.end());

    ExCryptRc4(derived_key, 16, temp.data(), temp.size());

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, temp.data(), sizeof(bl4_header) - 0x20);
    std::copy(temp.begin() + (sizeof(bl4_header) - 0x20), temp.begin() + (sizeof(bl4_header) - 0x20) + data.size(), data.begin());

    decrypted = false;
}

bool BootloaderCd::is_decrypted() const {
    return decrypted || (header.nonce_6bl[0] == 0x00);
}

std::vector<uint8_t> BootloaderCd::serialize() const {
    std::vector<uint8_t> out(sizeof(bl4_header));
    bl4_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);
    
    std::memcpy(out.data(), &temp_hdr, sizeof(bl4_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}