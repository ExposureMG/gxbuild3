#include "bootloaders/5bl.hpp"
#include "bootloaders/Keyvault.hpp"
#include "Utils.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCe BootloaderCe::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCe ce;
    if (bytes.size() < sizeof(bl5_header))
        throw std::runtime_error("CE/5BL data too short");
    
    std::memcpy(&ce.header, bytes.data(), sizeof(bl5_header));
    
    ce.header.header.magic = bswap16(ce.header.header.magic);
    ce.header.header.version = bswap16(ce.header.header.version);
    ce.header.header.flags = bswap16(ce.header.header.flags);
    ce.header.header.size = bswap32(ce.header.header.size);
    ce.header.header.entrypoint = bswap32(ce.header.header.entrypoint);
    
    ce.data = std::vector<uint8_t>(bytes.begin() + sizeof(bl5_header), bytes.end());
    ce.decrypted = ce.is_decrypted();
    return ce;
}

void BootloaderCe::decrypt(const uint8_t cd_key[16]) {
    if (decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(bl5_header);
    
    if (data.size() + sizeof(bl5_header) < header.header.size)
        throw std::runtime_error("CE/5BL payload too short");

    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }
    
    uint8_t derived_key[16];
    ExCryptHmacSha(cd_key, 16, header.key, 16, nullptr, 0, nullptr, 0, derived_key, 16);
    
    // Decrypt everything after the first 0x20 bytes (bl_header + key)
    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&header) + 0x20, reinterpret_cast<uint8_t*>(&header) + sizeof(bl5_header));
    temp.insert(temp.end(), data.begin(), data.end());
    
    ExCryptRc4(derived_key, 16, temp.data(), temp.size());
    
    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, temp.data(), sizeof(bl5_header) - 0x20);
    std::copy(temp.begin() + (sizeof(bl5_header) - 0x20), temp.begin() + (sizeof(bl5_header) - 0x20) + data.size(), data.begin());
    
    decrypted = true;
}

void BootloaderCe::encrypt(const uint8_t cd_key[16]) {
    if (!decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(bl5_header);
    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }

    bool is_zero = true;
    for (size_t i = 0; i < 16; ++i) {
        if (header.key[i] != 0) { is_zero = false; break; }
    }
    if (is_zero) {
        ExCryptRandom(header.key, 16);
    }

    uint8_t derived_key[16];
    ExCryptHmacSha(cd_key, 16, header.key, 16, nullptr, 0, nullptr, 0, derived_key, 16);

    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&header) + 0x20, reinterpret_cast<uint8_t*>(&header) + sizeof(bl5_header));
    temp.insert(temp.end(), data.begin(), data.end());

    ExCryptRc4(derived_key, 16, temp.data(), temp.size());

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, temp.data(), sizeof(bl5_header) - 0x20);
    std::copy(temp.begin() + (sizeof(bl5_header) - 0x20), temp.begin() + (sizeof(bl5_header) - 0x20) + data.size(), data.begin());

    decrypted = false;
}

bool BootloaderCe::is_decrypted() const {
    return decrypted || (header.unknown == 0x00000000);
}

std::vector<uint8_t> BootloaderCe::serialize() const {
    std::vector<uint8_t> out(sizeof(bl5_header));
    bl5_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);
    
    std::memcpy(out.data(), &temp_hdr, sizeof(bl5_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}