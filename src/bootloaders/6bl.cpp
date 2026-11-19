#include "bootloaders/6bl.hpp"
#include "bootloaders/Keyvault.hpp"
#include "Utils.hpp"
#include "excrypt.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCf BootloaderCf::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCf cf;
    if (bytes.size() < sizeof(bl6_header))
        throw std::runtime_error("CF/6BL data too short");
    
    std::memcpy(&cf.header, bytes.data(), sizeof(bl6_header));
    
    cf.header.header.magic = bswap16(cf.header.header.magic);
    cf.header.header.version = bswap16(cf.header.header.version);
    cf.header.header.flags = bswap16(cf.header.header.flags);
    cf.header.header.size = bswap32(cf.header.header.size);
    cf.header.header.entrypoint = bswap32(cf.header.header.entrypoint);
    
    cf.data = std::vector<uint8_t>(bytes.begin() + sizeof(bl6_header), bytes.end());
    cf.decrypted = cf.is_decrypted();
    return cf;
}

void BootloaderCf::decrypt(const uint8_t onebl_key[16]) {
    if (decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    
    if (data.size() + sizeof(bl6_header) - sizeof(bl_header) < payload_len)
        throw std::runtime_error("CF/6BL payload too short");
    
    uint8_t derived_key[16];
    ExCryptHmacSha(onebl_key, 16, header.key, 16, nullptr, 0, nullptr, 0, derived_key, 16);
    
    // Decrypt everything after the first 0x30 bytes (bl_header + metadata, starting at pairing)
    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&header) + 0x30, reinterpret_cast<uint8_t*>(&header) + sizeof(bl6_header));
    temp.insert(temp.end(), data.begin(), data.end());
    
    ExCryptRc4(derived_key, 16, temp.data(), temp.size());
    
    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x30, temp.data(), sizeof(bl6_header) - 0x30);
    std::copy(temp.begin() + (sizeof(bl6_header) - 0x30), temp.begin() + (sizeof(bl6_header) - 0x30) + data.size(), data.begin());
    
    decrypted = true;
}

void BootloaderCf::encrypt(const uint8_t onebl_key[16]) {
    if (!decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    
    if (data.size() + sizeof(bl6_header) - sizeof(bl_header) < payload_len) {
        size_t req = payload_len - (sizeof(bl6_header) - sizeof(bl_header));
        data.resize(req, 0x00);
    }

    bool is_zero = true;
    for (size_t i = 0; i < 16; ++i) {
        if (header.key[i] != 0) { is_zero = false; break; }
    }
    if (is_zero) {
        ExCryptRandom(header.key, 16);
    }

    uint8_t derived_key[16];
    ExCryptHmacSha(onebl_key, 16, header.key, 16, nullptr, 0, nullptr, 0, derived_key, 16);

    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<const uint8_t*>(&header) + 0x30, reinterpret_cast<const uint8_t*>(&header) + sizeof(bl6_header));
    temp.insert(temp.end(), data.begin(), data.end());

    ExCryptRc4(derived_key, 16, temp.data(), temp.size());

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x30, temp.data(), sizeof(bl6_header) - 0x30);
    std::copy(temp.begin() + (sizeof(bl6_header) - 0x30), temp.begin() + (sizeof(bl6_header) - 0x30) + data.size(), data.begin());

    decrypted = false;
}

void BootloaderCf::calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]) {
    if (!onebl_key || !cpu_key) return;

    auto serialized_hdr = serialize();
    if (serialized_hdr.size() < 0x220) return;

    std::vector<uint8_t> cf_copy(serialized_hdr.begin(), serialized_hdr.begin() + 0x220);

    uint8_t rc4_key[20] = {0};
    ExCryptHmacSha(onebl_key, 16, header.key, 16, nullptr, 0, nullptr, 0, rc4_key, 20);

    std::memcpy(cf_copy.data() + 0x20, rc4_key, 16);

    uint8_t hmac_digest[20] = {0};
    ExCryptHmacSha(cpu_key, 16, cf_copy.data(), 0x220, nullptr, 0, nullptr, 0, hmac_digest, 20);

    std::memcpy(header.mac, hmac_digest, 16);
}

bool BootloaderCf::is_decrypted() const {
    return decrypted || (reinterpret_cast<const uint8_t*>(&header)[0x30] == 0x00);
}

bool BootloaderCf::verify_signature() const {
    return true;
}

std::vector<uint8_t> BootloaderCf::serialize() const {
    std::vector<uint8_t> out(sizeof(bl6_header));
    bl6_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);
    
    std::memcpy(out.data(), &temp_hdr, sizeof(bl6_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}