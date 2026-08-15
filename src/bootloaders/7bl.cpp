#include "bootloaders/7bl.hpp"
#include "bootloaders/Keyvault.hpp"
#include "Utils.hpp"
#include "excrypt.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCg BootloaderCg::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCg cg;
    if (bytes.size() < sizeof(bl7_header))
        throw std::runtime_error("CG/7BL data too short");
    
    std::memcpy(&cg.header, bytes.data(), sizeof(bl7_header));
    
    cg.header.header.magic = bswap16(cg.header.header.magic);
    cg.header.header.version = bswap16(cg.header.header.version);
    cg.header.header.flags = bswap16(cg.header.header.flags);
    cg.header.header.size = bswap32(cg.header.header.size);
    cg.header.header.entrypoint = bswap32(cg.header.header.entrypoint);
    
    cg.data = std::vector<uint8_t>(bytes.begin() + sizeof(bl7_header), bytes.end());
    cg.decrypted = cg.is_decrypted();
    return cg;
}

void BootloaderCg::decrypt(const uint8_t cg_hmac[16]) {
    if (decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    
    if (data.size() + sizeof(bl7_header) - sizeof(bl_header) < payload_len) {
        size_t needed_data_size = payload_len - (sizeof(bl7_header) - sizeof(bl_header));
        data.resize(needed_data_size, 0x00);
    }
    
    uint8_t derived_key[16];
    ExCryptHmacSha(cg_hmac, 16, header.key, 16, nullptr, 0, nullptr, 0, derived_key, 16);
    
    // Decrypt everything after the first 0x20 bytes (bl_header + key)
    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<uint8_t*>(&header) + 0x20, reinterpret_cast<uint8_t*>(&header) + sizeof(bl7_header));
    temp.insert(temp.end(), data.begin(), data.end());
    
    ExCryptRc4(derived_key, 16, temp.data(), temp.size());
    
    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, temp.data(), sizeof(bl7_header) - 0x20);
    std::copy(temp.begin() + (sizeof(bl7_header) - 0x20), temp.begin() + (sizeof(bl7_header) - 0x20) + data.size(), data.begin());
    
    decrypted = true;
}

void BootloaderCg::encrypt(const uint8_t cg_hmac[16]) {
    if (!decrypted) return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    
    if (data.size() + sizeof(bl7_header) - sizeof(bl_header) < payload_len) {
        size_t req = payload_len - (sizeof(bl7_header) - sizeof(bl_header));
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
    ExCryptHmacSha(cg_hmac, 16, header.key, 16, nullptr, 0, nullptr, 0, derived_key, 16);

    std::vector<uint8_t> temp;
    temp.insert(temp.end(), reinterpret_cast<const uint8_t*>(&header) + 0x20, reinterpret_cast<const uint8_t*>(&header) + sizeof(bl7_header));
    temp.insert(temp.end(), data.begin(), data.end());

    ExCryptRc4(derived_key, 16, temp.data(), temp.size());

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, temp.data(), sizeof(bl7_header) - 0x20);
    std::copy(temp.begin() + (sizeof(bl7_header) - 0x20), temp.begin() + (sizeof(bl7_header) - 0x20) + data.size(), data.begin());

    decrypted = false;
}

bool BootloaderCg::is_decrypted() const {
    return decrypted || (header.original_size != 0 && (header.original_size & 0xFFF) == 0x000);
}

std::vector<uint8_t> BootloaderCg::serialize() const {
    std::vector<uint8_t> out(sizeof(bl7_header));
    bl7_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);
    
    std::memcpy(out.data(), &temp_hdr, sizeof(bl7_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

std::vector<uint8_t> BootloaderCg::split(size_t limit) {
    if (limit < sizeof(bl7_header)) {
        throw std::invalid_argument("Limit is smaller than 7BL/CG header size");
    }
    size_t max_data_size = limit - sizeof(bl7_header);
    if (data.size() <= max_data_size) {
        return {};
    }
    std::vector<uint8_t> split_buffer(data.begin() + max_data_size, data.end());
    data.resize(max_data_size);
    header.header.size = static_cast<uint32_t>(limit);
    return split_buffer;
}

