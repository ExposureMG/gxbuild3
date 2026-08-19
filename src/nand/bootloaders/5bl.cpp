#include "nand/bootloaders/5bl.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCe BootloaderCe::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCe ce;
    if (bytes.size() < sizeof(ce_header))
        throw std::runtime_error("CE/5BL data too short");

    std::memcpy(&ce.header, bytes.data(), sizeof(ce_header));

    ce.header.header.magic = bswap16(ce.header.header.magic);
    ce.header.header.version = bswap16(ce.header.header.version);
    ce.header.header.flags = bswap16(ce.header.header.flags);
    ce.header.header.size = bswap32(ce.header.header.size);
    ce.header.header.entrypoint = bswap32(ce.header.header.entrypoint);

    ce.data = std::vector<uint8_t>(bytes.begin() + sizeof(ce_header), bytes.end());
    ce.decrypted = ce.is_decrypted();
    Log::Debug("Parsed 5BL/CE: version={}, size=0x{:X}, entrypoint=0x{:08X}",
               ce.header.header.version, ce.header.header.size, ce.header.header.entrypoint);
    return ce;
}

void BootloaderCe::decrypt(const uint8_t cd_key[16]) {
    if (decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(ce_header);

    if (data.size() + sizeof(ce_header) < header.header.size)
        throw std::runtime_error("CE/5BL payload too short");

    if (data.size() < required_data_size) {
        data.resize(required_data_size, 0x00);
    }

    uint8_t cur_key[16];
    std::memcpy(cur_key, cd_key, 16);

    std::vector<uint8_t> buffer(sizeof(ce_header) + data.size());
    ce_header temp_hdr = header;
    std::memcpy(buffer.data(), &temp_hdr, sizeof(ce_header));
    std::memcpy(buffer.data() + sizeof(ce_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, 0x20);

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                sizeof(ce_header) - 0x20);
    std::memcpy(data.data(), buffer.data() + sizeof(ce_header), data.size());

    decrypted = true;
}

void BootloaderCe::encrypt(const uint8_t cd_key[16]) {
    if (!decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t required_data_size = size_aligned - sizeof(ce_header);
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
    std::memcpy(cur_key, cd_key, 16);

    std::vector<uint8_t> buffer(sizeof(ce_header) + data.size());
    ce_header temp_hdr = header;
    std::memcpy(buffer.data(), &temp_hdr, sizeof(ce_header));
    std::memcpy(buffer.data() + sizeof(ce_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, 0x20);

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                sizeof(ce_header) - 0x20);
    std::memcpy(data.data(), buffer.data() + sizeof(ce_header), data.size());

    decrypted = false;
}

bool BootloaderCe::is_decrypted() const {
    return decrypted || (header.padding == 0x00000000);
}

std::vector<uint8_t> BootloaderCe::serialize() const {
    std::vector<uint8_t> out(sizeof(ce_header));
    ce_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);

    std::memcpy(out.data(), &temp_hdr, sizeof(ce_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}