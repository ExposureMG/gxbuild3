#include "nand/bootloaders/3bl.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"

#include <cstring>
#include <stdexcept>

BootloaderSc BootloaderSc::parse(const std::vector<uint8_t>& bytes) {
    BootloaderSc sc;
    if (bytes.size() < sizeof(sc_header))
        throw std::runtime_error("SC/3BL data too short");

    std::memcpy(&sc.header, bytes.data(), sizeof(sc_header));

    sc.header.header.magic = bswap16(sc.header.header.magic);
    sc.header.header.version = bswap16(sc.header.header.version);
    sc.header.header.flags = bswap16(sc.header.header.flags);
    sc.header.header.size = bswap32(sc.header.header.size);
    sc.header.header.entrypoint = bswap32(sc.header.header.entrypoint);

    sc.data = std::vector<uint8_t>(bytes.begin() + sizeof(sc_header), bytes.end());
    sc.decrypted = sc.is_decrypted();
    Log::Debug("Parsed 3BL/SC: version={}, size=0x{:X}, entrypoint=0x{:08X}",
               sc.header.header.version, sc.header.header.size, sc.header.header.entrypoint);
    return sc;
}

void BootloaderSc::decrypt(const uint8_t cb_key[16]) {
    if (decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t encrypted_len = size_aligned - sizeof(sc_header);

    if (data.size() < encrypted_len)
        data.resize(encrypted_len, 0x00);

    uint8_t cur_key[16];
    std::memcpy(cur_key, cb_key, 16);

    std::vector<uint8_t> buffer(sizeof(sc_header) + data.size());
    sc_header temp_hdr = header;
    std::memcpy(buffer.data(), &temp_hdr, sizeof(sc_header));
    std::memcpy(buffer.data() + sizeof(sc_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, sizeof(sc_header));

    std::memcpy(data.data(), buffer.data() + sizeof(sc_header), data.size());
    decrypted = true;
}

void BootloaderSc::encrypt(const uint8_t cb_key[16]) {
    if (!decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t encrypted_len = size_aligned - sizeof(sc_header);

    if (data.size() < encrypted_len) {
        data.resize(encrypted_len, 0x00);
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
    std::memcpy(cur_key, cb_key, 16);

    std::vector<uint8_t> buffer(sizeof(sc_header) + data.size());
    sc_header temp_hdr = header;
    std::memcpy(buffer.data(), &temp_hdr, sizeof(sc_header));
    std::memcpy(buffer.data() + sizeof(sc_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, sizeof(sc_header));

    std::memcpy(data.data(), buffer.data() + sizeof(sc_header), data.size());
    decrypted = false;
}

bool BootloaderSc::is_decrypted() const {
    return decrypted;
}

std::vector<uint8_t> BootloaderSc::serialize() const {
    std::vector<uint8_t> out(sizeof(sc_header));
    sc_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);

    std::memcpy(out.data(), &temp_hdr, sizeof(sc_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}
