#include "nand/bootloaders/6bl.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCf BootloaderCf::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCf cf;
    if (bytes.size() < sizeof(cf_header))
        throw std::runtime_error("CF/6BL data too short");

    std::memcpy(&cf.header, bytes.data(), sizeof(cf_header));

    cf.header.header.magic = bswap16(cf.header.header.magic);
    cf.header.header.version = bswap16(cf.header.header.version);
    cf.header.header.flags = bswap16(cf.header.header.flags);
    cf.header.header.size = bswap32(cf.header.header.size);
    cf.header.header.entrypoint = bswap32(cf.header.header.entrypoint);

    cf.data = std::vector<uint8_t>(bytes.begin() + sizeof(cf_header), bytes.end());
    cf.decrypted = cf.is_decrypted();
    if (cf.decrypted)
        cf.parse_perbox();
    Log::Debug("Parsed 6BL/CF: version={}, size=0x{:X}, entrypoint=0x{:08X}",
               cf.header.header.version, cf.header.header.size, cf.header.header.entrypoint);
    return cf;
}

void BootloaderCf::decrypt(const uint8_t onebl_key[16]) {
    if (decrypted)
        return;

    uint8_t cur_key[16];
    std::memcpy(cur_key, onebl_key, 16);

    std::vector<uint8_t> buffer = serialize();
    if (buffer.size() < 0x230)
        throw std::runtime_error("CF/6BL payload too short");

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, 0x30);

    std::memcpy(&header.header, buffer.data(), sizeof(generic_header));
    header.header.magic = bswap16(header.header.magic);
    header.header.version = bswap16(header.header.version);
    header.header.flags = bswap16(header.header.flags);
    header.header.size = bswap32(header.header.size);
    header.header.entrypoint = bswap32(header.header.entrypoint);

    if (buffer.size() >= 0x40) {
        header.source_version = (buffer[0x20] << 8) | buffer[0x21];
        header.source_qfe = (buffer[0x22] << 8) | buffer[0x23];
        header.target_version = (buffer[0x24] << 8) | buffer[0x25];
        header.target_qfe = (buffer[0x26] << 8) | buffer[0x27];
        header.reserved = (buffer[0x28] << 24) | (buffer[0x29] << 16) | (buffer[0x2A] << 8) | buffer[0x2B];
        header.cg_size = (buffer[0x2C] << 24) | (buffer[0x2D] << 16) | (buffer[0x2E] << 8) | buffer[0x2F];
        std::memcpy(header.cg_key, buffer.data() + 0x30, 16);
    }

    data = std::vector<uint8_t>(buffer.begin() + sizeof(cf_header), buffer.end());

    decrypted = true;
    parse_perbox();
}

void BootloaderCf::encrypt(const uint8_t onebl_key[16]) {
    if (!decrypted)
        return;
    serialize_perbox();
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(generic_header);

    if (data.size() + sizeof(cf_header) - sizeof(generic_header) < payload_len) {
        size_t req = payload_len - (sizeof(cf_header) - sizeof(generic_header));
        data.resize(req, 0x00);
    }

    uint8_t cur_key[16];
    std::memcpy(cur_key, onebl_key, 16);

    std::vector<uint8_t> buffer(sizeof(cf_header) + data.size());
    cf_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);
    std::memcpy(buffer.data(), &temp_hdr, sizeof(cf_header));
    std::memcpy(buffer.data() + sizeof(cf_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, 0x30);

    std::memcpy(&header, buffer.data(), sizeof(cf_header));
    std::memcpy(data.data(), buffer.data() + sizeof(cf_header), data.size());

    decrypted = false;
}

void BootloaderCf::calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]) {
    if (!onebl_key || !cpu_key)
        return;

    auto serialized_hdr = serialize();
    if (serialized_hdr.size() < 0x220)
        return;

    std::vector<uint8_t> cf_copy(serialized_hdr.begin(), serialized_hdr.begin() + 0x220);

    uint8_t rc4_key[20] = {0};
    ExCryptHmacSha(onebl_key, 16, header.cg_key, 16, nullptr, 0, nullptr, 0, rc4_key, 20);

    std::memcpy(cf_copy.data() + 0x20, rc4_key, 16);

    uint8_t hmac_digest[20] = {0};
    ExCryptHmacSha(cpu_key, 16, cf_copy.data(), 0x220, nullptr, 0, nullptr, 0, hmac_digest, 20);

    if (data.size() >= 0x1C0 + sizeof(cf_perbox)) {
        std::memcpy(data.data() + 0x1C0 + 0x30, hmac_digest, 16);
    }
}

bool BootloaderCf::is_decrypted() const {
    return decrypted || (data.size() >= 0x10 && data[0] == 0x00 && data[1] == 0x00);
}

bool BootloaderCf::parse_perbox() {
    if (!is_decrypted() || data.size() < 0x1C0 + sizeof(cf_perbox))
        return false;

    cf_perbox pb{};
    std::memcpy(&pb, data.data() + 0x1C0, sizeof(cf_perbox));
    perbox = pb;
    return true;
}

bool BootloaderCf::serialize_perbox() {
    if (!is_decrypted() || !perbox.has_value() || data.size() < 0x1C0 + sizeof(cf_perbox))
        return false;

    std::memcpy(data.data() + 0x1C0, &(*perbox), sizeof(cf_perbox));
    return true;
}

std::vector<uint8_t> BootloaderCf::serialize() const {
    std::vector<uint8_t> out(sizeof(cf_header));
    cf_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);

    std::memcpy(out.data(), &temp_hdr, sizeof(cf_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}