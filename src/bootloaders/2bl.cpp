#include "bootloaders/2bl.hpp"

#include "Utils.hpp"
#include "bootloaders/Common.hpp"
#include "excrypt.h"

#include <cstring>
#include <stdexcept>

BootloaderCb BootloaderCb::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCb cb;

    if (bytes.size() < sizeof(bl_header))
        throw std::runtime_error("CB data too short");

    std::memcpy(&cb.header, bytes.data(), sizeof(bl_header));

    cb.header.header.magic = bswap16(cb.header.header.magic);
    cb.header.header.version = bswap16(cb.header.header.version);
    cb.header.header.flags = bswap16(cb.header.header.flags);
    cb.header.header.size = bswap32(cb.header.header.size);
    cb.header.header.entrypoint = bswap32(cb.header.header.entrypoint);

    cb.data = std::vector<uint8_t>(bytes.begin() + sizeof(bl_header), bytes.end());
    cb.decrypted = cb.verify_decrypted();
    if (cb.decrypted)
        cb.populate_metadata();
    return cb;
}

bool BootloaderCb::verify_decrypted() const {
    if (data.size() < 0x380)
        return false;

    for (size_t i = 0x260; i < 0x380; i++)
        if (data[i] != 0)
            return false;

    return true;
}

bool BootloaderCb::is_decrypted() const {
    return decrypted || verify_decrypted() || (data.size() > 0x240 && data[0x240] == 0x80);
}

void BootloaderCb::do_rc4_decrypt(const uint8_t key[16], size_t payload_len) {
    ExCryptRc4(key, 16, data.data() + 0x10, static_cast<uint32_t>(payload_len - 0x10));
}

void BootloaderCb::decrypt(const uint8_t onebl_key[16]) {
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    uint8_t digest[20];
    std::array<uint8_t, 16> key;

    if (data.size() < 0x10)
        throw std::runtime_error("CB data too short");
    if (data.size() < payload_len)
        data.resize(payload_len, 0x00);

    ExCryptHmacSha(onebl_key, 16, data.data(), 0x10, nullptr, 0, nullptr, 0, digest, 20);

    std::memcpy(key.data(), digest, 16);
    derived_key = key;

    do_rc4_decrypt(key.data(), payload_len);
    decrypted = !decrypted;

    if (decrypted)
        populate_metadata();
}

void BootloaderCb::decrypt_v1(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]) {
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    uint8_t digest[20];
    std::array<uint8_t, 16> key;

    if (data.size() < 0x10)
        throw std::runtime_error("CB data too short");
    if (data.size() < payload_len)
        data.resize(payload_len, 0x00);

    ExCryptHmacSha(cb_a_key, 16, data.data(), 0x10, cpu_key, 16, nullptr, 0, digest, 20);

    std::memcpy(key.data(), digest, 16);
    derived_key = key;

    do_rc4_decrypt(key.data(), payload_len);
    decrypted = !decrypted;

    if (decrypted)
        populate_metadata();
}

void BootloaderCb::decrypt_v2(const bl2_header& cb_a_hdr, const uint8_t cb_a_key[16],
                              const uint8_t cpu_key[16]) {
    uint8_t digest[20];
    uint8_t cb_a_hdr_copy[16];
    std::array<uint8_t, 16> key;

    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);

    if (data.size() < 0x10)
        throw std::runtime_error("CB data too short");
    if (data.size() < payload_len)
        data.resize(payload_len, 0x00);

    std::memcpy(cb_a_hdr_copy, &cb_a_hdr, 16);
    cb_a_hdr_copy[6] = 0;
    cb_a_hdr_copy[7] = 0;

    EXCRYPT_HMACSHA_STATE state;
    ExCryptHmacShaInit(&state, cb_a_key, 16);
    ExCryptHmacShaUpdate(&state, data.data(), 0x10);
    ExCryptHmacShaUpdate(&state, cpu_key, 16);
    ExCryptHmacShaUpdate(&state, cb_a_hdr_copy, 16);
    ExCryptHmacShaFinal(&state, digest, 20);

    std::memcpy(key.data(), digest, 16);
    derived_key = key;

    do_rc4_decrypt(key.data(), payload_len);
    decrypted = !decrypted;

    if (decrypted)
        populate_metadata();
}

void BootloaderCb::decrypt_mfg(const uint8_t cb_a_key[16]) {
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(bl_header);
    uint8_t hmac_input[0x20];
    uint8_t zero_key[16] = {};
    uint8_t digest[20];

    if (data.size() < 0x10)
        throw std::runtime_error("CB data too short");
    if (data.size() < payload_len)
        data.resize(payload_len, 0x00);

    std::memcpy(hmac_input, data.data(), 0x10);
    std::memcpy(hmac_input + 0x10, cb_a_key, 0x10);

    ExCryptHmacSha(zero_key, 16, hmac_input, 0x20, nullptr, 0, nullptr, 0, digest, 20);

    std::array<uint8_t, 16> key;
    std::memcpy(key.data(), digest, 16);
    derived_key = key;

    do_rc4_decrypt(key.data(), payload_len);
    decrypted = !decrypted;
    if (decrypted)
        populate_metadata();
}

void BootloaderCb::populate_metadata() {
    bl2_metadata meta = {};
    uint8_t ldv = data[0x13];
    uint64_t tmp = 0;

    if (!is_decrypted() || data.size() < 0x3B0)
        return;

    meta.b_flags = header.header.flags;
    meta.pairing_data = std::array<uint8_t, 3>{data[0x12], data[0x11], data[0x10]};

    meta.lockdown_value = (ldv <= 16) ? ldv : 0;

    std::memcpy(&tmp, &data[0x240], 8);
    meta.post_output_addr = bswap64(tmp);

    std::memcpy(&tmp, &data[0x248], 8);
    meta.sb_flash_addr = bswap64(tmp);

    std::memcpy(&tmp, &data[0x250], 8);
    meta.soc_mmio_addr = bswap64(tmp);

    std::array<uint8_t, 4> console_allow = {};
    std::memcpy(console_allow.data(), &data[0x3A0], console_allow.size());
    meta.console_allow = console_allow;

    metadata = meta;
}

std::vector<uint8_t> BootloaderCb::serialize() const {
    std::vector<uint8_t> out(sizeof(bl_header));

    bl_header temp_hdr = header.header;

    temp_hdr.magic = bswap16(temp_hdr.magic);
    temp_hdr.version = bswap16(temp_hdr.version);
    temp_hdr.flags = bswap16(temp_hdr.flags);
    temp_hdr.size = bswap32(temp_hdr.size);
    temp_hdr.entrypoint = bswap32(temp_hdr.entrypoint);

    std::memcpy(out.data(), &temp_hdr, sizeof(bl_header));
    out.insert(out.end(), data.begin(), data.end());

    return out;
}
