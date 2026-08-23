#include "nand/bootloaders/2bl.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"

#include <cstring>
#include <stdexcept>

BootloaderCb BootloaderCb::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCb cb;

    if (bytes.size() < sizeof(generic_header))
        throw std::runtime_error("CB data too short");

    std::memcpy(&cb.header, bytes.data(), sizeof(generic_header));

    cb.header.header.magic = bswap16(cb.header.header.magic);
    cb.header.header.version = bswap16(cb.header.header.version);
    cb.header.header.flags = bswap16(cb.header.header.flags);
    cb.header.header.size = bswap32(cb.header.header.size);
    cb.header.header.entrypoint = bswap32(cb.header.header.entrypoint);

    cb.data = std::vector<uint8_t>(bytes.begin() + sizeof(generic_header), bytes.end());
    cb.decrypted = cb.verify_decrypted();
    if (cb.decrypted)
        cb.populate_metadata();
    Log::Debug("Parsed 2BL/CB: version={}, size=0x{:X}, entrypoint=0x{:08X}",
               cb.header.header.version, cb.header.header.size, cb.header.header.entrypoint);
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

// CB / CB_A
void BootloaderCb::decrypt(const uint8_t onebl_key[16]) {
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(generic_header);
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

// CB_B
void BootloaderCb::decrypt_v1(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]) {
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(generic_header);
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

// Other CB_B impl?
void BootloaderCb::decrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                              const uint8_t cpu_key[16]) {
    uint8_t digest[20];
    uint8_t cb_a_hdr_copy[16];
    std::array<uint8_t, 16> key;

    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(generic_header);

    if (data.size() < 0x10)
        throw std::runtime_error("CB data too short");
    if (data.size() < payload_len)
        data.resize(payload_len, 0x00);

    generic_header be_hdr = cb_a_hdr.header;
    be_hdr.magic = bswap16(be_hdr.magic);
    be_hdr.version = bswap16(be_hdr.version);
    be_hdr.flags = bswap16(be_hdr.flags);
    be_hdr.size = bswap32(be_hdr.size);
    be_hdr.entrypoint = bswap32(be_hdr.entrypoint);

    std::memcpy(cb_a_hdr_copy, &be_hdr, 16);
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
    size_t payload_len = size_aligned - sizeof(generic_header);
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
    if (!is_decrypted() || data.size() < sizeof(cb_header) - sizeof(generic_header))
        return;

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + sizeof(generic_header), data.data(),
                sizeof(cb_header) - sizeof(generic_header));
    parse_perbox();
}

bool BootloaderCb::parse_perbox() {
    if (!is_decrypted() || data.size() < 0x30)
        return false;

    cb_perbox pb{};
    std::memcpy(&pb, data.data() + 0x10, sizeof(cb_perbox));
    perbox = pb;
    return true;
}

bool BootloaderCb::serialize_perbox() {
    if (!is_decrypted() || !perbox.has_value() || data.size() < 0x30)
        return false;

    std::memcpy(data.data() + 0x10, &(*perbox), sizeof(cb_perbox));
    return true;
}

std::vector<uint8_t> BootloaderCb::serialize() const {
    std::vector<uint8_t> out(sizeof(generic_header));

    generic_header temp_hdr = header.header;

    temp_hdr.magic = bswap16(temp_hdr.magic);
    temp_hdr.version = bswap16(temp_hdr.version);
    temp_hdr.flags = bswap16(temp_hdr.flags);
    temp_hdr.size = bswap32(temp_hdr.size);
    temp_hdr.entrypoint = bswap32(temp_hdr.entrypoint);

    std::memcpy(out.data(), &temp_hdr, sizeof(generic_header));
    out.insert(out.end(), data.begin(), data.end());

    return out;
}
