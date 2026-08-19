#include "nand/bootloaders/7bl.hpp"

#include "utils/Log.hpp"
#include "utils/Utils.hpp"
#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

BootloaderCg BootloaderCg::parse(const std::vector<uint8_t>& bytes) {
    BootloaderCg cg;
    if (bytes.size() < sizeof(cg_header))
        throw std::runtime_error("CG/7BL data too short");

    std::memcpy(&cg.header, bytes.data(), sizeof(cg_header));

    cg.header.header.magic = bswap16(cg.header.header.magic);
    cg.header.header.version = bswap16(cg.header.header.version);
    cg.header.header.flags = bswap16(cg.header.header.flags);
    cg.header.header.size = bswap32(cg.header.header.size);
    cg.header.header.entrypoint = bswap32(cg.header.header.entrypoint);

    cg.data = std::vector<uint8_t>(bytes.begin() + sizeof(cg_header), bytes.end());
    cg.decrypted = cg.is_decrypted();
    Log::Debug("Parsed 7BL/CG: version={}, size=0x{:X}, entrypoint=0x{:08X}",
               cg.header.header.version, cg.header.header.size, cg.header.header.entrypoint);
    return cg;
}

void BootloaderCg::decrypt(const uint8_t cg_hmac[16]) {
    if (decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(generic_header);

    if (data.size() + sizeof(cg_header) - sizeof(generic_header) < payload_len) {
        size_t needed_data_size = payload_len - (sizeof(cg_header) - sizeof(generic_header));
        data.resize(needed_data_size, 0x00);
    }

    uint8_t cur_key[16];
    std::memcpy(cur_key, cg_hmac, 16);

    std::vector<uint8_t> buffer(sizeof(cg_header) + data.size());
    cg_header temp_hdr = header;
    std::memcpy(buffer.data(), &temp_hdr, sizeof(cg_header));
    std::memcpy(buffer.data() + sizeof(cg_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, 0x20);

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                sizeof(cg_header) - 0x20);
    std::memcpy(data.data(), buffer.data() + sizeof(cg_header), data.size());

    decrypted = true;
}

void BootloaderCg::encrypt(const uint8_t cg_hmac[16]) {
    if (!decrypted)
        return;
    uint32_t size_aligned = (header.header.size + 0xF) & ~0xF;
    size_t payload_len = size_aligned - sizeof(generic_header);

    if (data.size() + sizeof(cg_header) - sizeof(generic_header) < payload_len) {
        size_t req = payload_len - (sizeof(cg_header) - sizeof(generic_header));
        data.resize(req, 0x00);
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
    std::memcpy(cur_key, cg_hmac, 16);

    std::vector<uint8_t> buffer(sizeof(cg_header) + data.size());
    cg_header temp_hdr = header;
    std::memcpy(buffer.data(), &temp_hdr, sizeof(cg_header));
    std::memcpy(buffer.data() + sizeof(cg_header), data.data(), data.size());

    gxbuild3::bootloaders::crypt_single_bl(buffer, gxbuild3::bootloaders::HmacType::Default,
                                           cur_key, nullptr, nullptr, 0x20);

    std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                sizeof(cg_header) - 0x20);
    std::memcpy(data.data(), buffer.data() + sizeof(cg_header), data.size());

    decrypted = false;
}

bool BootloaderCg::is_decrypted() const {
    return decrypted || (header.source_size != 0 && (header.source_size & 0xFFF) == 0x000);
}

std::vector<uint8_t> BootloaderCg::serialize() const {
    std::vector<uint8_t> out(sizeof(cg_header));
    cg_header temp_hdr = header;
    temp_hdr.header.magic = bswap16(temp_hdr.header.magic);
    temp_hdr.header.version = bswap16(temp_hdr.header.version);
    temp_hdr.header.flags = bswap16(temp_hdr.header.flags);
    temp_hdr.header.size = bswap32(temp_hdr.header.size);
    temp_hdr.header.entrypoint = bswap32(temp_hdr.header.entrypoint);

    std::memcpy(out.data(), &temp_hdr, sizeof(cg_header));
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

std::vector<uint8_t> BootloaderCg::split(size_t limit) {
    if (limit < sizeof(cg_header)) {
        throw std::invalid_argument("Limit is smaller than 7BL/CG header size");
    }
    size_t max_data_size = limit - sizeof(cg_header);
    if (data.size() <= max_data_size) {
        return {};
    }
    std::vector<uint8_t> split_buffer(data.begin() + max_data_size, data.end());
    data.resize(max_data_size);
    header.header.size = static_cast<uint32_t>(limit);
    return split_buffer;
}
