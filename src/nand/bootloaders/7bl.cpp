#include "nand/bootloaders/7bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    Result<BootloaderCg> BootloaderCg::parse(std::span<const uint8_t> bytes) {
        BootloaderCg cg;
        if (bytes.size() < sizeof(cg_header))
            return fail(ErrorCode::Truncated, "CG/7BL data too short");

        std::memcpy(&cg.header, bytes.data(), sizeof(cg_header));

        byteswap_generic_header(cg.header.header);
        byteswap_cg_header_numeric_fields(cg.header);
        if (auto size = aligned_stage_size(cg.header.header.size, sizeof(cg_header), "CG/7BL");
            !size)
            return std::unexpected(std::move(size.error()));

        cg.data = std::vector<uint8_t>(bytes.begin() + sizeof(cg_header), bytes.end());
        cg.decrypted = cg.is_decrypted();
        Log::Debug("Parsed 7BL/CG: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cg.header.header.version, cg.header.header.size, cg.header.header.entrypoint);
        return cg;
    }

    Result<void> BootloaderCg::prepare_payload() {
        auto size_aligned = aligned_stage_size(header.header.size, sizeof(cg_header), "CG/7BL");
        if (!size_aligned)
            return std::unexpected(std::move(size_aligned.error()));
        const size_t needed_data_size = *size_aligned - sizeof(cg_header);

        if (data.size() < needed_data_size)
            data.resize(needed_data_size, 0x00);
        return {};
    }

    Result<void> BootloaderCg::crypt_stage(const uint8_t cg_hmac[16]) {
        uint8_t cur_key[16];
        std::memcpy(cur_key, cg_hmac, 16);

        std::vector<uint8_t> buffer(sizeof(cg_header) + data.size());
        cg_header temp_hdr = header;
        byteswap_generic_header(temp_hdr.header);
        byteswap_cg_header_numeric_fields(temp_hdr);
        std::memcpy(buffer.data(), &temp_hdr, sizeof(cg_header));
        std::memcpy(buffer.data() + sizeof(cg_header), data.data(), data.size());

        if (auto crypted =
                crypt_single_bl(buffer, HmacType::Default, cur_key, nullptr, nullptr, 0x20);
            !crypted)
            return with_context(std::move(crypted), "CG/7BL");

        std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                    sizeof(cg_header) - 0x20);
        byteswap_cg_header_numeric_fields(header);
        std::memcpy(data.data(), buffer.data() + sizeof(cg_header), data.size());
        return {};
    }

    Result<void> BootloaderCg::decrypt(const uint8_t cg_hmac[16]) {
        if (decrypted)
            return {};
        if (auto prepared = prepare_payload(); !prepared)
            return prepared;

        if (auto crypted = crypt_stage(cg_hmac); !crypted)
            return crypted;
        decrypted = true;
        return {};
    }

    Result<void> BootloaderCg::encrypt(const uint8_t cg_hmac[16]) {
        if (!decrypted)
            return {};
        if (auto prepared = prepare_payload(); !prepared)
            return prepared;

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

        if (auto crypted = crypt_stage(cg_hmac); !crypted)
            return crypted;
        decrypted = false;
        return {};
    }

    bool BootloaderCg::is_decrypted() const {
        return decrypted || (header.source_size != 0 && (header.source_size & 0xFFF) == 0x000);
    }

    std::vector<uint8_t> BootloaderCg::serialize() const {
        std::vector<uint8_t> out(sizeof(cg_header));
        cg_header temp_hdr = header;
        byteswap_generic_header(temp_hdr.header);
        byteswap_cg_header_numeric_fields(temp_hdr);

        std::memcpy(out.data(), &temp_hdr, sizeof(cg_header));
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

} // namespace gxbuild3::nand
