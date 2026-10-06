#include "nand/bootloaders/4bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    Result<BootloaderCd> BootloaderCd::parse(std::span<const uint8_t> bytes) {
        BootloaderCd cd;
        if (bytes.size() < sizeof(cd_header))
            return fail(ErrorCode::Truncated, "CD/4BL data too short");

        std::memcpy(&cd.header, bytes.data(), sizeof(cd_header));

        byteswap_generic_header(cd.header.header);
        byteswap_cd_header_numeric_fields(cd.header);
        if (auto size = aligned_stage_size(cd.header.header.size, sizeof(cd_header), "CD/4BL");
            !size)
            return std::unexpected(std::move(size.error()));

        cd.data = std::vector<uint8_t>(bytes.begin() + sizeof(cd_header), bytes.end());
        cd.decrypted = cd.is_decrypted();
        Log::Debug("Parsed 4BL/CD: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cd.header.header.version, cd.header.header.size, cd.header.header.entrypoint);
        return cd;
    }

    Result<size_t> BootloaderCd::required_data_size() const {
        auto size_aligned = aligned_stage_size(header.header.size, sizeof(cd_header), "CD/4BL");
        if (!size_aligned)
            return std::unexpected(std::move(size_aligned.error()));
        return *size_aligned - sizeof(cd_header);
    }

    Result<void> BootloaderCd::crypt_stage(const uint8_t parent_key[16],
                                           const uint8_t cpu_key[16]) {
        uint8_t cur_key[16];
        std::memcpy(cur_key, parent_key, 16);

        std::vector<uint8_t> buffer(sizeof(cd_header) + data.size());
        cd_header temp_hdr = header;
        byteswap_generic_header(temp_hdr.header);
        byteswap_cd_header_numeric_fields(temp_hdr);
        std::memcpy(buffer.data(), &temp_hdr, sizeof(cd_header));
        std::memcpy(buffer.data() + sizeof(cd_header), data.data(), data.size());

        const auto hmac_type = cpu_key ? HmacType::Hmac1920 : HmacType::Default;
        if (auto crypted = crypt_single_bl(buffer, hmac_type, cur_key, cpu_key, nullptr, 0x20);
            !crypted)
            return with_context(std::move(crypted), "CD/4BL");
        derived_key.emplace();
        std::copy_n(cur_key, derived_key->size(), derived_key->begin());

        std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                    sizeof(cd_header) - 0x20);
        byteswap_cd_header_numeric_fields(header);
        std::memcpy(data.data(), buffer.data() + sizeof(cd_header), data.size());
        return {};
    }

    Result<void> BootloaderCd::decrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16]) {
        if (decrypted)
            return {};
        auto required = required_data_size();
        if (!required)
            return std::unexpected(std::move(required.error()));

        if (data.size() + sizeof(cd_header) < header.header.size)
            return fail(ErrorCode::Truncated, "CD/4BL payload too short");

        if (data.size() < *required) {
            data.resize(*required, 0x00);
        }

        if (auto crypted = crypt_stage(parent_key, cpu_key); !crypted)
            return crypted;
        decrypted = true;
        return {};
    }

    Result<void> BootloaderCd::encrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16]) {
        if (!decrypted)
            return {};
        auto required = required_data_size();
        if (!required)
            return std::unexpected(std::move(required.error()));
        if (data.size() < *required) {
            data.resize(*required, 0x00);
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

        if (auto crypted = crypt_stage(parent_key, cpu_key); !crypted)
            return crypted;
        decrypted = false;
        return {};
    }

    bool BootloaderCd::is_decrypted() const {
        return decrypted || (header.nonce_6bl[0] == 0x00 && header.ce_hash[0] != 0x00);
    }

    std::vector<uint8_t> BootloaderCd::serialize() const {
        std::vector<uint8_t> out(sizeof(cd_header));
        cd_header temp_hdr = header;
        byteswap_generic_header(temp_hdr.header);
        byteswap_cd_header_numeric_fields(temp_hdr);

        std::memcpy(out.data(), &temp_hdr, sizeof(cd_header));
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

} // namespace gxbuild3::nand
