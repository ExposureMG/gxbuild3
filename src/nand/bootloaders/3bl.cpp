#include "nand/bootloaders/3bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    Result<BootloaderSc> BootloaderSc::parse(std::span<const uint8_t> bytes) {
        BootloaderSc sc;
        if (bytes.size() < sizeof(sc_header))
            return fail(ErrorCode::Truncated, "SC/3BL data too short");

        std::memcpy(&sc.header, bytes.data(), sizeof(sc_header));

        byteswap_generic_header(sc.header.header);
        if (auto size = aligned_stage_size(sc.header.header.size, sizeof(sc_header), "SC/3BL");
            !size)
            return std::unexpected(std::move(size.error()));

        sc.data = std::vector<uint8_t>(bytes.begin() + sizeof(sc_header), bytes.end());
        sc.decrypted = sc.is_decrypted();
        Log::Debug("Parsed 3BL/SC: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   sc.header.header.version, sc.header.header.size, sc.header.header.entrypoint);
        return sc;
    }

    Result<void> BootloaderSc::prepare_payload() {
        auto size_aligned = aligned_stage_size(header.header.size, sizeof(sc_header), "SC/3BL");
        if (!size_aligned)
            return std::unexpected(std::move(size_aligned.error()));
        const size_t encrypted_len = *size_aligned - sizeof(sc_header);

        if (data.size() < encrypted_len)
            data.resize(encrypted_len, 0x00);
        return {};
    }

    Result<void> BootloaderSc::crypt_stage(const uint8_t secret[16]) {
        uint8_t cur_key[16];
        std::memcpy(cur_key, secret, 16);

        std::vector<uint8_t> buffer(sizeof(sc_header) + data.size());
        sc_header temp_hdr = header;
        byteswap_generic_header(temp_hdr.header);
        std::memcpy(buffer.data(), &temp_hdr, sizeof(sc_header));
        std::memcpy(buffer.data() + sizeof(sc_header), data.data(), data.size());

        // Same layout as CB/CD/CE: nonce at 0x10, cipher from 0x20 over signature and body.
        if (auto crypted =
                crypt_single_bl(buffer, HmacType::Default, cur_key, nullptr, nullptr, 0x20);
            !crypted)
            return with_context(std::move(crypted), "SC/3BL");
        derived_key.emplace();
        std::copy_n(cur_key, derived_key->size(), derived_key->begin());

        std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                    sizeof(sc_header) - 0x20);
        std::memcpy(data.data(), buffer.data() + sizeof(sc_header), data.size());
        return {};
    }

    Result<void> BootloaderSc::decrypt(const uint8_t secret[16]) {
        if (decrypted)
            return {};
        if (auto prepared = prepare_payload(); !prepared)
            return prepared;

        if (auto crypted = crypt_stage(secret); !crypted)
            return crypted;
        decrypted = true;
        return {};
    }

    Result<void> BootloaderSc::encrypt(const uint8_t secret[16]) {
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

        if (auto crypted = crypt_stage(secret); !crypted)
            return crypted;
        decrypted = false;
        return {};
    }

    bool BootloaderSc::is_decrypted() const {
        return decrypted;
    }

    std::vector<uint8_t> BootloaderSc::serialize() const {
        std::vector<uint8_t> out(sizeof(sc_header));
        sc_header temp_hdr = header;
        byteswap_generic_header(temp_hdr.header);

        std::memcpy(out.data(), &temp_hdr, sizeof(sc_header));
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

} // namespace gxbuild3::nand
