#include "nand/bootloaders/5bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    Result<BootloaderCe> BootloaderCe::parse(std::span<const uint8_t> bytes) {
        BootloaderCe ce;
        if (bytes.size() < sizeof(ce_header))
            return fail(ErrorCode::Truncated, "CE/5BL data too short");

        std::memcpy(&ce.header, bytes.data(), sizeof(ce_header));

        if (auto size = aligned_stage_size(ce.header.header.size, sizeof(ce_header), "CE/5BL");
            !size)
            return std::unexpected(std::move(size.error()));

        ce.data = std::vector<uint8_t>(bytes.begin() + sizeof(ce_header), bytes.end());
        ce.decrypted = ce.is_decrypted();
        Log::Debug("Parsed 5BL/CE: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   ce.header.header.version, ce.header.header.size, ce.header.header.entrypoint);
        return ce;
    }

    Result<size_t> BootloaderCe::required_data_size() const {
        auto size_aligned = aligned_stage_size(header.header.size, sizeof(ce_header), "CE/5BL");
        if (!size_aligned)
            return std::unexpected(std::move(size_aligned.error()));
        return *size_aligned - sizeof(ce_header);
    }

    Result<void> BootloaderCe::crypt_stage(const uint8_t cd_key[16]) {
        uint8_t cur_key[16];
        std::memcpy(cur_key, cd_key, 16);

        std::vector<uint8_t> buffer(sizeof(ce_header) + data.size());
        std::memcpy(buffer.data(), &header, sizeof(ce_header));
        std::memcpy(buffer.data() + sizeof(ce_header), data.data(), data.size());

        if (auto crypted =
                crypt_single_bl(buffer, HmacType::Default, cur_key, nullptr, nullptr, 0x20);
            !crypted)
            return with_context(std::move(crypted), "CE/5BL");

        std::memcpy(reinterpret_cast<uint8_t*>(&header) + 0x20, buffer.data() + 0x20,
                    sizeof(ce_header) - 0x20);
        std::memcpy(data.data(), buffer.data() + sizeof(ce_header), data.size());
        return {};
    }

    Result<void> BootloaderCe::decrypt(const uint8_t cd_key[16]) {
        if (decrypted)
            return {};
        auto required = required_data_size();
        if (!required)
            return std::unexpected(std::move(required.error()));

        if (data.size() + sizeof(ce_header) < header.header.size)
            return fail(ErrorCode::Truncated, "CE/5BL payload too short");

        if (data.size() < *required) {
            data.resize(*required, 0x00);
        }

        if (auto crypted = crypt_stage(cd_key); !crypted)
            return crypted;
        decrypted = true;
        return {};
    }

    Result<void> BootloaderCe::encrypt(const uint8_t cd_key[16]) {
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

        if (auto crypted = crypt_stage(cd_key); !crypted)
            return crypted;
        decrypted = false;
        return {};
    }

    bool BootloaderCe::is_decrypted() const {
        return decrypted || (header.padding == 0x00000000);
    }

    std::vector<uint8_t> BootloaderCe::serialize() const {
        std::vector<uint8_t> out(sizeof(ce_header));
        std::memcpy(out.data(), &header, sizeof(ce_header));
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

} // namespace gxbuild3::nand
