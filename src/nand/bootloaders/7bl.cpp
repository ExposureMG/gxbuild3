#include "nand/bootloaders/7bl.hpp"

#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "utils/Log.hpp"

#include <string_view>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr std::string_view kStage = "CG/7BL";

    } // namespace

    Result<BootloaderCg> BootloaderCg::parse(std::span<const uint8_t> bytes) {
        auto parsed = stage::parse_stage<cg_header>(bytes, kStage);
        if (!parsed)
            return std::unexpected(std::move(parsed.error()));

        BootloaderCg cg;
        cg.header = parsed->header;
        cg.data = std::move(parsed->data);
        cg.decrypted = cg.is_decrypted();
        Log::Debug("Parsed 7BL/CG: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cg.header.header.version, cg.header.header.size, cg.header.header.entrypoint);
        return cg;
    }

    Result<void> BootloaderCg::decrypt(const uint8_t cg_hmac[16]) {
        if (decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        stage::pad_payload(data, *payload_size);

        // CG keeps no derived key: the HMAC(cg_hmac, nonce) the crypt returns is dropped.
        if (auto key = stage::crypt_stage_record(header, data, HmacType::Default, cg_hmac, nullptr,
                                                 0x20, kStage);
            !key)
            return std::unexpected(std::move(key.error()));
        decrypted = true;
        return {};
    }

    Result<void> BootloaderCg::encrypt(const uint8_t cg_hmac[16]) {
        if (!decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        stage::pad_payload(data, *payload_size);

        stage::randomize_zero_nonce(header.key);

        if (auto key = stage::crypt_stage_record(header, data, HmacType::Default, cg_hmac, nullptr,
                                                 0x20, kStage);
            !key)
            return std::unexpected(std::move(key.error()));
        decrypted = false;
        return {};
    }

    bool BootloaderCg::is_decrypted() const {
        return decrypted || (header.source_size != 0 && (header.source_size & 0xFFF) == 0x000);
    }

    std::vector<uint8_t> BootloaderCg::serialize() const {
        return stage::serialize_stage(header, data);
    }

} // namespace gxbuild3::nand
