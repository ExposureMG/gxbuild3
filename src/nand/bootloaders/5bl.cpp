#include "nand/bootloaders/5bl.hpp"

#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "utils/Log.hpp"

#include <string_view>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr std::string_view kStage = "CE/5BL";

    } // namespace

    Result<BootloaderCe> BootloaderCe::parse(std::span<const uint8_t> bytes) {
        auto parsed = stage::parse_stage<ce_header>(bytes, kStage);
        if (!parsed)
            return std::unexpected(std::move(parsed.error()));

        BootloaderCe ce;
        ce.header = parsed->header;
        ce.data = std::move(parsed->data);
        ce.decrypted = ce.is_decrypted();
        Log::Debug("Parsed 5BL/CE: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   ce.header.header.version, ce.header.header.size, ce.header.header.entrypoint);
        return ce;
    }

    Result<void> BootloaderCe::decrypt(const uint8_t cd_key[16]) {
        if (decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));

        if (data.size() + sizeof(ce_header) < header.header.size)
            return fail(ErrorCode::Truncated, "CE/5BL payload too short");

        stage::pad_payload(data, *payload_size);

        // CE keeps no derived key: the HMAC(cd_key, nonce) the crypt returns is dropped.
        if (auto key = stage::crypt_stage_record(header, data, HmacType::Default, cd_key, nullptr,
                                                 0x20, kStage);
            !key)
            return std::unexpected(std::move(key.error()));
        decrypted = true;
        return {};
    }

    Result<void> BootloaderCe::encrypt(const uint8_t cd_key[16]) {
        if (!decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        stage::pad_payload(data, *payload_size);

        stage::randomize_zero_nonce(header.key);

        if (auto key = stage::crypt_stage_record(header, data, HmacType::Default, cd_key, nullptr,
                                                 0x20, kStage);
            !key)
            return std::unexpected(std::move(key.error()));
        decrypted = false;
        return {};
    }

    bool BootloaderCe::is_decrypted() const {
        return decrypted || (header.padding == 0x00000000);
    }

    std::vector<uint8_t> BootloaderCe::serialize() const {
        return stage::serialize_stage(header, data);
    }

} // namespace gxbuild3::nand
