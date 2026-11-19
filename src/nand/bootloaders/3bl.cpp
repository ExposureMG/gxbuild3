#include "nand/bootloaders/3bl.hpp"

#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "utils/Log.hpp"

#include <string_view>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr std::string_view kStage = "SC/3BL";

    } // namespace

    Result<BootloaderSc> BootloaderSc::parse(std::span<const uint8_t> bytes) {
        auto parsed = stage::parse_stage<sc_header>(bytes, kStage);
        if (!parsed)
            return std::unexpected(std::move(parsed.error()));

        BootloaderSc sc;
        sc.header = parsed->header;
        sc.data = std::move(parsed->data);
        sc.decrypted = sc.is_decrypted();
        Log::Debug("Parsed 3BL/SC: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   sc.header.header.version, sc.header.header.size, sc.header.header.entrypoint);
        return sc;
    }

    Result<void> BootloaderSc::decrypt(const uint8_t secret[16]) {
        if (decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        stage::pad_payload(data, *payload_size);

        // Same layout as CB/CD/CE: nonce at 0x10, cipher from 0x20 over signature and body.
        auto key = stage::crypt_stage_record(header, data, HmacType::Default, secret, nullptr, 0x20,
                                             kStage);
        if (!key)
            return std::unexpected(std::move(key.error()));
        derived_key = *key;
        decrypted = true;
        return {};
    }

    Result<void> BootloaderSc::encrypt(const uint8_t secret[16]) {
        if (!decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        stage::pad_payload(data, *payload_size);

        stage::randomize_zero_nonce(header.key);

        auto key = stage::crypt_stage_record(header, data, HmacType::Default, secret, nullptr, 0x20,
                                             kStage);
        if (!key)
            return std::unexpected(std::move(key.error()));
        derived_key = *key;
        decrypted = false;
        return {};
    }

    bool BootloaderSc::is_decrypted() const {
        return decrypted;
    }

    std::vector<uint8_t> BootloaderSc::serialize() const {
        return stage::serialize_stage(header, data);
    }

} // namespace gxbuild3::nand
