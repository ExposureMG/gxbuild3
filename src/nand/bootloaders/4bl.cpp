#include "nand/bootloaders/4bl.hpp"

#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr std::string_view kStage = "CD/4BL";

    } // namespace

    Result<BootloaderCd> BootloaderCd::parse(std::span<const uint8_t> bytes) {
        auto parsed = stage::parse_stage<cd_header>(bytes, kStage);
        if (!parsed)
            return std::unexpected(std::move(parsed.error()));

        BootloaderCd cd;
        cd.header = parsed->header;
        cd.data = std::move(parsed->data);
        cd.decrypted = cd.is_decrypted();
        Log::Debug("Parsed 4BL/CD: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cd.header.header.version, cd.header.header.size, cd.header.header.entrypoint);
        return cd;
    }

    Result<void> BootloaderCd::crypt_stage(const uint8_t parent_key[16],
                                           const uint8_t cpu_key[16]) {
        // With a CPU key the CD key is bound to the console: HMAC(cpu_key, HMAC(parent, nonce)).
        const auto hmac_type = cpu_key ? HmacType::Hmac1920 : HmacType::Default;
        auto key =
            stage::crypt_stage_record(header, data, hmac_type, parent_key, cpu_key, 0x20, kStage);
        if (!key)
            return std::unexpected(std::move(key.error()));
        derived_key = *key;
        return {};
    }

    Result<void> BootloaderCd::decrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16]) {
        if (decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));

        if (data.size() + sizeof(cd_header) < header.header.size)
            return fail(ErrorCode::Truncated, "CD/4BL payload too short");

        stage::pad_payload(data, *payload_size);

        if (auto crypted = crypt_stage(parent_key, cpu_key); !crypted)
            return crypted;
        decrypted = true;
        return {};
    }

    Result<void> BootloaderCd::encrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16]) {
        if (!decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        stage::pad_payload(data, *payload_size);

        stage::randomize_zero_nonce(header.key);

        if (auto crypted = crypt_stage(parent_key, cpu_key); !crypted)
            return crypted;
        decrypted = false;
        return {};
    }

    bool BootloaderCd::is_decrypted() const {
        // A sealed CD is told from a plaintext one by its 6BL salt, which only a plaintext CD
        // shows as the ROM constant. The first nonce byte and the CE hash are ciphertext in a
        // sealed CD, so testing them mistook about 1 in 256 sealed CDs for plaintext.
        return decrypted || std::ranges::equal(header.salt_6bl, kRomSalt6bl);
    }

    std::vector<uint8_t> BootloaderCd::serialize() const {
        return stage::serialize_stage(header, data);
    }

} // namespace gxbuild3::nand
