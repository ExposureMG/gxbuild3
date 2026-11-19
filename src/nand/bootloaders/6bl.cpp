#include "nand/bootloaders/6bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Stage.hpp"
#include "utils/Log.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr std::string_view kStage = "CF/6BL";

        // The per-box block sits after the payload's CG continuation (spill) table.
        constexpr size_t kCfPerboxOffset = kCfTableSize;
        constexpr size_t kCfPerboxEnd = kCfPerboxOffset + sizeof(cf_perbox);

        // CF is the one stage whose RC4 starts after its 0x30-byte header, not at +0x20.
        constexpr size_t kCfCryptStart = 0x30;

    } // namespace

    Result<BootloaderCf> BootloaderCf::parse(std::span<const uint8_t> bytes) {
        auto parsed = stage::parse_stage<cf_header>(bytes, kStage);
        if (!parsed)
            return std::unexpected(std::move(parsed.error()));

        BootloaderCf cf;
        cf.header = parsed->header;
        cf.data = std::move(parsed->data);
        cf.decrypted = cf.is_decrypted();
        // A plaintext CF too short for the per-box block still parses, without `perbox`.
        if (cf.decrypted) {
            if (auto parsed_perbox = cf.parse_perbox(); !parsed_perbox)
                Log::Debug("CF per-box data not parsed: {}", parsed_perbox.error().describe());
        }
        Log::Debug("Parsed 6BL/CF: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cf.header.header.version, cf.header.header.size, cf.header.header.entrypoint);
        return cf;
    }

    Result<void> BootloaderCf::decrypt(const uint8_t onebl_key[16]) {
        if (decrypted)
            return {};

        // CF does not pad on decrypt; the serialized stage must hold the per-box block.
        if (sizeof(cf_header) + data.size() < 0x230)
            return fail(ErrorCode::Truncated, "CF/6BL payload too short");

        // CF keeps no derived key: the HMAC(onebl_key, nonce) the crypt returns is dropped.
        if (auto key = stage::crypt_stage_record(header, data, HmacType::Default, onebl_key,
                                                 nullptr, kCfCryptStart, kStage);
            !key)
            return std::unexpected(std::move(key.error()));

        decrypted = true;
        // The 0x230-byte check above covers the per-box block, so this cannot fail; `perbox`
        // would otherwise keep its previous value.
        if (auto parsed = parse_perbox(); !parsed)
            Log::Debug("CF per-box data not parsed: {}", parsed.error().describe());
        return {};
    }

    Result<void> BootloaderCf::encrypt(const uint8_t onebl_key[16]) {
        if (!decrypted)
            return {};
        auto payload_size = stage::stage_payload_size(header, kStage);
        if (!payload_size)
            return std::unexpected(std::move(payload_size.error()));
        // A CF without parsed per-box data has nothing to write back; one whose payload no
        // longer holds it is an error.
        if (perbox.has_value()) {
            if (auto stored = serialize_perbox(); !stored)
                return with_context(std::move(stored), std::string(kStage));
        }
        stage::pad_payload(data, *payload_size);

        // CF keeps its stored nonce: unlike SC/CD/CE/CG, a zero nonce is not randomised.
        if (auto key = stage::crypt_stage_record(header, data, HmacType::Default, onebl_key,
                                                 nullptr, kCfCryptStart, kStage);
            !key)
            return std::unexpected(std::move(key.error()));

        decrypted = false;
        return {};
    }

    Result<void> BootloaderCf::calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]) {
        if (!onebl_key || !cpu_key)
            return fail(ErrorCode::InvalidArgument, "CF MAC needs the 1BL key and the CPU key");
        // Implies the 0x220 serialized bytes the MAC covers.
        if (data.size() < kCfPerboxEnd)
            return fail(ErrorCode::Truncated,
                        "CF payload (0x{:X} bytes) is too short for its per-box MAC", data.size());

        auto serialized_hdr = serialize();
        std::vector<uint8_t> cf_copy(serialized_hdr.begin(), serialized_hdr.begin() + 0x220);

        uint8_t rc4_key[20] = {0};
        ExCryptHmacSha(onebl_key, 16, header.fixpoint_nonce, 16, nullptr, 0, nullptr, 0, rc4_key,
                       20);

        std::memcpy(cf_copy.data() + 0x20, rc4_key, 16);

        uint8_t hmac_digest[20] = {0};
        ExCryptHmacSha(cpu_key, 16, cf_copy.data(), 0x220, nullptr, 0, nullptr, 0, hmac_digest, 20);

        std::memcpy(data.data() + kCfPerboxOffset + offsetof(cf_perbox, per_box_digest),
                    hmac_digest, 16);
        if (perbox.has_value())
            std::memcpy(perbox->per_box_digest, hmac_digest, 16);
        return {};
    }

    bool BootloaderCf::is_decrypted() const {
        return decrypted || (data.size() >= 0x10 && data[0] == 0x00 && data[1] == 0x00);
    }

    std::optional<std::array<uint8_t, 16>> BootloaderCf::cg_key() const {
        if (!is_decrypted())
            return std::nullopt;
        const auto serialized = serialize();
        if (serialized.size() < kCfCgNonceOffset + 16)
            return std::nullopt;
        std::array<uint8_t, 16> key{};
        std::copy_n(serialized.begin() + kCfCgNonceOffset, key.size(), key.begin());
        return key;
    }

    Result<void> BootloaderCf::parse_perbox() {
        if (!is_decrypted())
            return fail(ErrorCode::InvalidArgument, "CF per-box data needs a decrypted CF");
        if (data.size() < kCfPerboxEnd)
            return fail(ErrorCode::Truncated,
                        "CF payload (0x{:X} bytes) is too short for per-box data", data.size());

        auto pb = wire::read<cf_perbox>(data, kCfPerboxOffset, "CF per-box data");
        if (!pb)
            return std::unexpected(std::move(pb.error()));
        perbox = *pb;
        return {};
    }

    Result<void> BootloaderCf::serialize_perbox() {
        if (!is_decrypted())
            return fail(ErrorCode::InvalidArgument, "CF per-box data needs a decrypted CF");
        if (!perbox.has_value())
            return fail(ErrorCode::InvalidArgument, "CF has no per-box data to serialize");
        if (data.size() < kCfPerboxEnd)
            return fail(ErrorCode::Truncated,
                        "CF payload (0x{:X} bytes) is too short for per-box data", data.size());

        return wire::write(std::span<uint8_t>(data), kCfPerboxOffset, *perbox, "CF per-box data");
    }

    std::vector<uint8_t> BootloaderCf::serialize() const {
        return stage::serialize_stage(header, data);
    }

} // namespace gxbuild3::nand
