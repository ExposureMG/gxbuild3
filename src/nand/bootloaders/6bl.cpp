#include "nand/bootloaders/6bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        constexpr size_t kCfPerboxOffset = 0x1C0;
        // The per-box block sits after the 0x1C0-byte spill table of the payload.
        constexpr size_t kCfPerboxEnd = kCfPerboxOffset + sizeof(cf_perbox);

    } // namespace

    Result<BootloaderCf> BootloaderCf::parse(std::span<const uint8_t> bytes) {
        BootloaderCf cf;
        if (bytes.size() < sizeof(cf_header))
            return fail(ErrorCode::Truncated, "CF/6BL data too short");

        std::memcpy(&cf.header, bytes.data(), sizeof(cf_header));

        if (auto size = aligned_stage_size(cf.header.header.size, sizeof(cf_header), "CF/6BL");
            !size)
            return std::unexpected(std::move(size.error()));

        cf.data = std::vector<uint8_t>(bytes.begin() + sizeof(cf_header), bytes.end());
        cf.decrypted = cf.is_decrypted();
        // A plaintext CF too short for the per-box block still parses, without `perbox`.
        if (cf.decrypted) {
            if (auto parsed = cf.parse_perbox(); !parsed)
                Log::Debug("CF per-box data not parsed: {}", parsed.error().describe());
        }
        Log::Debug("Parsed 6BL/CF: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cf.header.header.version, cf.header.header.size, cf.header.header.entrypoint);
        return cf;
    }

    Result<void> BootloaderCf::decrypt(const uint8_t onebl_key[16]) {
        if (decrypted)
            return {};

        uint8_t cur_key[16];
        std::memcpy(cur_key, onebl_key, 16);

        std::vector<uint8_t> buffer = serialize();
        if (buffer.size() < 0x230)
            return fail(ErrorCode::Truncated, "CF/6BL payload too short");

        if (auto crypted =
                crypt_single_bl(buffer, HmacType::Default, cur_key, nullptr, nullptr, 0x30);
            !crypted)
            return with_context(std::move(crypted), "CF/6BL");

        std::memcpy(&header, buffer.data(), sizeof(cf_header));

        data = std::vector<uint8_t>(buffer.begin() + sizeof(cf_header), buffer.end());

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
        auto size_aligned = aligned_stage_size(header.header.size, sizeof(cf_header), "CF/6BL");
        if (!size_aligned)
            return std::unexpected(std::move(size_aligned.error()));
        // A CF without parsed per-box data has nothing to write back; one whose payload no
        // longer holds it is an error.
        if (perbox.has_value()) {
            if (auto stored = serialize_perbox(); !stored)
                return with_context(std::move(stored), "CF/6BL");
        }
        const size_t payload_len = *size_aligned - sizeof(generic_header);

        if (data.size() + sizeof(cf_header) - sizeof(generic_header) < payload_len) {
            size_t req = payload_len - (sizeof(cf_header) - sizeof(generic_header));
            data.resize(req, 0x00);
        }

        uint8_t cur_key[16];
        std::memcpy(cur_key, onebl_key, 16);

        std::vector<uint8_t> buffer(sizeof(cf_header) + data.size());
        std::memcpy(buffer.data(), &header, sizeof(cf_header));
        std::memcpy(buffer.data() + sizeof(cf_header), data.data(), data.size());

        if (auto crypted =
                crypt_single_bl(buffer, HmacType::Default, cur_key, nullptr, nullptr, 0x30);
            !crypted)
            return with_context(std::move(crypted), "CF/6BL");

        std::memcpy(&header, buffer.data(), sizeof(cf_header));
        std::memcpy(data.data(), buffer.data() + sizeof(cf_header), data.size());

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

        cf_perbox pb{};
        std::memcpy(&pb, data.data() + kCfPerboxOffset, sizeof(cf_perbox));
        perbox = pb;
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

        std::memcpy(data.data() + kCfPerboxOffset, &(*perbox), sizeof(cf_perbox));
        return {};
    }

    std::vector<uint8_t> BootloaderCf::serialize() const {
        std::vector<uint8_t> out(sizeof(cf_header));
        std::memcpy(out.data(), &header, sizeof(cf_header));
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

} // namespace gxbuild3::nand
