#pragma once

// Mechanics shared by the SC/CD/CE/CF/CG stage classes: the header read, the payload size and
// padding, serialization and the record crypt. Private to the stage sources (2bl.cpp-7bl.cpp).
//
// Only what is really identical lives here. Every per-stage asymmetry is an explicit argument at
// the call site, with no default arguments: the HMAC type (Hmac1920 for CD with a CPU key), the
// crypt start (0x30 for CF, 0x20 elsewhere) and the stage name. The state guards, the decrypt-only
// truncation checks (CD/CE), the derived-key retention (SC/CD) and the zero-nonce randomisation
// (SC/CD/CE/CG encrypt only) stay in each stage's own decrypt()/encrypt() body.

#include "Error.hpp"
#include "Wire.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand::stage {

    // A stage header record: a wire struct that opens with the generic bootloader header.
    template <class H>
    concept StageHeader = wire::WireLayout<H> && requires(const H& h) {
        { h.header } -> std::convertible_to<const generic_header&>;
    };

    template <StageHeader H> struct ParsedStage {
        H header;
        std::vector<uint8_t> data;
    };

    // Reads the stage header and keeps the bytes after it as the payload. Fails Truncated
    // ("{stage_name} data too short") when the bytes cannot hold H, or Malformed when the declared
    // size cannot hold H (aligned_stage_size).
    template <StageHeader H>
    [[nodiscard]] Result<ParsedStage<H>> parse_stage(std::span<const uint8_t> bytes,
                                                     std::string_view stage_name) {
        if (bytes.size() < sizeof(H)) {
            return fail(ErrorCode::Truncated, "{} data too short", stage_name);
        }
        auto head = wire::read_head<H>(bytes, stage_name);
        if (!head) {
            return std::unexpected(std::move(head.error()));
        }
        if (auto size = aligned_stage_size(head->value.header.size, sizeof(H), stage_name); !size) {
            return std::unexpected(std::move(size.error()));
        }
        return ParsedStage<H>{head->value,
                              std::vector<uint8_t>(head->rest.begin(), head->rest.end())};
    }

    // The payload length the declared size implies: the aligned stage size minus the header.
    template <StageHeader H>
    [[nodiscard]] Result<size_t> stage_payload_size(const H& header, std::string_view stage_name) {
        auto aligned = aligned_stage_size(header.header.size, sizeof(H), stage_name);
        if (!aligned) {
            return std::unexpected(std::move(aligned.error()));
        }
        return *aligned - sizeof(H);
    }

    // Grows the payload to n bytes with zeros; a longer payload is left as it is.
    inline void pad_payload(std::vector<uint8_t>& data, size_t n) {
        if (data.size() < n) {
            data.resize(n, 0x00);
        }
    }

    // The on-disk stage: the header record followed by the payload.
    template <StageHeader H>
    [[nodiscard]] std::vector<uint8_t> serialize_stage(const H& header,
                                                       std::span<const uint8_t> data) {
        std::vector<uint8_t> out;
        out.reserve(sizeof(H) + data.size());
        wire::append(out, header);
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

    // RC4s the serialized stage from crypt_start on under the key crypt_single_bl derives from
    // `key` (and cpu_key for the CPU-bound HMAC types), then decodes the header and payload back.
    // Returns the derived key. On failure header and data are untouched. crypt_single_bl writes
    // only from crypt_start onward, so the header bytes before it come back unchanged.
    template <StageHeader H>
    [[nodiscard]] Result<std::array<uint8_t, 16>>
    crypt_stage_record(H& header, std::vector<uint8_t>& data, HmacType hmac_type,
                       const uint8_t key[16], const uint8_t* cpu_key, size_t crypt_start,
                       std::string_view stage_name) {
        std::array<uint8_t, 16> cur_key{};
        std::copy_n(key, cur_key.size(), cur_key.begin());

        std::vector<uint8_t> buffer = serialize_stage(header, data);
        if (auto crypted =
                crypt_single_bl(buffer, hmac_type, cur_key.data(), cpu_key, nullptr, crypt_start);
            !crypted) {
            crypted.error().add_context(std::string(stage_name));
            return std::unexpected(std::move(crypted.error()));
        }

        // Cannot fail: the buffer holds the header serialize_stage wrote.
        auto decoded = wire::read<H>(buffer, 0, stage_name);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }
        header = *decoded;
        std::copy(buffer.begin() + static_cast<std::ptrdiff_t>(sizeof(H)), buffer.end(),
                  data.begin());
        return cur_key;
    }

    // Draws a fresh nonce when the stored one is all zero; a set nonce is kept.
    inline void randomize_zero_nonce(std::span<uint8_t, 16> nonce) {
        if (std::all_of(nonce.begin(), nonce.end(), [](uint8_t b) { return b == 0; })) {
            ExCryptRandom(nonce.data(), nonce.size());
        }
    }

} // namespace gxbuild3::nand::stage
