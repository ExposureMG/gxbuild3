#pragma once

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

    template <class H>
    concept StageHeader = wire::WireLayout<H> && requires(const H& h) {
        { h.header } -> std::convertible_to<const generic_header&>;
    };

    template <StageHeader H> struct ParsedStage {
        H header;
        std::vector<uint8_t> data;
    };

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

    template <StageHeader H>
    [[nodiscard]] Result<size_t> stage_payload_size(const H& header, std::string_view stage_name) {
        auto aligned = aligned_stage_size(header.header.size, sizeof(H), stage_name);
        if (!aligned) {
            return std::unexpected(std::move(aligned.error()));
        }
        return *aligned - sizeof(H);
    }

    inline void pad_payload(std::vector<uint8_t>& data, size_t n) {
        if (data.size() < n) {
            data.resize(n, 0x00);
        }
    }

    template <StageHeader H>
    [[nodiscard]] std::vector<uint8_t> serialize_stage(const H& header,
                                                       std::span<const uint8_t> data) {
        std::vector<uint8_t> out;
        out.reserve(sizeof(H) + data.size());
        wire::append(out, header);
        out.insert(out.end(), data.begin(), data.end());
        return out;
    }

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

        auto decoded = wire::read<H>(buffer, 0, stage_name);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }
        header = *decoded;
        std::copy(buffer.begin() + static_cast<std::ptrdiff_t>(sizeof(H)), buffer.end(),
                  data.begin());
        return cur_key;
    }

    inline void randomize_zero_nonce(std::span<uint8_t, 16> nonce) {
        if (std::all_of(nonce.begin(), nonce.end(), [](uint8_t b) { return b == 0; })) {
            ExCryptRandom(nonce.data(), nonce.size());
        }
    }

} // namespace gxbuild3::nand::stage
