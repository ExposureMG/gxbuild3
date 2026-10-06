#include "nand/bootloaders/2bl.hpp"

#include "excrypt.h"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <utility>

namespace gxbuild3::nand {

    namespace {

        // A header-only CB still parses, but the crypt needs the generic header and the 16-byte
        // nonce. The rest of cb_header lives inside the encrypted payload.
        constexpr size_t kCbCryptMinimumSize = sizeof(generic_header) + 0x10;

    } // namespace

    Result<BootloaderCb> BootloaderCb::parse(std::span<const uint8_t> bytes) {
        BootloaderCb cb{};

        if (bytes.size() < sizeof(generic_header))
            return fail(ErrorCode::Truncated, "CB data too short");

        std::memcpy(&cb.header, bytes.data(), sizeof(generic_header));

        if (auto size = aligned_stage_size(cb.header.header.size, sizeof(generic_header), "CB");
            !size)
            return std::unexpected(std::move(size.error()));

        cb.data = std::vector<uint8_t>(bytes.begin() + sizeof(generic_header), bytes.end());
        cb.decrypted = cb.verify_decrypted();
        if (cb.decrypted)
            cb.populate_metadata();
        Log::Debug("Parsed 2BL/CB: version={}, size=0x{:X}, entrypoint=0x{:08X}",
                   cb.header.header.version, cb.header.header.size, cb.header.header.entrypoint);
        return cb;
    }

    bool BootloaderCb::verify_decrypted() const {
        if (data.size() < 0x380)
            return false;

        for (size_t i = 0x260; i < 0x380; i++)
            if (data[i] != 0)
                return false;

        return true;
    }

    bool BootloaderCb::is_decrypted() const {
        return decrypted || verify_decrypted() || (data.size() > 0x240 && data[0x240] == 0x80);
    }

    bool BootloaderCb::requires_cpu_key_for_cd() const {
        if (header.header.version < 1920) {
            return false;
        }

        if (perbox.has_value()) {
            const auto* bytes = reinterpret_cast<const uint8_t*>(&(*perbox));
            return !std::all_of(bytes, bytes + sizeof(cb_perbox),
                                [](uint8_t value) { return value == 0; });
        }

        if (data.size() < 0x30) {
            return false;
        }
        return !std::all_of(data.begin() + 0x10, data.begin() + 0x30,
                            [](uint8_t value) { return value == 0; });
    }

    void BootloaderCb::do_rc4_decrypt(const uint8_t key[16], size_t payload_len) {
        ExCryptRc4(key, 16, data.data() + 0x10, static_cast<uint32_t>(payload_len - 0x10));
    }

    Result<size_t> BootloaderCb::prepare_payload() {
        auto size_aligned = aligned_stage_size(header.header.size, kCbCryptMinimumSize, "CB");
        if (!size_aligned)
            return std::unexpected(std::move(size_aligned.error()));
        const size_t payload_len = *size_aligned - sizeof(generic_header);

        if (data.size() < 0x10)
            return fail(ErrorCode::Truncated, "CB data too short");
        if (data.size() < payload_len)
            data.resize(payload_len, 0x00);
        if (decrypted)
            synchronize_header_numeric_fields_to_data();
        return payload_len;
    }

    void BootloaderCb::apply_derived_key(const uint8_t digest[20], size_t payload_len) {
        std::array<uint8_t, 16> key;
        std::memcpy(key.data(), digest, 16);
        derived_key = key;

        do_rc4_decrypt(key.data(), payload_len);
        decrypted = !decrypted;

        if (decrypted)
            populate_metadata();
    }

    // CB / CB_A
    Result<void> BootloaderCb::decrypt(const uint8_t onebl_key[16]) {
        auto payload_len = prepare_payload();
        if (!payload_len)
            return std::unexpected(std::move(payload_len.error()));

        uint8_t digest[20];
        ExCryptHmacSha(onebl_key, 16, data.data(), 0x10, nullptr, 0, nullptr, 0, digest, 20);
        apply_derived_key(digest, *payload_len);
        return {};
    }

    // CB_B
    Result<void> BootloaderCb::decrypt_v1(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]) {
        auto payload_len = prepare_payload();
        if (!payload_len)
            return std::unexpected(std::move(payload_len.error()));

        uint8_t digest[20];
        ExCryptHmacSha(cb_a_key, 16, data.data(), 0x10, cpu_key, 16, nullptr, 0, digest, 20);
        apply_derived_key(digest, *payload_len);
        return {};
    }

    // Other CB_B impl?
    Result<void> BootloaderCb::decrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                          const uint8_t cpu_key[16]) {
        uint8_t digest[20];

        auto payload_len = prepare_payload();
        if (!payload_len)
            return std::unexpected(std::move(payload_len.error()));

        // The CB_A generic header with its flags cleared.
        auto cb_a_hdr_copy = wire::encode(cb_a_hdr.header);
        cb_a_hdr_copy[6] = 0;
        cb_a_hdr_copy[7] = 0;

        EXCRYPT_HMACSHA_STATE state;
        ExCryptHmacShaInit(&state, cb_a_key, 16);
        ExCryptHmacShaUpdate(&state, data.data(), 0x10);
        ExCryptHmacShaUpdate(&state, cpu_key, 16);
        ExCryptHmacShaUpdate(&state, cb_a_hdr_copy.data(), cb_a_hdr_copy.size());
        ExCryptHmacShaFinal(&state, digest, 20);

        apply_derived_key(digest, *payload_len);
        return {};
    }

    Result<void> BootloaderCb::encrypt_retail(const uint8_t parent_key[16],
                                              std::span<const uint8_t> cpu_key,
                                              std::span<const uint8_t> encrypted_smc,
                                              const cb_header* cb_a_header) {
        if (!decrypted || cpu_key.size() != 16 || encrypted_smc.empty() ||
            encrypted_smc.size() % 4 != 0 || !parse_perbox()) {
            return fail(ErrorCode::InvalidArgument,
                        "Retail CB authentication requires plaintext per-box data, a CPU "
                        "key, and an aligned encrypted SMC");
        }

        // A CB_B under a manufacturing CB_A, or bound to an all-zero CPU key, binds no SMC:
        // its digest slot is sixteen zeros (xeBuild "zeropairing CB_B").
        const bool unbound_cb_b = cb_a_header && (manufacturing_chain(*cb_a_header) ||
                                                  std::all_of(cpu_key.begin(), cpu_key.end(),
                                                              [](uint8_t b) { return b == 0; }));
        if (unbound_cb_b) {
            std::fill(std::begin(perbox->per_box_digest), std::end(perbox->per_box_digest), 0);
            if (auto stored = serialize_perbox(); !stored)
                return with_context(std::move(stored),
                                    "Could not serialize retail CB authentication digest");
            return encrypt_cb_b(*cb_a_header, parent_key, cpu_key.data());
        }

        // Match the existing CB/CB_B encryption derivation, including the v2 CB_A header.
        uint8_t rc4_key[16];
        EXCRYPT_HMACSHA_STATE state;
        ExCryptHmacShaInit(&state, parent_key, 16);
        ExCryptHmacShaUpdate(&state, data.data(), 16);
        if (cb_a_header) {
            ExCryptHmacShaUpdate(&state, cpu_key.data(), 16);
            if ((cb_a_header->header.flags & 0x1000) != 0) {
                generic_header header = cb_a_header->header;
                header.flags = 0;
                const auto head = wire::encode(header);
                ExCryptHmacShaUpdate(&state, head.data(), head.size());
            }
        }
        ExCryptHmacShaFinal(&state, rc4_key, 16);

        // The SMC checksum is two wrapping 64-bit accumulators over big-endian words.
        uint64_t sum = 0, difference = 0;
        for (size_t offset = 0; offset < encrypted_smc.size(); offset += 4) {
            const uint32_t word = (uint32_t(encrypted_smc[offset]) << 24) |
                                  (uint32_t(encrypted_smc[offset + 1]) << 16) |
                                  (uint32_t(encrypted_smc[offset + 2]) << 8) |
                                  encrypted_smc[offset + 3];
            sum = std::rotl(sum + word, 29);
            difference = std::rotl(difference - word, 31);
        }
        uint8_t checksum[16];
        for (size_t i = 0; i < 8; ++i) {
            checksum[i] = static_cast<uint8_t>(sum >> (56 - 8 * i));
            checksum[8 + i] = static_cast<uint8_t>(difference >> (56 - 8 * i));
        }
        ExCryptHmacSha(cpu_key.data(), 16, rc4_key, 16, data.data() + 0x10, 16, checksum, 16,
                       perbox->per_box_digest, 16);
        if (auto stored = serialize_perbox(); !stored)
            return with_context(std::move(stored),
                                "Could not serialize retail CB authentication digest");

        if (!cb_a_header)
            return encrypt(parent_key);
        return encrypt_cb_b(*cb_a_header, parent_key, cpu_key.data());
    }

    Result<void> BootloaderCb::decrypt_cb_b(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                            const uint8_t cpu_key[16]) {
        static constexpr uint8_t zero_key[16] = {};
        if (manufacturing_chain(cb_a_hdr))
            return decrypt_v1(cb_a_key, zero_key);
        if ((cb_a_hdr.header.flags & 0x1000) != 0)
            return decrypt_v2(cb_a_hdr, cb_a_key, cpu_key);
        return decrypt_v1(cb_a_key, cpu_key);
    }

    Result<void> BootloaderCb::decrypt_mfg(const uint8_t cb_a_key[16]) {
        uint8_t hmac_input[0x20];
        uint8_t zero_key[16] = {};
        uint8_t digest[20];

        auto payload_len = prepare_payload();
        if (!payload_len)
            return std::unexpected(std::move(payload_len.error()));

        std::memcpy(hmac_input, data.data(), 0x10);
        std::memcpy(hmac_input + 0x10, cb_a_key, 0x10);

        ExCryptHmacSha(zero_key, 16, hmac_input, 0x20, nullptr, 0, nullptr, 0, digest, 20);

        apply_derived_key(digest, *payload_len);
        return {};
    }

    bool BootloaderCb::patch_rgh3_v1_cb_x() {
        struct Word {
            size_t offset;
            uint32_t value;
        };
        // Offsets are from the start of the stage, header included.
        static constexpr Word kV1Marker{0x354, 0x646A0002};
        static constexpr std::array<Word, 4> kV1Fix{{
            {0x354, 0x64690002}, // oris r9, r3, 2
            {0x368, 0x7D8C482A}, // ldx r12, r12, r9
            {0x370, 0x64690006}, // oris r9, r3, 6
            {0x37C, 0xF8491010}, // std r2, 0x1010(r9)
        }};
        constexpr size_t kHeaderSize = sizeof(generic_header);

        const auto word_at = [this](size_t offset) -> uint8_t* {
            return data.data() + (offset - kHeaderSize);
        };
        if (!decrypted || data.size() < 0x380 - kHeaderSize)
            return false;

        uint32_t marker = 0;
        for (size_t i = 0; i < 4; ++i)
            marker = (marker << 8) | word_at(kV1Marker.offset)[i];
        if (marker != kV1Marker.value)
            return false;

        for (const auto& word : kV1Fix)
            for (size_t i = 0; i < 4; ++i)
                word_at(word.offset)[i] = static_cast<uint8_t>(word.value >> (24 - 8 * i));
        return true;
    }

    void BootloaderCb::populate_metadata() {
        if (!is_decrypted() || data.size() < sizeof(cb_header) - sizeof(generic_header))
            return;

        std::memcpy(reinterpret_cast<uint8_t*>(&header) + sizeof(generic_header), data.data(),
                    sizeof(cb_header) - sizeof(generic_header));
        // The size check above covers the per-box block, so this only degrades on an
        // inconsistent stage; `perbox` then keeps its previous value.
        if (auto parsed = parse_perbox(); !parsed)
            Log::Debug("CB per-box data not parsed: {}", parsed.error().describe());
    }

    Result<void> BootloaderCb::parse_perbox() {
        if (!is_decrypted())
            return fail(ErrorCode::InvalidArgument, "CB per-box data needs a decrypted CB");
        if (data.size() < 0x10 + sizeof(cb_perbox))
            return fail(ErrorCode::Truncated,
                        "CB payload (0x{:X} bytes) is too short for per-box data", data.size());

        cb_perbox pb{};
        std::memcpy(&pb, data.data() + 0x10, sizeof(cb_perbox));
        perbox = pb;
        return {};
    }

    Result<void> BootloaderCb::serialize_perbox() {
        if (!is_decrypted())
            return fail(ErrorCode::InvalidArgument, "CB per-box data needs a decrypted CB");
        if (!perbox.has_value())
            return fail(ErrorCode::InvalidArgument, "CB has no per-box data to serialize");
        if (data.size() < 0x10 + sizeof(cb_perbox))
            return fail(ErrorCode::Truncated,
                        "CB payload (0x{:X} bytes) is too short for per-box data", data.size());

        std::memcpy(data.data() + 0x10, &(*perbox), sizeof(cb_perbox));
        return {};
    }

    void BootloaderCb::synchronize_header_numeric_fields_to_data() {
        constexpr size_t console_sequence_allow_offset =
            offsetof(cb_header, console_seq_allow) +
            offsetof(ConsoleTypeSeqAllow, console_sequence_allow) - sizeof(generic_header);
        const auto& wire_value = header.console_seq_allow.console_sequence_allow.raw();
        if (data.size() < console_sequence_allow_offset + wire_value.size())
            return;

        std::memcpy(data.data() + console_sequence_allow_offset, wire_value.data(),
                    wire_value.size());
    }

    std::vector<uint8_t> BootloaderCb::serialize() const {
        std::vector<uint8_t> out(sizeof(generic_header));
        std::memcpy(out.data(), &header.header, sizeof(generic_header));
        auto serialized_data = data;
        if (decrypted) {
            constexpr size_t console_sequence_allow_offset =
                offsetof(cb_header, console_seq_allow) +
                offsetof(ConsoleTypeSeqAllow, console_sequence_allow) - sizeof(generic_header);
            const auto& wire_value = header.console_seq_allow.console_sequence_allow.raw();
            if (serialized_data.size() >= console_sequence_allow_offset + wire_value.size()) {
                std::memcpy(serialized_data.data() + console_sequence_allow_offset,
                            wire_value.data(), wire_value.size());
            }
        }
        out.insert(out.end(), serialized_data.begin(), serialized_data.end());

        return out;
    }

} // namespace gxbuild3::nand
