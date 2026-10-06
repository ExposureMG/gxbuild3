#include "nand/objects/SecuredFiles.hpp"

#include "excrypt.h"
#include "nand/bootloaders/Common.hpp"
#include "nand/objects/Keyvault.hpp"

#include <algorithm>
#include <cstring>
#include <string_view>

namespace gxbuild3::nand {

    namespace {

        using Key = std::array<uint8_t, 16>;

        constexpr size_t kNonceSize = 0x10;
        constexpr size_t kRecordLengthOffset = 0x04;
        constexpr size_t kRecordHashOffset = 0x0C;
        constexpr size_t kRecordHashedFrom = 0x150;
        constexpr size_t kCrlIvOffset = 0x120;
        constexpr size_t kCrlWrappedKeyOffset = 0x130;
        constexpr size_t kCrlBodyOffset = 0x140;
        constexpr size_t kDaeFieldOffset = 0x120;
        constexpr size_t kDaeBodyOffset = 0x130;
        constexpr std::string_view kDaeMagic = "DAEP";
        constexpr uint8_t kExtendedNonceTail[2] = {0x07, 0x12};
        constexpr size_t kOddFeaturesOffset = 0x1C;
        constexpr size_t kFcrtSize = 0x4000;
        constexpr size_t kFcrtIvOffset = 0x100;
        constexpr size_t kFcrtBodyOffsetField = 0x11C;
        constexpr size_t kFcrtHashOffset = 0x12C;

        Key hmac_sha(std::span<const uint8_t> key, std::span<const uint8_t> first,
                     std::span<const uint8_t> second = {}, std::span<const uint8_t> third = {}) {
            uint8_t digest[20]{};
            ExCryptHmacSha(key.data(), static_cast<uint32_t>(key.size()), first.data(),
                           static_cast<uint32_t>(first.size()), second.data(),
                           static_cast<uint32_t>(second.size()), third.data(),
                           static_cast<uint32_t>(third.size()), digest, sizeof(digest));
            Key out{};
            std::memcpy(out.data(), digest, out.size());
            return out;
        }

        // The XEX key the retail update package's copies are sealed under, which xeBuild derives
        // from the 1BL key: sixteen fixed bytes under RC4 keyed with HMAC-SHA("thisisjustajunky",
        // 1BL key).
        Key retail_xex_key() {
            static constexpr std::array<uint8_t, 16> kFixed{0x95, 0x27, 0x72, 0xBF, 0x47, 0xC0,
                                                            0xF6, 0x98, 0x5C, 0x7D, 0xF2, 0x50,
                                                            0x65, 0x4D, 0x55, 0xCD};
            static constexpr std::string_view kSecret = "thisisjustajunky";
            const auto rc4_key = hmac_sha(
                std::span(reinterpret_cast<const uint8_t*>(kSecret.data()), kSecret.size()),
                std::span<const uint8_t>(key_1bl, sizeof(key_1bl)));
            Key key = kFixed;
            ExCryptRc4(rc4_key.data(), static_cast<uint32_t>(rc4_key.size()), key.data(),
                       static_cast<uint32_t>(key.size()));
            return key;
        }

        // The keys a crl.bin or dae.bin record is opened under, in order: the console's, the
        // retail XEX key, and the development kit XEX key, which is all zero.
        std::array<Key, 3> master_keys(std::span<const uint8_t> cpu_key) {
            Key cpu{};
            std::copy_n(cpu_key.begin(), cpu.size(), cpu.begin());
            return {cpu, retail_xex_key(), Key{}};
        }

        std::vector<uint8_t> aes_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv,
                                     std::span<const uint8_t> data, bool encrypt) {
            alignas(16) EXCRYPT_AES_STATE state{};
            ExCryptAesKey(&state, key.data());
            Key feed{};
            std::copy_n(iv.begin(), feed.size(), feed.begin());
            std::vector<uint8_t> out(data.size());
            ExCryptAesCbc(&state, data.data(), static_cast<uint32_t>(data.size()), out.data(),
                          feed.data(), encrypt ? 1 : 0);
            return out;
        }

        Key aes_ecb(std::span<const uint8_t> key, std::span<const uint8_t> block, bool encrypt) {
            alignas(16) EXCRYPT_AES_STATE state{};
            ExCryptAesKey(&state, key.data());
            Key out{};
            ExCryptAesEcb(&state, block.data(), out.data(), encrypt ? 1 : 0);
            return out;
        }

        // Whether a signed record's body, in the clear, is what the record's header hashes: the
        // SHA-1 of everything from the record's 0x150 on. `body` starts at `body_offset` of the
        // record.
        bool vouched(std::span<const uint8_t> record, std::span<const uint8_t> body,
                     size_t body_offset) {
            if (record.size() < kRecordHashOffset + 20 ||
                body_offset + body.size() < kRecordHashedFrom) {
                return false;
            }
            const auto hashed = body.subspan(kRecordHashedFrom - body_offset);
            uint8_t digest[20]{};
            ExCryptSha(hashed.data(), static_cast<uint32_t>(hashed.size()), nullptr, 0, nullptr, 0,
                       digest, sizeof(digest));
            return std::equal(digest, digest + sizeof(digest), record.begin() + kRecordHashOffset);
        }

        bool sealable_body(std::span<const uint8_t> blob, size_t body_offset) {
            return blob.size() >= kRecordHashedFrom && (blob.size() - body_offset) % 16 == 0;
        }

        struct OpenedCrl {
            std::vector<uint8_t> body;
            // Which of master_keys opened it; nothing for a crl.bin in the clear.
            std::optional<size_t> master;
            Key file_key{};
        };

        Result<OpenedCrl> open_crl(std::span<const uint8_t> blob,
                                   std::span<const uint8_t> cpu_key) {
            if (!sealable_body(blob, kCrlBodyOffset)) {
                return fail(ErrorCode::Malformed,
                            "crl.bin of 0x{:X} bytes is not a record with a whole-block body",
                            blob.size());
            }
            const auto sealed = blob.subspan(kCrlBodyOffset);
            if (vouched(blob, sealed, kCrlBodyOffset)) {
                return OpenedCrl{{sealed.begin(), sealed.end()}, std::nullopt, {}};
            }
            const auto masters = master_keys(cpu_key);
            for (size_t index = 0; index < masters.size(); ++index) {
                const auto file_key =
                    aes_ecb(masters[index], blob.subspan(kCrlWrappedKeyOffset, 16), false);
                auto body = aes_cbc(file_key, blob.subspan(kCrlIvOffset, 16), sealed, false);
                if (vouched(blob, body, kCrlBodyOffset)) {
                    return OpenedCrl{std::move(body), index, file_key};
                }
            }
            return fail(ErrorCode::AuthFailed, "crl.bin opens under no key it is tried under");
        }

        struct DaeRecord {
            std::vector<uint8_t> header;
            std::vector<uint8_t> body;
            std::optional<size_t> master;
        };

        // The records of a dae.bin, each opened, walked by the length each states. AuthFailed
        // when any record opens under no key, Malformed when the records do not cover the file.
        Result<std::vector<DaeRecord>> open_dae(std::span<const uint8_t> blob,
                                                std::span<const uint8_t> cpu_key) {
            const auto masters = master_keys(cpu_key);
            std::vector<DaeRecord> records;
            size_t at = 0;
            while (at < blob.size()) {
                if (blob.size() - at < kRecordHashedFrom ||
                    !std::equal(kDaeMagic.begin(), kDaeMagic.end(), blob.begin() + at)) {
                    return fail(ErrorCode::Malformed, "dae.bin has no DAEP record at 0x{:X}", at);
                }
                const size_t length = (static_cast<size_t>(blob[at + kRecordLengthOffset]) << 8) |
                                      blob[at + kRecordLengthOffset + 1];
                if (length < kRecordHashedFrom || length > blob.size() - at ||
                    (length - kDaeBodyOffset) % 16 != 0) {
                    return fail(ErrorCode::Malformed,
                                "dae.bin record at 0x{:X} states an unusable length 0x{:X}", at,
                                length);
                }
                const auto record = blob.subspan(at, length);
                const auto sealed = record.subspan(kDaeBodyOffset);
                DaeRecord opened{{record.begin(), record.begin() + kDaeBodyOffset}, {}, {}};
                if (vouched(record, sealed, kDaeBodyOffset)) {
                    opened.body.assign(sealed.begin(), sealed.end());
                } else {
                    for (size_t index = 0; index < masters.size() && opened.body.empty(); ++index) {
                        auto body = aes_cbc(masters[index], Key{}, sealed, false);
                        if (vouched(record, body, kDaeBodyOffset)) {
                            opened.body = std::move(body);
                            opened.master = index;
                        }
                    }
                    if (opened.body.empty()) {
                        return fail(ErrorCode::AuthFailed,
                                    "dae.bin record at 0x{:X} opens under no key it is tried under",
                                    at);
                    }
                }
                records.push_back(std::move(opened));
                at += length;
            }
            if (records.empty()) {
                return fail(ErrorCode::Truncated, "dae.bin is empty");
            }
            return records;
        }

        void put_stamp(std::span<uint8_t> destination, int64_t build_seconds) {
            const auto stamp = secured_file_stamp(build_seconds);
            std::copy(stamp.begin(), stamp.end(), destination.begin());
        }

        // A keyvault-style file sealed: the nonce, then the plaintext under RC4 keyed with
        // HMAC-SHA(CPU key, nonce).
        std::vector<uint8_t> seal_under_nonce(const Key& nonce, std::vector<uint8_t> plain,
                                              std::span<const uint8_t> cpu_key) {
            const auto key = hmac_sha(cpu_key, nonce);
            ExCryptRc4(key.data(), static_cast<uint32_t>(key.size()), plain.data(),
                       static_cast<uint32_t>(plain.size()));
            std::vector<uint8_t> out(nonce.begin(), nonce.end());
            out.insert(out.end(), plain.begin(), plain.end());
            return out;
        }

        bool valid_cpu_key(std::span<const uint8_t> cpu_key) {
            return cpu_key.size() == 16;
        }

        std::unexpected<Error> invalid_cpu_key(std::span<const uint8_t> cpu_key) {
            return fail(ErrorCode::InvalidArgument, "CPU key is {} bytes, not 16", cpu_key.size());
        }

        Key derived_nonce(std::span<const uint8_t> plain, std::span<const uint8_t> cpu_key,
                          bool extended) {
            return extended ? hmac_sha(cpu_key, plain, kExtendedNonceTail)
                            : hmac_sha(cpu_key, plain);
        }

        Result<std::vector<uint8_t>> open_loose(std::span<const uint8_t> blob,
                                                std::span<const uint8_t> cpu_key, bool extended) {
            if (!valid_cpu_key(cpu_key)) {
                return invalid_cpu_key(cpu_key);
            }
            if (blob.size() < kNonceSize) {
                return fail(ErrorCode::Truncated, "File of 0x{:X} bytes is shorter than its nonce",
                            blob.size());
            }
            const auto opened_under = [&](std::span<const uint8_t> clear) {
                const auto nonce = derived_nonce(clear.subspan(kNonceSize), cpu_key, extended);
                return std::equal(nonce.begin(), nonce.end(), clear.begin());
            };
            std::vector<uint8_t> opened(blob.begin(), blob.end());
            if (auto crypted = crypt_secfile(cpu_key, opened); !crypted) {
                return std::unexpected(std::move(crypted.error()));
            }
            if (opened_under(opened)) {
                return opened;
            }
            const bool zero_nonce = std::all_of(blob.begin(), blob.begin() + kNonceSize,
                                                [](uint8_t b) { return b == 0; });
            if (zero_nonce || opened_under(blob)) {
                std::vector<uint8_t> clear(blob.begin(), blob.end());
                const auto nonce =
                    derived_nonce(std::span(clear).subspan(kNonceSize), cpu_key, extended);
                std::copy(nonce.begin(), nonce.end(), clear.begin());
                return clear;
            }
            return opened;
        }

        // Whether fcrt.bin's hash at 0x12C is the SHA-1 of `body`, its sealed part in the clear.
        bool fcrt_hash_holds(std::span<const uint8_t> blob, std::span<const uint8_t> body) {
            uint8_t digest[20]{};
            ExCryptSha(body.data(), static_cast<uint32_t>(body.size()), nullptr, 0, nullptr, 0,
                       digest, sizeof(digest));
            return std::equal(digest, digest + sizeof(digest), blob.begin() + kFcrtHashOffset);
        }

        // fcrt.bin's sealed part under the CPU key and the vector at 0x100, either way; a part
        // that is not whole blocks comes back as it stands.
        std::vector<uint8_t> crypt_fcrt_body(std::span<const uint8_t> blob,
                                             std::span<const uint8_t> cpu_key, size_t body_offset,
                                             bool encrypt) {
            const auto body = blob.subspan(body_offset);
            if (body.size() % 16 != 0) {
                return {body.begin(), body.end()};
            }
            return aes_cbc(cpu_key, blob.subspan(kFcrtIvOffset, 16), body, encrypt);
        }

    } // namespace

    std::array<uint8_t, 8> secured_file_stamp(int64_t build_seconds) {
        // Seconds from 1601-01-01 to 1970-01-01, and FILETIME's 100 ns ticks per second.
        constexpr uint64_t kWindowsEpochOffset = 11644473600ULL;
        constexpr uint64_t kTicksPerSecond = 10000000ULL;
        const auto seconds =
            static_cast<uint64_t>(std::max<int64_t>(build_seconds, 0) + 2) & ~uint64_t{1};
        const uint64_t ticks = (seconds + kWindowsEpochOffset) * kTicksPerSecond;
        std::array<uint8_t, 8> out{};
        for (size_t index = 0; index < out.size(); ++index) {
            out[index] = static_cast<uint8_t>(ticks >> (56 - 8 * index));
        }
        return out;
    }

    Result<CrlSealing> crl_sealing(std::span<const uint8_t> own, std::span<const uint8_t> cpu_key) {
        if (!valid_cpu_key(cpu_key)) {
            return invalid_cpu_key(cpu_key);
        }
        const auto opened = open_crl(own, cpu_key);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        if (opened->master != size_t{0}) {
            return fail(ErrorCode::AuthFailed, "crl.bin is not sealed under the CPU key");
        }
        CrlSealing sealing{};
        std::copy_n(own.begin() + kCrlIvOffset, sealing.iv.size(), sealing.iv.begin());
        sealing.file_key = opened->file_key;
        return sealing;
    }

    Result<DaeSealing> dae_sealing(std::span<const uint8_t> own, std::span<const uint8_t> cpu_key) {
        if (!valid_cpu_key(cpu_key)) {
            return invalid_cpu_key(cpu_key);
        }
        const auto records = open_dae(own, cpu_key);
        if (!records) {
            return std::unexpected(records.error());
        }
        if (records->front().master != size_t{0}) {
            return fail(ErrorCode::AuthFailed, "dae.bin is not sealed under the CPU key");
        }
        const auto& first = records->front();
        DaeSealing sealing{};
        std::copy_n(first.body.begin() + 0x08, sealing.head.size(), sealing.head.begin());
        std::copy_n(first.header.begin() + kDaeFieldOffset, sealing.field.size(),
                    sealing.field.begin());
        return sealing;
    }

    CrlSealing random_crl_sealing() {
        CrlSealing sealing{};
        ExCryptRandom(sealing.iv.data(), sealing.iv.size());
        ExCryptRandom(sealing.file_key.data(), sealing.file_key.size());
        return sealing;
    }

    DaeSealing random_dae_sealing() {
        DaeSealing sealing{};
        ExCryptRandom(sealing.head.data(), sealing.head.size());
        ExCryptRandom(sealing.field.data(), sealing.field.size());
        return sealing;
    }

    Result<std::vector<uint8_t>> reseal_crl(std::span<const uint8_t> content,
                                            std::span<const uint8_t> cpu_key,
                                            const CrlSealing& sealing,
                                            const SecuredFileBuild& build) {
        if (!valid_cpu_key(cpu_key)) {
            return invalid_cpu_key(cpu_key);
        }
        auto opened = open_crl(content, cpu_key);
        if (!opened) {
            return std::unexpected(std::move(opened.error()));
        }
        auto& plain = opened->body;
        put_stamp(plain, build.build_seconds);
        plain[0x0F] = build.lockdown_value;

        std::vector<uint8_t> out(content.begin(), content.begin() + kCrlBodyOffset);
        std::copy(sealing.iv.begin(), sealing.iv.end(), out.begin() + kCrlIvOffset);
        const auto wrapped = aes_ecb(cpu_key, sealing.file_key, true);
        std::copy(wrapped.begin(), wrapped.end(), out.begin() + kCrlWrappedKeyOffset);
        const auto sealed = aes_cbc(sealing.file_key, sealing.iv, plain, true);
        out.insert(out.end(), sealed.begin(), sealed.end());
        return out;
    }

    Result<std::vector<uint8_t>> reseal_dae(std::span<const uint8_t> content,
                                            std::span<const uint8_t> cpu_key,
                                            const DaeSealing& sealing,
                                            const SecuredFileBuild& build) {
        if (!valid_cpu_key(cpu_key)) {
            return invalid_cpu_key(cpu_key);
        }
        auto records = open_dae(content, cpu_key);
        if (!records) {
            return std::unexpected(std::move(records.error()));
        }
        auto field = sealing.field;
        field[1] |= 0x01;
        std::vector<uint8_t> out;
        out.reserve(content.size());
        for (auto& record : *records) {
            auto& plain = record.body;
            put_stamp(plain, build.build_seconds);
            std::copy(sealing.head.begin(), sealing.head.end(), plain.begin() + 0x08);
            plain[0x0F] = build.lockdown_value;
            const auto mac = hmac_sha(cpu_key, field, std::span<const uint8_t>(plain).first(0x10));
            std::copy(mac.begin(), mac.end(), plain.begin() + 0x10);
            std::copy(field.begin(), field.end(), record.header.begin() + kDaeFieldOffset);
            const auto sealed = aes_cbc(cpu_key, Key{}, plain, true);
            out.insert(out.end(), record.header.begin(), record.header.end());
            out.insert(out.end(), sealed.begin(), sealed.end());
        }
        return out;
    }

    bool extended_opened(std::span<const uint8_t> clear, std::span<const uint8_t> cpu_key) {
        if (!valid_cpu_key(cpu_key) || clear.size() <= kNonceSize) {
            return false;
        }
        const auto nonce = hmac_sha(cpu_key, clear.subspan(kNonceSize), kExtendedNonceTail);
        return std::equal(nonce.begin(), nonce.end(), clear.begin());
    }

    bool secdata_opened(std::span<const uint8_t> clear, std::span<const uint8_t> cpu_key) {
        if (!valid_cpu_key(cpu_key) || clear.size() <= kNonceSize) {
            return false;
        }
        const auto nonce = hmac_sha(cpu_key, clear.subspan(kNonceSize));
        return std::equal(nonce.begin(), nonce.end(), clear.begin());
    }

    Result<std::vector<uint8_t>> reseal_extended(std::span<const uint8_t> clear,
                                                 std::span<const uint8_t> cpu_key,
                                                 std::span<const uint8_t, 8> keyvault_head) {
        if (!valid_cpu_key(cpu_key)) {
            return invalid_cpu_key(cpu_key);
        }
        if (clear.size() < kNonceSize + keyvault_head.size()) {
            return fail(ErrorCode::Truncated, "extended.bin of 0x{:X} bytes holds no head",
                        clear.size());
        }
        std::vector<uint8_t> plain(clear.begin() + kNonceSize, clear.end());
        std::copy(keyvault_head.begin(), keyvault_head.end(), plain.begin());
        const auto nonce = hmac_sha(cpu_key, plain, kExtendedNonceTail);
        return seal_under_nonce(nonce, std::move(plain), cpu_key);
    }

    Result<std::vector<uint8_t>> reseal_secdata(std::span<const uint8_t> clear,
                                                std::span<const uint8_t> cpu_key,
                                                std::optional<std::array<uint8_t, 8>> head,
                                                const SecuredFileBuild& build) {
        if (!valid_cpu_key(cpu_key)) {
            return invalid_cpu_key(cpu_key);
        }
        if (clear.size() < kNonceSize + 0x18) {
            return fail(ErrorCode::Truncated, "secdata.bin of 0x{:X} bytes holds no stamp",
                        clear.size());
        }
        std::vector<uint8_t> plain(clear.begin() + kNonceSize, clear.end());
        if (head) {
            std::copy(head->begin(), head->end(), plain.begin());
        }
        plain[0x08] = 0x01;
        plain[0x09] = build.lockdown_value;
        put_stamp(std::span(plain).subspan(0x10), build.build_seconds);
        const auto nonce = hmac_sha(cpu_key, plain);
        return seal_under_nonce(nonce, std::move(plain), cpu_key);
    }

    Result<std::vector<uint8_t>> clean_extended(std::span<const uint8_t> cpu_key,
                                                std::span<const uint8_t, 8> keyvault_head) {
        return reseal_extended(std::vector<uint8_t>(kExtendedSize), cpu_key, keyvault_head);
    }

    Result<std::vector<uint8_t>> clean_secdata(std::span<const uint8_t> cpu_key,
                                               std::span<const uint8_t, 8> head,
                                               const SecuredFileBuild& build) {
        std::array<uint8_t, 8> own_head{};
        std::copy(head.begin(), head.end(), own_head.begin());
        return reseal_secdata(std::vector<uint8_t>(kSecdataSize), cpu_key, own_head, build);
    }

    std::array<uint8_t, 8> random_secdata_head() {
        std::array<uint8_t, 8> head{};
        ExCryptRandom(head.data(), head.size());
        return head;
    }

    Result<std::vector<uint8_t>> open_loose_extended(std::span<const uint8_t> blob,
                                                     std::span<const uint8_t> cpu_key) {
        return open_loose(blob, cpu_key, true);
    }

    Result<std::vector<uint8_t>> open_loose_secdata(std::span<const uint8_t> blob,
                                                    std::span<const uint8_t> cpu_key) {
        return open_loose(blob, cpu_key, false);
    }

    SealedFcrt seal_fcrt(std::span<const uint8_t> content, std::span<const uint8_t> cpu_key) {
        SealedFcrt out{{content.begin(), content.end()}, FcrtSealing::Carried};
        if (content.size() != kFcrtSize) {
            out.sealing = FcrtSealing::InvalidSize;
            return out;
        }
        const size_t body_offset = (static_cast<size_t>(content[kFcrtBodyOffsetField]) << 24) |
                                   (static_cast<size_t>(content[kFcrtBodyOffsetField + 1]) << 16) |
                                   (static_cast<size_t>(content[kFcrtBodyOffsetField + 2]) << 8) |
                                   content[kFcrtBodyOffsetField + 3];
        if (body_offset >= kFcrtSize) {
            out.sealing = FcrtSealing::InvalidOffset;
            return out;
        }
        if (!valid_cpu_key(cpu_key)) {
            out.sealing = FcrtSealing::Damaged;
            return out;
        }
        if (fcrt_hash_holds(content, content.subspan(body_offset))) {
            const auto sealed = crypt_fcrt_body(content, cpu_key, body_offset, true);
            std::copy(sealed.begin(), sealed.end(), out.data.begin() + body_offset);
            out.sealing = FcrtSealing::Sealed;
            return out;
        }
        // xeBuild opens it in place; where the hash then fails, what it writes is the opened part.
        const auto opened = crypt_fcrt_body(content, cpu_key, body_offset, false);
        if (!fcrt_hash_holds(content, opened)) {
            std::copy(opened.begin(), opened.end(), out.data.begin() + body_offset);
            out.sealing = FcrtSealing::Damaged;
        }
        return out;
    }

    FcrtRequirement fcrt_requirement(std::span<const uint8_t> clear_keyvault) {
        if (clear_keyvault.size() < kOddFeaturesOffset + 2) {
            return FcrtRequirement::NotRequired;
        }
        const auto features = static_cast<uint16_t>((clear_keyvault[kOddFeaturesOffset] << 8) |
                                                    clear_keyvault[kOddFeaturesOffset + 1]);
        if ((features & 0x0300) != 0) {
            return FcrtRequirement::RequiredByDrive;
        }
        if ((features & 0x0020) != 0) {
            return FcrtRequirement::Required;
        }
        return FcrtRequirement::NotRequired;
    }

    Result<std::array<uint8_t, 8>> secdata_head(std::span<const uint8_t> clear) {
        std::array<uint8_t, 8> head{};
        if (clear.size() < kNonceSize + head.size()) {
            return fail(ErrorCode::Truncated, "secdata.bin of 0x{:X} bytes holds no head",
                        clear.size());
        }
        std::copy_n(clear.begin() + kNonceSize, head.size(), head.begin());
        return head;
    }

} // namespace gxbuild3::nand
