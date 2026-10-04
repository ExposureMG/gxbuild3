#include "excrypt.h"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/SecuredFiles.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

using namespace gxbuild3::NAND;

namespace {

    using Bytes = std::vector<uint8_t>;
    using Key = std::array<uint8_t, 16>;

    bool check(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
        }
        return condition;
    }

    // Synthetic keys: no console's.
    constexpr Key kCpuKey{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    constexpr Key kOtherKey{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    // The retail XEX key, which the 1BL key derives; an update package's copies open under it.
    constexpr Key kRetailXexKey{0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3,
                                0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91};
    constexpr SecuredFileBuild kBuild{0x5A123457, 14};

    Key hmac(std::span<const uint8_t> key, std::span<const uint8_t> first,
             std::span<const uint8_t> second = {}) {
        uint8_t digest[20]{};
        ExCryptHmacSha(key.data(), static_cast<uint32_t>(key.size()), first.data(),
                       static_cast<uint32_t>(first.size()), second.data(),
                       static_cast<uint32_t>(second.size()), nullptr, 0, digest, sizeof(digest));
        Key out{};
        std::copy_n(digest, out.size(), out.begin());
        return out;
    }

    Bytes aes_cbc_decrypt(std::span<const uint8_t> key, std::span<const uint8_t> iv,
                          std::span<const uint8_t> data) {
        alignas(16) EXCRYPT_AES_STATE state{};
        ExCryptAesKey(&state, key.data());
        Key feed{};
        std::copy_n(iv.begin(), feed.size(), feed.begin());
        Bytes out(data.size());
        ExCryptAesCbc(&state, data.data(), static_cast<uint32_t>(data.size()), out.data(),
                      feed.data(), 0);
        return out;
    }

    // A signed record in the clear: magic, length and the SHA-1 of everything from 0x150 on.
    Bytes a_record(std::string_view magic, size_t length, uint8_t fill) {
        Bytes out(length);
        std::copy(magic.begin(), magic.end(), out.begin());
        out[4] = static_cast<uint8_t>(length >> 8);
        out[5] = static_cast<uint8_t>(length);
        for (size_t at = 0x150; at < length; ++at) {
            out[at] = static_cast<uint8_t>(at * 7 + fill);
        }
        ExCryptSha(out.data() + 0x150, static_cast<uint32_t>(length - 0x150), nullptr, 0, nullptr,
                   0, out.data() + 0x0C, 20);
        return out;
    }

    Bytes clear_dae() {
        auto out = a_record("DAEP", 0x400, 2);
        const auto second = a_record("DAEP", 0x300, 3);
        out.insert(out.end(), second.begin(), second.end());
        return out;
    }

    const CrlSealing kCrlSealing{{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
                                  0xAB, 0xAC, 0xAD, 0xAE, 0xAF},
                                 {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                  0x0E, 0x0F, 0x10, 0x11, 0x12}};
    const DaeSealing kDaeSealing{{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77},
                                 {0xD0, 0xD2, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
                                  0xDB, 0xDC, 0xDD, 0xDE, 0xDF}};

    bool test_the_stamp_is_the_build_time_plus_two_seconds_to_the_even_second() {
        // 0x5A123458 seconds after 1970 as 100 ns ticks after 1601, big-endian.
        const uint64_t ticks = (uint64_t{0x5A123458} + 11644473600ULL) * 10000000ULL;
        std::array<uint8_t, 8> expected{};
        for (size_t index = 0; index < expected.size(); ++index) {
            expected[index] = static_cast<uint8_t>(ticks >> (56 - 8 * index));
        }
        return check(secured_file_stamp(0x5A123456) == expected,
                     "an even build time is stamped two seconds later") &&
               check(secured_file_stamp(0x5A123457) == expected,
                     "an odd build time is stamped down to the even second");
    }

    bool test_a_crl_is_sealed_under_the_given_vector_and_file_key() {
        const auto clear = a_record("CRLP", 0xA00, 1);
        const auto sealed = reseal_crl(clear, kCpuKey, kCrlSealing, kBuild);
        if (!check(sealed && sealed->size() == clear.size(), "a clear crl.bin is sealed")) {
            return false;
        }
        const auto opened = crl_sealing(*sealed, kCpuKey);
        const auto body = aes_cbc_decrypt(kCrlSealing.file_key, kCrlSealing.iv,
                                          std::span(*sealed).subspan(0x140));
        const auto stamp = secured_file_stamp(kBuild.build_seconds);
        return check(std::equal(clear.begin(), clear.begin() + 0x120, sealed->begin()),
                     "the header up to the vector is the content's") &&
               check(opened && opened->iv == kCrlSealing.iv &&
                         opened->file_key == kCrlSealing.file_key,
                     "its vector and file key are read back under the CPU key") &&
               check(!crl_sealing(*sealed, kOtherKey), "another console's key does not open it") &&
               check(std::equal(stamp.begin(), stamp.end(), body.begin()),
                     "the body carries the stamp at 0x00") &&
               check(body[0x0F] == kBuild.lockdown_value, "and the lockdown value at 0x0F") &&
               check(std::equal(body.begin() + 0x10, body.end(), clear.begin() + 0x150),
                     "and the content behind them");
    }

    bool test_a_crl_from_an_update_package_is_resealed_for_the_console() {
        const auto clear = a_record("CRLP", 0xA00, 1);
        const auto shipped = reseal_crl(clear, kRetailXexKey, kCrlSealing, {0, 0});
        const auto from_clear = reseal_crl(clear, kCpuKey, kCrlSealing, kBuild);
        const auto from_shipped =
            shipped ? reseal_crl(*shipped, kCpuKey, kCrlSealing, kBuild) : std::nullopt;
        const auto devkit = reseal_crl(clear, Key{}, kCrlSealing, {0, 0});
        const auto from_devkit =
            devkit ? reseal_crl(*devkit, kCpuKey, kCrlSealing, kBuild) : std::nullopt;
        auto damaged = clear;
        damaged[0x200] ^= 1;
        return check(from_shipped && from_shipped == from_clear,
                     "a copy under the retail XEX key opens and seals as the clear one") &&
               check(!crl_sealing(*shipped, kCpuKey),
                     "a shipped copy carries no console sealing") &&
               check(from_devkit && from_devkit == from_clear,
                     "a copy under the all-zero development XEX key opens too") &&
               check(!reseal_crl(damaged, kCpuKey, kCrlSealing, kBuild),
                     "a copy whose hash does not hold opens under no key");
    }

    bool test_a_dae_is_sealed_record_by_record() {
        const auto clear = clear_dae();
        const auto sealed = reseal_dae(clear, kCpuKey, kDaeSealing, kBuild);
        if (!check(sealed && sealed->size() == clear.size(), "a clear dae.bin is sealed")) {
            return false;
        }
        auto field = kDaeSealing.field;
        field[1] |= 0x01;
        const auto stamp = secured_file_stamp(kBuild.build_seconds);
        bool records_hold = true;
        for (const auto [at, length] : {std::pair<size_t, size_t>{0, 0x400}, {0x400, 0x300}}) {
            const auto record = std::span(*sealed).subspan(at, length);
            const auto body = aes_cbc_decrypt(kCpuKey, Key{}, record.subspan(0x130));
            const auto mac = hmac(kCpuKey, field, std::span(body).first(0x10));
            records_hold =
                records_hold &&
                check(std::equal(field.begin(), field.end(), record.begin() + 0x120),
                      "each header carries the field with bit 0 of its second byte set") &&
                check(std::equal(stamp.begin(), stamp.end(), body.begin()) &&
                          std::equal(kDaeSealing.head.begin(), kDaeSealing.head.end(),
                                     body.begin() + 0x08) &&
                          body[0x0F] == kBuild.lockdown_value,
                      "each body carries the stamp, the head and the lockdown value") &&
                check(std::equal(mac.begin(), mac.end(), body.begin() + 0x10),
                      "and HMAC-SHA(CPU key, field + preamble) at 0x10") &&
                check(std::equal(body.begin() + 0x20, body.end(),
                                 clear.begin() + static_cast<std::ptrdiff_t>(at) + 0x150),
                      "and the content behind the preamble");
        }
        const auto own = dae_sealing(*sealed, kCpuKey);
        return records_hold &&
               check(own && own->head == kDaeSealing.head && own->field == field,
                     "the head and field are read back under the CPU key") &&
               check(reseal_dae(*sealed, kCpuKey, *own, kBuild) == sealed,
                     "a sealed dae.bin seals again to the same bytes") &&
               check(!dae_sealing(*sealed, kOtherKey), "another console's key does not open it");
    }

    bool test_a_dae_whose_records_do_not_cover_it_is_refused() {
        auto clear = clear_dae();
        clear.push_back(0);
        auto wrong_magic = clear_dae();
        wrong_magic[0x400] = 'X';
        return check(!reseal_dae(clear, kCpuKey, kDaeSealing, kBuild),
                     "trailing bytes after the last record are refused") &&
               check(!reseal_dae(wrong_magic, kCpuKey, kDaeSealing, kBuild),
                     "a record without the DAEP magic is refused");
    }

    Bytes clear_keyvault_style(size_t length, uint8_t fill, bool extended) {
        Bytes plain(length - 0x10);
        for (size_t at = 0; at < plain.size(); ++at) {
            plain[at] = static_cast<uint8_t>(at + fill);
        }
        static constexpr uint8_t kTail[2] = {0x07, 0x12};
        const auto nonce =
            extended ? hmac(kCpuKey, plain, kTail) : hmac(kCpuKey, plain, std::span<uint8_t>{});
        Bytes out(nonce.begin(), nonce.end());
        out.insert(out.end(), plain.begin(), plain.end());
        return out;
    }

    bool test_extended_takes_the_keyvault_head_and_derives_its_nonce() {
        const auto clear = clear_keyvault_style(0x4000, 5, true);
        const std::array<uint8_t, 8> head{1, 2, 3, 4, 5, 6, 7, 8};
        const auto sealed = reseal_extended(clear, kCpuKey, head);
        if (!check(sealed && sealed->size() == clear.size(), "extended.bin is sealed")) {
            return false;
        }
        auto opened = *sealed;
        crypt_secfile(kCpuKey, opened);
        return check(extended_opened(clear, kCpuKey), "an opened extended.bin is recognised") &&
               check(!extended_opened(clear, kOtherKey), "under its own key only") &&
               check(extended_opened(opened, kCpuKey),
                     "its nonce is the one its plaintext derives") &&
               check(std::equal(head.begin(), head.end(), opened.begin() + 0x10),
                     "its head is the keyvault's") &&
               check(std::equal(opened.begin() + 0x18, opened.end(), clear.begin() + 0x18),
                     "and the rest is its own");
    }

    bool test_secdata_takes_the_build_fields_and_derives_its_nonce() {
        const auto clear = clear_keyvault_style(0x400, 9, false);
        const std::array<uint8_t, 8> head{8, 7, 6, 5, 4, 3, 2, 1};
        const auto sealed = reseal_secdata(clear, kCpuKey, head, kBuild);
        const auto kept = reseal_secdata(clear, kCpuKey, std::nullopt, kBuild);
        if (!check(sealed && kept, "secdata.bin is sealed")) {
            return false;
        }
        auto opened = *sealed;
        crypt_secfile(kCpuKey, opened);
        auto opened_kept = *kept;
        crypt_secfile(kCpuKey, opened_kept);
        const auto stamp = secured_file_stamp(kBuild.build_seconds);
        return check(secdata_opened(clear, kCpuKey) && !extended_opened(clear, kCpuKey),
                     "secdata.bin's nonce takes nothing behind the plaintext") &&
               check(secdata_opened(opened, kCpuKey),
                     "its nonce is the one its plaintext derives") &&
               check(std::equal(head.begin(), head.end(), opened.begin() + 0x10),
                     "a given head is written") &&
               check(secdata_head(opened_kept) == secdata_head(clear), "else its own is kept") &&
               check(opened[0x18] == 0x01 && opened[0x19] == kBuild.lockdown_value,
                     "it states 1 and the lockdown value at 0x08") &&
               check(std::equal(stamp.begin(), stamp.end(), opened.begin() + 0x20),
                     "and the stamp at 0x10") &&
               check(std::equal(opened.begin() + 0x28, opened.end(), clear.begin() + 0x28),
                     "and the rest is its own");
    }

    bool test_loose_copies_reach_the_input_boundary_in_the_clear() {
        const auto clear = clear_keyvault_style(0x400, 9, false);
        auto sealed = clear;
        crypt_secfile(kCpuKey, sealed);
        auto zero_nonce = clear;
        std::fill(zero_nonce.begin(), zero_nonce.begin() + 0x10, uint8_t{0});
        auto stale = sealed;
        std::fill(stale.begin(), stale.begin() + 0x10, uint8_t{0x51});
        auto stale_opened = stale;
        crypt_secfile(kCpuKey, stale_opened);
        const auto extended = clear_keyvault_style(0x4000, 5, true);
        auto zero_extended = extended;
        std::fill(zero_extended.begin(), zero_extended.begin() + 0x10, uint8_t{0});
        return check(open_loose_secdata(sealed, kCpuKey) == clear,
                     "a sealed secdata.bin is opened") &&
               check(open_loose_secdata(clear, kCpuKey) == clear,
                     "one in the clear behind its derived nonce is kept") &&
               check(open_loose_secdata(zero_nonce, kCpuKey) == clear,
                     "one in the clear behind a zero nonce gets its derived nonce") &&
               check(open_loose_extended(zero_extended, kCpuKey) == extended,
                     "so does an extended.bin in the clear behind a zero nonce") &&
               check(open_loose_secdata(stale, kCpuKey) == stale_opened,
                     "anything else is opened under the nonce it carries") &&
               check(!open_loose_secdata(Bytes(8), kCpuKey), "a file shorter than a nonce fails");
    }

    // An fcrt.bin in the clear: the vector at 0x100, where the sealed part starts at 0x11C, and
    // the SHA-1 of that part at 0x12C.
    Bytes clear_fcrt(size_t body_offset = 0x140, size_t length = 0x4000) {
        Bytes out(length);
        for (size_t at = 0x100; at < 0x110; ++at) {
            out[at] = static_cast<uint8_t>(at);
        }
        for (size_t index = 0; index < 4; ++index) {
            out[0x11C + index] = static_cast<uint8_t>(body_offset >> (24 - 8 * index));
        }
        for (size_t at = body_offset; at < length; ++at) {
            out[at] = static_cast<uint8_t>(at * 3 + 1);
        }
        ExCryptSha(out.data() + body_offset, static_cast<uint32_t>(length - body_offset), nullptr,
                   0, nullptr, 0, out.data() + 0x12C, 20);
        return out;
    }

    bool test_an_fcrt_in_the_clear_is_sealed_under_the_cpu_key_and_its_vector() {
        bool held = true;
        for (const size_t body_offset : {size_t{0x140}, size_t{0x150}}) {
            const auto clear = clear_fcrt(body_offset);
            const auto sealed = seal_fcrt(clear, kCpuKey);
            const auto body = aes_cbc_decrypt(kCpuKey, std::span(clear).subspan(0x100, 16),
                                              std::span(sealed.data).subspan(body_offset));
            held =
                check(sealed.sealing == FcrtSealing::Sealed,
                      "an fcrt.bin in the clear is sealed") &&
                check(std::equal(clear.begin(), clear.begin() + body_offset, sealed.data.begin()),
                      "everything before where its header says the sealed part starts is kept") &&
                check(!std::equal(clear.begin() + body_offset, clear.end(),
                                  sealed.data.begin() + body_offset),
                      "the part after it is sealed") &&
                check(std::equal(body.begin(), body.end(), clear.begin() + body_offset),
                      "and opens under the CPU key and the vector at 0x100") &&
                check(seal_fcrt(clear, kCpuKey).data == sealed.data, "the sealing draws nothing") &&
                held;
        }
        // A sealed part that is not whole blocks is left as it stands, as XeCrypt leaves it.
        const auto unaligned = clear_fcrt(0x148);
        const auto sealed = seal_fcrt(unaligned, kCpuKey);
        return check(sealed.sealing == FcrtSealing::Sealed && sealed.data == unaligned,
                     "a sealed part that is not whole blocks is left as it stands") &&
               held;
    }

    bool test_an_fcrt_sealed_under_the_cpu_key_is_carried_byte_for_byte() {
        const auto sealed = seal_fcrt(clear_fcrt(), kCpuKey).data;
        const auto again = seal_fcrt(sealed, kCpuKey);
        return check(again.sealing == FcrtSealing::Carried, "a sealed fcrt.bin verifies") &&
               check(again.data == sealed, "and is carried byte for byte");
    }

    bool test_an_fcrt_of_the_wrong_size_or_offset_is_carried_as_supplied() {
        auto longer = clear_fcrt();
        longer.insert(longer.end(), 5, 0xAB);
        auto shorter = clear_fcrt();
        shorter.resize(0x3FF0);
        auto moved = clear_fcrt();
        moved[0x11C] = 0x00;
        moved[0x11D] = 0x00;
        moved[0x11E] = 0x40;
        moved[0x11F] = 0x00;
        const auto from_longer = seal_fcrt(longer, kCpuKey);
        const auto from_shorter = seal_fcrt(shorter, kCpuKey);
        const auto from_moved = seal_fcrt(moved, kCpuKey);
        return check(from_longer.sealing == FcrtSealing::InvalidSize && from_longer.data == longer,
                     "an fcrt.bin longer than 0x4000 bytes is carried as supplied") &&
               check(from_shorter.sealing == FcrtSealing::InvalidSize &&
                         from_shorter.data == shorter,
                     "so is one shorter") &&
               check(from_moved.sealing == FcrtSealing::InvalidOffset && from_moved.data == moved,
                     "and one whose header puts the sealed part past 0x3FFF");
    }

    bool test_an_fcrt_that_does_not_open_is_carried_as_supplied() {
        auto damaged = seal_fcrt(clear_fcrt(), kCpuKey).data;
        damaged[0x2000] ^= 0x01;
        const auto other = seal_fcrt(clear_fcrt(), kOtherKey).data;
        const auto from_damaged = seal_fcrt(damaged, kCpuKey);
        const auto from_other = seal_fcrt(other, kCpuKey);
        const auto short_key = seal_fcrt(clear_fcrt(), std::span(kCpuKey).first(8));
        return check(from_damaged.sealing == FcrtSealing::Damaged && from_damaged.data == damaged,
                     "a damaged fcrt.bin is carried as supplied") &&
               check(from_other.sealing == FcrtSealing::Damaged && from_other.data == other,
                     "so is one sealed under another console's key") &&
               check(short_key.sealing == FcrtSealing::Damaged && short_key.data == clear_fcrt(),
                     "and any fcrt.bin with a CPU key that is not 16 bytes");
    }

    bool test_drawn_sealing_differs_between_draws() {
        const auto first = random_crl_sealing();
        const auto second = random_crl_sealing();
        const auto dae_first = random_dae_sealing();
        const auto dae_second = random_dae_sealing();
        return check(first.iv != second.iv && first.file_key != second.file_key,
                     "a drawn crl.bin vector and file key differ between draws") &&
               check(dae_first.field != dae_second.field,
                     "a drawn dae.bin field differs between draws");
    }

} // namespace

int main() {
    bool passed = test_the_stamp_is_the_build_time_plus_two_seconds_to_the_even_second();
    passed = test_a_crl_is_sealed_under_the_given_vector_and_file_key() && passed;
    passed = test_a_crl_from_an_update_package_is_resealed_for_the_console() && passed;
    passed = test_a_dae_is_sealed_record_by_record() && passed;
    passed = test_a_dae_whose_records_do_not_cover_it_is_refused() && passed;
    passed = test_extended_takes_the_keyvault_head_and_derives_its_nonce() && passed;
    passed = test_secdata_takes_the_build_fields_and_derives_its_nonce() && passed;
    passed = test_loose_copies_reach_the_input_boundary_in_the_clear() && passed;
    passed = test_an_fcrt_in_the_clear_is_sealed_under_the_cpu_key_and_its_vector() && passed;
    passed = test_an_fcrt_sealed_under_the_cpu_key_is_carried_byte_for_byte() && passed;
    passed = test_an_fcrt_of_the_wrong_size_or_offset_is_carried_as_supplied() && passed;
    passed = test_an_fcrt_that_does_not_open_is_carried_as_supplied() && passed;
    passed = test_drawn_sealing_differs_between_draws() && passed;
    return passed ? 0 : 1;
}
