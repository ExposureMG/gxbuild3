// Pins the on-disk layout of every bootloader record in src/nand/bootloaders/Common.hpp.
//
// The expected values below come from the Xbox 360 on-disk bootloader layout, not from the
// compiler: they are the byte offsets the wire format puts each field at. Today the records are
// declared under #pragma pack(1); these asserts must keep passing unchanged when the pack is
// dropped, which is the proof that dropping it is layout-neutral. A failure is a compile error
// that names the record and field.

#include "excrypt.h"
#include "nand/bootloaders/Common.hpp"

#include <cstddef>
#include <iostream>
#include <type_traits>

using namespace gxbuild3::nand;

namespace {

    // Every record is memcpy'd to and from wire bytes, so it must stay a plain byte image.
    template <class T>
    constexpr bool kIsWireRecord = std::is_standard_layout_v<T> && std::is_trivially_copyable_v<T>;

    int record_count = 0;
    int field_count = 0;

} // namespace

#define PIN_SIZE(type, expected)                                                                   \
    static_assert(kIsWireRecord<type>, #type " is not a standard-layout trivially copyable "       \
                                             "record");                                            \
    static_assert(sizeof(type) == (expected), "sizeof(" #type ") != " #expected);                  \
    ++record_count

#define PIN_FIELD(type, field, expected)                                                           \
    static_assert(offsetof(type, field) == (expected),                                             \
                  "offsetof(" #type ", " #field ") != " #expected);                                \
    ++field_count

// Wire-level building blocks from GxCrypt that the headers embed.
static_assert(sizeof(EXCRYPT_SIG) == 0x100, "sizeof(EXCRYPT_SIG) != 0x100");
static_assert(sizeof(EXCRYPT_RSAPUB_2048) == 0x110, "sizeof(EXCRYPT_RSAPUB_2048) != 0x110");

static void pin_records() {
    PIN_SIZE(generic_header, 0x10);
    PIN_SIZE(cb_perbox, 0x20);
    PIN_SIZE(ConsoleTypeSeqAllow, 0x4);
    PIN_SIZE(cb_header, 0x3C0);
    PIN_SIZE(sc_header, 0x120);
    PIN_SIZE(cd_header, 0x260);
    PIN_SIZE(ce_header, 0x30);
    PIN_SIZE(cf_perbox, 0x40);
    PIN_SIZE(cf_header, 0x30);
    PIN_SIZE(cg_header, 0x50);
}

// CB/2BL writes cb_perbox over padding_or_args (payload offset 0x10, absolute 0x20).
static_assert(sizeof(cb_perbox) == sizeof(cb_header::padding_or_args),
              "cb_perbox no longer fills cb_header::padding_or_args");

// The CB console_sequence_allow wire position that 2bl.cpp derives with offsetof.
static_assert(offsetof(cb_header, console_seq_allow) +
                      offsetof(ConsoleTypeSeqAllow, console_sequence_allow) ==
                  0x3B2,
              "CB console_sequence_allow is no longer at absolute 0x3B2");

// The CG nonce in the decrypted CF payload lies past the 0x1C0-byte spill table and per-box block.
static_assert(kCfCgNonceOffset == 0x330, "kCfCgNonceOffset != 0x330");
static_assert(kCfCgNonceOffset >= sizeof(cf_header) + 0x1C0 + sizeof(cf_perbox),
              "kCfCgNonceOffset overlaps the CF header, spill table or per-box block");

static void pin_fields() {
    PIN_FIELD(generic_header, magic, 0x0);
    PIN_FIELD(generic_header, version, 0x2);
    PIN_FIELD(generic_header, pairing, 0x4);
    PIN_FIELD(generic_header, flags, 0x6);
    PIN_FIELD(generic_header, entrypoint, 0x8);
    PIN_FIELD(generic_header, size, 0xC);

    PIN_FIELD(cb_perbox, pairing_data, 0x0);
    PIN_FIELD(cb_perbox, lockdown_value, 0x3);
    PIN_FIELD(cb_perbox, reserved, 0x4);
    PIN_FIELD(cb_perbox, per_box_digest, 0x10);

    PIN_FIELD(ConsoleTypeSeqAllow, console_type, 0x0);
    PIN_FIELD(ConsoleTypeSeqAllow, console_sequence, 0x1);
    PIN_FIELD(ConsoleTypeSeqAllow, console_sequence_allow, 0x2);

    PIN_FIELD(cb_header, header, 0x0);
    PIN_FIELD(cb_header, key, 0x10);
    PIN_FIELD(cb_header, padding_or_args, 0x20);
    PIN_FIELD(cb_header, signature, 0x40);
    PIN_FIELD(cb_header, globals, 0x140);
    PIN_FIELD(cb_header, dev_pub_key, 0x268);
    PIN_FIELD(cb_header, nonce_3bl, 0x378);
    PIN_FIELD(cb_header, salt_3bl, 0x388);
    PIN_FIELD(cb_header, salt_4bl, 0x392);
    PIN_FIELD(cb_header, next_hash, 0x39C);
    PIN_FIELD(cb_header, console_seq_allow, 0x3B0);
    PIN_FIELD(cb_header, reserved, 0x3B4);

    PIN_FIELD(sc_header, header, 0x0);
    PIN_FIELD(sc_header, key, 0x10);
    PIN_FIELD(sc_header, signature, 0x20);

    PIN_FIELD(cd_header, header, 0x0);
    PIN_FIELD(cd_header, key, 0x10);
    PIN_FIELD(cd_header, signature, 0x20);
    PIN_FIELD(cd_header, rsa_pub_key, 0x120);
    PIN_FIELD(cd_header, nonce_6bl, 0x230);
    PIN_FIELD(cd_header, salt_6bl, 0x240);
    PIN_FIELD(cd_header, padding, 0x24A);
    PIN_FIELD(cd_header, ce_hash, 0x24C);

    PIN_FIELD(ce_header, header, 0x0);
    PIN_FIELD(ce_header, key, 0x10);
    PIN_FIELD(ce_header, address, 0x20);
    PIN_FIELD(ce_header, size, 0x28);
    PIN_FIELD(ce_header, padding, 0x2C);

    PIN_FIELD(cf_perbox, reserved_per_box, 0x0);
    PIN_FIELD(cf_perbox, update_slot, 0x2B);
    PIN_FIELD(cf_perbox, pairing_data, 0x2C);
    PIN_FIELD(cf_perbox, lockdown_value, 0x2F);
    PIN_FIELD(cf_perbox, per_box_digest, 0x30);

    PIN_FIELD(cf_header, header, 0x0);
    PIN_FIELD(cf_header, source_version, 0x10);
    PIN_FIELD(cf_header, source_qfe, 0x12);
    PIN_FIELD(cf_header, target_version, 0x14);
    PIN_FIELD(cf_header, target_qfe, 0x16);
    PIN_FIELD(cf_header, reserved, 0x18);
    PIN_FIELD(cf_header, cg_size, 0x1C);
    PIN_FIELD(cf_header, fixpoint_nonce, 0x20);

    PIN_FIELD(cg_header, header, 0x0);
    PIN_FIELD(cg_header, key, 0x10);
    PIN_FIELD(cg_header, source_size, 0x20);
    PIN_FIELD(cg_header, source_hash, 0x24);
    PIN_FIELD(cg_header, target_size, 0x38);
    PIN_FIELD(cg_header, target_hash, 0x3C);
}

#undef PIN_FIELD
#undef PIN_SIZE

int main() {
    // The layout is proven at compile time; the run only reports what the build pinned, so a
    // missing or empty translation unit cannot pass as a pinned layout.
    pin_records();
    pin_fields();
    constexpr int kExpectedRecords = 10;
    constexpr int kExpectedFields = 60;
    std::cout << "records pinned " << record_count << "/" << kExpectedRecords << ", fields pinned "
              << field_count << "/" << kExpectedFields << '\n';
    if (record_count != kExpectedRecords || field_count != kExpectedFields) {
        std::cerr << "FAIL: pinned record or field count does not match the expected totals\n";
        return 1;
    }
    return 0;
}
