#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

// The console-bound FlashFS files a build seals for its console, as xeBuild 1.21 seals them.
//
// crl.bin is one signed record and dae.bin a chain of them. A record states its length at 0x04
// and, at 0x0C, the SHA-1 of everything from its 0x150 on, which the build never rewrites. crl.bin
// keeps a 0x140-byte header and an AES-128-CBC body under its own file key; the file key is kept
// at 0x130 under the master key (AES-ECB) and the vector at 0x120. Each dae.bin record keeps a
// 0x130-byte header and a body under the master key itself with a zero vector. The master key is
// the CPU key; the copies an update package ships are sealed under an XEX key instead.
//
// extended.bin and secdata.bin are a 16-byte nonce and then RC4 under HMAC-SHA(CPU key, nonce).
// Their nonce follows from the plaintext: HMAC-SHA(CPU key, plaintext + 07 12) for extended.bin,
// as for a keyvault, and HMAC-SHA(CPU key, plaintext) for secdata.bin. The Input boundary carries
// both in the clear behind the nonce they were sealed with.
//
// fcrt.bin is 0x4000 bytes: a header that keeps the vector at 0x100, at 0x11C a big-endian word
// saying where the sealed part starts (0x140 in every copy seen), and at 0x12C the SHA-1 of the
// sealed part in the clear; the sealed part runs to the end under AES-128-CBC with the CPU key. A
// sealed part that is not whole blocks is left as it stands by both directions, as XeCrypt leaves
// it.
namespace gxbuild3::NAND {

    // The vector and file key a crl.bin is sealed under.
    struct CrlSealing {
        std::array<uint8_t, 16> iv{};
        std::array<uint8_t, 16> file_key{};
    };

    // The seven bytes every dae.bin record's body carries at 0x08 and the sixteen its header
    // carries at 0x120.
    struct DaeSealing {
        std::array<uint8_t, 7> head{};
        std::array<uint8_t, 16> field{};
    };

    // What a build writes into crl.bin, dae.bin and secdata.bin: its time and the console's
    // lockdown value.
    struct SecuredFileBuild {
        int64_t build_seconds{0};
        uint8_t lockdown_value{0};
    };

    // The build's time as the three files state it: the build time plus two seconds, down to an
    // even second, as a big-endian Windows FILETIME.
    [[nodiscard]] std::array<uint8_t, 8> secured_file_stamp(int64_t build_seconds);

    // The sealing a console's own crl.bin or dae.bin carries, when it opens under the CPU key.
    [[nodiscard]] std::optional<CrlSealing> crl_sealing(std::span<const uint8_t> own,
                                                        std::span<const uint8_t> cpu_key);
    [[nodiscard]] std::optional<DaeSealing> dae_sealing(std::span<const uint8_t> own,
                                                        std::span<const uint8_t> cpu_key);

    // Sealing drawn from the system's cryptographic random source, for a build with no console
    // copy to take it from.
    [[nodiscard]] CrlSealing random_crl_sealing();
    [[nodiscard]] DaeSealing random_dae_sealing();

    // crl.bin sealed for the console: the content's body, in the clear or opened under the CPU key
    // or an XEX key, takes the stamp at 0x00 and the lockdown value at 0x0F and is sealed under the
    // CPU key with `sealing`. The header up to 0x120 is the content's. Nothing when the content
    // opens under no key.
    [[nodiscard]] std::optional<std::vector<uint8_t>> reseal_crl(std::span<const uint8_t> content,
                                                                 std::span<const uint8_t> cpu_key,
                                                                 const CrlSealing& sealing,
                                                                 const SecuredFileBuild& build);

    // dae.bin sealed for the console, record by record: each body, in the clear or opened under
    // the CPU key or an XEX key, takes the stamp at 0x00, the head at 0x08, the lockdown value at
    // 0x0F and HMAC-SHA(CPU key, field + body[0..0x10]) at 0x10; its header takes the field, with
    // bit 0 of its second byte set, at 0x120. Nothing when any record opens under no key or the
    // records do not cover the file.
    [[nodiscard]] std::optional<std::vector<uint8_t>> reseal_dae(std::span<const uint8_t> content,
                                                                 std::span<const uint8_t> cpu_key,
                                                                 const DaeSealing& sealing,
                                                                 const SecuredFileBuild& build);

    // Whether an extended.bin or secdata.bin in the clear is the plaintext of the nonce it
    // carries, that is, whether it was opened under this CPU key.
    [[nodiscard]] bool extended_opened(std::span<const uint8_t> clear,
                                       std::span<const uint8_t> cpu_key);
    [[nodiscard]] bool secdata_opened(std::span<const uint8_t> clear,
                                      std::span<const uint8_t> cpu_key);

    // extended.bin sealed for the console: its plaintext with the keyvault's eight-byte head at
    // 0x00, under the nonce that plaintext derives. `clear` is the nonce and the plaintext.
    [[nodiscard]] std::optional<std::vector<uint8_t>>
    reseal_extended(std::span<const uint8_t> clear, std::span<const uint8_t> cpu_key,
                    std::span<const uint8_t, 8> keyvault_head);

    // secdata.bin sealed for the console: its plaintext with `head` at 0x00 when one is given, 1
    // at 0x08, the lockdown value at 0x09 and the stamp at 0x10, under the nonce that plaintext
    // derives. `clear` is the nonce and the plaintext.
    [[nodiscard]] std::optional<std::vector<uint8_t>>
    reseal_secdata(std::span<const uint8_t> clear, std::span<const uint8_t> cpu_key,
                   std::optional<std::array<uint8_t, 8>> head, const SecuredFileBuild& build);

    // A loose extended.bin or secdata.bin in the form the Input boundary carries it. A copy sealed
    // under the CPU key is opened. A copy in the clear, as xeBuild takes one (an all-zero nonce,
    // or the nonce its plaintext derives), gets the nonce its plaintext derives. Anything else is
    // opened under the nonce it carries; it then does not verify, and RunBuild writes it back as
    // supplied. Nothing for a CPU key that is not 16 bytes or a file shorter than its nonce.
    [[nodiscard]] std::optional<std::vector<uint8_t>>
    open_loose_extended(std::span<const uint8_t> blob, std::span<const uint8_t> cpu_key);
    [[nodiscard]] std::optional<std::vector<uint8_t>>
    open_loose_secdata(std::span<const uint8_t> blob, std::span<const uint8_t> cpu_key);

    // What a build makes of the fcrt.bin it is handed, as xeBuild 1.21 makes it.
    enum class FcrtSealing {
        // It was in the clear, its hash holding as it stands, and is now sealed under the CPU key.
        Sealed,
        // It is sealed under the CPU key already: it opens and its hash holds. Carried byte for
        // byte.
        Carried,
        // It is not 0x4000 bytes long. Carried as supplied.
        InvalidSize,
        // Its header puts the sealed part past 0x3FFF. Carried as supplied.
        InvalidOffset,
        // It is neither in the clear nor opens under the CPU key (or the CPU key is not 16
        // bytes). Carried as supplied.
        Damaged,
    };

    struct SealedFcrt {
        std::vector<uint8_t> data;
        FcrtSealing sealing{FcrtSealing::Carried};
    };

    // fcrt.bin sealed for the console: a copy in the clear is sealed under the CPU key and the
    // vector it carries, which makes the sealing deterministic; any other copy is carried as
    // supplied, and `sealing` says why.
    [[nodiscard]] SealedFcrt seal_fcrt(std::span<const uint8_t> content,
                                       std::span<const uint8_t> cpu_key);

    // The eight-byte head of an opened secdata.bin (`clear` is the nonce and the plaintext).
    [[nodiscard]] std::optional<std::array<uint8_t, 8>>
    secdata_head(std::span<const uint8_t> clear);

} // namespace gxbuild3::NAND
