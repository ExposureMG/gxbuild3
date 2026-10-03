#pragma once
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class BootloaderCb {
  public:
    cb_header header;
    std::optional<cb_perbox> perbox;
    std::vector<uint8_t> data;
    std::optional<std::array<uint8_t, 16>> derived_key;
    bool decrypted = false;

    static BootloaderCb parse(const std::vector<uint8_t>& bytes);

    void decrypt(const uint8_t onebl_key[16]);
    void decrypt_v1(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]);
    void decrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                    const uint8_t cpu_key[16]);
    void decrypt_mfg(const uint8_t cb_a_key[16]);

    void encrypt(const uint8_t onebl_key[16]) { decrypt(onebl_key); }
    void encrypt_v1(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]) {
        decrypt_v1(cb_a_key, cpu_key);
    }
    void encrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                    const uint8_t cpu_key[16]) {
        decrypt_v2(cb_a_hdr, cb_a_key, cpu_key);
    }
    void encrypt_mfg(const uint8_t cb_a_key[16]) { decrypt_mfg(cb_a_key); }

    // CB_B keyed as its CB_A's flags select. Bit 0 (manufacturing) keys it over its nonce
    // and sixteen zero bytes instead of the CPU key, and takes precedence over bit 0x1000,
    // which appends CB_A's head (flag word cleared) after the CPU key.
    void decrypt_cb_b(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                      const uint8_t cpu_key[16]);
    void encrypt_cb_b(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                      const uint8_t cpu_key[16]) {
        decrypt_cb_b(cb_a_hdr, cb_a_key, cpu_key);
    }
    static bool manufacturing_chain(const cb_header& cb_a_hdr) {
        return (cb_a_hdr.header.flags & 0x0001) != 0;
    }

    // Bind CB/CB_B to the final encrypted SMC, then encrypt. A null CB_A header selects
    // the single-CB (1BL parent) derivation.
    void encrypt_retail(const uint8_t parent_key[16], std::span<const uint8_t> cpu_key,
                        std::span<const uint8_t> encrypted_smc,
                        const cb_header* cb_a_header = nullptr);

    // A plaintext v1 RGH3 CB_X (big-endian word 0x646A0002, "oris r10,r3,2", at +0x354)
    // gets the four-word fix RGH2to3 applies, which moves that sequence from r10 to r9.
    // Returns true when it patched; any other CB_X, v2 included, is left untouched.
    bool patch_rgh3_v1_cb_x();

    bool is_decrypted() const;
    bool verify_decrypted() const;
    bool requires_cpu_key_for_cd() const;
    void populate_metadata();
    bool parse_perbox();
    bool serialize_perbox();
    std::vector<uint8_t> serialize() const;

  private:
    void do_rc4_decrypt(const uint8_t key[16], size_t payload_len);
    void synchronize_header_numeric_fields_to_data();
};
