#pragma once
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
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

    bool is_decrypted() const;
    bool verify_decrypted() const;
    void populate_metadata();
    bool parse_perbox();
    bool serialize_perbox();
    std::vector<uint8_t> serialize() const;

  private:
    void do_rc4_decrypt(const uint8_t key[16], size_t payload_len);
};