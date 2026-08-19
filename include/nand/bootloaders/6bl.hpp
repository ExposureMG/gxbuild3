#pragma once
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <vector>

class BootloaderCf {
  public:
    cf_header header;
    std::optional<cf_perbox> perbox;
    std::vector<uint8_t> data;
    bool decrypted = false;

    static BootloaderCf parse(const std::vector<uint8_t>& bytes);

    void decrypt(const uint8_t onebl_key[16]);
    void encrypt(const uint8_t onebl_key[16]);
    void calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]);

    bool is_decrypted() const;
    bool verify_signature() const;
    bool parse_perbox();
    bool serialize_perbox();
    std::vector<uint8_t> serialize() const;
};
