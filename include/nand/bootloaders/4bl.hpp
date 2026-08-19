#pragma once
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <vector>

class BootloaderCd {
  public:
    cd_header header;
    std::vector<uint8_t> data;
    bool decrypted = false;

    static BootloaderCd parse(const std::vector<uint8_t>& bytes);

    void decrypt(const uint8_t cb_b_key[16]);
    void encrypt(const uint8_t cb_b_key[16]);

    bool is_decrypted() const;
    std::vector<uint8_t> serialize() const;
};
