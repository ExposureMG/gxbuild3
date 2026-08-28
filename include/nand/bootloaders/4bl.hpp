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

    void decrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16] = nullptr);
    void encrypt(const uint8_t parent_key[16], const uint8_t cpu_key[16] = nullptr);

    bool is_decrypted() const;
    std::vector<uint8_t> serialize() const;
};
