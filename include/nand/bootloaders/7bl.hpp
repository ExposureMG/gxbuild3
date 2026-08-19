#pragma once
#include "nand/bootloaders/Common.hpp"

#include <cstdint>
#include <optional>
#include <vector>

class BootloaderCg {
  public:
    cg_header header;
    std::vector<uint8_t> data;
    bool decrypted = false;

    static BootloaderCg parse(const std::vector<uint8_t>& bytes);

    void decrypt(const uint8_t cg_hmac[16]);
    void encrypt(const uint8_t cg_hmac[16]);

    bool is_decrypted() const;
    std::vector<uint8_t> serialize() const;
    std::vector<uint8_t> split(size_t limit);
};
