#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::NAND {

enum class SmcMotherboard {
    Unknown = 0,
    Xenon = 1,
    Zephyr = 2,
    Falcon = 3,
    Jasper = 4,
    Trinity = 5,
    Corona = 6,
    Winchester = 7,
};

enum class SmcType {
    Unknown = -1,
    Retail = 0,
    Glitch = 1,
    Jtag = 2,
    Cygnos = 3,
    RJtag = 4,
    RJtagCygnos = 5,
    CR4 = 6,
    SmcPlus = 7,
    Rgh3V1 = 8,
    Rgh3V2 = 9,
    Rgh13 = 10,
};

std::string_view smc_motherboard_name(SmcMotherboard mb);
std::string_view smc_type_name(SmcType type);

struct Smc {
    SmcMotherboard motherboard{SmcMotherboard::Unknown};
    std::string version;
    SmcType variant{SmcType::Unknown};
    bool encrypted{true};
    std::vector<uint8_t> data;

    static std::optional<Smc> parse(std::span<const uint8_t> bytes);
    static std::optional<Smc> parse(const std::vector<uint8_t>& bytes);

    void decrypt();
    void encrypt();
};

std::vector<uint8_t> smc_decrypt(std::span<const uint8_t> data);
std::vector<uint8_t> smc_encrypt(std::span<const uint8_t> data);
bool smc_is_encrypted(std::span<const uint8_t> data);
SmcType smc_get_type(std::span<const uint8_t> data);

} // namespace gxbuild3::NAND
