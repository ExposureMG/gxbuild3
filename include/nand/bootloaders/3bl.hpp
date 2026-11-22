#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderSc {
      public:
        sc_header header;
        std::vector<uint8_t> data;
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        [[nodiscard]] static Result<BootloaderSc> parse(std::span<const uint8_t> bytes);

        [[nodiscard]] Result<void> decrypt(const uint8_t secret[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t secret[16]);

        static constexpr uint8_t kZeroSecret[16] = {};

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
