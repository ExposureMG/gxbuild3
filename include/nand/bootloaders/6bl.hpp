#pragma once
#include "gxbuild/Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild::nand {

    class BootloaderCf {
      public:
        cf_header header;
        std::optional<cf_perbox> perbox;
        std::vector<uint8_t> data;
        bool decrypted = false;

        [[nodiscard]] static Result<BootloaderCf> parse(std::span<const uint8_t> bytes);

        [[nodiscard]] Result<void> decrypt(const uint8_t onebl_key[16]);
        [[nodiscard]] Result<void> encrypt(const uint8_t onebl_key[16]);
        [[nodiscard]] Result<void> calc_mac(const uint8_t onebl_key[16], const uint8_t cpu_key[16]);

        bool is_decrypted() const;
        // grabs the 7bl nonce from offset 0x330 of the decrypted cf, not the header fixpoint at 0x20
        std::optional<std::array<uint8_t, 16>> cg_key() const;
        [[nodiscard]] Result<void> parse_perbox();
        [[nodiscard]] Result<void> serialize_perbox();
        std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild::nand
