#pragma once
#include "gxbuild/Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild::nand {

    class BootloaderCd {
      public:
        cd_header header;
        std::vector<uint8_t> data;
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        [[nodiscard]] static Result<BootloaderCd> parse(std::span<const uint8_t> bytes);

        [[nodiscard]] Result<void> decrypt(const uint8_t parent_key[16],
                                           const uint8_t cpu_key[16] = nullptr);
        [[nodiscard]] Result<void> encrypt(const uint8_t parent_key[16],
                                           const uint8_t cpu_key[16] = nullptr);

        bool is_decrypted() const;
        std::vector<uint8_t> serialize() const;

      private:
        [[nodiscard]] Result<void> crypt_stage(const uint8_t parent_key[16],
                                               const uint8_t cpu_key[16]);
    };

} // namespace gxbuild::nand
