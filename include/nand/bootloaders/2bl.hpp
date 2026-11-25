#pragma once
#include "gxbuild/Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild::nand {

    class BootloaderCb {
      public:
        cb_header header;
        std::optional<cb_perbox> perbox;
        std::vector<uint8_t> data;
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        [[nodiscard]] static Result<BootloaderCb> parse(std::span<const uint8_t> bytes);

        [[nodiscard]] Result<void> decrypt(const uint8_t onebl_key[16]);
        [[nodiscard]] Result<void> decrypt_v1(const uint8_t cb_a_key[16],
                                              const uint8_t cpu_key[16]);
        [[nodiscard]] Result<void> decrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                              const uint8_t cpu_key[16]);
        [[nodiscard]] Result<void> decrypt_mfg(const uint8_t cb_a_key[16]);

        [[nodiscard]] Result<void> encrypt(const uint8_t onebl_key[16]) {
            return decrypt(onebl_key);
        }
        [[nodiscard]] Result<void> encrypt_v1(const uint8_t cb_a_key[16],
                                              const uint8_t cpu_key[16]) {
            return decrypt_v1(cb_a_key, cpu_key);
        }
        [[nodiscard]] Result<void> encrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                              const uint8_t cpu_key[16]) {
            return decrypt_v2(cb_a_hdr, cb_a_key, cpu_key);
        }
        [[nodiscard]] Result<void> encrypt_mfg(const uint8_t cb_a_key[16]) {
            return decrypt_mfg(cb_a_key);
        }

        // picks v1, v2, or zero-key manufacturing decryption based on cba's flags
        [[nodiscard]] Result<void> decrypt_cb_b(const cb_header& cb_a_hdr,
                                                const uint8_t cb_a_key[16],
                                                const uint8_t cpu_key[16]);
        [[nodiscard]] Result<void> encrypt_cb_b(const cb_header& cb_a_hdr,
                                                const uint8_t cb_a_key[16],
                                                const uint8_t cpu_key[16]) {
            return decrypt_cb_b(cb_a_hdr, cb_a_key, cpu_key);
        }
        static bool manufacturing_chain(const cb_header& cb_a_hdr) {
            return (cb_a_hdr.header.flags & 0x0001) != 0;
        }

        [[nodiscard]] Result<void> encrypt_retail(const uint8_t parent_key[16],
                                                  std::span<const uint8_t> cpu_key,
                                                  std::span<const uint8_t> encrypted_smc,
                                                  const cb_header* cb_a_header = nullptr);

        // patches v1 rgh3 cbx payloads to use r9 instead of r10
        bool patch_rgh3_v1_cb_x();

        bool is_decrypted() const;
        bool verify_decrypted() const;
        bool requires_cpu_key_for_cd() const;
        void populate_metadata();
        [[nodiscard]] Result<void> parse_perbox();
        [[nodiscard]] Result<void> serialize_perbox();
        std::vector<uint8_t> serialize() const;

      private:
        [[nodiscard]] Result<size_t> prepare_payload();
        void apply_derived_key(const uint8_t digest[20], size_t payload_len);
        void do_rc4_decrypt(const uint8_t key[16], size_t payload_len);
        void write_console_allow(std::span<uint8_t> payload) const;
    };

} // namespace gxbuild::nand
