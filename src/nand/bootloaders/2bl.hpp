#pragma once
#include "Error.hpp"
#include "nand/bootloaders/Common.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    class BootloaderCb {
      public:
        cb_header header;
        std::optional<cb_perbox> perbox;
        std::vector<uint8_t> data;
        std::optional<std::array<uint8_t, 16>> derived_key;
        bool decrypted = false;

        // Fails when the bytes or the declared size cannot hold the generic header. A header-only
        // CB parses; its crypt then fails, as the crypt also needs the 16-byte nonce.
        [[nodiscard]] static Result<BootloaderCb> parse(std::span<const uint8_t> bytes);

        // Each crypt toggles `decrypted`. On failure the stage is unchanged.
        [[nodiscard]] Result<void> decrypt(const uint8_t onebl_key[16]);
        [[nodiscard]] Result<void> decrypt_v1(const uint8_t cb_a_key[16],
                                              const uint8_t cpu_key[16]);
        [[nodiscard]] Result<void> decrypt_v2(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                              const uint8_t cpu_key[16]);
        // Not yet wired: manufacturing CB keyed over its nonce and CB_A's key with a zero HMAC
        // key. No caller yet; kept for manufacturing images (see cba_9188_mfg.bin fixture).
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
        // Not yet wired: inverse of decrypt_mfg.
        [[nodiscard]] Result<void> encrypt_mfg(const uint8_t cb_a_key[16]) {
            return decrypt_mfg(cb_a_key);
        }

        // CB_B keyed as its CB_A's flags select. Bit 0 (manufacturing) keys it over its nonce
        // and sixteen zero bytes instead of the CPU key, and takes precedence over bit 0x1000,
        // which appends CB_A's head (flag word cleared) after the CPU key.
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

        // Bind CB/CB_B to the final encrypted SMC, then encrypt. A null CB_A header selects
        // the single-CB (1BL parent) derivation.
        [[nodiscard]] Result<void> encrypt_retail(const uint8_t parent_key[16],
                                                  std::span<const uint8_t> cpu_key,
                                                  std::span<const uint8_t> encrypted_smc,
                                                  const cb_header* cb_a_header = nullptr);

        // Throwing shims over the Result API above (std::runtime_error carrying
        // Error::describe()). TODO(test-phase): test-only; src must not call them
        // (ErrorConventionGuard.cmake).
        static BootloaderCb parse_or_throw(const std::vector<uint8_t>& bytes) {
            return detail::value_or_throw(parse(bytes));
        }
        void decrypt_or_throw(const uint8_t onebl_key[16]) {
            detail::value_or_throw(decrypt(onebl_key));
        }
        void decrypt_v1_or_throw(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]) {
            detail::value_or_throw(decrypt_v1(cb_a_key, cpu_key));
        }
        void decrypt_v2_or_throw(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                 const uint8_t cpu_key[16]) {
            detail::value_or_throw(decrypt_v2(cb_a_hdr, cb_a_key, cpu_key));
        }
        void decrypt_mfg_or_throw(const uint8_t cb_a_key[16]) {
            detail::value_or_throw(decrypt_mfg(cb_a_key));
        }
        void encrypt_or_throw(const uint8_t onebl_key[16]) {
            detail::value_or_throw(encrypt(onebl_key));
        }
        void encrypt_v1_or_throw(const uint8_t cb_a_key[16], const uint8_t cpu_key[16]) {
            detail::value_or_throw(encrypt_v1(cb_a_key, cpu_key));
        }
        void encrypt_v2_or_throw(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                 const uint8_t cpu_key[16]) {
            detail::value_or_throw(encrypt_v2(cb_a_hdr, cb_a_key, cpu_key));
        }
        void encrypt_mfg_or_throw(const uint8_t cb_a_key[16]) {
            detail::value_or_throw(encrypt_mfg(cb_a_key));
        }
        void decrypt_cb_b_or_throw(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                   const uint8_t cpu_key[16]) {
            detail::value_or_throw(decrypt_cb_b(cb_a_hdr, cb_a_key, cpu_key));
        }
        void encrypt_cb_b_or_throw(const cb_header& cb_a_hdr, const uint8_t cb_a_key[16],
                                   const uint8_t cpu_key[16]) {
            detail::value_or_throw(encrypt_cb_b(cb_a_hdr, cb_a_key, cpu_key));
        }
        void encrypt_retail_or_throw(const uint8_t parent_key[16], std::span<const uint8_t> cpu_key,
                                     std::span<const uint8_t> encrypted_smc,
                                     const cb_header* cb_a_header = nullptr) {
            detail::value_or_throw(encrypt_retail(parent_key, cpu_key, encrypted_smc, cb_a_header));
        }

        // A plaintext v1 RGH3 CB_X (big-endian word 0x646A0002, "oris r10,r3,2", at +0x354)
        // gets the four-word fix RGH2to3 applies, which moves that sequence from r10 to r9.
        // Returns true when it patched; any other CB_X, v2 included, is left untouched.
        bool patch_rgh3_v1_cb_x();

        bool is_decrypted() const;
        bool verify_decrypted() const;
        bool requires_cpu_key_for_cd() const;
        void populate_metadata();
        // Reads the per-box block out of the plaintext payload into `perbox`.
        [[nodiscard]] Result<void> parse_perbox();
        // Writes `perbox` back into the plaintext payload.
        [[nodiscard]] Result<void> serialize_perbox();
        std::vector<uint8_t> serialize() const;

      private:
        // Validates the declared size and pads the payload to it; returns the payload length.
        [[nodiscard]] Result<size_t> prepare_payload();
        // Keeps the first 16 digest bytes as the derived key and RC4s the payload with it.
        void apply_derived_key(const uint8_t digest[20], size_t payload_len);
        void do_rc4_decrypt(const uint8_t key[16], size_t payload_len);
        // Copies the mirror's console sequence allowance into a plaintext payload large enough
        // to hold it; a shorter payload is left as it is.
        void write_console_allow(std::span<uint8_t> payload) const;
    };

} // namespace gxbuild3::nand
