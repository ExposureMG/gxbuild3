#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace gxbuild3::utils {

    // An unsigned integer of any size, for the RSA arithmetic of XeCrypt signatures. Plain
    // schoolbook arithmetic: not constant-time, which a build tool signing its own images
    // on its own machine does not need.
    //
    // BigUint is the one utils type that throws instead of returning Result: every throw is a
    // precondition violation (std::invalid_argument for a digit run that is not whole 64-bit
    // words, std::domain_error for division by zero, a zero modulus or an underflowing
    // subtraction), a caller bug rather than an expected failure. Callers check their
    // operands first, as XeRsaPrivateKey::parse does.
    class BigUint {
      public:
        BigUint() = default;
        explicit BigUint(uint64_t value);

        // Big-endian bytes, most significant first.
        static BigUint from_be_bytes(std::span<const uint8_t> bytes);
        // XeCrypt's layout: 64-bit digits, least significant first, each digit big-endian.
        // The length must be a multiple of eight.
        static BigUint from_xe_digits(std::span<const uint8_t> bytes);
        // The value in XeCrypt's layout over `size` bytes (a multiple of eight); nothing when
        // it does not fit.
        std::optional<std::vector<uint8_t>> to_xe_digits(size_t size) const;

        bool is_zero() const noexcept { return limbs_.empty(); }
        bool is_odd() const noexcept { return !limbs_.empty() && (limbs_.front() & 1) != 0; }
        size_t bit_length() const noexcept;
        bool bit(size_t index) const noexcept;
        // The remainder by a small divisor, which must not be zero.
        uint32_t mod_small(uint32_t divisor) const;

        friend BigUint operator+(const BigUint& left, const BigUint& right);
        // The difference; the left operand must not be the smaller.
        friend BigUint operator-(const BigUint& left, const BigUint& right);
        friend BigUint operator*(const BigUint& left, const BigUint& right);
        friend BigUint operator/(const BigUint& left, const BigUint& right);
        friend BigUint operator%(const BigUint& left, const BigUint& right);
        friend std::strong_ordering operator<=>(const BigUint& left, const BigUint& right);
        friend bool operator==(const BigUint& left, const BigUint& right) = default;

        // Quotient and remainder; the divisor must not be zero.
        static std::pair<BigUint, BigUint> divmod(const BigUint& dividend, const BigUint& divisor);
        // base^exponent mod modulus; the modulus must not be zero.
        static BigUint pow_mod(const BigUint& base, const BigUint& exponent,
                               const BigUint& modulus);

      private:
        // Little-endian 32-bit limbs with no leading zero limb; zero has none.
        std::vector<uint32_t> limbs_;
        void trim() noexcept;
    };

} // namespace gxbuild3::utils
