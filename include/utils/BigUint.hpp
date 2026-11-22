#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace gxbuild3::utils {

    class BigUint {
      public:
        BigUint() = default;
        explicit BigUint(uint64_t value);

        static BigUint from_be_bytes(std::span<const uint8_t> bytes);
        // xecrypt stores big ints as little-endian arrays of big-endian 64-bit words
        static BigUint from_xe_digits(std::span<const uint8_t> bytes);
        std::optional<std::vector<uint8_t>> to_xe_digits(size_t size) const;

        bool is_zero() const noexcept { return limbs_.empty(); }
        bool is_odd() const noexcept { return !limbs_.empty() && (limbs_.front() & 1) != 0; }
        size_t bit_length() const noexcept;
        bool bit(size_t index) const noexcept;
        uint32_t mod_small(uint32_t divisor) const;

        friend BigUint operator+(const BigUint& left, const BigUint& right);
        friend BigUint operator-(const BigUint& left, const BigUint& right);
        friend BigUint operator*(const BigUint& left, const BigUint& right);
        friend BigUint operator/(const BigUint& left, const BigUint& right);
        friend BigUint operator%(const BigUint& left, const BigUint& right);
        friend std::strong_ordering operator<=>(const BigUint& left, const BigUint& right);
        friend bool operator==(const BigUint& left, const BigUint& right) = default;

        static std::pair<BigUint, BigUint> divmod(const BigUint& dividend, const BigUint& divisor);
        static BigUint pow_mod(const BigUint& base, const BigUint& exponent,
                               const BigUint& modulus);

      private:
        std::vector<uint32_t> limbs_;
        void trim() noexcept;
    };

} // namespace gxbuild3::utils
