#include "utils/BigUint.hpp"

#include <algorithm>
#include <bit>
#include <stdexcept>

namespace gxbuild3::utils {

    namespace {

        constexpr uint64_t kLimbBase = uint64_t{1} << 32;

        std::vector<uint32_t> shifted_left(const std::vector<uint32_t>& limbs, unsigned shift,
                                           size_t extra) {
            std::vector<uint32_t> out(limbs.size() + extra, 0);
            for (size_t index = 0; index < limbs.size(); ++index) {
                const uint64_t value = uint64_t{limbs[index]} << shift;
                out[index] |= static_cast<uint32_t>(value);
                if (index + 1 < out.size()) {
                    out[index + 1] |= static_cast<uint32_t>(value >> 32);
                }
            }
            return out;
        }

    } // namespace

    BigUint::BigUint(uint64_t value) {
        if (value != 0) {
            limbs_.push_back(static_cast<uint32_t>(value));
            limbs_.push_back(static_cast<uint32_t>(value >> 32));
            trim();
        }
    }

    void BigUint::trim() noexcept {
        while (!limbs_.empty() && limbs_.back() == 0) {
            limbs_.pop_back();
        }
    }

    BigUint BigUint::from_be_bytes(std::span<const uint8_t> bytes) {
        BigUint out;
        out.limbs_.assign((bytes.size() + 3) / 4, 0);
        for (size_t index = 0; index < bytes.size(); ++index) {
            const size_t from_end = bytes.size() - 1 - index;
            out.limbs_[from_end / 4] |= uint32_t{bytes[index]} << (8 * (from_end % 4));
        }
        out.trim();
        return out;
    }

    BigUint BigUint::from_xe_digits(std::span<const uint8_t> bytes) {
        if (bytes.size() % 8 != 0) {
            throw std::invalid_argument("XeCrypt digits come in whole 64-bit words");
        }
        BigUint out;
        out.limbs_.reserve(bytes.size() / 4);
        for (size_t digit = 0; digit < bytes.size(); digit += 8) {
            uint64_t value = 0;
            for (size_t index = 0; index < 8; ++index) {
                value = (value << 8) | bytes[digit + index];
            }
            out.limbs_.push_back(static_cast<uint32_t>(value));
            out.limbs_.push_back(static_cast<uint32_t>(value >> 32));
        }
        out.trim();
        return out;
    }

    std::optional<std::vector<uint8_t>> BigUint::to_xe_digits(size_t size) const {
        if (size % 8 != 0 || limbs_.size() > size / 4) {
            return std::nullopt;
        }
        std::vector<uint8_t> out(size, 0);
        for (size_t digit = 0; digit < size / 8; ++digit) {
            const uint64_t low = 2 * digit < limbs_.size() ? limbs_[2 * digit] : 0;
            const uint64_t high = 2 * digit + 1 < limbs_.size() ? limbs_[2 * digit + 1] : 0;
            const uint64_t value = (high << 32) | low;
            for (size_t index = 0; index < 8; ++index) {
                out[digit * 8 + index] = static_cast<uint8_t>(value >> (56 - 8 * index));
            }
        }
        return out;
    }

    size_t BigUint::bit_length() const noexcept {
        if (limbs_.empty()) {
            return 0;
        }
        return limbs_.size() * 32 - static_cast<size_t>(std::countl_zero(limbs_.back()));
    }

    bool BigUint::bit(size_t index) const noexcept {
        const size_t limb = index / 32;
        return limb < limbs_.size() && ((limbs_[limb] >> (index % 32)) & 1) != 0;
    }

    uint32_t BigUint::mod_small(uint32_t divisor) const {
        if (divisor == 0) {
            throw std::domain_error("division by zero");
        }
        uint64_t remainder = 0;
        for (auto limb = limbs_.rbegin(); limb != limbs_.rend(); ++limb) {
            remainder = ((remainder << 32) | *limb) % divisor;
        }
        return static_cast<uint32_t>(remainder);
    }

    BigUint operator+(const BigUint& left, const BigUint& right) {
        BigUint out;
        const size_t size = std::max(left.limbs_.size(), right.limbs_.size());
        out.limbs_.resize(size + 1, 0);
        uint64_t carry = 0;
        for (size_t index = 0; index < size; ++index) {
            const uint64_t sum = carry + (index < left.limbs_.size() ? left.limbs_[index] : 0) +
                                 (index < right.limbs_.size() ? right.limbs_[index] : 0);
            out.limbs_[index] = static_cast<uint32_t>(sum);
            carry = sum >> 32;
        }
        out.limbs_[size] = static_cast<uint32_t>(carry);
        out.trim();
        return out;
    }

    BigUint operator-(const BigUint& left, const BigUint& right) {
        if (left < right) {
            throw std::domain_error("unsigned subtraction underflow");
        }
        BigUint out = left;
        int64_t borrow = 0;
        for (size_t index = 0; index < out.limbs_.size(); ++index) {
            const int64_t difference = int64_t{out.limbs_[index]} - borrow -
                                       (index < right.limbs_.size() ? right.limbs_[index] : 0);
            out.limbs_[index] = static_cast<uint32_t>(difference);
            borrow = difference < 0 ? 1 : 0;
        }
        out.trim();
        return out;
    }

    BigUint operator*(const BigUint& left, const BigUint& right) {
        BigUint out;
        if (left.is_zero() || right.is_zero()) {
            return out;
        }
        out.limbs_.assign(left.limbs_.size() + right.limbs_.size(), 0);
        for (size_t i = 0; i < left.limbs_.size(); ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < right.limbs_.size(); ++j) {
                const uint64_t product =
                    uint64_t{left.limbs_[i]} * right.limbs_[j] + out.limbs_[i + j] + carry;
                out.limbs_[i + j] = static_cast<uint32_t>(product);
                carry = product >> 32;
            }
            out.limbs_[i + right.limbs_.size()] = static_cast<uint32_t>(carry);
        }
        out.trim();
        return out;
    }

    std::strong_ordering operator<=>(const BigUint& left, const BigUint& right) {
        if (left.limbs_.size() != right.limbs_.size()) {
            return left.limbs_.size() <=> right.limbs_.size();
        }
        for (size_t index = left.limbs_.size(); index-- > 0;) {
            if (left.limbs_[index] != right.limbs_[index]) {
                return left.limbs_[index] <=> right.limbs_[index];
            }
        }
        return std::strong_ordering::equal;
    }

    // Knuth's algorithm D (TAOCP 4.3.1), after Hacker's Delight's divmnu.
    std::pair<BigUint, BigUint> BigUint::divmod(const BigUint& dividend, const BigUint& divisor) {
        if (divisor.is_zero()) {
            throw std::domain_error("division by zero");
        }
        if (dividend < divisor) {
            return {BigUint{}, dividend};
        }
        BigUint quotient;
        BigUint remainder;
        const size_t n = divisor.limbs_.size();
        const size_t m = dividend.limbs_.size() - n;
        quotient.limbs_.assign(m + 1, 0);

        if (n == 1) {
            uint64_t rest = 0;
            for (size_t index = dividend.limbs_.size(); index-- > 0;) {
                const uint64_t value = (rest << 32) | dividend.limbs_[index];
                quotient.limbs_[index] = static_cast<uint32_t>(value / divisor.limbs_[0]);
                rest = value % divisor.limbs_[0];
            }
            quotient.trim();
            return {quotient, BigUint{rest}};
        }

        const auto shift = static_cast<unsigned>(std::countl_zero(divisor.limbs_.back()));
        const auto vn = shifted_left(divisor.limbs_, shift, 0);
        auto un = shifted_left(dividend.limbs_, shift, 1);

        for (size_t j = m + 1; j-- > 0;) {
            const uint64_t numerator = (uint64_t{un[j + n]} << 32) | un[j + n - 1];
            uint64_t qhat = numerator / vn[n - 1];
            uint64_t rhat = numerator % vn[n - 1];
            while (qhat >= kLimbBase || qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2])) {
                --qhat;
                rhat += vn[n - 1];
                if (rhat >= kLimbBase) {
                    break;
                }
            }

            int64_t borrow = 0;
            uint64_t carry = 0;
            for (size_t i = 0; i < n; ++i) {
                const uint64_t product = qhat * vn[i] + carry;
                carry = product >> 32;
                const int64_t difference =
                    int64_t{un[i + j]} - borrow - static_cast<int64_t>(product & 0xFFFFFFFFU);
                un[i + j] = static_cast<uint32_t>(difference);
                borrow = difference < 0 ? 1 : 0;
            }
            const int64_t top = int64_t{un[j + n]} - borrow - static_cast<int64_t>(carry);
            un[j + n] = static_cast<uint32_t>(top);
            quotient.limbs_[j] = static_cast<uint32_t>(qhat);

            if (top < 0) {
                // qhat was one too large: add the divisor back once.
                --quotient.limbs_[j];
                uint64_t add_carry = 0;
                for (size_t i = 0; i < n; ++i) {
                    const uint64_t sum = uint64_t{un[i + j]} + vn[i] + add_carry;
                    un[i + j] = static_cast<uint32_t>(sum);
                    add_carry = sum >> 32;
                }
                un[j + n] = static_cast<uint32_t>(un[j + n] + add_carry);
            }
        }

        remainder.limbs_.assign(n, 0);
        for (size_t index = 0; index < n; ++index) {
            remainder.limbs_[index] =
                shift == 0 ? un[index]
                           : static_cast<uint32_t>((un[index] >> shift) |
                                                   (uint64_t{un[index + 1]} << (32 - shift)));
        }
        quotient.trim();
        remainder.trim();
        return {quotient, remainder};
    }

    BigUint operator/(const BigUint& left, const BigUint& right) {
        return BigUint::divmod(left, right).first;
    }

    BigUint operator%(const BigUint& left, const BigUint& right) {
        return BigUint::divmod(left, right).second;
    }

    BigUint BigUint::pow_mod(const BigUint& base, const BigUint& exponent, const BigUint& modulus) {
        if (modulus.is_zero()) {
            throw std::domain_error("modulus is zero");
        }
        BigUint result = BigUint{1} % modulus;
        const BigUint reduced = base % modulus;
        for (size_t index = exponent.bit_length(); index-- > 0;) {
            result = (result * result) % modulus;
            if (exponent.bit(index)) {
                result = (result * reduced) % modulus;
            }
        }
        return result;
    }

} // namespace gxbuild3::utils
