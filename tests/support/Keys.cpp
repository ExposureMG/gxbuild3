#include "Keys.hpp"

#include "excrypt.h"

namespace gxbuild3::test {

    CpuKey ecc_encoded_bit_range(unsigned first_bit, unsigned end_bit) {
        CpuKey key{};
        for (unsigned bit = first_bit; bit < end_bit && bit < 128u; ++bit) {
            key[bit / 8] |= static_cast<uint8_t>(1u << (bit % 8));
        }
        XeCryptUidEccEncode(key.data());
        return key;
    }

    CpuKey different_valid_cpu_key() {
        return ecc_encoded_bit_range(53u, 106u);
    }

} // namespace gxbuild3::test
