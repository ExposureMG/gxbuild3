#pragma once

// The synthetic glitch-chain fixture shared by the tests in tests/bootloaders/glitch: hand-built
// CB, CD and CE stages and a run_build input per build type, plus expect_chain, which checks a
// built image's CB_A .. CE against the independent oracle in GlitchOracle.hpp (included here,
// with its Bytes and Key). stage_header, cb() and fixture() are the old
// tests/GlitchCryptoTests.cpp builders, same bytes.

#include "Args.hpp"
#include "bootloaders/glitch/GlitchOracle.hpp"
#include "nand/bootloaders/Common.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace gxbuild3::bootloaders::glitch {

    // A generic stage header from host values (wire fields assign one at a time).
    [[nodiscard]] nand::generic_header stage_header(uint16_t magic, uint16_t version,
                                                    uint16_t pairing, uint16_t flags,
                                                    uint32_t entrypoint, size_t size);

    // A decrypted 0x600-byte CB whose nonce is sixteen `nonce` bytes and whose payload has
    // 0x42 at +0x400.
    [[nodiscard]] Bytes cb(uint16_t version, uint16_t flags, uint8_t nonce);

    // A small-block input for `type` with the 53-bit test CPU key (bits 0..52 ECC-encoded), a
    // zero SMC, a blank keyvault, CB_A (single CB for Glitch) with `flags`, CB_B, CB_X for
    // Glitch3, CD, CE, donor nonces equal to the templates' and, except for retail, an empty
    // automatic patchset with a KHV payload.
    [[nodiscard]] Input fixture(BuildType type, uint16_t flags = 0x800);

    // Checks CB_A, CB_X/CB_B, CD and CE of the built image `bytes` against the oracle for
    // `input`. Its ASSERTs end only the helper, so callers wrap it in EXPECT_NO_FATAL_FAILURE
    // (or ASSERT_NO_FATAL_FAILURE when nothing follows). Every message starts with `label`.
    void expect_chain(const Input& input, const Bytes& bytes, const std::string& label);

    // An optional stage's serialized bytes.
    template <class Stage>
    [[nodiscard]] std::optional<Bytes> serialized(const std::optional<Stage>& stage) {
        if (!stage) {
            return std::nullopt;
        }
        return stage->serialize();
    }

    // Presence, then bytes as EXPECT_BYTES_EQ reports them (sizes and first differing offset,
    // never contents): the old `optional == optional` and `optional && *optional == bytes`.
    ::testing::AssertionResult optional_bytes_equal(const char* expected_expression,
                                                    const char* actual_expression,
                                                    const std::optional<Bytes>& expected,
                                                    const std::optional<Bytes>& actual);

} // namespace gxbuild3::bootloaders::glitch

#define EXPECT_OPTIONAL_BYTES_EQ(expected, actual)                                                 \
    EXPECT_PRED_FORMAT2(::gxbuild3::bootloaders::glitch::optional_bytes_equal, expected, actual)
