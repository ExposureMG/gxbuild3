// Direct tests for src/nand/bootloaders/Stage.hpp, covering what the bootloader corpus
// (tests/golden/wire_corpus_bootloaders.txt) does not reach through the stage classes: the
// parse failures and their messages, payload padding, crypt_stage_record against a plain
// crypt_single_bl over the serialized stage (crypt starts 0x20 and 0x30), its failure path
// leaving the stage untouched, and randomize_zero_nonce on zero and set nonces.

#include "Error.hpp"
#include "nand/bootloaders/BootloaderPacker.hpp"
#include "nand/bootloaders/Common.hpp"
#include "nand/bootloaders/Stage.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

    namespace nand = gxbuild3::nand;
    namespace stage = gxbuild3::nand::stage;
    using gxbuild3::ErrorCode;

    using Bytes = std::vector<std::uint8_t>;

    int failures = 0;

    void check(bool condition, std::string_view what) {
        if (!condition) {
            ++failures;
            std::cerr << "FAIL: " << what << '\n';
        }
    }

    // A stage image of `total` bytes (a counting pattern) whose generic header declares `declared`.
    Bytes stage_image(std::uint16_t magic, std::size_t total, std::uint32_t declared) {
        Bytes bytes(total);
        for (std::size_t i = 0; i < total; ++i) {
            bytes[i] = static_cast<std::uint8_t>(i * 7 + 3);
        }
        bytes[0] = static_cast<std::uint8_t>(magic >> 8);
        bytes[1] = static_cast<std::uint8_t>(magic);
        for (std::size_t i = 0; i < 4; ++i) {
            bytes[0xC + i] = static_cast<std::uint8_t>(declared >> (24 - 8 * i));
        }
        return bytes;
    }

    void test_parse_stage() {
        const Bytes image = stage_image(nand::SC, sizeof(nand::sc_header) + 0x40,
                                        static_cast<std::uint32_t>(sizeof(nand::sc_header) + 0x40));
        auto parsed = stage::parse_stage<nand::sc_header>(image, "SC/3BL");
        check(parsed.has_value(), "parse_stage accepts a well-formed SC");
        if (parsed) {
            check(parsed->header.header.magic == nand::SC, "parse_stage decodes the magic");
            check(parsed->header.header.size == sizeof(nand::sc_header) + 0x40,
                  "parse_stage decodes the declared size");
            check(parsed->data == Bytes(image.begin() + sizeof(nand::sc_header), image.end()),
                  "parse_stage keeps the bytes after the header as the payload");
            check(stage::serialize_stage(parsed->header, parsed->data) == image,
                  "serialize_stage reproduces the parsed image");
        }

        const Bytes short_image(sizeof(nand::sc_header) - 1, 0);
        auto short_parse = stage::parse_stage<nand::sc_header>(short_image, "SC/3BL");
        check(!short_parse && short_parse.error().code == ErrorCode::Truncated &&
                  short_parse.error().describe() == "SC/3BL data too short",
              "parse_stage refuses bytes shorter than the header with the stage message");

        const Bytes undersized = stage_image(nand::CG, sizeof(nand::cg_header) + 0x20, 0x10);
        auto undersized_parse = stage::parse_stage<nand::cg_header>(undersized, "CG/7BL");
        check(!undersized_parse && undersized_parse.error().code == ErrorCode::Malformed &&
                  undersized_parse.error().describe().starts_with("CG/7BL declared size 0x10"),
              "parse_stage refuses a declared size smaller than the header");
    }

    void test_payload_size_and_padding() {
        nand::sc_header header{};
        header.header.size = static_cast<std::uint32_t>(sizeof(nand::sc_header) + 0x31);
        auto size = stage::stage_payload_size(header, "SC/3BL");
        check(size && *size == 0x40, "stage_payload_size is the aligned size minus the header");

        header.header.size = 0x10;
        auto undersized = stage::stage_payload_size(header, "SC/3BL");
        check(!undersized && undersized.error().code == ErrorCode::Malformed,
              "stage_payload_size refuses a declared size smaller than the header");

        Bytes data(0x10, 0xAB);
        stage::pad_payload(data, 0x40);
        check(data.size() == 0x40 &&
                  std::all_of(data.begin(), data.begin() + 0x10,
                              [](std::uint8_t b) { return b == 0xAB; }) &&
                  std::all_of(data.begin() + 0x10, data.end(),
                              [](std::uint8_t b) { return b == 0x00; }),
              "pad_payload grows the payload with zeros");
        stage::pad_payload(data, 0x20);
        check(data.size() == 0x40, "pad_payload never shrinks the payload");
    }

    // crypt_stage_record must give exactly what crypt_single_bl gives over the serialized stage.
    template <class H>
    void check_crypt_matches_packer(const Bytes& image, std::size_t crypt_start,
                                    nand::HmacType hmac_type, const std::uint8_t* cpu_key,
                                    std::string_view label) {
        const std::array<std::uint8_t, 16> key = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                                                  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        auto parsed = stage::parse_stage<H>(image, label);
        check(parsed.has_value(), std::string(label) + " parses");
        if (!parsed) {
            return;
        }

        Bytes expected = image;
        std::array<std::uint8_t, 16> expected_key = key;
        check(nand::crypt_single_bl(expected, hmac_type, expected_key.data(), cpu_key, nullptr,
                                    crypt_start)
                  .has_value(),
              std::string(label) + " crypt_single_bl succeeds");

        H header = parsed->header;
        Bytes data = parsed->data;
        auto derived = stage::crypt_stage_record(header, data, hmac_type, key.data(), cpu_key,
                                                 crypt_start, label);
        check(derived.has_value(), std::string(label) + " crypt_stage_record succeeds");
        if (!derived) {
            return;
        }
        check(stage::serialize_stage(header, data) == expected,
              std::string(label) + " crypt_stage_record matches crypt_single_bl byte for byte");
        check(*derived == expected_key,
              std::string(label) + " crypt_stage_record returns the derived key");

        auto restored = stage::crypt_stage_record(header, data, hmac_type, key.data(), cpu_key,
                                                  crypt_start, label);
        check(restored && stage::serialize_stage(header, data) == image,
              std::string(label) + " a second crypt_stage_record restores the image");
    }

    void test_crypt_stage_record() {
        const std::array<std::uint8_t, 16> cpu_key = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
                                                      0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
                                                      0xCC, 0xCD, 0xCE, 0xCF};
        const auto sc_size = static_cast<std::uint32_t>(sizeof(nand::sc_header) + 0x60);
        check_crypt_matches_packer<nand::sc_header>(stage_image(nand::SC, sc_size, sc_size), 0x20,
                                                    nand::HmacType::Default, nullptr, "SC/3BL");
        const auto cd_size = static_cast<std::uint32_t>(sizeof(nand::cd_header) + 0x40);
        check_crypt_matches_packer<nand::cd_header>(stage_image(nand::CD, cd_size, cd_size), 0x20,
                                                    nand::HmacType::Hmac1920, cpu_key.data(),
                                                    "CD/4BL");
        const auto cf_size = static_cast<std::uint32_t>(sizeof(nand::cf_header) + 0x200);
        check_crypt_matches_packer<nand::cf_header>(stage_image(nand::CF, cf_size, cf_size), 0x30,
                                                    nand::HmacType::Default, nullptr, "CF/6BL");
    }

    void test_crypt_stage_record_failure_leaves_stage_untouched() {
        const auto size = static_cast<std::uint32_t>(sizeof(nand::sc_header) + 0x20);
        const Bytes image = stage_image(nand::SC, size, size);
        auto parsed = stage::parse_stage<nand::sc_header>(image, "SC/3BL");
        check(parsed.has_value(), "failure fixture parses");
        if (!parsed) {
            return;
        }
        const std::uint8_t key[16] = {};
        nand::sc_header header = parsed->header;
        Bytes data = parsed->data;

        // Hmac1920 without a CPU key is refused by crypt_single_bl before it writes anything.
        auto refused = stage::crypt_stage_record(header, data, nand::HmacType::Hmac1920, key,
                                                 nullptr, 0x20, "SC/3BL");
        check(!refused && refused.error().code == ErrorCode::InvalidArgument &&
                  refused.error().describe() == "SC/3BL: bootloader HMAC type needs a CPU key",
              "crypt_stage_record adds the stage context to a crypt failure");
        check(stage::serialize_stage(header, data) == image,
              "a failed crypt_stage_record leaves header and payload untouched");

        // A crypt start past the end of the stage is Truncated.
        auto truncated = stage::crypt_stage_record(header, data, nand::HmacType::Default, key,
                                                   nullptr, image.size() + 1, "SC/3BL");
        check(!truncated && truncated.error().code == ErrorCode::Truncated,
              "crypt_stage_record refuses a crypt start past the stage");
        check(stage::serialize_stage(header, data) == image,
              "a truncated crypt_stage_record leaves header and payload untouched");
    }

    void test_randomize_zero_nonce() {
        std::array<std::uint8_t, 16> set_nonce{};
        set_nonce[15] = 0x01;
        const auto kept = set_nonce;
        stage::randomize_zero_nonce(set_nonce);
        check(set_nonce == kept, "randomize_zero_nonce keeps a nonce with any set byte");

        std::array<std::uint8_t, 16> zero_nonce{};
        stage::randomize_zero_nonce(zero_nonce);
        check(std::any_of(zero_nonce.begin(), zero_nonce.end(),
                          [](std::uint8_t b) { return b != 0; }),
              "randomize_zero_nonce draws a fresh nonce for an all-zero one");
    }

} // namespace

int main() {
    test_parse_stage();
    test_payload_size_and_padding();
    test_crypt_stage_record();
    test_crypt_stage_record_failure_leaves_stage_untouched();
    test_randomize_zero_nonce();
    if (failures != 0) {
        std::cerr << failures << " stage check(s) failed\n";
        return 1;
    }
    std::cout << "Stage tests passed\n";
    return 0;
}
