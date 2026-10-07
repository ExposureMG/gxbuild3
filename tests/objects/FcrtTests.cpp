// src/nand/objects/SecuredFiles.hpp: fcrt.bin sealed for the console as xeBuild 1.21 seals it (a
// copy in the clear sealed under the CPU key and its vector, a sealed copy carried, a copy of the
// wrong size or offset carried as supplied, a damaged one written as its failed opening), checked
// against the independent oracle in SecuredFilesOracle.hpp; and how a keyvault's OddFeatures word
// flags fcrt.bin.

#include "excrypt.h"
#include "nand/objects/SecuredFiles.hpp"
#include "objects/SecuredFilesOracle.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <gtest/gtest.h>
#include <ostream>
#include <span>

namespace gxbuild3::nand {
    // Found by ADL: a failed comparison names the enumerator instead of printing raw bytes.
    // Internal linkage: these printers belong to this file only.
    [[maybe_unused]] static void PrintTo(FcrtSealing sealing, std::ostream* os) {
        switch (sealing) {
            case FcrtSealing::Sealed:
                *os << "Sealed";
                return;
            case FcrtSealing::Carried:
                *os << "Carried";
                return;
            case FcrtSealing::InvalidSize:
                *os << "InvalidSize";
                return;
            case FcrtSealing::InvalidOffset:
                *os << "InvalidOffset";
                return;
            case FcrtSealing::Damaged:
                *os << "Damaged";
                return;
        }
        *os << "FcrtSealing(" << static_cast<int>(sealing) << ")";
    }

    [[maybe_unused]] static void PrintTo(FcrtRequirement requirement, std::ostream* os) {
        switch (requirement) {
            case FcrtRequirement::NotRequired:
                *os << "NotRequired";
                return;
            case FcrtRequirement::Required:
                *os << "Required";
                return;
            case FcrtRequirement::RequiredByDrive:
                *os << "RequiredByDrive";
                return;
        }
        *os << "FcrtRequirement(" << static_cast<int>(requirement) << ")";
    }
} // namespace gxbuild3::nand

namespace gxbuild3::objects {
    namespace {

        using nand::fcrt_requirement;
        using nand::FcrtSealing;
        using nand::seal_fcrt;
        using secured_oracle::aes_cbc_decrypt;
        using secured_oracle::Bytes;
        using secured_oracle::kCpuKey;
        using secured_oracle::kOtherKey;
        using Requirement = nand::FcrtRequirement;

        // An fcrt.bin in the clear: the vector at 0x100, where the sealed part starts at 0x11C,
        // and the SHA-1 of that part at 0x12C.
        Bytes clear_fcrt(size_t body_offset = 0x140, size_t length = 0x4000) {
            Bytes out(length);
            for (size_t at = 0x100; at < 0x110; ++at) {
                out[at] = static_cast<uint8_t>(at);
            }
            for (size_t index = 0; index < 4; ++index) {
                out[0x11C + index] = static_cast<uint8_t>(body_offset >> (24 - 8 * index));
            }
            for (size_t at = body_offset; at < length; ++at) {
                out[at] = static_cast<uint8_t>(at * 3 + 1);
            }
            ExCryptSha(out.data() + body_offset, static_cast<uint32_t>(length - body_offset),
                       nullptr, 0, nullptr, 0, out.data() + 0x12C, 20);
            return out;
        }

        TEST(FcrtSeal, AnFcrtInTheClearIsSealedUnderTheCpuKeyAndItsVector) {
            for (const size_t body_offset : {size_t{0x140}, size_t{0x150}}) {
                SCOPED_TRACE(std::format("the sealed part at 0x{:X}", body_offset));
                const auto clear = clear_fcrt(body_offset);
                const auto sealed = seal_fcrt(clear, kCpuKey);
                EXPECT_EQ(sealed.sealing, FcrtSealing::Sealed)
                    << "an fcrt.bin in the clear is sealed";
                ASSERT_EQ(sealed.data.size(), clear.size()) << "an fcrt.bin in the clear is sealed";
                const auto body = aes_cbc_decrypt(kCpuKey, std::span(clear).subspan(0x100, 16),
                                                  std::span(sealed.data).subspan(body_offset));
                EXPECT_BYTES_EQ(std::span(clear).first(body_offset),
                                std::span(sealed.data).first(body_offset))
                    << "everything before where its header says the sealed part starts is kept";
                EXPECT_FALSE(std::ranges::equal(std::span(clear).subspan(body_offset),
                                                std::span(sealed.data).subspan(body_offset)))
                    << "the part after it is sealed";
                EXPECT_BYTES_EQ(std::span(clear).subspan(body_offset), body)
                    << "and opens under the CPU key and the vector at 0x100";
                EXPECT_BYTES_EQ(sealed.data, seal_fcrt(clear, kCpuKey).data)
                    << "the sealing draws nothing";
            }
            // A sealed part that is not whole blocks is left as it stands, as XeCrypt leaves it.
            const auto unaligned = clear_fcrt(0x148);
            const auto sealed = seal_fcrt(unaligned, kCpuKey);
            EXPECT_EQ(sealed.sealing, FcrtSealing::Sealed)
                << "a sealed part that is not whole blocks is left as it stands";
            EXPECT_BYTES_EQ(unaligned, sealed.data)
                << "a sealed part that is not whole blocks is left as it stands";
        }

        TEST(FcrtSeal, AnFcrtSealedUnderTheCpuKeyIsCarriedByteForByte) {
            const auto sealed = seal_fcrt(clear_fcrt(), kCpuKey).data;
            const auto again = seal_fcrt(sealed, kCpuKey);
            EXPECT_EQ(again.sealing, FcrtSealing::Carried) << "a sealed fcrt.bin verifies";
            EXPECT_BYTES_EQ(sealed, again.data) << "and is carried byte for byte";
        }

        TEST(FcrtSeal, AnFcrtOfTheWrongSizeOrOffsetIsCarriedAsSupplied) {
            auto longer = clear_fcrt();
            longer.insert(longer.end(), 5, 0xAB);
            auto shorter = clear_fcrt();
            shorter.resize(0x3FF0);
            auto moved = clear_fcrt();
            moved[0x11C] = 0x00;
            moved[0x11D] = 0x00;
            moved[0x11E] = 0x40;
            moved[0x11F] = 0x00;
            const auto from_longer = seal_fcrt(longer, kCpuKey);
            const auto from_shorter = seal_fcrt(shorter, kCpuKey);
            const auto from_moved = seal_fcrt(moved, kCpuKey);
            EXPECT_EQ(from_longer.sealing, FcrtSealing::InvalidSize)
                << "an fcrt.bin longer than 0x4000 bytes is carried as supplied";
            EXPECT_BYTES_EQ(longer, from_longer.data)
                << "an fcrt.bin longer than 0x4000 bytes is carried as supplied";
            EXPECT_EQ(from_shorter.sealing, FcrtSealing::InvalidSize) << "so is one shorter";
            EXPECT_BYTES_EQ(shorter, from_shorter.data) << "so is one shorter";
            EXPECT_EQ(from_moved.sealing, FcrtSealing::InvalidOffset)
                << "and one whose header puts the sealed part past 0x3FFF";
            EXPECT_BYTES_EQ(moved, from_moved.data)
                << "and one whose header puts the sealed part past 0x3FFF";
        }

        // xeBuild 1.21 opens an fcrt.bin in place and, where the hash then fails, writes what the
        // opening left: the header as supplied and the sealed part opened under the CPU key and
        // the vector at 0x100.
        TEST(FcrtSeal, AnFcrtThatDoesNotOpenIsWrittenAsItsFailedOpening) {
            const auto failed_opening = [](const Bytes& blob) {
                Bytes out(blob.begin(), blob.begin() + 0x140);
                const auto body = aes_cbc_decrypt(kCpuKey, std::span(blob).subspan(0x100, 16),
                                                  std::span(blob).subspan(0x140));
                out.insert(out.end(), body.begin(), body.end());
                return out;
            };
            auto damaged = seal_fcrt(clear_fcrt(), kCpuKey).data;
            damaged[0x2000] ^= 0x01;
            const auto other = seal_fcrt(clear_fcrt(), kOtherKey).data;
            const auto from_damaged = seal_fcrt(damaged, kCpuKey);
            const auto from_other = seal_fcrt(other, kCpuKey);
            auto unaligned = clear_fcrt(0x148);
            unaligned[0x2000] ^= 0x01;
            const auto from_unaligned = seal_fcrt(unaligned, kCpuKey);
            const auto short_key = seal_fcrt(clear_fcrt(), std::span(kCpuKey).first(8));

            EXPECT_EQ(from_damaged.sealing, FcrtSealing::Damaged)
                << "a damaged fcrt.bin is written as its failed opening";
            EXPECT_BYTES_EQ(failed_opening(damaged), from_damaged.data)
                << "a damaged fcrt.bin is written as its failed opening";
            EXPECT_FALSE(std::ranges::equal(damaged, from_damaged.data))
                << "a damaged fcrt.bin is written as its failed opening";
            EXPECT_EQ(from_other.sealing, FcrtSealing::Damaged)
                << "so is one sealed under another console's key";
            EXPECT_BYTES_EQ(failed_opening(other), from_other.data)
                << "so is one sealed under another console's key";
            EXPECT_EQ(from_unaligned.sealing, FcrtSealing::Damaged)
                << "a sealed part that is not whole blocks stays as it stands";
            EXPECT_BYTES_EQ(unaligned, from_unaligned.data)
                << "a sealed part that is not whole blocks stays as it stands";
            EXPECT_EQ(short_key.sealing, FcrtSealing::Damaged)
                << "and any fcrt.bin with a CPU key that is not 16 bytes is carried as supplied";
            EXPECT_BYTES_EQ(clear_fcrt(), short_key.data)
                << "and any fcrt.bin with a CPU key that is not 16 bytes is carried as supplied";
        }

        // xeBuild 1.21's test (its 0x413370) on the big-endian OddFeatures word at 0x1C: each row
        // is one word and the class it gives, in the old three loops' order.
        struct FeaturesRow {
            const char* name;
            uint16_t features;
            Requirement expected;
            const char* message;
        };
        GX_PRINT_ROW_AS_NAME(FeaturesRow)

        constexpr const char* kByDrive = "bits 0x0300 make the drive need fcrt.bin";
        constexpr const char* kRequired = "bit 0x0020 alone makes fcrt.bin required";
        constexpr const char* kNothing = "no other bit requires fcrt.bin, read big-endian";

        constexpr FeaturesRow kFeaturesRows[]{
            {"Word0x0100", 0x0100, Requirement::RequiredByDrive, kByDrive},
            {"Word0x0200", 0x0200, Requirement::RequiredByDrive, kByDrive},
            {"Word0x0300", 0x0300, Requirement::RequiredByDrive, kByDrive},
            {"Word0x0120", 0x0120, Requirement::RequiredByDrive, kByDrive},
            {"Word0x0320", 0x0320, Requirement::RequiredByDrive, kByDrive},
            {"Word0xFFFF", 0xFFFF, Requirement::RequiredByDrive, kByDrive},
            {"Word0x0020", 0x0020, Requirement::Required, kRequired},
            {"Word0x00F0", 0x00F0, Requirement::Required, kRequired},
            {"Word0x0021", 0x0021, Requirement::Required, kRequired},
            {"Word0x0000", 0x0000, Requirement::NotRequired, kNothing},
            {"Word0x0001", 0x0001, Requirement::NotRequired, kNothing},
            {"Word0x00DF", 0x00DF, Requirement::NotRequired, kNothing},
            {"Word0x2000", 0x2000, Requirement::NotRequired, kNothing},
            {"Word0x2001", 0x2001, Requirement::NotRequired, kNothing},
            {"Word0xFCDF", 0xFCDF, Requirement::NotRequired, kNothing},
        };

        class FcrtRequirement : public ::testing::TestWithParam<FeaturesRow> {};

        TEST_P(FcrtRequirement, TheKeyvaultFlagsFcrtByItsOddFeaturesWord) {
            const auto& row = GetParam();
            Bytes keyvault(0x4000, 0x00);
            keyvault[0x1C] = static_cast<uint8_t>(row.features >> 8);
            keyvault[0x1D] = static_cast<uint8_t>(row.features);
            EXPECT_EQ(fcrt_requirement(keyvault), row.expected) << row.message;
        }

        INSTANTIATE_TEST_SUITE_P(Features, FcrtRequirement, ::testing::ValuesIn(kFeaturesRows),
                                 test::RowName{});

        TEST(FcrtRequirementShort, ShortKeyvaultRequiresNothing) {
            EXPECT_EQ(fcrt_requirement(Bytes(0x1D, 0xFF)), Requirement::NotRequired)
                << "a keyvault too short for the word requires nothing";
        }

    } // namespace
} // namespace gxbuild3::objects
