// run_build's input and donor contract (src/BuildRunner.cpp): a structurally invalid input is a
// structured InvalidInput error, an extracted plaintext keyvault is sealed again for a fresh
// layout, a donor sealed under another valid CPU key is refused as InvalidDonor, and the fixed
// payloads (the 0x200-byte payload, the rebooter's 0x1000-byte region and the 0x60-byte fuses)
// refuse any other size. One ctest entry per case (each runs run_build).

#include "BuildRunner.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/Keyvault.hpp"
#include "orchestration/RunBuildImage.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"
#include "support/builders/Inputs.hpp"
#include "support/builders/Stages.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <utility>

namespace gxbuild3::orchestration {
    namespace {

        using test::Bytes;

        TEST(RunBuildInput, InvalidInputReturnsStructuredError) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.metadata.cpu_key.pop_back();

            EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidInput)
                << "invalid input is rejected; invalid input has an InvalidInput build error";
        }

        TEST(RunBuildInput, ExtractedPlaintextKeyvaultReencryptsForAFreshLayout) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            for (size_t i = 0; i < source.metadata.keyvault->size(); ++i) {
                (*source.metadata.keyvault)[i] = static_cast<uint8_t>(i);
            }
            source.metadata.keyvault =
                test::canonical_keyvault(source.metadata.cpu_key, *source.metadata.keyvault);
            ASSERT_OK_AND_ASSIGN(const auto donor, test::make_donor(source, {}));
            auto extracted = extract_all(donor, source.metadata.cpu_key);
            ASSERT_OK(extracted) << "extraction exposes the canonical plaintext keyvault";
            ASSERT_TRUE(extracted->metadata.keyvault.has_value())
                << "extraction exposes the canonical plaintext keyvault";
            EXPECT_BYTES_EQ(*source.metadata.keyvault, *extracted->metadata.keyvault)
                << "extraction exposes the canonical plaintext keyvault";

            extracted->metadata.nand_image.reset();
            const auto rebuilt = run_build(*extracted);
            ASSERT_OK(rebuilt) << "fresh layout rebuild with extracted keyvault succeeds";
            auto parsed = parse_image(*rebuilt);
            ASSERT_TRUE(parsed.has_value()) << "rebuilt keyvault decrypts";
            ASSERT_OK(parsed->decrypt_all(extracted->metadata.cpu_key))
                << "rebuilt keyvault decrypts";
            ASSERT_TRUE(parsed->keyvault.has_value())
                << "rebuilt keyvault decrypts to the extracted plaintext";
            EXPECT_BYTES_EQ(*source.metadata.keyvault, parsed->keyvault->serialize())
                << "rebuilt keyvault decrypts to the extracted plaintext";
        }

        TEST(RunBuildInput, DonorRejectsADifferentStructurallyValidCpuKey) {
            auto source = test::fresh_input(ImageType::SmallBlock);
            ASSERT_OK_AND_ASSIGN(const auto donor, test::make_donor(source, {}));

            auto input = source;
            const auto wrong_key = test::different_valid_cpu_key();
            input.metadata.cpu_key.assign(wrong_key.begin(), wrong_key.end());
            input.metadata.nand_image = donor;
            EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidDonor)
                << "wrong valid CPU key rejects donor; wrong valid CPU key maps to InvalidDonor";
        }

        TEST(RunBuildInput, PayloadMustMatchIts0x200SizeContract) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            input.payloads = InputPayloads{};
            input.payloads->payload = Bytes{0xC0, 0xDE};

            EXPECT_ERROR_MSG(run_build(input), BuildErrorCode::InvalidInput,
                             "Payload must contain exactly 0x200 bytes")
                << "mis-sized payload is rejected; mis-sized payload returns InvalidInput; "
                   "mis-sized payload explains the 0x200-byte contract";
        }

        TEST(RunBuildInput, FixedPayloadsRejectNoncanonicalSizes) {
            // The rebooter only has to fit its 0x1000-byte window region; the embedded freeBOOT
            // rebooter is 0xd40 bytes and is deliberately not padded.
            const std::array<size_t, 2> valid_rebooter_sizes{{0xd40, 0x1000}};
            for (const auto size : valid_rebooter_sizes) {
                SCOPED_TRACE(::testing::Message() << "rebooter of 0x" << std::hex << size);
                auto input = test::fresh_input(ImageType::SmallBlock);
                InputPayloads payloads{};
                payloads.rebooter = Bytes(size, 0x71);
                input.payloads = std::move(payloads);
                EXPECT_OK(run_build(input)) << "rebooter fitting its region is accepted";
            }

            const std::array<size_t, 2> invalid_rebooter_sizes{{0x1001, 0x2000}};
            for (const auto size : invalid_rebooter_sizes) {
                SCOPED_TRACE(::testing::Message() << "rebooter of 0x" << std::hex << size);
                auto input = test::fresh_input(ImageType::SmallBlock);
                InputPayloads payloads{};
                payloads.rebooter = Bytes(size, 0x71);
                input.payloads = std::move(payloads);
                EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidInput)
                    << "oversized rebooter is rejected; oversized rebooter is an input error";
            }

            const std::array<size_t, 4> invalid_fuse_sizes{{0x5F, 0x61, 0, 0x100}};
            for (const auto size : invalid_fuse_sizes) {
                SCOPED_TRACE(::testing::Message() << "fuses of 0x" << std::hex << size);
                auto input = test::fresh_input(ImageType::SmallBlock);
                InputPayloads payloads{};
                payloads.fuses = Bytes(size, 0x72);
                input.payloads = std::move(payloads);
                EXPECT_ERROR(run_build(input), BuildErrorCode::InvalidInput)
                    << "noncanonical fuse size is rejected; noncanonical fuse size is an input "
                       "error";
            }
        }

    } // namespace
} // namespace gxbuild3::orchestration
