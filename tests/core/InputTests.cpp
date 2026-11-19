// The Input model (include/GxBuildTypes.hpp: the typed image layout, the mobile slot mapping)
// and validate_input (src/InputValidator.cpp): required values, patchset rules per build type,
// payload, rebooter and settings block sizes.

#include "Args.hpp"
#include "InputSample.hpp"
#include "InputValidator.hpp"
#include "support/Expect.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <vector>

namespace gxbuild3::core {
    namespace {

        Input valid_jtag_input() {
            auto input = valid_input();
            input.build_type = BuildType::Jtag;
            input.patches = InputPatches{.automatic = InputPatchFile{"auto", {0x01}}, .addons = {}};
            return input;
        }

        TEST(InputLayout, StoresOneTypedImageLayout) {
            Input input{};
            input.image_type = ImageType::BigBlock;
            EXPECT_EQ(input.image_type, ImageType::BigBlock)
                << "input stores one typed image layout";
        }

        TEST(InputLayout, MobileSlotsMapA0x31ToI0x39AndReject0x30) {
            InputMobileData mobiles{};
            auto* const mobile_a = mobiles.slot(0x31);
            auto* const mobile_i = mobiles.slot(0x39);
            ASSERT_NE(mobile_a, nullptr) << "mobile A maps to 0x31";
            ASSERT_NE(mobile_i, nullptr) << "mobile I maps to 0x39";
            *mobile_a = std::vector<uint8_t>{1};
            *mobile_i = std::vector<uint8_t>{9};
            EXPECT_EQ(mobiles.slot(0x31)->value().front(), uint8_t{1}) << "mobile A maps to 0x31";
            EXPECT_EQ(mobiles.slot(0x39)->value().front(), uint8_t{9}) << "mobile I maps to 0x39";
            EXPECT_EQ(mobiles.slot(0x30), nullptr) << "invalid mobile slot is rejected";
        }

        // One required value removed from an otherwise valid input, and the code it fails with.
        struct MissingRequiredRow {
            const char* name;
            void (*remove)(Input&);
            InputErrorCode code;
            const char* message;
        };
        GX_PRINT_ROW_AS_NAME(MissingRequiredRow)

        class InputMissingRequired : public ::testing::TestWithParam<MissingRequiredRow> {};

        TEST_P(InputMissingRequired, IsRejectedWithItsInputErrorCode) {
            const auto& row = GetParam();
            auto input = valid_input();
            row.remove(input);
            EXPECT_ERROR(validate_input(input), row.code) << row.message;
        }

        INSTANTIATE_TEST_SUITE_P(
            Row, InputMissingRequired,
            ::testing::Values(
                MissingRequiredRow{
                    "CpuKeyOneByteShort", [](Input& input) { input.metadata.cpu_key.pop_back(); },
                    InputErrorCode::InvalidCpuKey, "a CPU key must contain exactly 16 bytes"},
                MissingRequiredRow{"NoSmc", [](Input& input) { input.metadata.smc.reset(); },
                                   InputErrorCode::MissingSmc, "an SMC is required"},
                MissingRequiredRow{"NoKeyvault",
                                   [](Input& input) { input.metadata.keyvault.reset(); },
                                   InputErrorCode::MissingKeyvault, "a keyvault is required"},
                MissingRequiredRow{"NoCb", [](Input& input) { input.bootloaders.cb_or_a.clear(); },
                                   InputErrorCode::MissingCb, "a CB or A bootloader is required"},
                MissingRequiredRow{"NoCd", [](Input& input) { input.bootloaders.cd.clear(); },
                                   InputErrorCode::MissingCd, "a CD bootloader is required"}),
            test::RowName{});

        TEST(InputValidate, Glitch2RequiresPatchset) {
            auto input = valid_input();
            input.build_type = BuildType::Glitch2;
            EXPECT_ERROR(validate_input(input), InputErrorCode::MissingPatchset)
                << "glitch2 requires an automatic patchset";
        }

        TEST(InputValidate, RetailRejectsAutomaticPatchset) {
            auto input = valid_input();
            input.patches = InputPatches{.automatic = InputPatchFile{"auto", {0x01}}, .addons = {}};
            EXPECT_ERROR(validate_input(input), InputErrorCode::UnexpectedPatchset)
                << "retail rejects an automatic patchset";
        }

        // A build type that takes no patch data at all.
        struct AddonRow {
            const char* name;
            BuildType build_type;
        };
        GX_PRINT_ROW_AS_NAME(AddonRow)

        class InputRejectsAddonPatchData : public ::testing::TestWithParam<AddonRow> {};

        TEST_P(InputRejectsAddonPatchData, AsAnUnexpectedPatchset) {
            auto input = valid_input();
            input.build_type = GetParam().build_type;
            input.patches = InputPatches{.automatic = std::nullopt,
                                         .addons = {InputPatchFile{"addon", {0x01}}}};
            EXPECT_ERROR(validate_input(input), InputErrorCode::UnexpectedPatchset)
                << "retail and devkit reject add-on patch data";
        }

        INSTANTIATE_TEST_SUITE_P(Row, InputRejectsAddonPatchData,
                                 ::testing::Values(AddonRow{"Retail", BuildType::Retail},
                                                   AddonRow{"Devkit", BuildType::Devkit}),
                                 test::RowName{});

        TEST(InputValidate, PayloadIs0x200AndRebooterFitsIts0x1000Region) {
            auto input = valid_jtag_input();
            input.payloads = InputPayloads{};
            input.payloads->payload = std::vector<uint8_t>(0x200, 0x00);
            input.payloads->rebooter = std::vector<uint8_t>(0xd40, 0x00);
            EXPECT_OK(validate_input(input)) << "a 0x200 payload with a 0xd40 rebooter is valid";

            input.payloads->rebooter = std::vector<uint8_t>(0x1000, 0x00);
            EXPECT_OK(validate_input(input))
                << "a rebooter that exactly fills its 0x1000-byte region is valid";

            input.payloads->rebooter = std::vector<uint8_t>(0xd40, 0x00);
            input.payloads->payload = std::vector<uint8_t>(0x100, 0x00);
            EXPECT_ERROR(validate_input(input), InputErrorCode::InvalidPayloadSize)
                << "a payload must contain exactly 0x200 bytes";

            input.payloads->payload = std::vector<uint8_t>(0x200, 0x00);
            input.payloads->rebooter = std::vector<uint8_t>(0x1001, 0x00);
            EXPECT_ERROR(validate_input(input), InputErrorCode::InvalidRebooterSize)
                << "a rebooter must not exceed its 0x1000-byte region";
        }

        TEST(InputValidate, SettingsBlocksAre0x400And0x1000) {
            auto input = valid_input();
            input.metadata.smc_config = std::vector<uint8_t>(0x400, 0x00);
            input.metadata.statistics = std::vector<uint8_t>(0x1000, 0xFF);
            input.metadata.manufacturing = std::vector<uint8_t>(0x1000, 0xFF);
            EXPECT_OK(validate_input(input))
                << "0x400 of settings and 0x1000 of statistics and manufacturing are valid";

            input.metadata.smc_config = std::vector<uint8_t>(0x3FF, 0x00);
            EXPECT_ERROR(validate_input(input), InputErrorCode::InvalidSettingsBlockSize)
                << "a settings block must contain exactly 0x400 bytes";

            input.metadata.smc_config.reset();
            input.metadata.manufacturing = std::vector<uint8_t>(0x1001, 0xFF);
            EXPECT_ERROR(validate_input(input), InputErrorCode::InvalidSettingsBlockSize)
                << "a manufacturing block must contain exactly 0x1000 bytes";
        }

    } // namespace
} // namespace gxbuild3::core
