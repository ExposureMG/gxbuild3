// CB_B carries two LDVs: the per-box LDV at +0x23, which pairs it with the console, and the
// display LDV at +0x3B1. The extract_* APIs report the per-box one as the donor's CB LDV,
// inspection reports the display one, and a rebuild keeps both apart.

#include "BuildRunner.hpp"
#include "bootloaders/glitch/GlitchFixture.hpp"
#include "support/Expect.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <optional>

namespace gxbuild3::bootloaders::glitch {
    namespace {

        struct PerboxLdvRow {
            const char* name;
            uint8_t perbox_ldv;
        };
        GX_PRINT_ROW_AS_NAME(PerboxLdvRow)
        constexpr PerboxLdvRow kPerboxLdvRows[] = {
            {"Ldv0", 0},
            {"Ldv7", 7},
        };

        class CbBPerboxLdv : public ::testing::TestWithParam<PerboxLdvRow> {};

        TEST_P(CbBPerboxLdv, ExtractionKeepsThePerBoxLdvApartFromTheDisplayLdv) {
            const unsigned perbox_ldv = GetParam().perbox_ldv;
            auto input = fixture(BuildType::Retail);
            input.metadata.cb_ldv = GetParam().perbox_ldv;
            input.metadata.pairing_data = {1, 2, 3};
            ASSERT_TRUE(input.bootloaders.cb_b.has_value()) << "the retail fixture has a CB_B";
            (*input.bootloaders.cb_b)[0x3B1] = 12;
            const auto donor = run_build(input);
            ASSERT_OK(donor) << "distinct per-box/display LDV donor builds";

            const auto metadata = extract_metadata(*donor, input.metadata.cpu_key);
            const auto extracted = extract_all(*donor, input.metadata.cpu_key);
            const auto info = extract_all_info(*donor, input.metadata.cpu_key);
            ASSERT_OK(metadata) << "distinct LDV donor extracts through all APIs";
            ASSERT_OK(extracted) << "distinct LDV donor extracts through all APIs";
            ASSERT_OK(info) << "distinct LDV donor extracts through all APIs";
            ASSERT_TRUE(info->bootloaders.cb_b.has_value())
                << "distinct LDV donor extracts through all APIs";
            EXPECT_EQ(unsigned{metadata->cb_ldv}, perbox_ldv)
                << "extract_metadata preserves CB_B +0x23 instead of display +0x3B1";
            EXPECT_EQ(unsigned{extracted->metadata.cb_ldv}, perbox_ldv)
                << "extract_all preserves CB_B +0x23 instead of display +0x3B1";
            EXPECT_EQ(info->bootloaders.cb_b->ldv, std::optional<uint8_t>{12})
                << "inspection still reports the independent display LDV";
            EXPECT_EQ(unsigned{info->bootloaders.cb_ldv}, 12u)
                << "inspection still reports the independent display LDV";

            // Exercise both donor-metadata builds and full extract/rebuild workflows.
            for (bool full_extract : {false, true}) {
                SCOPED_TRACE(full_extract ? "extract_all input rebuilt"
                                          : "extract_metadata donor rebuilt");
                auto rebuild_input = full_extract ? *extracted : input;
                if (!full_extract) {
                    rebuild_input.metadata = *metadata;
                    // extract_metadata supplies donor metadata; the resolver supplies SMC
                    // separately.
                    rebuild_input.metadata.smc = input.metadata.smc;
                }
                const auto rebuilt = run_build(rebuild_input);
                ASSERT_OK(rebuilt) << "extracted LDV donor rebuilds";
                const auto decoded = extract_all(*rebuilt, input.metadata.cpu_key);
                ASSERT_OK(decoded) << "rebuilt CB_B decrypts";
                ASSERT_TRUE(decoded->bootloaders.cb_b.has_value()) << "rebuilt CB_B decrypts";
                EXPECT_EQ(unsigned{(*decoded->bootloaders.cb_b)[0x23]}, perbox_ldv)
                    << "rebuild preserves per-box and display LDV independently";
                EXPECT_EQ(unsigned{(*decoded->bootloaders.cb_b)[0x3B1]}, 12u)
                    << "rebuild preserves per-box and display LDV independently";
                EXPECT_OPTIONAL_BYTES_EQ(extracted->bootloaders.cb_b, decoded->bootloaders.cb_b)
                    << "unchanged CB_B rebuild preserves its authenticated plaintext";
            }
        }

        INSTANTIATE_TEST_SUITE_P(Row, CbBPerboxLdv, ::testing::ValuesIn(kPerboxLdvRows),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::bootloaders::glitch
