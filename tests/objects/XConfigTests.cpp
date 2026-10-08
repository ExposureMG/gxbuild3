// src/nand/objects/XConfig.hpp: SmcConfig is deliberately unwired (AGENTS.md: the maintainer
// will generate xconfigs with it), so these cases only name what objects_corpus.txt pins as
// xconfig.base_0x0.* and xconfig.base_0xC000.* lines: serialize(parse(b)) gives back the
// 0x1A18-byte settings region at the base and zero everywhere else in the 64 KiB blob.

#include "nand/objects/XConfig.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        // The settings region: kOffsetSystem 0x1A08 plus the 0x10-byte system settings.
        constexpr size_t kRegion = 0x1A18;
        constexpr size_t kBlob = 0x10000;

        // Each base is reached through its own entry point: SmcConfig's default base 0 and the
        // xconfig namespace's default base 0xC000.
        struct RegionRow {
            const char* name;
            size_t base;
            bool via_xconfig_namespace;
        };
        GX_PRINT_ROW_AS_NAME(RegionRow)
        constexpr RegionRow kRegionRows[] = {
            {"Zero", 0x0000, false},
            {"C000", 0xC000, true},
        };

        // The corpus input: byte i = i * 7 + 3 over the whole blob, so almost every byte outside
        // the region is non-zero.
        Bytes region_pattern() {
            Bytes bytes(kBlob);
            for (size_t i = 0; i < bytes.size(); ++i) {
                bytes[i] = static_cast<uint8_t>(i * 7 + 3);
            }
            return bytes;
        }

        class XConfig : public ::testing::TestWithParam<RegionRow> {};

        TEST_P(XConfig, SerializeOfParseRoundTripsOnlyItsRegion) {
            const auto& row = GetParam();
            const Bytes input = region_pattern();
            ASSERT_OK_AND_ASSIGN(const SmcConfig parsed, row.via_xconfig_namespace
                                                             ? xconfig::parse(input)
                                                             : SmcConfig::parse(input));
            const Bytes out =
                row.via_xconfig_namespace ? xconfig::serialize(parsed) : parsed.serialize();
            ASSERT_EQ(out.size(), kBlob) << "serialize fills the default 64 KiB blob";

            EXPECT_BYTES_EQ(std::span(input).subspan(row.base, kRegion),
                            std::span(out).subspan(row.base, kRegion))
                << "the 0x1A18-byte region at the base round-trips";
            EXPECT_BYTES_EQ(Bytes(row.base, 0), std::span(out).first(row.base))
                << "serialize writes zero before the region";
            EXPECT_BYTES_EQ(Bytes(kBlob - row.base - kRegion, 0),
                            std::span(out).subspan(row.base + kRegion))
                << "serialize writes zero after the region";
        }

        INSTANTIATE_TEST_SUITE_P(Base, XConfig, ::testing::ValuesIn(kRegionRows), test::RowName{});

    } // namespace
} // namespace gxbuild3::nand
